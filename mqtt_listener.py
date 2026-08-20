import base64
import json
import os
import re
import ssl
import threading
import time
import urllib.request

import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from device_registry import accept_hello_counter, get_registered_device, normalize_device_id

OPTIONS_PATH = "/data/options.json"
SUPERVISOR_TOKEN = os.environ.get("SUPERVISOR_TOKEN", "")
COMPACT_ID_RE = re.compile(r"^[0-9a-fA-F]{16}$")
MESSAGE_ID_RE = re.compile(r"^[0-9a-fA-F]{16}$")
MAX_COUNTER = (1 << 63) - 1

RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
MAGENTA = "\033[35m"
RED = "\033[31m"
BLUE = "\033[34m"


def _log(prefix, color, text):
    print(f"{color}{BOLD}[{prefix}]{RESET} {text}", flush=True)


def log_zigbee(text):
    _log("ZIGBEE/MQTT", CYAN, text)


def log_internal(text):
    _log("OTA/INTERNAL", YELLOW, text)


def log_verify(text):
    _log("OTA/VERIFY", GREEN, text)


def log_https(text):
    _log("OTA/HTTPS", MAGENTA, text)


def log_tx(text):
    _log("ZIGBEE/TX", BLUE, text)


def log_error(text):
    _log("OTA/ERROR", RED, text)


CHALLENGE_RETRY_SECONDS = 15
CHALLENGE_MAX_ATTEMPTS = 3
CHALLENGE_PENDING_TTL_SECONDS = 90

pending_challenges = {}
pending_publish_mids = {}
pending_lock = threading.Lock()


def load_options():
    try:
        with open(OPTIONS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def get_mqtt_service():
    req = urllib.request.Request(
        "http://supervisor/services/mqtt",
        headers={"Authorization": f"Bearer {SUPERVISOR_TOKEN}"},
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        payload = json.loads(response.read().decode("utf-8"))
    data = payload.get("data", payload)
    return {
        "host": data["host"],
        "port": int(data["port"]),
        "username": data.get("username") or "",
        "password": data.get("password") or "",
    }


def topic_device_to_compact(topic_device):
    value = topic_device.lower()
    if value.startswith("0x"):
        value = value[2:]
    return value if COMPACT_ID_RE.fullmatch(value) else None


def b64url_decode(value):
    return base64.urlsafe_b64decode(value + ("=" * ((-len(value)) % 4)))


def request_challenge(device_id, ota_port):
    log_internal(f"building challenge request device_id={device_id}")
    body = json.dumps({"device_id": device_id}).encode("utf-8")
    req = urllib.request.Request(
        f"https://127.0.0.1:{ota_port}/api/device/challenge",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    ctx = ssl._create_unverified_context()
    log_https("internal challenge API call -> local OTA service /api/device/challenge")
    with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
        result = json.loads(response.read().decode("utf-8"))
    log_https("internal challenge API call <- HTTP 200")
    return result


def verify_single_hello(payload, topic_device, expected_ecosystem):
    parts = payload.split("|")
    if len(parts) != 3 or parts[0] != "H":
        raise ValueError("HELLO must contain exactly H|counter|signature")

    compact_id = topic_device_to_compact(topic_device)
    if compact_id is None:
        raise ValueError("MQTT topic does not contain a valid Zigbee IEEE address")
    device_id = normalize_device_id(compact_id)

    try:
        counter = int(parts[1], 10)
    except ValueError as exc:
        raise ValueError("HELLO counter is not decimal") from exc
    if counter <= 0 or counter > MAX_COUNTER:
        raise ValueError("HELLO counter is outside supported range")

    signature_raw = b64url_decode(parts[2])
    if len(signature_raw) != 64:
        raise ValueError(f"HELLO raw P-256 signature must be 64 bytes, got {len(signature_raw)}")

    registered = get_registered_device(device_id)
    if registered is None:
        raise ValueError("device certificate is not registered in OTA")
    if registered["ecosystem"] != expected_ecosystem:
        raise ValueError(
            f"registered ecosystem mismatch received={registered['ecosystem']} expected={expected_ecosystem}"
        )
    now = int(time.time())
    if now < int(registered["certificate_not_before"]) or now > int(registered["certificate_not_after"]):
        raise ValueError("registered device certificate is outside its validity period")

    public_key = serialization.load_der_public_key(registered["public_key_der"])
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("registered device public key is not EC")

    r = int.from_bytes(signature_raw[:32], "big")
    s = int.from_bytes(signature_raw[32:], "big")
    signature_der = encode_dss_signature(r, s)
    canonical = f"H|{device_id}|{counter}".encode("utf-8")
    public_key.verify(signature_der, canonical, ec.ECDSA(hashes.SHA256()))

    if not accept_hello_counter(device_id, counter):
        return {"status": "STALE", "device_id": device_id, "counter": counter, "registered": registered}

    return {"status": "ACCEPTED", "device_id": device_id, "counter": counter, "registered": registered}


def publish_pending_challenge(client, base_topic, item, reason):
    command = f"A|{item['message_id']}|{item['challenge']}"
    topic = f"{base_topic}/{item['topic_device']}/set"
    body = json.dumps({"ota_command": command}, separators=(",", ":"))

    log_internal(
        f"challenge assembled device_id={item['device_id']} message_id={item['message_id']} "
        f"bytes={len(command)} attempt={item['attempts']}/{CHALLENGE_MAX_ATTEMPTS}"
    )
    log_tx(f"MQTT publish -> topic={topic} payload=ota_command:A|{item['message_id']}|<64-hex> qos=1 reason={reason}")

    result = client.publish(topic, body, qos=1, retain=False)
    if result.rc != mqtt.MQTT_ERR_SUCCESS:
        raise RuntimeError(f"MQTT publish rejected immediately rc={result.rc}")

    with pending_lock:
        pending_publish_mids[result.mid] = {
            "device_id": item["device_id"],
            "message_id": item["message_id"],
            "reason": reason,
        }

    # Do not wait_for_publish() here. Initial publish is called from Paho's on_message
    # callback; blocking that callback prevents the network loop from processing PUBACK.
    log_tx(
        f"MQTT publish queued mid={result.mid} device_id={item['device_id']} "
        f"message_id={item['message_id']}; PUBACK will be handled asynchronously"
    )


def challenge_retry_loop(client, base_topic):
    while True:
        time.sleep(1)
        now = time.monotonic()
        to_retry = []
        to_drop = []
        with pending_lock:
            for device_id, item in list(pending_challenges.items()):
                age = now - item["created_mono"]
                since_send = now - item["last_sent_mono"]
                if age >= CHALLENGE_PENDING_TTL_SECONDS:
                    to_drop.append((device_id, "ttl"))
                    continue
                if since_send < CHALLENGE_RETRY_SECONDS:
                    continue
                if item["attempts"] >= CHALLENGE_MAX_ATTEMPTS:
                    to_drop.append((device_id, "max_attempts"))
                    continue
                item["attempts"] += 1
                item["last_sent_mono"] = now
                to_retry.append(dict(item))

            for device_id, why in to_drop:
                item = pending_challenges.pop(device_id, None)
                if item:
                    log_error(
                        f"challenge delivery failed device_id={device_id} message_id={item['message_id']} "
                        f"reason={why} attempts={item['attempts']}; no more messages queued"
                    )

        for item in to_retry:
            try:
                publish_pending_challenge(client, base_topic, item, "retry")
            except Exception as exc:
                log_error(f"challenge MQTT retry failed device_id={item['device_id']}: {exc}")


def handle_application_ack(payload, topic_device):
    parts = payload.split("|")
    if len(parts) != 3 or parts[0] != "R" or not MESSAGE_ID_RE.fullmatch(parts[1]):
        log_error(f"transport ACK ignored malformed payload={payload}")
        return

    message_id = parts[1].lower()
    status = parts[2].upper()
    compact_id = topic_device_to_compact(topic_device)
    if compact_id is None:
        return
    device_id = normalize_device_id(compact_id)

    log_zigbee(f"RX application ACK <- ESP device_id={device_id} message_id={message_id} status={status}")
    with pending_lock:
        item = pending_challenges.get(device_id)
        if item is None or item["message_id"].lower() != message_id:
            log_error(f"transport ACK unmatched device_id={device_id} message_id={message_id} status={status}")
            return
        if status == "OK":
            pending_challenges.pop(device_id, None)
            log_verify(
                f"end-to-end challenge delivery confirmed device_id={device_id} message_id={message_id} attempts={item['attempts']}"
            )
        else:
            log_error(f"transport ACK negative device_id={device_id} message_id={message_id} status={status}")


def build_client(base_topic, ota_port, expected_ecosystem):
    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="ota-server-enrollment")
    except (AttributeError, TypeError):
        client = mqtt.Client(client_id="ota-server-enrollment")

    def on_connect(client, userdata, flags, reason_code, properties=None):
        code = int(reason_code) if hasattr(reason_code, "__int__") else reason_code
        if code != 0:
            log_error(f"MQTT connect failed: {reason_code}")
            return
        topic = f"{base_topic}/+/action"
        client.subscribe(topic, qos=0)
        log_zigbee(f"listener subscribed topic={topic}")
        log_internal("transport policy: one outstanding challenge/device; MQTT QoS1 broker ACK; final delivery only after ESP application ACK")

    def on_publish(client, userdata, mid, reason_code=None, properties=None):
        with pending_lock:
            info = pending_publish_mids.pop(mid, None)
        if info is None:
            return
        code = int(reason_code) if reason_code is not None and hasattr(reason_code, "__int__") else 0
        if code not in (0, None):
            log_error(
                f"MQTT broker PUBACK error mid={mid} rc={reason_code} device_id={info['device_id']} "
                f"message_id={info['message_id']}"
            )
            return
        log_tx(
            f"MQTT broker ACK <- challenge accepted by broker device_id={info['device_id']} "
            f"message_id={info['message_id']} mid={mid}; waiting for ESP R|message_id|OK"
        )

    def on_message(client, userdata, message):
        try:
            payload = message.payload.decode("utf-8").strip()
        except UnicodeDecodeError:
            log_error("MQTT RX ignored: non-UTF8 payload")
            return

        topic_parts = message.topic.split("/")
        if len(topic_parts) != 3 or topic_parts[0] != base_topic or topic_parts[2] != "action":
            return

        topic_device = topic_parts[1]
        if payload.startswith("R|"):
            handle_application_ack(payload, topic_device)
            return
        if not payload.startswith("H|"):
            return

        log_zigbee(f"RX HELLO <- device_topic={topic_device} bytes={len(payload)} counter={payload.split('|', 2)[1] if '|' in payload else '?'}")
        log_internal("HELLO received; starting registry/certificate/signature/counter validation")
        try:
            hello = verify_single_hello(payload, topic_device, expected_ecosystem)
        except Exception as e:
            log_error(f"HELLO rejected device_topic={topic_device}: {e}")
            return

        registered = hello["registered"]
        if hello["status"] == "STALE":
            log_error(
                f"HELLO stale/replay device_id={hello['device_id']} counter={hello['counter']} stored_counter={registered['last_hello_counter']}"
            )
            return

        log_verify(
            f"certificate registry OK device_id={hello['device_id']} cert_sha256={registered['certificate_fingerprint']}"
        )
        log_verify(
            f"identity OK ecosystem={registered['ecosystem']} group={registered['device_group']} model={registered['device_model']} "
            f"role={registered['product_role']} hw={registered['hardware_revision']} chip={registered['chip_family']} flash={registered['flash_size']}"
        )
        log_verify(f"ECDSA signature OK device_id={hello['device_id']} counter={hello['counter']} counter_policy=strictly-greater-gaps-allowed")

        now = time.monotonic()
        with pending_lock:
            existing = pending_challenges.get(hello["device_id"])
            if existing is not None:
                log_internal(
                    f"HELLO accepted but challenge already outstanding device_id={hello['device_id']} "
                    f"message_id={existing['message_id']} attempts={existing['attempts']}; no new challenge queued"
                )
                return

        try:
            challenge = request_challenge(hello["device_id"], ota_port)
            message_id = str(challenge["message_id"]).lower()
            challenge_hex = str(challenge["challenge"]).lower()
            if not MESSAGE_ID_RE.fullmatch(message_id):
                raise ValueError("challenge message_id is not 16 hex chars")
            if not re.fullmatch(r"[0-9a-f]{64}", challenge_hex):
                raise ValueError("challenge is not 64 hex chars")
        except Exception as e:
            log_error(f"challenge creation failed device_id={hello['device_id']}: {e}")
            return

        item = {
            "device_id": hello["device_id"],
            "topic_device": topic_device,
            "message_id": message_id,
            "challenge": challenge_hex,
            "attempts": 1,
            "created_mono": now,
            "last_sent_mono": now,
        }
        with pending_lock:
            if hello["device_id"] in pending_challenges:
                return
            pending_challenges[hello["device_id"]] = item

        log_internal(
            f"challenge ready device_id={hello['device_id']} counter={hello['counter']} message_id={message_id}; handing to MQTT"
        )
        try:
            publish_pending_challenge(client, base_topic, item, "initial")
        except Exception as exc:
            log_error(f"challenge MQTT publish failed device_id={hello['device_id']} message_id={message_id}: {exc}")

    client.on_connect = on_connect
    client.on_publish = on_publish
    client.on_message = on_message
    return client


def main():
    options = load_options()
    base_topic = str(options.get("mqtt_base_topic") or "zigbee2mqtt").strip()
    ota_port = int(options.get("ota_port") or 8443)
    expected_ecosystem = str(options.get("ota_ecosystem") or "JaroslavZemanESP").strip()

    while True:
        try:
            service = get_mqtt_service()
            break
        except Exception as e:
            log_error(f"MQTT service unavailable, retrying: {e}")
            time.sleep(3)

    client = build_client(base_topic, ota_port, expected_ecosystem)
    if service["username"]:
        client.username_pw_set(service["username"], service["password"])

    retry_thread = threading.Thread(target=challenge_retry_loop, args=(client, base_topic), name="challenge-retry", daemon=True)
    retry_thread.start()

    while True:
        try:
            log_zigbee(f"connecting MQTT broker {service['host']}:{service['port']}")
            client.connect(service["host"], service["port"], keepalive=60)
            client.loop_forever(retry_first_connection=True)
        except Exception as e:
            log_error(f"MQTT connection error: {e}; retrying")
            time.sleep(3)


if __name__ == "__main__":
    main()
