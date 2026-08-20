import base64
import json
import os
import re
import threading
import time
import urllib.request

import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from device_registry import accept_hello_counter, get_registered_device, normalize_device_id
from secure_transport import build_challenge, build_provisioning, verify_response

OPTIONS_PATH = "/data/options.json"
SECRETS_PATH = "/share/ota_server/secrets.json"
SUPERVISOR_TOKEN = os.environ.get("SUPERVISOR_TOKEN", "")
COMPACT_ID_RE = re.compile(r"^[0-9a-fA-F]{16}$")
MAX_COUNTER = (1 << 63) - 1
SESSION_TIMEOUT_SECONDS = 60

RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
MAGENTA = "\033[35m"
RED = "\033[31m"
BLUE = "\033[34m"

pending_sessions = {}
pending_publish_mids = {}
pending_lock = threading.Lock()


def _log(prefix, color, text):
    print(f"{color}{BOLD}[{prefix}]{RESET} {text}", flush=True)


def log_zigbee(text):
    _log("ZIGBEE/MQTT", CYAN, text)


def log_internal(text):
    _log("OTA/INTERNAL", YELLOW, text)


def log_verify(text):
    _log("OTA/VERIFY", GREEN, text)


def log_crypto(text):
    _log("OTA/CRYPTO", MAGENTA, text)


def log_tx(text):
    _log("ZIGBEE/TX", BLUE, text)


def log_error(text):
    _log("OTA/ERROR", RED, text)


def load_options():
    try:
        with open(OPTIONS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def load_wifi_password(secret_name):
    try:
        with open(SECRETS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return str((data.get("wifi_passwords") or {}).get(secret_name) or "")
    except Exception as exc:
        raise RuntimeError(f"cannot load WiFi secret '{secret_name}': {exc}") from exc


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


def publish_command(client, base_topic, topic_device, wire, kind, device_id):
    topic = f"{base_topic}/{topic_device}/set"
    body = json.dumps({"ota_command": wire}, separators=(",", ":"))
    log_tx(f"MQTT publish -> kind={kind} topic={topic} zigbee_bytes={len(wire.encode('utf-8'))} qos=1")
    result = client.publish(topic, body, qos=1, retain=False)
    if result.rc != mqtt.MQTT_ERR_SUCCESS:
        raise RuntimeError(f"MQTT publish rejected immediately rc={result.rc}")
    with pending_lock:
        pending_publish_mids[result.mid] = {"kind": kind, "device_id": device_id}
    return result.mid


def provisioning_from_options(options):
    secret_name = str(options.get("wifi_password_secret") or "main_wifi")
    password = load_wifi_password(secret_name)
    if not password:
        raise RuntimeError(f"WiFi password secret '{secret_name}' is empty")
    return {
        "ssid": str(options.get("wifi_ssid") or ""),
        "password": password,
        "host": str(options.get("ota_host") or "192.168.2.120"),
        "port": int(options.get("ota_port") or 8443),
        "security": str(options.get("wifi_security") or "WPA2"),
        "channel": int(options.get("wifi_channel") or 0),
    }


def session_timeout_loop():
    while True:
        time.sleep(1)
        now = time.monotonic()
        expired = []
        with pending_lock:
            for device_id, session in list(pending_sessions.items()):
                if now - session.created_mono >= SESSION_TIMEOUT_SECONDS:
                    expired.append(device_id)
            for device_id in expired:
                session = pending_sessions.pop(device_id, None)
                if session is not None:
                    log_error(
                        f"secure flow timed out device_id={device_id} counter={session.counter}; "
                        "no transport retry queued; ESP will restart from HELLO after 60 s"
                    )


def build_client(base_topic, expected_ecosystem, options):
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
        log_internal(
            "protocol: HELLO -> one authenticated A1 challenge -> one R1 success -> immediate encrypted P1 provisioning; "
            "no extra OTA/ESP ping-pong; whole flow restarts after 60 s on failure"
        )

    def on_publish(client, userdata, mid, reason_code=None, properties=None):
        with pending_lock:
            info = pending_publish_mids.pop(mid, None)
        if info is None:
            return
        code = int(reason_code) if reason_code is not None and hasattr(reason_code, "__int__") else 0
        if code not in (0, None):
            log_error(f"MQTT PUBACK error kind={info['kind']} device_id={info['device_id']} mid={mid} rc={reason_code}")
            return
        log_tx(f"MQTT broker ACK <- kind={info['kind']} device_id={info['device_id']} mid={mid}")

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

        if payload.startswith("R1|"):
            compact_id = topic_device_to_compact(topic_device)
            if compact_id is None:
                return
            device_id = normalize_device_id(compact_id)
            with pending_lock:
                session = pending_sessions.get(device_id)
            if session is None:
                log_error(f"R1 ignored: no pending secure session device_id={device_id}")
                return
            log_zigbee(f"RX challenge SUCCESS <- device_id={device_id} counter={session.counter} bytes={len(payload)}")
            if not verify_response(session, payload):
                log_error(f"R1 authentication failed device_id={device_id} counter={session.counter}")
                return
            log_verify(f"challenge response VERIFIED device_id={device_id} counter={session.counter}")

            try:
                config = provisioning_from_options(options)
                wire = build_provisioning(session, **config)
                log_crypto(
                    f"provisioning encrypted+authenticated device_id={device_id} counter={session.counter} "
                    f"ssid={config['ssid']} ota={config['host']}:{config['port']} security={config['security']} "
                    f"channel={config['channel']} password_len={len(config['password'])}"
                )
                publish_command(client, base_topic, topic_device, wire, "P1-provisioning", device_id)
                log_internal(
                    f"provisioning queued immediately after verified R1 device_id={device_id}; "
                    "protocol ends here, no further ESP response is required"
                )
            except Exception as exc:
                log_error(f"provisioning creation/send failed device_id={device_id}: {exc}")
            finally:
                with pending_lock:
                    pending_sessions.pop(device_id, None)
            return

        if not payload.startswith("H|"):
            return

        counter_text = payload.split("|", 2)[1] if "|" in payload else "?"
        log_zigbee(f"RX HELLO <- device_topic={topic_device} bytes={len(payload)} counter={counter_text}")
        log_internal("HELLO received; validating registered CA certificate, ECDSA signature and monotonic counter")
        try:
            hello = verify_single_hello(payload, topic_device, expected_ecosystem)
        except Exception as exc:
            log_error(f"HELLO rejected device_topic={topic_device}: {exc}")
            return

        registered = hello["registered"]
        if hello["status"] == "STALE":
            log_error(
                f"HELLO stale/replay device_id={hello['device_id']} counter={hello['counter']} "
                f"stored_counter={registered['last_hello_counter']}"
            )
            return

        log_verify(
            f"HELLO CA registry OK device_id={hello['device_id']} cert_sha256={registered['certificate_fingerprint']}"
        )
        log_verify(
            f"HELLO ECDSA signature OK device_id={hello['device_id']} counter={hello['counter']} "
            "counter_policy=strictly-greater-gaps-allowed"
        )

        try:
            session = build_challenge(
                hello["device_id"], topic_device, hello["counter"],
                registered["public_key_der"], time.monotonic(),
            )
        except Exception as exc:
            log_error(f"A1 challenge creation failed device_id={hello['device_id']}: {exc}")
            return

        with pending_lock:
            pending_sessions[hello["device_id"]] = session

        log_crypto(
            f"A1 challenge assembled device_id={hello['device_id']} counter={hello['counter']} "
            f"random_bytes=16 crc32={session.crc32:08x} auth=HMAC-SHA256(ECDH-P256,CA-bound) "
            f"wire_bytes={len(session.challenge_wire)}"
        )
        try:
            publish_command(client, base_topic, topic_device, session.challenge_wire, "A1-challenge", hello["device_id"])
        except Exception as exc:
            with pending_lock:
                pending_sessions.pop(hello["device_id"], None)
            log_error(f"A1 challenge MQTT publish failed device_id={hello['device_id']}: {exc}")

    client.on_connect = on_connect
    client.on_publish = on_publish
    client.on_message = on_message
    return client


def main():
    options = load_options()
    base_topic = str(options.get("mqtt_base_topic") or "zigbee2mqtt")
    expected_ecosystem = str(options.get("ota_ecosystem") or "JaroslavZemanESP")
    service = get_mqtt_service()

    log_zigbee(f"connecting MQTT broker {service['host']}:{service['port']}")
    client = build_client(base_topic, expected_ecosystem, options)
    if service["username"]:
        client.username_pw_set(service["username"], service["password"])
    client.connect(service["host"], service["port"], keepalive=60)

    threading.Thread(target=session_timeout_loop, daemon=True, name="ota-secure-timeout").start()
    client.loop_forever()


if __name__ == "__main__":
    main()
