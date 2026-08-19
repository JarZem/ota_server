import base64
import json
import os
import re
import ssl
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
MAX_COUNTER = (1 << 63) - 1


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
    body = json.dumps({"device_id": device_id}).encode("utf-8")
    req = urllib.request.Request(
        f"https://127.0.0.1:{ota_port}/api/device/challenge",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    ctx = ssl._create_unverified_context()
    with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
        return json.loads(response.read().decode("utf-8"))


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
        return {
            "status": "STALE",
            "device_id": device_id,
            "counter": counter,
            "registered": registered,
        }

    return {
        "status": "ACCEPTED",
        "device_id": device_id,
        "counter": counter,
        "registered": registered,
    }


def build_client(base_topic, ota_port, expected_ecosystem):
    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="ota-server-enrollment")
    except (AttributeError, TypeError):
        client = mqtt.Client(client_id="ota-server-enrollment")

    def on_connect(client, userdata, flags, reason_code, properties=None):
        code = int(reason_code) if hasattr(reason_code, "__int__") else reason_code
        if code != 0:
            print(f"MQTT enrollment connect failed: {reason_code}", flush=True)
            return
        topic = f"{base_topic}/+/action"
        client.subscribe(topic, qos=0)
        print(f"MQTT enrollment listener subscribed: {topic}", flush=True)
        print("MQTT enrollment uses single-frame signed HELLO + OTA device certificate registry", flush=True)

    def on_message(client, userdata, message):
        try:
            payload = message.payload.decode("utf-8").strip()
        except UnicodeDecodeError:
            print("MQTT enrollment ignored: non-UTF8 payload", flush=True)
            return

        topic_parts = message.topic.split("/")
        if len(topic_parts) != 3 or topic_parts[0] != base_topic or topic_parts[2] != "action":
            return
        if not payload.startswith("H|"):
            return

        topic_device = topic_parts[1]
        try:
            hello = verify_single_hello(payload, topic_device, expected_ecosystem)
        except Exception as e:
            print(f"HELLO rejected device_topic={topic_device}: {e}", flush=True)
            return

        registered = hello["registered"]
        if hello["status"] == "STALE":
            print(
                f"HELLO stale/replay ignored device_id={hello['device_id']} counter={hello['counter']} "
                f"stored_counter={registered['last_hello_counter']}",
                flush=True,
            )
            return

        print(
            f"HELLO certificate registry: OK device_id={hello['device_id']} "
            f"cert_sha256={registered['certificate_fingerprint']} subject={registered['certificate_subject']}",
            flush=True,
        )
        print(
            f"HELLO identity from certificate: ecosystem={registered['ecosystem']} "
            f"group={registered['device_group']} model={registered['device_model']} "
            f"role={registered['product_role']} hw={registered['hardware_revision']} "
            f"chip={registered['chip_family']} flash={registered['flash_size']}",
            flush=True,
        )
        print(
            f"HELLO ECDSA signature verification: OK device_id={hello['device_id']} "
            f"counter={hello['counter']} counter_policy=strictly-greater-gaps-allowed",
            flush=True,
        )

        try:
            challenge = request_challenge(hello["device_id"], ota_port)
            message_id = str(challenge["message_id"])
            challenge_hex = str(challenge["challenge"])
        except Exception as e:
            print(f"MQTT enrollment challenge creation failed device_id={hello['device_id']}: {e}", flush=True)
            return

        command = f"A|{message_id}|{challenge_hex}"
        topic = f"{base_topic}/{topic_device}/set"
        body = json.dumps({"ota_command": command}, separators=(",", ":"))
        result = client.publish(topic, body, qos=0, retain=False)
        print(
            f"DEVICE_AUTH_CHALLENGE sent after single-frame registered-cert HELLO verification "
            f"device_id={hello['device_id']} message_id={message_id} topic={topic} rc={result.rc}",
            flush=True,
        )

    client.on_connect = on_connect
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
            print(f"MQTT service unavailable, retrying: {e}", flush=True)
            time.sleep(3)

    client = build_client(base_topic, ota_port, expected_ecosystem)
    if service["username"]:
        client.username_pw_set(service["username"], service["password"])

    while True:
        try:
            print(f"MQTT enrollment connecting to {service['host']}:{service['port']}", flush=True)
            client.connect(service["host"], service["port"], keepalive=60)
            client.loop_forever(retry_first_connection=True)
        except Exception as e:
            print(f"MQTT enrollment connection error: {e}; retrying", flush=True)
            time.sleep(3)


if __name__ == "__main__":
    main()
