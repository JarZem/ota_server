import base64
import json
import os
import re
import ssl
import time
import urllib.request
from dataclasses import dataclass, field

import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from device_registry import accept_hello_counter, get_registered_device, normalize_device_id

OPTIONS_PATH = "/data/options.json"
SUPERVISOR_TOKEN = os.environ.get("SUPERVISOR_TOKEN", "")
COMPACT_ID_RE = re.compile(r"^[0-9a-fA-F]{16}$")
TX_RE = re.compile(r"^[0-9a-fA-F]{8}$")
NONCE_RE = re.compile(r"^[0-9a-fA-F]{8}$")
SESSION_TTL = 30


@dataclass
class HelloSession:
    topic_device: str
    protocol: int
    tx: str
    compact_device_id: str
    device_id: str
    counter: int
    nonce: str
    sig_total: int
    canonical: str
    created_at: float = field(default_factory=time.time)
    sig_parts: dict = field(default_factory=dict)


sessions = {}


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


def purge_sessions():
    now = time.time()
    for key in list(sessions):
        if now - sessions[key].created_at > SESSION_TTL:
            print(f"HELLO session expired tx={sessions[key].tx} device={sessions[key].device_id}", flush=True)
            del sessions[key]


def parse_start(parts, topic_device, expected_ecosystem):
    if len(parts) != 7:
        raise ValueError("HELLO H must contain exactly 7 fields")
    _, protocol_text, tx, compact_id, counter_text, nonce, sig_total_text = parts
    protocol = int(protocol_text)
    if protocol != 1:
        raise ValueError("unsupported HELLO protocol")
    if not TX_RE.fullmatch(tx) or not COMPACT_ID_RE.fullmatch(compact_id) or not NONCE_RE.fullmatch(nonce):
        raise ValueError("invalid HELLO transaction/device/nonce field")
    counter = int(counter_text)
    sig_total = int(sig_total_text)
    if counter <= 0 or not (1 <= sig_total <= 4):
        raise ValueError("invalid HELLO counter or signature fragment count")
    topic_compact = topic_device_to_compact(topic_device)
    if topic_compact != compact_id.lower():
        raise ValueError(f"topic/device mismatch topic={topic_compact} hello={compact_id}")

    device_id = normalize_device_id(compact_id)
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

    canonical = f"{protocol}|{compact_id.lower()}|{counter}|{nonce.lower()}|{tx.lower()}"
    return HelloSession(topic_device, protocol, tx.lower(), compact_id.lower(), device_id,
                        counter, nonce.lower(), sig_total, canonical)


def accept_signature_fragment(session, parts):
    if len(parts) != 5 or parts[0] != "S":
        raise ValueError("signature fragment must contain exactly 5 fields")
    _, tx, index_text, total_text, data = parts
    if tx.lower() != session.tx:
        raise ValueError("signature fragment transaction mismatch")
    index = int(index_text)
    total = int(total_text)
    if total != session.sig_total or index < 0 or index >= total:
        raise ValueError("invalid signature fragment index/total")
    session.sig_parts[index] = data


def signature_complete(session):
    return len(session.sig_parts) == session.sig_total and all(i in session.sig_parts for i in range(session.sig_total))


def verify_signed_hello(session):
    registered = get_registered_device(session.device_id)
    if registered is None:
        raise ValueError("registered certificate disappeared")
    signature_b64 = "".join(session.sig_parts[i] for i in range(session.sig_total))
    signature_der = b64url_decode(signature_b64)
    public_key = serialization.load_der_public_key(registered["public_key_der"])
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("registered device public key is not EC")
    public_key.verify(signature_der, session.canonical.encode("utf-8"), ec.ECDSA(hashes.SHA256()))

    if not accept_hello_counter(session.device_id, session.counter):
        raise ValueError("HELLO counter replay or rollback")

    print(
        f"HELLO certificate registry: OK device_id={session.device_id} "
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
        f"HELLO ECDSA signature verification: OK device_id={session.device_id} "
        f"tx={session.tx} counter={session.counter} nonce={session.nonce}",
        flush=True,
    )


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
        print("MQTT enrollment uses OTA device certificate registry; certificates are not transported over Zigbee", flush=True)

    def on_message(client, userdata, message):
        purge_sessions()
        try:
            payload = message.payload.decode("utf-8").strip()
        except UnicodeDecodeError:
            print("MQTT enrollment ignored: non-UTF8 payload", flush=True)
            return

        topic_parts = message.topic.split("/")
        if len(topic_parts) != 3 or topic_parts[0] != base_topic or topic_parts[2] != "action":
            return
        topic_device = topic_parts[1]
        parts = payload.split("|")
        kind = parts[0] if parts else ""

        try:
            if kind == "H":
                session = parse_start(parts, topic_device, expected_ecosystem)
                sessions[(topic_device, session.tx)] = session
                print(
                    f"HELLO start received device_id={session.device_id} tx={session.tx} "
                    f"counter={session.counter} nonce={session.nonce} sig_parts={session.sig_total}",
                    flush=True,
                )
                return

            if kind != "S" or len(parts) < 2:
                return
            key = (topic_device, parts[1].lower())
            session = sessions.get(key)
            if session is None:
                print(f"HELLO signature fragment ignored: no session device={topic_device} tx={parts[1]}", flush=True)
                return

            accept_signature_fragment(session, parts)
            print(
                f"HELLO signature fragment received tx={session.tx} "
                f"progress={len(session.sig_parts)}/{session.sig_total}",
                flush=True,
            )
            if not signature_complete(session):
                return

            verify_signed_hello(session)
            del sessions[key]
        except Exception as e:
            print(f"HELLO rejected device_topic={topic_device}: {e}", flush=True)
            if len(parts) > 1:
                sessions.pop((topic_device, parts[1].lower()), None)
            return

        try:
            challenge = request_challenge(session.device_id, ota_port)
            message_id = str(challenge["message_id"])
            challenge_hex = str(challenge["challenge"])
        except Exception as e:
            print(f"MQTT enrollment challenge creation failed device_id={session.device_id}: {e}", flush=True)
            return

        command = f"A|{message_id}|{challenge_hex}"
        topic = f"{base_topic}/{topic_device}/set"
        body = json.dumps({"ota_command": command}, separators=(",", ":"))
        result = client.publish(topic, body, qos=0, retain=False)
        print(
            f"DEVICE_AUTH_CHALLENGE sent only after registered-cert HELLO verification "
            f"device_id={session.device_id} message_id={message_id} topic={topic} rc={result.rc}",
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
