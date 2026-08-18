import base64
import json
import os
import re
import ssl
import time
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone

import paho.mqtt.client as mqtt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

OPTIONS_PATH = "/data/options.json"
ROOT_CA_CERT_PATH = "/share/ota_server/cert/root_ca_cert.pem"
SUPERVISOR_TOKEN = os.environ.get("SUPERVISOR_TOKEN", "")
DEVICE_ID_RE = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){7}$")
TX_RE = re.compile(r"^[0-9a-fA-F]{8}$")
SESSION_TTL = 30
HELLO_FIELD_COUNT = 12


@dataclass
class HelloSession:
    topic_device: str
    protocol: int
    tx: str
    data_total: int
    cert_total: int
    sig_total: int
    created_at: float = field(default_factory=time.time)
    data_parts: dict = field(default_factory=dict)
    cert_parts: dict = field(default_factory=dict)
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


def topic_device_to_id(topic_device):
    value = topic_device.lower()
    if value.startswith("0x"):
        value = value[2:]
    if not re.fullmatch(r"[0-9a-f]{16}", value):
        return None
    return ":".join(value[i:i + 2] for i in range(0, 16, 2))


def b64url_decode(value):
    padding_len = (-len(value)) % 4
    return base64.urlsafe_b64decode(value + ("=" * padding_len))


def fingerprint_hex(cert):
    return cert.fingerprint(hashes.SHA256()).hex()


def load_root_ca():
    with open(ROOT_CA_CERT_PATH, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def verify_certificate_with_root(cert, root):
    now = datetime.now(timezone.utc)
    not_before = getattr(cert, "not_valid_before_utc", cert.not_valid_before.replace(tzinfo=timezone.utc))
    not_after = getattr(cert, "not_valid_after_utc", cert.not_valid_after.replace(tzinfo=timezone.utc))
    if now < not_before or now > not_after:
        raise ValueError("device certificate is outside its validity period")
    if cert.issuer != root.subject:
        raise ValueError("device certificate issuer does not match configured Root CA")

    root_key = root.public_key()
    if isinstance(root_key, ec.EllipticCurvePublicKey):
        root_key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
    elif isinstance(root_key, rsa.RSAPublicKey):
        root_key.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
    else:
        raise ValueError("unsupported Root CA public key type")


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
            print(f"HELLO session expired tx={sessions[key].tx} device={sessions[key].topic_device}", flush=True)
            del sessions[key]


def parse_start(parts, topic_device):
    if len(parts) != 6:
        raise ValueError("H0 must contain exactly 6 fields")
    protocol = int(parts[1])
    tx = parts[2]
    data_total = int(parts[3])
    cert_total = int(parts[4])
    sig_total = int(parts[5])
    if protocol != 1 or not TX_RE.fullmatch(tx):
        raise ValueError("invalid HELLO protocol or transaction id")
    if not (1 <= data_total <= 32 and 1 <= cert_total <= 64 and 1 <= sig_total <= 8):
        raise ValueError("invalid HELLO fragment counts")
    return HelloSession(topic_device, protocol, tx, data_total, cert_total, sig_total)


def accept_fragment(session, parts):
    if len(parts) != 5:
        raise ValueError("HELLO fragment must contain exactly 5 fields")
    kind, tx, index_text, total_text, data = parts
    if tx != session.tx:
        raise ValueError("fragment transaction mismatch")
    index = int(index_text)
    total = int(total_text)
    target = {
        "HD": (session.data_parts, session.data_total),
        "HC": (session.cert_parts, session.cert_total),
        "HS": (session.sig_parts, session.sig_total),
    }.get(kind)
    if target is None:
        raise ValueError("unknown HELLO fragment type")
    store, expected_total = target
    if total != expected_total or index < 0 or index >= total:
        raise ValueError("invalid HELLO fragment index/total")
    store[index] = data


def series_complete(parts, total):
    return len(parts) == total and all(i in parts for i in range(total))


def join_series(parts, total):
    return "".join(parts[i] for i in range(total))


def verify_complete_hello(session, expected_ecosystem):
    canonical = join_series(session.data_parts, session.data_total)
    cert_b64 = join_series(session.cert_parts, session.cert_total)
    signature_b64 = join_series(session.sig_parts, session.sig_total)

    fields = canonical.split("|")
    if len(fields) != HELLO_FIELD_COUNT:
        raise ValueError(f"canonical HELLO field count={len(fields)} expected={HELLO_FIELD_COUNT}")

    protocol, device_id, ecosystem, device_model, product_role, hardware_revision, chip_family, flash_size, firmware_version, firmware_channel, key_id, public_key_b64 = fields
    if int(protocol) != session.protocol:
        raise ValueError("canonical protocol mismatch")
    if not DEVICE_ID_RE.fullmatch(device_id):
        raise ValueError("invalid canonical device_id")
    topic_device_id = topic_device_to_id(session.topic_device)
    if topic_device_id != device_id.lower():
        raise ValueError(f"topic/device mismatch topic={topic_device_id} hello={device_id}")
    if ecosystem != expected_ecosystem:
        raise ValueError(f"ecosystem mismatch received={ecosystem} expected={expected_ecosystem}")

    cert_der = b64url_decode(cert_b64)
    cert = x509.load_der_x509_certificate(cert_der)
    root = load_root_ca()

    print(
        f"HELLO certificate assembled device_id={device_id} tx={session.tx} "
        f"chunks={session.cert_total} der_bytes={len(cert_der)}",
        flush=True,
    )
    print(
        f"HELLO certificate subject={cert.subject.rfc4514_string()} issuer={cert.issuer.rfc4514_string()}",
        flush=True,
    )
    print(f"HELLO certificate fingerprint_sha256={fingerprint_hex(cert)}", flush=True)

    verify_certificate_with_root(cert, root)
    print(f"HELLO certificate CA verification: OK device_id={device_id}", flush=True)

    sent_public_key_der = b64url_decode(public_key_b64)
    cert_public_key_der = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if sent_public_key_der != cert_public_key_der:
        raise ValueError("HELLO public key does not match certificate")
    print(f"HELLO certificate/public-key binding: OK key_id={key_id}", flush=True)

    signature_der = b64url_decode(signature_b64)
    cert_key = cert.public_key()
    if not isinstance(cert_key, ec.EllipticCurvePublicKey):
        raise ValueError("device certificate public key is not EC")
    cert_key.verify(signature_der, canonical.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    print(f"HELLO ECDSA signature verification: OK device_id={device_id} tx={session.tx}", flush=True)

    metadata = {
        "device_id": device_id.lower(),
        "ecosystem": ecosystem,
        "device_model": device_model,
        "product_role": product_role,
        "hardware_revision": hardware_revision,
        "chip_family": chip_family,
        "flash_size": flash_size,
        "firmware_version": firmware_version,
        "firmware_channel": firmware_channel,
        "key_id": int(key_id),
        "certificate_fingerprint": fingerprint_hex(cert),
    }
    print(
        "HELLO identity verified: "
        + " ".join(f"{k}={v}" for k, v in metadata.items()),
        flush=True,
    )
    return metadata


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
        print(f"MQTT enrollment Root CA: {ROOT_CA_CERT_PATH}", flush=True)

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
            if kind == "H0":
                session = parse_start(parts, topic_device)
                sessions[(topic_device, session.tx)] = session
                print(
                    f"HELLO start received device_topic={topic_device} tx={session.tx} "
                    f"parts=data:{session.data_total} cert:{session.cert_total} sig:{session.sig_total}",
                    flush=True,
                )
                return

            if kind not in ("HD", "HC", "HS") or len(parts) < 2:
                return
            key = (topic_device, parts[1])
            session = sessions.get(key)
            if session is None:
                print(f"HELLO fragment ignored: no session device={topic_device} tx={parts[1]}", flush=True)
                return

            accept_fragment(session, parts)
            print(
                f"HELLO fragment received type={kind} tx={session.tx} "
                f"progress=data:{len(session.data_parts)}/{session.data_total} "
                f"cert:{len(session.cert_parts)}/{session.cert_total} "
                f"sig:{len(session.sig_parts)}/{session.sig_total}",
                flush=True,
            )

            if not (series_complete(session.data_parts, session.data_total) and
                    series_complete(session.cert_parts, session.cert_total) and
                    series_complete(session.sig_parts, session.sig_total)):
                return

            metadata = verify_complete_hello(session, expected_ecosystem)
            del sessions[key]
        except Exception as e:
            print(f"HELLO rejected device_topic={topic_device}: {e}", flush=True)
            if len(parts) > 1:
                sessions.pop((topic_device, parts[1]), None)
            return

        device_id = metadata["device_id"]
        try:
            challenge = request_challenge(device_id, ota_port)
            message_id = str(challenge["message_id"])
            challenge_hex = str(challenge["challenge"])
        except Exception as e:
            print(f"MQTT enrollment challenge creation failed device_id={device_id}: {e}", flush=True)
            return

        command = f"A|{message_id}|{challenge_hex}"
        topic = f"{base_topic}/{topic_device}/set"
        body = json.dumps({"ota_command": command}, separators=(",", ":"))
        result = client.publish(topic, body, qos=0, retain=False)
        print(
            f"DEVICE_AUTH_CHALLENGE sent only after verified HELLO device_id={device_id} "
            f"message_id={message_id} topic={topic} rc={result.rc}",
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

    try:
        root = load_root_ca()
        print(
            f"MQTT enrollment Root CA loaded subject={root.subject.rfc4514_string()} "
            f"fingerprint_sha256={fingerprint_hex(root)}",
            flush=True,
        )
    except Exception as e:
        raise RuntimeError(f"Root CA required for device HELLO verification: {e}") from e

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
