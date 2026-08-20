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


def log_zigbee(text): _log("ZIGBEE/MQTT", CYAN, text)
def log_internal(text): _log("OTA/STATE", YELLOW, text)
def log_verify(text): _log("OTA/VERIFY", GREEN, text)
def log_crypto(text): _log("OTA/CRYPTO", MAGENTA, text)
def log_tx(text): _log("ZIGBEE/TX", BLUE, text)
def log_error(text): _log("OTA/ERROR", RED, text)


def load_options():
    try:
        with open(OPTIONS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def load_wifi_password(secret_name):
    with open(SECRETS_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    value = str((data.get("wifi_passwords") or {}).get(secret_name) or "")
    if not value:
        raise RuntimeError(f"WiFi secret '{secret_name}' is empty")
    return value


def get_mqtt_service():
    req = urllib.request.Request("http://supervisor/services/mqtt",
                                 headers={"Authorization": f"Bearer {SUPERVISOR_TOKEN}"})
    with urllib.request.urlopen(req, timeout=10) as response:
        payload = json.loads(response.read().decode("utf-8"))
    data = payload.get("data", payload)
    return {"host": data["host"], "port": int(data["port"]),
            "username": data.get("username") or "", "password": data.get("password") or ""}


def topic_device_to_compact(topic_device):
    value = topic_device.lower().removeprefix("0x")
    return value if COMPACT_ID_RE.fullmatch(value) else None


def topic_device_id(topic_device):
    compact = topic_device_to_compact(topic_device)
    return normalize_device_id(compact) if compact else None


def b64url_decode(value):
    return base64.urlsafe_b64decode(value + ("=" * ((-len(value)) % 4)))


def verify_single_hello(payload, topic_device, expected_ecosystem):
    parts = payload.split("|")
    if len(parts) != 3 or parts[0] != "H":
        raise ValueError("HELLO must be H|counter|signature")
    device_id = topic_device_id(topic_device)
    if device_id is None:
        raise ValueError("MQTT topic does not contain valid Zigbee IEEE")
    counter = int(parts[1], 10)
    if counter <= 0 or counter > MAX_COUNTER:
        raise ValueError("HELLO counter outside supported range")
    signature_raw = b64url_decode(parts[2])
    if len(signature_raw) != 64:
        raise ValueError("HELLO signature must decode to 64 bytes")

    registered = get_registered_device(device_id)
    if registered is None:
        raise ValueError("device certificate is not registered")
    if registered["ecosystem"] != expected_ecosystem:
        raise ValueError("registered ecosystem mismatch")
    now = int(time.time())
    if now < int(registered["certificate_not_before"]) or now > int(registered["certificate_not_after"]):
        raise ValueError("device certificate outside validity period")

    public_key = serialization.load_der_public_key(registered["public_key_der"])
    r = int.from_bytes(signature_raw[:32], "big")
    s = int.from_bytes(signature_raw[32:], "big")
    public_key.verify(encode_dss_signature(r, s),
                      f"H|{device_id}|{counter}".encode("ascii"),
                      ec.ECDSA(hashes.SHA256()))
    if not accept_hello_counter(device_id, counter):
        return {"status": "STALE", "device_id": device_id, "counter": counter, "registered": registered}
    return {"status": "ACCEPTED", "device_id": device_id, "counter": counter, "registered": registered}


def publish_command(client, base_topic, topic_device, wire, kind, device_id):
    topic = f"{base_topic}/{topic_device}/set"
    body = json.dumps({"ota_command": wire}, separators=(",", ":"))
    log_tx(f"MQTT -> kind={kind} topic={topic} bytes={len(wire.encode('utf-8'))} qos=1")
    result = client.publish(topic, body, qos=1, retain=False)
    if result.rc != mqtt.MQTT_ERR_SUCCESS:
        raise RuntimeError(f"MQTT publish rejected rc={result.rc}")
    with pending_lock:
        pending_publish_mids[result.mid] = {"kind": kind, "device_id": device_id}


def provisioning_from_options(options):
    return {
        "ssid": str(options.get("wifi_ssid") or ""),
        "password": load_wifi_password(str(options.get("wifi_password_secret") or "main_wifi")),
        "host": str(options.get("ota_host") or "192.168.2.120"),
        "port": int(options.get("ota_port") or 8443),
        "security": str(options.get("wifi_security") or "WPA2"),
        "channel": int(options.get("wifi_channel") or 0),
    }


def session_timeout_loop():
    while True:
        time.sleep(1)
        now = time.monotonic()
        with pending_lock:
            expired = [device_id for device_id, s in pending_sessions.items()
                       if now - s.created_mono >= SESSION_TIMEOUT_SECONDS]
            for device_id in expired:
                s = pending_sessions.pop(device_id)
                log_error(f"session timeout device_id={device_id} state={s.state} counter={s.counter}; state -> IDLE")


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
        log_internal("state machine: IDLE --H--> WAIT_RESPONSE --R--> PROVISIONING_SENT; timeout=60s; replay/out-of-order dropped")

    def on_publish(client, userdata, mid, reason_code=None, properties=None):
        with pending_lock:
            info = pending_publish_mids.pop(mid, None)
        if info:
            log_tx(f"MQTT broker ACK <- kind={info['kind']} device_id={info['device_id']} mid={mid}")

    def on_message(client, userdata, message):
        try:
            payload = message.payload.decode("utf-8").strip()
        except UnicodeDecodeError:
            return
        parts = message.topic.split("/")
        if len(parts) != 3 or parts[0] != base_topic or parts[2] != "action":
            return
        topic_device = parts[1]
        device_id = topic_device_id(topic_device)
        if device_id is None:
            return

        if payload.startswith("R|"):
            with pending_lock:
                session = pending_sessions.get(device_id)
                state = session.state if session else "IDLE"
            if session is None or state != "WAIT_RESPONSE":
                log_error(f"R replay/out-of-order dropped device_id={device_id} state={state}")
                return
            log_zigbee(f"RX R <- device_id={device_id} state=WAIT_RESPONSE bytes={len(payload)}")
            if not verify_response(session, payload):
                log_error(f"R signature rejected device_id={device_id} counter={session.counter}")
                return

            with pending_lock:
                current = pending_sessions.get(device_id)
                if current is not session or current.state != "WAIT_RESPONSE":
                    log_error(f"R replay dropped during state transition device_id={device_id}")
                    return
                session.state = "PROVISIONING_SENT"
            log_verify(f"R signature OK device_id={device_id}; state WAIT_RESPONSE -> PROVISIONING_SENT")

            try:
                config = provisioning_from_options(options)
                wire = build_provisioning(session, **config)
                log_crypto(f"P encrypted AES-256-GCM device_id={device_id} counter={session.counter} bytes={len(wire)}")
                publish_command(client, base_topic, topic_device, wire, "P-provisioning", device_id)
                log_internal(f"P queued device_id={device_id}; no further ESP response required")
            except Exception as exc:
                log_error(f"P creation/send failed device_id={device_id}: {exc}")
            return

        if not payload.startswith("H|"):
            return

        with pending_lock:
            existing = pending_sessions.get(device_id)
            state = existing.state if existing else "IDLE"
        if existing is not None:
            log_error(f"H out-of-order dropped device_id={device_id} state={state}; wait for 60s timeout")
            return

        log_zigbee(f"RX H <- device_id={device_id} state=IDLE bytes={len(payload)}")
        try:
            hello = verify_single_hello(payload, topic_device, expected_ecosystem)
        except Exception as exc:
            log_error(f"H rejected device_id={device_id}: {exc}")
            return
        if hello["status"] == "STALE":
            log_error(f"H replay/stale dropped device_id={device_id} counter={hello['counter']}")
            return

        registered = hello["registered"]
        log_verify(f"H CA/certificate/ECDSA/counter OK device_id={device_id} counter={hello['counter']}")
        try:
            session = build_challenge(device_id, topic_device, hello["counter"],
                                      registered["public_key_der"], time.monotonic())
        except Exception as exc:
            log_error(f"A creation failed device_id={device_id}: {exc}")
            return

        with pending_lock:
            if device_id in pending_sessions:
                log_error(f"H race/replay dropped device_id={device_id}")
                return
            pending_sessions[device_id] = session
        log_internal(f"state IDLE -> WAIT_RESPONSE device_id={device_id} counter={session.counter}")
        log_crypto(f"A signed ECDSA-P256 random_bytes=8 wire_bytes={len(session.challenge_wire)} session_key=ECDH+counter+random")
        try:
            publish_command(client, base_topic, topic_device, session.challenge_wire, "A-challenge", device_id)
        except Exception as exc:
            log_error(f"A MQTT publish failed device_id={device_id}: {exc}")

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
