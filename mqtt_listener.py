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

from activity import firmware_device_state
from device_registry import accept_hello_counter, get_registered_device, normalize_device_id
from ota_check_security import confirm_completed_download_b64, save_provisioning_context
from secure_transport import build_challenge, build_provisioning, verify_response

OPTIONS_PATH = "/data/options.json"
SECRETS_PATH = "/share/ota_server/secrets.json"
SUPERVISOR_TOKEN = os.environ.get("SUPERVISOR_TOKEN", "")
COMPACT_ID_RE = re.compile(r"^[0-9a-fA-F]{16}$")
MAX_COUNTER = (1 << 63) - 1
SESSION_TIMEOUT_SECONDS = 120
PROVISIONING_FINISHED_STATUS = 0x42

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
                log_error(f"session timeout device_id={device_id} state={s.state} counter={s.counter}; current attempt discarded")


def extract_protocol_payload(message, base_topic):
    parts = message.topic.split("/")

    if len(parts) == 3 and parts[0] == base_topic and parts[2] == "action":
        try:
            payload = message.payload.decode("utf-8").strip()
        except UnicodeDecodeError:
            return None, None
        return parts[1], payload

    if len(parts) == 2 and parts[0] == base_topic:
        try:
            state = json.loads(message.payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
            return None, None
        payload = state.get("ota_transport") if isinstance(state, dict) else None
        if isinstance(payload, str) and payload:
            return parts[1], payload

    return None, None


def handle_control_state(device_id, payload):
    parts = payload.split("|")
    if len(parts) != 3 or parts[0] != "T":
        return False
    try:
        enabled = int(parts[1], 10)
        status = int(parts[2], 16)
    except ValueError:
        log_error(f"control-state frame malformed device_id={device_id} payload={payload}")
        return True

    if enabled != 0 or status != PROVISIONING_FINISHED_STATUS:
        return True

    with pending_lock:
        session = pending_sessions.get(device_id)
        if session is None or session.state != "PROVISIONING_SENT":
            log_internal(f"provisioning-finished confirmation ignored device_id={device_id}; no matching active attempt")
            return True
        pending_sessions.pop(device_id, None)

    try:
        save_provisioning_context(device_id, session.counter, session.random8)
    except Exception as exc:
        log_error(f"provisioning completed on ESP but durable OTA context save failed device_id={device_id}: {exc}")
        return True

    log_verify(f"provisioning completed device_id={device_id} counter={session.counter}; durable context updated; server returned to idle")
    return True


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
        state_topic = f"{base_topic}/+"
        action_topic = f"{base_topic}/+/action"
        client.subscribe(state_topic, qos=0)
        client.subscribe(action_topic, qos=0)
        log_zigbee(f"listener subscribed topic={state_topic} field=ota_transport")
        log_zigbee(f"compatibility listener subscribed topic={action_topic}")
        log_internal("provisioning state machine ready: new authenticated HELLO may restart an unfinished attempt; provisioning context changes only after ESP confirms completion")

    def on_publish(client, userdata, mid, reason_code=None, properties=None):
        with pending_lock:
            info = pending_publish_mids.pop(mid, None)
        if info:
            log_tx(f"MQTT broker ACK <- kind={info['kind']} device_id={info['device_id']} mid={mid}")

    def on_message(client, userdata, message):
        topic_device, payload = extract_protocol_payload(message, base_topic)
        if not topic_device or not payload:
            return
        device_id = topic_device_id(topic_device)
        if device_id is None:
            return
        if not (payload.startswith("H|") or payload.startswith("R|") or payload.startswith("F|") or payload.startswith("T|")):
            return

        log_zigbee(f"protocol frame topic={message.topic} device_id={device_id} bytes={len(payload)} kind={payload[:1]}")

        if payload.startswith("T|"):
            handle_control_state(device_id, payload)
            return

        if payload.startswith("F|"):
            parts = payload.split("|")
            if len(parts) != 2 or not parts[1]:
                log_error(f"F completion malformed device_id={device_id}")
                return
            completed = confirm_completed_download_b64(device_id, parts[1])
            if not completed:
                log_error(f"OTA firmware confirmation rejected device_id={device_id}; no matching completed HTTPS transfer")
                return
            firmware_device_state(
                device_id=device_id,
                sha256=completed["sha256"],
                filename=completed["firmware_filename"],
                version=completed["version"],
                code=completed["code"],
                state="DEVICE_CONFIRMED",
            )
            log_verify(
                f"OTA firmware confirmed by ESP device_id={device_id} filename={completed['firmware_filename']} "
                f"sha256={completed['sha256'][:12]} random={parts[1]}"
            )
            return

        if payload.startswith("R|"):
            with pending_lock:
                session = pending_sessions.get(device_id)
                state = session.state if session else "IDLE"
            if session is None or state != "WAIT_RESPONSE":
                log_internal(f"R ignored device_id={device_id}; current state={state}, expected device response")
                return
            log_zigbee(f"RX R <- device_id={device_id} state=WAIT_RESPONSE bytes={len(payload)}")
            if not verify_response(session, payload):
                log_error(f"R signature rejected device_id={device_id} counter={session.counter}")
                return

            with pending_lock:
                current = pending_sessions.get(device_id)
                if current is not session or current.state != "WAIT_RESPONSE":
                    log_internal(f"R ignored after concurrent state change device_id={device_id}")
                    return
                session.state = "PROVISIONING_SENT"
            log_verify(f"R signature OK device_id={device_id}; sending encrypted provisioning")

            try:
                config = provisioning_from_options(options)
                wire = build_provisioning(session, **config)
                log_crypto(f"P encrypted AES-256-GCM device_id={device_id} counter={session.counter} bytes={len(wire)}")
                publish_command(client, base_topic, topic_device, wire, "P-provisioning", device_id)
                log_internal(f"P queued device_id={device_id} counter={session.counter}; waiting for ESP completion confirmation before replacing durable context")
            except Exception as exc:
                log_error(f"P creation/send failed device_id={device_id}: {exc}")
                with pending_lock:
                    if pending_sessions.get(device_id) is session:
                        pending_sessions.pop(device_id, None)
            return

        log_zigbee(f"RX H <- device_id={device_id} bytes={len(payload)}")
        try:
            hello = verify_single_hello(payload, topic_device, expected_ecosystem)
        except Exception as exc:
            log_error(f"H rejected device_id={device_id}: {exc}")
            return
        if hello["status"] == "STALE":
            log_internal(f"H ignored as stale/replayed device_id={device_id} counter={hello['counter']}")
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
            previous = pending_sessions.get(device_id)
            pending_sessions[device_id] = session
        if previous is not None:
            log_internal(f"new authenticated H replaced unfinished attempt device_id={device_id} old_state={previous.state} old_counter={previous.counter} new_counter={session.counter}")
        else:
            log_internal(f"new provisioning attempt accepted device_id={device_id} counter={session.counter}")

        log_crypto(f"A signed ECDSA-P256 random_bytes=8 wire_bytes={len(session.challenge_wire)} session_key=ECDH+counter+random")
        try:
            publish_command(client, base_topic, topic_device, session.challenge_wire, "A-challenge", device_id)
        except Exception as exc:
            log_error(f"A MQTT publish failed device_id={device_id}: {exc}")
            with pending_lock:
                if pending_sessions.get(device_id) is session:
                    pending_sessions.pop(device_id, None)

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
