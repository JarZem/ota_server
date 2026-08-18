import json
import os
import re
import ssl
import time
import urllib.error
import urllib.request

import paho.mqtt.client as mqtt

OPTIONS_PATH = "/data/options.json"
SUPERVISOR_TOKEN = os.environ.get("SUPERVISOR_TOKEN", "")
DEVICE_ID_RE = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){7}$")


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


def build_client(base_topic, ota_port):
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

    def on_message(client, userdata, message):
        try:
            payload = message.payload.decode("utf-8").strip()
        except UnicodeDecodeError:
            print("MQTT enrollment ignored: non-UTF8 payload", flush=True)
            return

        parts = message.topic.split("/")
        if len(parts) != 3 or parts[0] != base_topic or parts[2] != "action":
            return
        if not payload.startswith("H|"):
            return

        device_id = payload[2:].strip().lower()
        topic_device_id = topic_device_to_id(parts[1])
        if not DEVICE_ID_RE.fullmatch(device_id):
            print(f"MQTT enrollment HELLO rejected: invalid device_id={device_id}", flush=True)
            return
        if topic_device_id is None or topic_device_id != device_id:
            print(
                f"MQTT enrollment HELLO rejected: topic_device={parts[1]} payload_device={device_id}",
                flush=True,
            )
            return

        print(f"MQTT enrollment HELLO received device_id={device_id}", flush=True)
        try:
            challenge = request_challenge(device_id, ota_port)
            message_id = str(challenge["message_id"])
            challenge_hex = str(challenge["challenge"])
        except Exception as e:
            print(f"MQTT enrollment challenge creation failed device_id={device_id}: {e}", flush=True)
            return

        command = f"A|{message_id}|{challenge_hex}"
        if len(command.encode("utf-8")) > 254:
            print("MQTT enrollment challenge too long for Zigbee attribute", flush=True)
            return

        topic = f"{base_topic}/{parts[1]}/set"
        body = json.dumps({"ota_command": command}, separators=(",", ":"))
        result = client.publish(topic, body, qos=0, retain=False)
        print(
            f"MQTT enrollment challenge sent device_id={device_id} topic={topic} rc={result.rc}",
            flush=True,
        )

    client.on_connect = on_connect
    client.on_message = on_message
    return client


def main():
    options = load_options()
    base_topic = str(options.get("mqtt_base_topic") or "zigbee2mqtt").strip()
    ota_port = int(options.get("ota_port") or 8443)

    while True:
        try:
            service = get_mqtt_service()
            break
        except Exception as e:
            print(f"MQTT service unavailable, retrying: {e}", flush=True)
            time.sleep(3)

    client = build_client(base_topic, ota_port)
    if service["username"]:
        client.username_pw_set(service["username"], service["password"])

    while True:
        try:
            print(
                f"MQTT enrollment connecting to {service['host']}:{service['port']}",
                flush=True,
            )
            client.connect(service["host"], service["port"], keepalive=60)
            client.loop_forever(retry_first_connection=True)
        except Exception as e:
            print(f"MQTT enrollment connection error: {e}; retrying", flush=True)
            time.sleep(3)


if __name__ == "__main__":
    main()
