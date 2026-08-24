import base64
import json
import os
import re
import time
import urllib.request

import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from database import db_connect
from device_registry import get_registered_device, normalize_device_id

OPTIONS_PATH = '/data/options.json'
SUPERVISOR_TOKEN = os.environ.get('SUPERVISOR_TOKEN', '')
COMPACT_ID_RE = re.compile(r'^[0-9a-fA-F]{16}$')
MAX_COUNTER = (1 << 63) - 1
MAX_FW_VERSION_LEN = 63


def load_options():
    try:
        with open(OPTIONS_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def get_mqtt_service():
    req = urllib.request.Request('http://supervisor/services/mqtt', headers={'Authorization': f'Bearer {SUPERVISOR_TOKEN}'})
    with urllib.request.urlopen(req, timeout=10) as response:
        payload = json.loads(response.read().decode('utf-8'))
    data = payload.get('data', payload)
    return {'host': data['host'], 'port': int(data['port']), 'username': data.get('username') or '', 'password': data.get('password') or ''}


def topic_device_id(topic_device):
    compact = topic_device.lower().removeprefix('0x')
    return normalize_device_id(compact) if COMPACT_ID_RE.fullmatch(compact) else None


def b64url_decode(value):
    return base64.urlsafe_b64decode(value + ('=' * ((-len(value)) % 4)))


def extract_status(message, base_topic):
    parts = message.topic.split('/')
    if len(parts) == 3 and parts[0] == base_topic and parts[2] == 'action':
        try:
            payload = message.payload.decode('utf-8').strip()
        except UnicodeDecodeError:
            return None, None
        return parts[1], payload if payload.startswith('S|') else None
    if len(parts) == 2 and parts[0] == base_topic:
        try:
            state = json.loads(message.payload.decode('utf-8'))
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
            return None, None
        payload = state.get('ota_transport') if isinstance(state, dict) else None
        return parts[1], payload if isinstance(payload, str) and payload.startswith('S|') else None
    return None, None


def verify_and_store(topic_device, payload, expected_ecosystem):
    device_id = topic_device_id(topic_device)
    if device_id is None:
        raise ValueError('MQTT topic does not contain valid Zigbee IEEE')
    parts = payload.split('|')
    if len(parts) != 4 or parts[0] != 'S':
        raise ValueError('STATUS must be S|counter|fw_version|signature')
    counter = int(parts[1], 10)
    fw_version = parts[2]
    if counter <= 0 or counter > MAX_COUNTER:
        raise ValueError('STATUS counter outside supported range')
    if not fw_version or len(fw_version) > MAX_FW_VERSION_LEN or '|' in fw_version:
        raise ValueError('STATUS firmware version invalid')
    signature_raw = b64url_decode(parts[3])
    if len(signature_raw) != 64:
        raise ValueError('STATUS signature must decode to 64 bytes')

    registered = get_registered_device(device_id)
    if registered is None:
        raise ValueError('device certificate is not registered')
    if registered['ecosystem'] != expected_ecosystem:
        raise ValueError('registered ecosystem mismatch')
    now = int(time.time())
    if now < int(registered['certificate_not_before']) or now > int(registered['certificate_not_after']):
        raise ValueError('device certificate outside validity period')

    public_key = serialization.load_der_public_key(registered['public_key_der'])
    r = int.from_bytes(signature_raw[:32], 'big')
    s = int.from_bytes(signature_raw[32:], 'big')
    canonical = f'S|{device_id}|{counter}|{fw_version}'.encode('ascii')
    public_key.verify(encode_dss_signature(r, s), canonical, ec.ECDSA(hashes.SHA256()))

    with db_connect() as conn:
        result = conn.execute(
            '''UPDATE device_certificates
               SET last_status_counter=?, running_firmware_version=?, last_status_at=?, updated_at=?
               WHERE device_id=? AND last_status_counter < ?''',
            (counter, fw_version, now, now, device_id, counter),
        )
        if result.rowcount != 1:
            return False, device_id, counter, fw_version
    return True, device_id, counter, fw_version


def main():
    options = load_options()
    base_topic = str(options.get('mqtt_base_topic') or 'zigbee2mqtt')
    ecosystem = str(options.get('ota_ecosystem') or 'JaroslavZemanESP')
    service = get_mqtt_service()
    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id='ota-server-status')
    except (AttributeError, TypeError):
        client = mqtt.Client(client_id='ota-server-status')
    if service['username']:
        client.username_pw_set(service['username'], service['password'])

    def on_connect(client, userdata, flags, reason_code, properties=None):
        code = int(reason_code) if hasattr(reason_code, '__int__') else reason_code
        if code != 0:
            print(f'[OTA/STATUS] MQTT connect failed: {reason_code}', flush=True)
            return
        client.subscribe(f'{base_topic}/+', qos=0)
        client.subscribe(f'{base_topic}/+/action', qos=0)
        print(f'[OTA/STATUS] listening for signed boot STATUS on {base_topic}/+', flush=True)

    def on_message(client, userdata, message):
        topic_device, payload = extract_status(message, base_topic)
        if not topic_device or not payload:
            return
        try:
            accepted, device_id, counter, fw = verify_and_store(topic_device, payload, ecosystem)
            if accepted:
                print(f'[OTA/STATUS] verified device_id={device_id} counter={counter} fw={fw}', flush=True)
            else:
                print(f'[OTA/STATUS] stale/replayed device_id={device_id} counter={counter}', flush=True)
        except Exception as exc:
            print(f'[OTA/STATUS] rejected topic_device={topic_device}: {exc}', flush=True)

    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(service['host'], service['port'], keepalive=60)
    client.loop_forever()


if __name__ == '__main__':
    main()
