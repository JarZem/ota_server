from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.request

import paho.mqtt.client as mqtt

from activity import firmware_device_state, record_activity
from database import db_connect
from device_registry import normalize_device_id

OPTIONS_PATH = '/data/options.json'
SUPERVISOR_TOKEN = os.environ.get('SUPERVISOR_TOKEN', '')
DUPLICATE_WINDOW_SECONDS = 3.0
COMPACT_ID_RE = re.compile(r'^[0-9a-fA-F]{16}$')

_recent_wires: dict[tuple[str, str, str], float] = {}
_seen_status: dict[tuple[str, int], float] = {}
_lock = threading.Lock()


def _options() -> dict:
    try:
        with open(OPTIONS_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def _mqtt_service() -> dict:
    req = urllib.request.Request('http://supervisor/services/mqtt', headers={'Authorization': f'Bearer {SUPERVISOR_TOKEN}'})
    with urllib.request.urlopen(req, timeout=10) as response:
        payload = json.loads(response.read().decode('utf-8'))
    data = payload.get('data', payload)
    return {'host': data['host'], 'port': int(data['port']), 'username': data.get('username') or '', 'password': data.get('password') or ''}


def _device_id(topic_part: str) -> str | None:
    compact = topic_part.lower().removeprefix('0x')
    return normalize_device_id(compact) if COMPACT_ID_RE.fullmatch(compact) else None


def _payload_from_message(message, base_topic: str) -> tuple[str | None, str | None, str]:
    parts = message.topic.split('/')
    try:
        text = message.payload.decode('utf-8')
    except UnicodeDecodeError:
        return None, None, 'UNKNOWN'
    if len(parts) == 3 and parts[0] == base_topic and parts[2] == 'set':
        try:
            body = json.loads(text)
        except Exception:
            return None, None, 'OTA_TO_ESP'
        payload = body.get('ota_command') if isinstance(body, dict) else None
        return parts[1], payload if isinstance(payload, str) else None, 'OTA_TO_ESP'
    if len(parts) == 2 and parts[0] == base_topic:
        try:
            body = json.loads(text)
        except Exception:
            return None, None, 'ESP_TO_OTA'
        payload = body.get('ota_transport') if isinstance(body, dict) else None
        return parts[1], payload if isinstance(payload, str) else None, 'ESP_TO_OTA'
    return None, None, 'UNKNOWN'


def _is_duplicate(device_id: str, wire: str, direction: str) -> bool:
    now = time.monotonic()
    key = (device_id, direction, wire)
    with _lock:
        previous = _recent_wires.get(key)
        _recent_wires[key] = now
        stale = [k for k, seen in _recent_wires.items() if now - seen > 30.0]
        for stale_key in stale:
            _recent_wires.pop(stale_key, None)
    return previous is not None and now - previous <= DUPLICATE_WINDOW_SECONDS


def _status_already_seen(device_id: str, wire: str) -> bool:
    parts = wire.split('|', 3)
    if len(parts) != 4 or parts[0] != 'S':
        return False
    try:
        counter = int(parts[1], 10)
    except ValueError:
        return False
    key = (device_id, counter)
    now = time.monotonic()
    with _lock:
        if key in _seen_status:
            return True
        _seen_status[key] = now
        stale = [k for k, seen in _seen_status.items() if now - seen > 86400.0]
        for stale_key in stale:
            _seen_status.pop(stale_key, None)
    return False


def _image_for_code(code: str) -> dict | None:
    with db_connect() as conn:
        row = conn.execute("SELECT i.filename, i.version, i.sha256, a.code FROM firmware_alias a JOIN firmware_images i ON i.filename=a.filename WHERE a.code=? LIMIT 1", (code,)).fetchone()
    return dict(row) if row else None


def _grant_expiry(device_id: str, code: str, sha256_hex: str) -> int | None:
    with db_connect() as conn:
        row = conn.execute("SELECT expires_at FROM download_grants WHERE device_id=? AND code=? AND sha256=? ORDER BY id DESC LIMIT 1", (device_id, code, sha256_hex)).fetchone()
    return int(row['expires_at']) if row else None


def _handle_non_provisioning(device_id: str, wire: str, direction: str) -> None:
    # Provisioning state is deliberately NOT inferred here. mqtt_listener.py is
    # authoritative because only it knows whether H/R/P were cryptographically
    # accepted or rejected. The observer records transport activity only.
    if wire.startswith('C|') and direction == 'OTA_TO_ESP':
        parts = wire.split('|')
        if len(parts) >= 3:
            version, code = parts[1], parts[2]
            image = _image_for_code(code)
            if image:
                firmware_device_state(
                    device_id=device_id,
                    sha256=image['sha256'],
                    filename=image['filename'],
                    version=version,
                    code=code,
                    state='CHECK_SENT',
                    token_expires_at=_grant_expiry(device_id, code, image['sha256']),
                )


def main() -> None:
    options = _options()
    base_topic = str(options.get('mqtt_base_topic') or 'zigbee2mqtt')
    service = _mqtt_service()
    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id='ota-server-observer')
    except (AttributeError, TypeError):
        client = mqtt.Client(client_id='ota-server-observer')
    if service['username']:
        client.username_pw_set(service['username'], service['password'])

    def on_connect(client, userdata, flags, reason_code, properties=None):
        code = int(reason_code) if hasattr(reason_code, '__int__') else reason_code
        if code == 0:
            client.subscribe(f'{base_topic}/#', qos=0)
            print(f'[OTA/OBSERVE] subscribed {base_topic}/# for transport activity only', flush=True)

    def on_message(client, userdata, message):
        topic_device, wire, direction = _payload_from_message(message, base_topic)
        if not topic_device or not wire:
            return
        device_id = _device_id(topic_device)
        if not device_id:
            return
        if wire[:2] not in ('H|', 'A|', 'R|', 'P|', 'T|', 'S|', 'C|', 'F|'):
            return
        if wire.startswith('S|') and direction == 'ESP_TO_OTA' and _status_already_seen(device_id, wire):
            return
        if _is_duplicate(device_id, wire, direction):
            return
        kind = wire[:1]
        try:
            record_activity('MQTT', f'{direction} {kind}', device_id=device_id,
                            detail=f'topic={message.topic} bytes={len(message.payload)}')
            _handle_non_provisioning(device_id, wire, direction)
        except Exception as exc:
            print(f'[OTA/OBSERVE] activity write failed device_id={device_id}: {exc}', flush=True)

    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(service['host'], service['port'], keepalive=60)
    client.loop_forever()


if __name__ == '__main__':
    main()
