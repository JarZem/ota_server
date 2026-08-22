from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.request

import paho.mqtt.client as mqtt

from activity import firmware_device_state, provisioning_state
from database import db_connect
from device_registry import normalize_device_id

OPTIONS_PATH = '/data/options.json'
SUPERVISOR_TOKEN = os.environ.get('SUPERVISOR_TOKEN', '')
PROVISION_TIMEOUT_SECONDS = 130
COMPACT_ID_RE = re.compile(r'^[0-9a-fA-F]{16}$')

_active: dict[str, dict] = {}
_lock = threading.Lock()


def _options() -> dict:
    try:
        with open(OPTIONS_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def _mqtt_service() -> dict:
    req = urllib.request.Request(
        'http://supervisor/services/mqtt',
        headers={'Authorization': f'Bearer {SUPERVISOR_TOKEN}'},
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        payload = json.loads(response.read().decode('utf-8'))
    data = payload.get('data', payload)
    return {
        'host': data['host'], 'port': int(data['port']),
        'username': data.get('username') or '', 'password': data.get('password') or '',
    }


def _device_id(topic_part: str) -> str | None:
    compact = topic_part.lower().removeprefix('0x')
    if not COMPACT_ID_RE.fullmatch(compact):
        return None
    return normalize_device_id(compact)


def _payload_from_message(message, base_topic: str) -> tuple[str | None, str | None, str]:
    parts = message.topic.split('/')
    direction = 'UNKNOWN'
    try:
        text = message.payload.decode('utf-8')
    except UnicodeDecodeError:
        return None, None, direction

    if len(parts) == 3 and parts[0] == base_topic and parts[2] == 'set':
        direction = 'OTA_TO_ESP'
        try:
            body = json.loads(text)
        except Exception:
            return None, None, direction
        payload = body.get('ota_command') if isinstance(body, dict) else None
        return parts[1], payload if isinstance(payload, str) else None, direction

    if len(parts) == 3 and parts[0] == base_topic and parts[2] == 'action':
        direction = 'ESP_TO_OTA'
        return parts[1], text.strip(), direction

    if len(parts) == 2 and parts[0] == base_topic:
        direction = 'ESP_TO_OTA'
        try:
            body = json.loads(text)
        except Exception:
            return None, None, direction
        payload = body.get('ota_transport') if isinstance(body, dict) else None
        return parts[1], payload if isinstance(payload, str) else None, direction

    return None, None, direction


def _active_counter(device_id: str) -> int | None:
    with _lock:
        row = _active.get(device_id)
        return int(row['counter']) if row else None


def _set_active(device_id: str, counter: int) -> None:
    with _lock:
        _active[device_id] = {'counter': int(counter), 'updated': time.monotonic()}


def _touch(device_id: str) -> None:
    with _lock:
        if device_id in _active:
            _active[device_id]['updated'] = time.monotonic()


def _clear(device_id: str) -> None:
    with _lock:
        _active.pop(device_id, None)


def _image_for_code(code: str) -> dict | None:
    with db_connect() as conn:
        row = conn.execute(
            """
            SELECT i.filename, i.version, i.sha256, a.code
            FROM firmware_alias a
            JOIN firmware_images i ON i.filename=a.filename
            WHERE a.code=? LIMIT 1
            """,
            (code,),
        ).fetchone()
    return dict(row) if row else None


def _grant_expiry(device_id: str, code: str, sha256_hex: str) -> int | None:
    with db_connect() as conn:
        row = conn.execute(
            """
            SELECT expires_at FROM download_grants
            WHERE device_id=? AND code=? AND sha256=?
            ORDER BY id DESC LIMIT 1
            """,
            (device_id, code, sha256_hex),
        ).fetchone()
    return int(row['expires_at']) if row else None


def _firmware_for_grant_random(device_id: str, random_b64: str) -> dict | None:
    import base64
    try:
        raw = base64.urlsafe_b64decode(random_b64 + '=' * ((-len(random_b64)) % 4))
    except Exception:
        return None
    with db_connect() as conn:
        row = conn.execute(
            """
            SELECT g.sha256, g.version, g.code, i.filename
            FROM download_grants g
            JOIN firmware_alias a ON a.code=g.code
            JOIN firmware_images i ON i.filename=a.filename AND i.sha256=g.sha256
            WHERE g.device_id=? AND g.grant_random=?
            ORDER BY g.id DESC LIMIT 1
            """,
            (device_id, raw),
        ).fetchone()
    return dict(row) if row else None


def _handle(device_id: str, wire: str, direction: str) -> None:
    if wire.startswith('H|') and direction == 'ESP_TO_OTA':
        parts = wire.split('|')
        if len(parts) >= 2:
            try:
                counter = int(parts[1])
            except ValueError:
                return
            _set_active(device_id, counter)
            provisioning_state(device_id, counter, 'STARTED')
        return

    counter = _active_counter(device_id)
    if wire.startswith('A|') and direction == 'OTA_TO_ESP' and counter:
        _touch(device_id); provisioning_state(device_id, counter, 'CHALLENGE_SENT'); return
    if wire.startswith('R|') and direction == 'ESP_TO_OTA' and counter:
        _touch(device_id); provisioning_state(device_id, counter, 'RESPONSE_VERIFIED'); return
    if wire.startswith('P|') and direction == 'OTA_TO_ESP' and counter:
        _touch(device_id); provisioning_state(device_id, counter, 'PROVISIONING_SENT'); return

    if wire.startswith('T|') and direction == 'ESP_TO_OTA':
        parts = wire.split('|')
        if counter and len(parts) == 3 and parts[1] == '0' and parts[2].lower() == '42':
            provisioning_state(device_id, counter, 'COMPLETED')
            _clear(device_id)
        return

    if wire.startswith('C|') and direction == 'OTA_TO_ESP':
        parts = wire.split('|')
        if len(parts) >= 3:
            version, code = parts[1], parts[2]
            image = _image_for_code(code)
            if image:
                firmware_device_state(
                    device_id=device_id, sha256=image['sha256'], filename=image['filename'],
                    version=version, code=code, state='CHECK_SENT',
                    token_expires_at=_grant_expiry(device_id, code, image['sha256']),
                )
        return

    if wire.startswith('F|') and direction == 'ESP_TO_OTA':
        parts = wire.split('|')
        if len(parts) == 2:
            image = _firmware_for_grant_random(device_id, parts[1])
            if image:
                firmware_device_state(
                    device_id=device_id, sha256=image['sha256'], filename=image['filename'],
                    version=image['version'], code=image['code'], state='GRANT_CONSUMED',
                )


def _timeout_loop() -> None:
    while True:
        time.sleep(2)
        now = time.monotonic()
        expired = []
        with _lock:
            for device_id, row in _active.items():
                if now - float(row['updated']) >= PROVISION_TIMEOUT_SECONDS:
                    expired.append((device_id, int(row['counter'])))
            for device_id, _ in expired:
                _active.pop(device_id, None)
        for device_id, counter in expired:
            provisioning_state(device_id, counter, 'TIMEOUT', 'observer timeout without completion')


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
            print(f'[OTA/OBSERVE] subscribed {base_topic}/# for persistent activity history', flush=True)

    def on_message(client, userdata, message):
        topic_device, wire, direction = _payload_from_message(message, base_topic)
        if not topic_device or not wire:
            return
        device_id = _device_id(topic_device)
        if not device_id:
            return
        if wire[:2] in ('H|', 'A|', 'R|', 'P|', 'T|', 'C|', 'F|'):
            try:
                _handle(device_id, wire, direction)
            except Exception as exc:
                print(f'[OTA/OBSERVE] activity write failed device_id={device_id}: {exc}', flush=True)

    client.on_connect = on_connect
    client.on_message = on_message
    threading.Thread(target=_timeout_loop, daemon=True).start()
    client.connect(service['host'], service['port'], keepalive=60)
    client.loop_forever()


if __name__ == '__main__':
    main()
