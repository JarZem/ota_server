#!/usr/bin/env python3
import json
import os
import threading
import urllib.request
from pathlib import Path

import paho.mqtt.client as mqtt

SUPERVISOR_TOKEN = os.environ.get('SUPERVISOR_TOKEN', '')
SECRETS_PATH = Path('/share/ota_server/secrets.json')


def supervisor_json(path: str) -> dict:
    if not SUPERVISOR_TOKEN:
        raise RuntimeError('SUPERVISOR_TOKEN is missing')
    req = urllib.request.Request(
        'http://supervisor' + path,
        headers={'Authorization': f'Bearer {SUPERVISOR_TOKEN}'},
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.loads(response.read().decode('utf-8'))


def ota_options() -> dict:
    addons = supervisor_json('/addons')
    items = (addons.get('data') or {}).get('addons') or []
    for item in items:
        slug = str(item.get('slug') or '')
        name = str(item.get('name') or '')
        if 'ota_server' not in slug.lower() and name.strip().lower() != 'ota server':
            continue
        info = supervisor_json(f'/addons/{slug}/info')
        data = info.get('data', info)
        options = data.get('options') or {}
        print(f'OTA add-on slug={slug!r} version={data.get("version")!r}', flush=True)
        return options
    raise RuntimeError('OTA Server add-on not found')


def secret_value(name: str) -> str:
    if not name or not SECRETS_PATH.is_file():
        return ''
    try:
        data = json.loads(SECRETS_PATH.read_text(encoding='utf-8'))
    except Exception:
        return ''
    for bucket_name in ('mqtt_passwords', 'database_passwords', 'mysql_passwords', 'secrets'):
        bucket = data.get(bucket_name)
        if isinstance(bucket, dict) and name in bucket:
            return str(bucket[name])
    value = data.get(name)
    return str(value) if value is not None else ''


def main() -> None:
    print('TEST OTA MQTT credentials from SSH context', flush=True)
    options = ota_options()
    host = str(options.get('mqtt_host') or 'core-mosquitto').strip()
    port = int(options.get('mqtt_port') or 1883)
    username = str(options.get('mqtt_username') or '').strip()
    secret_name = str(options.get('mqtt_password_secret') or '').strip()
    password = os.environ.get('OTA_MQTT_PASSWORD', '') or secret_value(secret_name)

    print(
        f'MQTT host={host!r} port={port} username={username!r} '
        f'password_secret={secret_name!r} password_present={bool(password)}',
        flush=True,
    )

    if not username:
        print('FAIL mqtt_username is empty in OTA add-on options', flush=True)
        return
    if not password:
        print('FAIL MQTT password is unavailable: set mqtt_password_secret to a key present in /share/ota_server/secrets.json', flush=True)
        return

    connected = threading.Event()
    result = {'reason_code': None}
    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id='ota-e2e-mqtt-debug')
    except (AttributeError, TypeError):
        client = mqtt.Client(client_id='ota-e2e-mqtt-debug')
    client.username_pw_set(username, password)

    def on_connect(client, userdata, flags, reason_code, properties=None):
        try:
            code = int(reason_code)
        except (TypeError, ValueError):
            code = reason_code
        result['reason_code'] = code
        print(f'MQTT on_connect reason_code={reason_code!r} numeric={code!r}', flush=True)
        connected.set()

    client.on_connect = on_connect
    try:
        rc = client.connect(host, port, keepalive=30)
        print(f'MQTT connect() returned rc={rc}', flush=True)
        client.loop_start()
        if not connected.wait(12):
            print('FAIL no CONNACK/on_connect received within 12 seconds', flush=True)
        elif result['reason_code'] == 0:
            print('PASS MQTT connection accepted by broker', flush=True)
        else:
            print(f"FAIL broker rejected MQTT connection reason_code={result['reason_code']!r}", flush=True)
    finally:
        try:
            client.disconnect()
        except Exception:
            pass
        try:
            client.loop_stop()
        except Exception:
            pass


if __name__ == '__main__':
    main()
