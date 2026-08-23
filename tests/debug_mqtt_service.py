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


def mosquitto_logins() -> list[tuple[str, str]]:
    try:
        payload = supervisor_json('/addons/core_mosquitto/info')
    except Exception as exc:
        print(f'Mosquitto add-on info unavailable: {exc}', flush=True)
        return []
    data = payload.get('data', payload)
    options = data.get('options') if isinstance(data, dict) else None
    logins = options.get('logins') if isinstance(options, dict) else None
    result = []
    if isinstance(logins, list):
        for item in logins:
            if not isinstance(item, dict):
                continue
            username = str(item.get('username') or '').strip()
            password = str(item.get('password') or '')
            if username and password:
                result.append((username, password))
    print(f'Mosquitto configured login count={len(result)} users={[u for u, _ in result]!r}', flush=True)
    return result


def try_connect(host: str, port: int, username: str, password: str, label: str) -> bool:
    connected = threading.Event()
    result = {'reason_code': None}
    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id='ota-e2e-mqtt-debug')
    except (AttributeError, TypeError):
        client = mqtt.Client(client_id='ota-e2e-mqtt-debug')
    if username:
        client.username_pw_set(username, password)

    def on_connect(client, userdata, flags, reason_code, properties=None):
        try:
            code = int(reason_code)
        except (TypeError, ValueError):
            code = reason_code
        result['reason_code'] = code
        print(f'{label}: MQTT on_connect reason_code={reason_code!r} numeric={code!r}', flush=True)
        connected.set()

    client.on_connect = on_connect
    try:
        rc = client.connect(host, port, keepalive=30)
        print(f'{label}: connect() rc={rc}', flush=True)
        client.loop_start()
        if not connected.wait(12):
            print(f'{label}: FAIL no CONNACK/on_connect within 12 seconds', flush=True)
            return False
        if result['reason_code'] == 0:
            print(f'{label}: PASS broker accepted connection', flush=True)
            return True
        print(f"{label}: FAIL broker rejected connection reason_code={result['reason_code']!r}", flush=True)
        return False
    finally:
        try:
            client.disconnect()
        except Exception:
            pass
        try:
            client.loop_stop()
        except Exception:
            pass


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

    if username and password:
        if try_connect(host, port, username, password, 'OTA options'):
            return
    else:
        print('OTA options do not currently contain usable MQTT credentials', flush=True)

    logins = mosquitto_logins()
    if not logins:
        print('FAIL no explicit Mosquitto login credentials are available through Supervisor', flush=True)
        return

    for candidate_user, candidate_password in logins:
        if try_connect(host, port, candidate_user, candidate_password, f'Mosquitto login {candidate_user!r}'):
            print(f'PASS usable MQTT login found username={candidate_user!r}; password intentionally not printed', flush=True)
            return

    print('FAIL none of the configured Mosquitto login accounts could connect', flush=True)


if __name__ == '__main__':
    main()
