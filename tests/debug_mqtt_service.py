#!/usr/bin/env python3
import json
import os
import threading
import urllib.error
import urllib.request

import paho.mqtt.client as mqtt

SUPERVISOR_TOKEN = os.environ.get('SUPERVISOR_TOKEN', '')


def supervisor_json(path: str) -> dict:
    if not SUPERVISOR_TOKEN:
        raise RuntimeError('SUPERVISOR_TOKEN is missing')
    req = urllib.request.Request(
        'http://supervisor' + path,
        headers={'Authorization': f'Bearer {SUPERVISOR_TOKEN}'},
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.loads(response.read().decode('utf-8'))


def try_connect(host: str, port: int, username: str, password: str) -> bool:
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
        print(f'MQTT on_connect reason_code={reason_code!r} numeric={code!r}', flush=True)
        connected.set()

    client.on_connect = on_connect
    try:
        rc = client.connect(host, port, keepalive=30)
        print(f'MQTT connect() rc={rc}', flush=True)
        client.loop_start()
        if not connected.wait(12):
            print('FAIL no CONNACK/on_connect within 12 seconds', flush=True)
            return False
        if result['reason_code'] == 0:
            print('PASS broker accepted connection', flush=True)
            return True
        print(f"FAIL broker rejected connection reason_code={result['reason_code']!r}", flush=True)
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
    print('TEST MQTT service credentials for current add-on context', flush=True)
    try:
        payload = supervisor_json('/services/mqtt')
    except urllib.error.HTTPError as exc:
        body = exc.read().decode('utf-8', 'replace')
        print(f'FAIL current add-on cannot access /services/mqtt: HTTP {exc.code} {body}', flush=True)
        print('Run this diagnostic through OTA add-on stdin, not directly from Terminal & SSH.', flush=True)
        return

    data = payload.get('data', payload)
    host = str(data.get('host') or '')
    port = int(data.get('port') or 1883)
    username = str(data.get('username') or '')
    password = str(data.get('password') or '')
    print(
        f'MQTT service host={host!r} port={port} username_present={bool(username)} '
        f'password_present={bool(password)}',
        flush=True,
    )
    if not host:
        print('FAIL Supervisor returned no MQTT host', flush=True)
        return
    try_connect(host, port, username, password)


if __name__ == '__main__':
    main()
