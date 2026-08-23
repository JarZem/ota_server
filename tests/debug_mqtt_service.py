#!/usr/bin/env python3
import json
import os
import threading
import urllib.request

import paho.mqtt.client as mqtt

SUPERVISOR_TOKEN = os.environ.get('SUPERVISOR_TOKEN', '')


def supervisor_get(path: str) -> bytes:
    if not SUPERVISOR_TOKEN:
        raise RuntimeError('SUPERVISOR_TOKEN is missing')
    req = urllib.request.Request(
        'http://supervisor' + path,
        headers={'Authorization': f'Bearer {SUPERVISOR_TOKEN}'},
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        return response.read()


def main() -> None:
    print('TEST Supervisor MQTT service credentials', flush=True)
    payload = json.loads(supervisor_get('/services/mqtt').decode('utf-8'))
    data = payload.get('data', payload)
    host = data['host']
    port = int(data['port'])
    username = data.get('username') or ''
    password = data.get('password') or ''

    print(
        f"MQTT service host={host!r} port={port} username={username!r} "
        f"password_present={bool(password)} password_length={len(password)}",
        flush=True,
    )

    connected = threading.Event()
    result = {'reason_code': None, 'disconnect_code': None}

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

    def on_disconnect(client, userdata, disconnect_flags, reason_code=None, properties=None):
        # Compatible enough for Callback API v2; on older paho the positional values
        # may differ, but repr still gives useful diagnostic evidence.
        result['disconnect_code'] = reason_code
        print(
            f'MQTT on_disconnect flags={disconnect_flags!r} reason_code={reason_code!r}',
            flush=True,
        )

    client.on_connect = on_connect
    client.on_disconnect = on_disconnect

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
        except Exception as exc:
            print(f'MQTT disconnect exception={exc!r}', flush=True)
        try:
            client.loop_stop()
        except Exception:
            pass


if __name__ == '__main__':
    main()
