#!/usr/bin/env python3
"""Interactive launcher for test_ota_e2e_live.py from Home Assistant SSH.

Accepts both encrypted and unencrypted PEM private keys pasted directly into the
terminal without putting CA secrets on a command line. Network calls that the
core E2E test addresses to 127.0.0.1 are redirected to the configured ota_host,
because the OTA server runs in a separate add-on container.
"""
from __future__ import annotations

import json
import queue
import re
import urllib.request
from pathlib import Path

import paho.mqtt.client as mqtt
import test_ota_e2e_live as e2e


def install_ha_host_url_redirect() -> None:
    options = e2e.load_options()
    ota_host = str(options.get('ota_host') or '').strip()
    if not ota_host:
        raise RuntimeError('ota_host is missing in OTA options')

    original_urlopen = urllib.request.urlopen
    source = 'https://127.0.0.1:'
    target = f'https://{ota_host}:'

    def redirected_urlopen(url, *args, **kwargs):
        if isinstance(url, urllib.request.Request):
            old_url = url.full_url
            new_url = old_url.replace(source, target, 1) if old_url.startswith(source) else old_url
            if new_url != old_url:
                url = urllib.request.Request(
                    new_url,
                    data=url.data,
                    headers=dict(url.header_items()),
                    method=url.get_method(),
                )
        elif isinstance(url, str) and url.startswith(source):
            url = url.replace(source, target, 1)
        return original_urlopen(url, *args, **kwargs)

    urllib.request.urlopen = redirected_urlopen
    e2e.say(f'HA SSH network mode: OTA endpoints 127.0.0.1 -> {ota_host}')


def read_pem_any(label: str, _end_marker: str) -> bytes:
    if 'certificate' in label.lower():
        endings = {'-----END CERTIFICATE-----'}
    else:
        endings = {
            '-----END PRIVATE KEY-----',
            '-----END ENCRYPTED PRIVATE KEY-----',
            '-----END EC PRIVATE KEY-----',
        }
    e2e.say(f"\nPaste {label}. The PEM END line finishes input:")
    lines: list[str] = []
    while True:
        line = input()
        lines.append(line)
        if line.strip() in endings:
            return ('\n'.join(lines) + '\n').encode('ascii')


def newest_result(before: set[Path]) -> Path:
    root = e2e.RESULT_ROOT
    candidates = [p for p in root.iterdir() if p.is_dir() and p not in before]
    if not candidates:
        raise AssertionError('E2E test did not create a result-log directory')
    return max(candidates, key=lambda p: p.stat().st_mtime)


def verify_collected_logs(result_dir: Path) -> tuple[str, str, str]:
    required_files = ('ota.log', 'zigbee2mqtt.log', 'mosquitto.log', 'mqtt_transcript.log')
    for name in required_files:
        path = result_dir / name
        if not path.is_file() or path.stat().st_size == 0:
            raise AssertionError(f'missing/empty diagnostic log: {path}')
        text = path.read_text(encoding='utf-8', errors='replace')
        if 'LOG FETCH FAILED:' in text or 'ADDON DISCOVERY FAILED:' in text:
            raise AssertionError(f'diagnostic log retrieval failed: {path}')

    transcript = (result_dir / 'mqtt_transcript.log').read_text(encoding='utf-8', errors='replace')
    for marker in (
        'ESP -> OTA H|', 'OTA -> ESP A|', 'ESP -> OTA R|',
        'OTA -> ESP P|', 'OTA -> ESP C|', 'ESP -> OTA F|',
    ):
        if marker not in transcript:
            raise AssertionError(f'MQTT transcript does not contain {marker}')

    ota_log = (result_dir / 'ota.log').read_text(encoding='utf-8', errors='replace')
    match = re.findall(
        r'Firmware publish accepted device_id=([0-9a-f:]{23}) filename=(ota-e2e-[A-Za-z0-9.-]+\.bin)',
        ota_log,
        flags=re.IGNORECASE,
    )
    if not match:
        raise AssertionError('cannot identify this E2E virtual device/firmware in OTA log')
    device_id, filename = match[-1]
    compact = device_id.replace(':', '').lower()
    e2e.passed('OTA, Zigbee2MQTT, Mosquitto and MQTT transcript logs collected and readable')
    return device_id.lower(), compact, filename


def loaded_converter_names() -> set[str]:
    service = e2e.mqtt_service()
    q: queue.Queue[object] = queue.Queue()
    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id='ota-e2e-cleanup-check')
    except (AttributeError, TypeError):
        client = mqtt.Client(client_id='ota-e2e-cleanup-check')
    if service['username']:
        client.username_pw_set(service['username'], service['password'])

    def on_message(_client, _userdata, message):
        try:
            q.put(json.loads(message.payload.decode('utf-8')))
        except Exception:
            pass

    client.on_message = on_message
    client.connect(service['host'], service['port'], 30)
    client.subscribe(f"{e2e.load_options().get('mqtt_base_topic') or 'zigbee2mqtt'}/bridge/converters")
    client.loop_start()
    try:
        payload = q.get(timeout=10)
    finally:
        client.disconnect()
        client.loop_stop()
    names = set()
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict) and item.get('name'):
                names.add(str(item['name']))
    return names


def verify_cleanup(device_id: str, compact: str, filename: str) -> None:
    converter = Path(filename).stem + '.mjs'
    if e2e.ha_registry_contains(compact):
        raise AssertionError(f'temporary HA MQTT device still exists: {device_id}')
    if converter in loaded_converter_names():
        raise AssertionError(f'temporary Zigbee2MQTT converter still loaded: {converter}')
    if (e2e.FIRMWARE_DIR / filename).exists() or (e2e.FIRMWARE_DIR / (Path(filename).stem + '.release.json')).exists():
        raise AssertionError(f'temporary firmware still exists: {filename}')
    checks = [
        ('SELECT device_id FROM device_certificates WHERE device_id=?', (device_id,)),
        ('SELECT filename FROM firmware_images WHERE filename=?', (filename,)),
        ('SELECT id FROM artifact_publications WHERE publisher_device_id=?', (device_id,)),
        ('SELECT id FROM provisioning_attempts WHERE device_id=?', (device_id,)),
        ('SELECT device_id FROM device_firmware_status WHERE device_id=?', (device_id,)),
    ]
    with e2e.db_connect() as conn:
        for sql, params in checks:
            if conn.execute(sql, params).fetchone():
                raise AssertionError(f'test cleanup left database state: {sql}')
    e2e.passed('successful test cleanup verified: no virtual ESP, BIN, MJS or OTA DB rows remain')


e2e.read_pem = read_pem_any

if __name__ == '__main__':
    install_ha_host_url_redirect()
    root = e2e.RESULT_ROOT
    root.mkdir(parents=True, exist_ok=True)
    before = {p for p in root.iterdir() if p.is_dir()}
    e2e.main()
    result = newest_result(before)
    device_id, compact, filename = verify_collected_logs(result)
    verify_cleanup(device_id, compact, filename)
    print(f'\nFINAL RESULT: PASS; diagnostic evidence: {result}', flush=True)
