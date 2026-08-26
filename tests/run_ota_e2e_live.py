#!/usr/bin/env python3
"""Interactive launcher for test_ota_e2e_live.py from Home Assistant SSH.

The SSH add-on has its own /data/options.json and may not have permission to
read Supervisor service credentials. This launcher loads OTA Server options
through the Supervisor add-on API, injects them into the E2E/database layers,
and uses the MQTT connection configured for OTA instead of /services/mqtt.
"""
from __future__ import annotations

import json
import os
import queue
import re
import sys
import urllib.request
from pathlib import Path

import paho.mqtt.client as mqtt
import test_ota_e2e_live as e2e


_OTA_OPTIONS: dict | None = None


def supervisor_json(path: str) -> dict:
    token = os.environ.get('SUPERVISOR_TOKEN', '')
    if not token:
        raise RuntimeError('SUPERVISOR_TOKEN is missing; SSH add-on must have Supervisor API access')
    req = urllib.request.Request(
        'http://supervisor' + path,
        headers={'Authorization': f'Bearer {token}'},
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.loads(response.read().decode('utf-8'))


def ota_addon_options() -> dict:
    global _OTA_OPTIONS
    if _OTA_OPTIONS is not None:
        return dict(_OTA_OPTIONS)

    payload = supervisor_json('/addons')
    data = payload.get('data', payload)
    addons = data.get('addons') if isinstance(data, dict) else None
    if not isinstance(addons, list):
        raise RuntimeError('Supervisor /addons response does not contain an add-on list')

    candidates: list[str] = []
    for item in addons:
        if not isinstance(item, dict):
            continue
        slug = str(item.get('slug') or '')
        name = str(item.get('name') or '')
        if 'ota_server' in slug.lower() or name.strip().lower() == 'ota server':
            candidates.append(slug)

    if not candidates:
        raise RuntimeError('OTA Server add-on was not found through Supervisor API')

    last_error: Exception | None = None
    for slug in candidates:
        try:
            info_payload = supervisor_json(f'/addons/{slug}/info')
            info = info_payload.get('data', info_payload)
            options = info.get('options') if isinstance(info, dict) else None
            if isinstance(options, dict) and options.get('ota_host'):
                _OTA_OPTIONS = dict(options)
                e2e.say(f'HA SSH mode: using OTA add-on {slug}; ota_host={options.get("ota_host")}')
                return dict(_OTA_OPTIONS)
        except Exception as exc:
            last_error = exc

    detail = f': {last_error}' if last_error else ''
    raise RuntimeError('OTA Server options could not be loaded from Supervisor API' + detail)


def _secret_from_shared_file(name: str) -> str:
    path = Path('/share/ota_server/secrets.json')
    if not name or not path.is_file():
        return ''
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return ''
    for bucket_name in ('mqtt_passwords', 'database_passwords', 'mysql_passwords', 'secrets'):
        bucket = data.get(bucket_name)
        if isinstance(bucket, dict) and name in bucket:
            return str(bucket[name])
    value = data.get(name)
    return str(value) if value is not None else ''


def _mqtt_service_from_options(options: dict) -> dict:
    secret_name = str(options.get('mqtt_password_secret') or '').strip()
    password = os.environ.get('OTA_MQTT_PASSWORD', '') or _secret_from_shared_file(secret_name)
    return {
        'host': str(options.get('mqtt_host') or 'core-mosquitto').strip(),
        'port': int(options.get('mqtt_port') or 1883),
        'username': str(options.get('mqtt_username') or '').strip(),
        'password': password,
    }


def install_ha_host_environment() -> None:
    options = ota_addon_options()
    ota_host = str(options.get('ota_host') or '').strip()
    if not ota_host:
        raise RuntimeError('ota_host is missing in OTA Server options')

    # All core E2E helpers must use OTA add-on configuration. In particular,
    # mqtt_service() must not call Supervisor /services/mqtt: SSH add-ons often
    # receive HTTP 403 for that endpoint even though they can inspect add-ons.
    e2e.load_options = lambda: dict(options)
    e2e.mqtt_service = lambda: _mqtt_service_from_options(options)

    database_module = sys.modules.get('database')
    if database_module is not None:
        database_module.database_config = lambda: _database_config_from_options(options, database_module)
        if hasattr(database_module, '_engine'):
            database_module._engine = None

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
    e2e.say(f'HA SSH network mode: OTA HTTPS 127.0.0.1 -> {ota_host}; MQTT from OTA options')


def _database_config_from_options(options: dict, database_module) -> dict:
    secret_name = str(options.get('mysql_password_secret') or 'homeassistant_mysql').strip()
    password = os.environ.get('OTA_MYSQL_PASSWORD', '') or database_module._secret(secret_name)
    if not password:
        raise RuntimeError(f'MySQL password secret {secret_name!r} is missing')
    return {
        'host': str(options.get('mysql_host') or 'core-mariadb').strip(),
        'port': int(options.get('mysql_port') or 3306),
        'database': str(options.get('mysql_database') or 'homeassistant').strip(),
        'username': str(options.get('mysql_username') or 'homeassistant').strip(),
        'password': password,
        'password_secret': secret_name,
    }


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
    install_ha_host_environment()
    root = e2e.RESULT_ROOT
    root.mkdir(parents=True, exist_ok=True)
    before = {p for p in root.iterdir() if p.is_dir()}
    e2e.main()
    result = newest_result(before)
    device_id, compact, filename = verify_collected_logs(result)
    verify_cleanup(device_id, compact, filename)
    print(f'\nFINAL RESULT: PASS; diagnostic evidence: {result}', flush=True)
