#!/usr/bin/env python3
"""Interactive launcher for test_ota_e2e_live.py.

Accepts both encrypted and unencrypted PEM private keys pasted directly into the
Home Assistant add-on terminal without putting CA secrets on a command line.
After the protocol test it also requires the OTA, Zigbee2MQTT, Mosquitto and
captured MQTT transcript logs to have been collected successfully.
"""
from __future__ import annotations

from pathlib import Path

import test_ota_e2e_live as e2e


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


def verify_collected_logs(result_dir: Path) -> None:
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
    e2e.passed('OTA, Zigbee2MQTT, Mosquitto and MQTT transcript logs collected and readable')


e2e.read_pem = read_pem_any

if __name__ == '__main__':
    root = e2e.RESULT_ROOT
    root.mkdir(parents=True, exist_ok=True)
    before = {p for p in root.iterdir() if p.is_dir()}
    e2e.main()
    result = newest_result(before)
    verify_collected_logs(result)
    print(f'\nFINAL RESULT: PASS; diagnostic evidence: {result}', flush=True)
