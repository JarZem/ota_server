#!/usr/bin/env python3
"""Run the live OTA E2E test inside the OTA add-on from Home Assistant SSH.

This launcher owns the Supervisor stdin/log plumbing so the user never has to
paste PEM blocks into curl. The E2E process itself runs inside the OTA add-on,
therefore it receives that add-on's dynamic MQTT service credentials.

Usage:
    python tests/run_ota_e2e_supervisor.py

Optional file-based input:
    python tests/run_ota_e2e_supervisor.py \
        --ca-cert /path/root_ca_cert.pem \
        --ca-key /path/root_ca_private.pem

If paths are omitted, PEM values are pasted interactively into this Python
program. The Root CA private key is never written by this launcher.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

SUPERVISOR = 'http://supervisor'
DEFAULT_SLUG = 'local_ota_server'
POLL_SECONDS = 0.7
TIMEOUT_SECONDS = 300
START_MARKER = 'STDIN: starting live OTA E2E test inside OTA add-on'


def token() -> str:
    value = os.environ.get('SUPERVISOR_TOKEN', '')
    if not value:
        raise RuntimeError('SUPERVISOR_TOKEN is missing; run this from Home Assistant SSH')
    return value


def supervisor_request(path: str, *, data: bytes | None = None,
                       content_type: str | None = None) -> bytes:
    headers = {'Authorization': f'Bearer {token()}'}
    if content_type:
        headers['Content-Type'] = content_type
    req = urllib.request.Request(SUPERVISOR + path, data=data, headers=headers,
                                 method='POST' if data is not None else 'GET')
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode('utf-8', 'replace')
        raise RuntimeError(f'Supervisor {path} HTTP {exc.code}: {body}') from exc


def addon_info(slug: str) -> dict:
    payload = json.loads(supervisor_request(f'/addons/{slug}/info').decode('utf-8'))
    return payload.get('data', payload)


def addon_logs(slug: str) -> str:
    return supervisor_request(f'/addons/{slug}/logs').decode('utf-8', 'replace')


def send_stdin(slug: str, text: str) -> None:
    response = supervisor_request(
        f'/addons/{slug}/stdin',
        data=text.encode('utf-8'),
        content_type='text/plain; charset=utf-8',
    )
    if response:
        parsed = json.loads(response.decode('utf-8'))
        if parsed.get('result') != 'ok':
            raise RuntimeError(f'Supervisor stdin rejected input: {parsed}')


def read_pem_file(path: str, kind: str) -> str:
    value = Path(path).expanduser().read_text(encoding='ascii')
    if kind == 'certificate':
        if '-----BEGIN CERTIFICATE-----' not in value or '-----END CERTIFICATE-----' not in value:
            raise RuntimeError(f'{path}: not a PEM certificate')
    else:
        if 'PRIVATE KEY-----' not in value:
            raise RuntimeError(f'{path}: not a PEM private key')
    return value.rstrip('\r\n') + '\n'


def paste_pem(label: str, endings: set[str]) -> str:
    print(f'Paste {label}; PEM END line finishes input:')
    lines: list[str] = []
    while True:
        line = input()
        lines.append(line)
        if line.strip() in endings:
            return '\n'.join(lines) + '\n'


def wait_for_new_occurrence(slug: str, marker: str, previous_count: int,
                            timeout: int = TIMEOUT_SECONDS) -> tuple[str, int]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        text = addon_logs(slug)
        count = text.count(marker)
        if count > previous_count:
            return text, text.rfind(marker)
        time.sleep(POLL_SECONDS)
    text = addon_logs(slug)
    tail = text[-4000:]
    raise TimeoutError(
        f'timeout waiting for new OTA log marker: {marker!r}; '
        f'previous_count={previous_count} current_count={text.count(marker)}\n'
        f'--- OTA LOG TAIL ---\n{tail}'
    )


def wait_for_after(slug: str, marker: str, start_marker: str,
                   timeout: int = TIMEOUT_SECONDS) -> tuple[str, int]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        text = addon_logs(slug)
        start = text.rfind(start_marker)
        if start >= 0:
            pos = text.find(marker, start)
            if pos >= 0:
                return text, pos
        time.sleep(POLL_SECONDS)
    text = addon_logs(slug)
    tail = text[-4000:]
    raise TimeoutError(
        f'timeout waiting for OTA log marker after current E2E start: {marker!r}\n'
        f'--- OTA LOG TAIL ---\n{tail}'
    )


def newest_e2e_tail(text: str) -> str:
    pos = text.rfind(START_MARKER)
    return text[pos:] if pos >= 0 else text[-12000:]


def run(slug: str, ca_cert: str | None, ca_key: str | None,
        password_env: str | None) -> int:
    info = addon_info(slug)
    if info.get('state') != 'started':
        raise RuntimeError(f'OTA add-on {slug!r} is not started: state={info.get("state")!r}')
    if not info.get('stdin'):
        raise RuntimeError(f'OTA add-on {slug!r} does not have stdin enabled')

    initial_logs = addon_logs(slug)
    previous_start_count = initial_logs.count(START_MARKER)

    print(f"OTA add-on {slug} version={info.get('version')} state={info.get('state')}")
    print('Starting E2E inside OTA add-on...')
    send_stdin(slug, 'RUN_E2E\n')

    wait_for_new_occurrence(slug, START_MARKER, previous_start_count, timeout=30)
    wait_for_after(slug, 'Paste Root CA certificate PEM.', START_MARKER, timeout=30)

    cert_pem = (
        read_pem_file(ca_cert, 'certificate') if ca_cert else
        paste_pem('Root CA certificate', {'-----END CERTIFICATE-----'})
    )
    send_stdin(slug, cert_pem)

    wait_for_after(slug, 'Paste Root CA private key PEM.', START_MARKER, timeout=30)

    key_pem = (
        read_pem_file(ca_key, 'private key') if ca_key else
        paste_pem('Root CA private key', {
            '-----END PRIVATE KEY-----',
            '-----END ENCRYPTED PRIVATE KEY-----',
            '-----END EC PRIVATE KEY-----',
        })
    )
    send_stdin(slug, key_pem)

    _, password_prompt_pos = wait_for_after(
        slug, 'Root CA private key password', START_MARKER, timeout=30)

    if password_env:
        password = os.environ.get(password_env)
        if password is None:
            raise RuntimeError(f'environment variable {password_env!r} is not set')
    else:
        password = getpass.getpass('Root CA private key password (empty if unencrypted): ')
    send_stdin(slug, password + '\n')

    print('E2E is running; streaming test output...')
    printed = password_prompt_pos
    deadline = time.monotonic() + TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        text = addon_logs(slug)
        current_start = text.rfind(START_MARKER)
        if current_start >= 0 and printed < current_start:
            printed = current_start
        if len(text) > printed:
            chunk = text[printed:]
            sys.stdout.write(chunk)
            if not chunk.endswith('\n'):
                sys.stdout.write('\n')
            sys.stdout.flush()
            printed = len(text)

        tail = newest_e2e_tail(text)
        if 'FINAL RESULT: PASS' in tail or 'PASS  live E2E test completed' in tail:
            print('\nFINAL RESULT: PASS')
            return 0
        if ('Traceback (most recent call last):' in tail or
                'AssertionError:' in tail or
                'FAILED run evidence intentionally retained' in tail):
            print('\nFINAL RESULT: FAIL')
            return 1
        time.sleep(POLL_SECONDS)

    print('\nFINAL RESULT: TIMEOUT')
    return 2


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--slug', default=DEFAULT_SLUG)
    parser.add_argument('--ca-cert', help='local Root CA certificate PEM path')
    parser.add_argument('--ca-key', help='local Root CA private key PEM path')
    parser.add_argument(
        '--password-env',
        help='read Root CA private-key password from this environment variable instead of prompting')
    args = parser.parse_args()
    return run(args.slug, args.ca_cert, args.ca_key, args.password_env)


if __name__ == '__main__':
    raise SystemExit(main())
