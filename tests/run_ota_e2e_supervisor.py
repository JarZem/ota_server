#!/usr/bin/env python3
"""Launch the live OTA E2E test inside the OTA add-on from Home Assistant SSH.

The launcher gathers Root CA material locally, writes one short-lived mode-0600
bundle under /share, and sends only the bundle path through Supervisor stdin.
The OTA-side runner deletes the bundle immediately after reading it. This keeps
Supervisor stdin as a command channel only and avoids mixing PEM/password input
with run.sh commands.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

SUPERVISOR = 'http://supervisor'
DEFAULT_SLUG = 'local_ota_server'
DEFAULT_CA_CERT = '/share/ota_server/cert/root_ca_cert.pem'
INPUT_ROOT = Path('/share/ota_server/e2e-input')
POLL_SECONDS = 0.7
TIMEOUT_SECONDS = 300


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
    req = urllib.request.Request(
        SUPERVISOR + path,
        data=data,
        headers=headers,
        method='POST' if data is not None else 'GET',
    )
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


def send_stdin(slug: str, line: str) -> None:
    response = supervisor_request(
        f'/addons/{slug}/stdin',
        data=(line.rstrip('\r\n') + '\n').encode('utf-8'),
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
    elif 'PRIVATE KEY-----' not in value:
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


def write_bundle(cert: str, key: str, password: str) -> Path:
    INPUT_ROOT.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(INPUT_ROOT, 0o700)
    except OSError:
        pass
    path = INPUT_ROOT / f'e2e-{int(time.time())}-{secrets.token_hex(4)}.json'
    payload = {
        'root_ca_cert_pem': cert,
        'root_ca_private_key_pem': key,
        'root_ca_private_key_password': password,
    }
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(payload, f, separators=(',', ':'))
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise
    return path


def wait_for_marker(slug: str, marker: str, timeout: int = 30) -> int:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        text = addon_logs(slug)
        pos = text.rfind(marker)
        if pos >= 0:
            return pos
        time.sleep(POLL_SECONDS)
    text = addon_logs(slug)
    raise TimeoutError(f'timeout waiting for {marker!r}\n--- OTA LOG TAIL ---\n{text[-5000:]}')


def run(slug: str, ca_cert: str | None, ca_key: str | None,
        password_env: str | None) -> int:
    info = addon_info(slug)
    if info.get('state') != 'started':
        raise RuntimeError(f'OTA add-on {slug!r} is not started: state={info.get("state")!r}')
    if not info.get('stdin'):
        raise RuntimeError(f'OTA add-on {slug!r} does not have stdin enabled')

    cert_path = ca_cert or DEFAULT_CA_CERT
    cert = read_pem_file(cert_path, 'certificate')
    key = (
        read_pem_file(ca_key, 'private key') if ca_key else
        paste_pem('Root CA private key', {
            '-----END PRIVATE KEY-----',
            '-----END ENCRYPTED PRIVATE KEY-----',
            '-----END EC PRIVATE KEY-----',
        })
    )
    if password_env:
        password = os.environ.get(password_env)
        if password is None:
            raise RuntimeError(f'environment variable {password_env!r} is not set')
    else:
        password = getpass.getpass('Root CA private key password (empty if unencrypted): ')

    bundle = write_bundle(cert, key, password)
    marker = f'STDIN: starting live OTA E2E test bundle={bundle}'
    print(f"OTA add-on {slug} version={info.get('version')} state={info.get('state')}")
    print(f'Starting E2E inside OTA add-on using temporary bundle {bundle.name}...')

    try:
        send_stdin(slug, f'RUN_E2E_FILE {bundle}')
        start = wait_for_marker(slug, marker, timeout=30)
        print('E2E is running...')
        printed = start
        deadline = time.monotonic() + TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            text = addon_logs(slug)
            if len(text) > printed:
                chunk = text[printed:]
                sys.stdout.write(chunk)
                if not chunk.endswith('\n'):
                    sys.stdout.write('\n')
                sys.stdout.flush()
                printed = len(text)

            tail_start = text.rfind(marker)
            tail = text[tail_start:] if tail_start >= 0 else ''
            if 'PASS  live E2E test completed' in tail or 'FINAL RESULT: PASS' in tail:
                print('\nFINAL RESULT: PASS')
                return 0
            if ('FAILED run evidence intentionally retained' in tail or
                    'Traceback (most recent call last):' in tail or
                    'AssertionError:' in tail):
                print('\nFINAL RESULT: FAIL')
                return 1
            time.sleep(POLL_SECONDS)
        print('\nFINAL RESULT: TIMEOUT')
        return 2
    finally:
        # Normally the OTA-side runner deletes it immediately after reading.
        try:
            bundle.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--slug', default=DEFAULT_SLUG)
    parser.add_argument('--ca-cert', default=None, help=f'Root CA certificate PEM (default {DEFAULT_CA_CERT})')
    parser.add_argument('--ca-key', help='Root CA private key PEM path; otherwise paste once into Python')
    parser.add_argument('--password-env', help='read Root CA key password from this environment variable')
    args = parser.parse_args()
    return run(args.slug, args.ca_cert, args.ca_key, args.password_env)


if __name__ == '__main__':
    raise SystemExit(main())
