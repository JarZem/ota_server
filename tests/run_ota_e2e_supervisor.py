#!/usr/bin/env python3
"""Launch the live OTA E2E test inside the OTA add-on from Home Assistant SSH.

The Root CA certificate is read from the OTA public trust anchor. The offline
Root CA private key is never stored in OTA: it is pasted into this Python
launcher from the keyboard and kept only in memory long enough to create the
short-lived mode-0600 E2E input bundle under /share. The OTA-side runner deletes
the bundle immediately after reading it.
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

PRIVATE_KEY_ENDINGS = {
    '-----END PRIVATE KEY-----',
    '-----END ENCRYPTED PRIVATE KEY-----',
    '-----END EC PRIVATE KEY-----',
}


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
    p = Path(path).expanduser()
    if not p.is_file():
        raise RuntimeError(f'{p}: file does not exist')
    value = p.read_text(encoding='ascii')
    if kind == 'certificate':
        if '-----BEGIN CERTIFICATE-----' not in value or '-----END CERTIFICATE-----' not in value:
            raise RuntimeError(f'{p}: not a PEM certificate')
    elif 'PRIVATE KEY-----' not in value:
        raise RuntimeError(f'{p}: not a PEM private key')
    return value.rstrip('\r\n') + '\n'


def paste_private_key() -> str:
    print('Paste Root CA private key PEM now.')
    print('The launcher continues automatically when the PEM END line is received.')
    lines: list[str] = []
    saw_begin = False
    while True:
        try:
            line = input()
        except EOFError as exc:
            raise RuntimeError('EOF received before complete Root CA private key PEM') from exc
        stripped = line.strip()
        if not saw_begin:
            if stripped.startswith('-----BEGIN ') and stripped.endswith('PRIVATE KEY-----'):
                saw_begin = True
                lines.append(stripped)
            elif stripped:
                raise RuntimeError('first non-empty line is not a PEM private-key BEGIN line')
            continue
        lines.append(stripped)
        if stripped in PRIVATE_KEY_ENDINGS:
            value = '\n'.join(lines) + '\n'
            print('Root CA private key received.')
            return value


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


def run(slug: str, ca_cert: str, ca_key: str | None,
        password_env: str | None) -> int:
    info = addon_info(slug)
    if info.get('state') != 'started':
        raise RuntimeError(f'OTA add-on {slug!r} is not started: state={info.get("state")!r}')
    if not info.get('stdin'):
        raise RuntimeError(f'OTA add-on {slug!r} does not have stdin enabled')

    cert = read_pem_file(ca_cert, 'certificate')
    key = read_pem_file(ca_key, 'private key') if ca_key else paste_private_key()

    if password_env:
        password = os.environ.get(password_env)
        if password is None:
            raise RuntimeError(f'environment variable {password_env!r} is not set')
    else:
        password = getpass.getpass('Root CA private key password (empty if unencrypted): ')

    bundle = write_bundle(cert, key, password)
    status_path = bundle.with_suffix('.status.json')
    try:
        status_path.unlink()
    except FileNotFoundError:
        pass

    marker = f'STDIN: starting live OTA E2E test bundle={bundle}'
    print(f"OTA add-on {slug} version={info.get('version')} state={info.get('state')}")
    print(f'Root CA certificate: {ca_cert}')
    print(f'Starting E2E inside OTA add-on using temporary bundle {bundle.name}...')

    try:
        send_stdin(slug, f'RUN_E2E_FILE {bundle}')
        start = wait_for_marker(slug, marker, timeout=30)
        print('E2E is running...')
        printed = start
        deadline = time.monotonic() + TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            text = addon_logs(slug)
            if len(text) < printed:
                printed = 0
            if len(text) > printed:
                chunk = text[printed:]
                sys.stdout.write(chunk)
                if not chunk.endswith('\n'):
                    sys.stdout.write('\n')
                sys.stdout.flush()
                printed = len(text)

            if status_path.is_file():
                status = json.loads(status_path.read_text(encoding='utf-8'))
                state = str(status.get('state') or '')
                detail = str(status.get('detail') or '')
                if state == 'PASS':
                    print('\nFINAL RESULT: PASS')
                    return 0
                if state == 'FAIL':
                    print(f'\nFINAL RESULT: FAIL{": " + detail if detail else ""}')
                    return 1
            time.sleep(POLL_SECONDS)

        print('\nFINAL RESULT: TIMEOUT waiting for OTA-side completion status')
        return 2
    finally:
        for path in (bundle, status_path):
            try:
                path.unlink()
            except FileNotFoundError:
                pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--slug', default=DEFAULT_SLUG)
    parser.add_argument('--ca-cert', default=DEFAULT_CA_CERT,
                        help=f'Root CA certificate PEM path (default {DEFAULT_CA_CERT})')
    parser.add_argument('--ca-key',
                        help='optional Root CA private key PEM path; otherwise paste it from keyboard')
    parser.add_argument('--password-env', help='read Root CA key password from this environment variable')
    args = parser.parse_args()
    return run(args.slug, args.ca_cert, args.ca_key, args.password_env)


if __name__ == '__main__':
    raise SystemExit(main())
