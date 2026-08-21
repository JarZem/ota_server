#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import ssl
import subprocess
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

PUBLISH_DOMAIN = b'JaroslavZemanESP|firmware-publish-v1|'


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def detected_version(project: Path, build: Path) -> str:
    description = build / 'project_description.json'
    if description.is_file():
        try:
            value = str(json.loads(description.read_text(encoding='utf-8')).get('project_version') or '').strip()
            if value:
                return value
        except Exception:
            pass
    try:
        return subprocess.check_output(
            ['git', '-C', str(project), 'describe', '--tags', '--always', '--dirty'],
            text=True, stderr=subprocess.DEVNULL, timeout=5,
        ).strip()
    except Exception:
        return 'unknown'


def main() -> None:
    parser = argparse.ArgumentParser(description='Publish a successful ESP-IDF build to the JarZem OTA server.')
    parser.add_argument('--project', type=Path, required=True)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--project-name', required=True)
    args = parser.parse_args()

    project = args.project.resolve()
    build = args.build.resolve()
    config_path = project / '.jarzem_ota' / 'project.json'
    if not config_path.is_file():
        raise SystemExit('JarZem OTA project manifest is missing; build output will not be published.')
    config = json.loads(config_path.read_text(encoding='utf-8'))

    bin_path = build / f'{args.project_name}.bin'
    if not bin_path.is_file():
        raise SystemExit(f'ESP-IDF application binary not found: {bin_path}')

    credentials = project / 'device_credentials'
    private_key_path = credentials / 'device_private.pem'
    certificate_path = credentials / 'device_cert.pem'
    root_ca_path = credentials / 'root_ca_cert.pem'
    for path in (private_key_path, certificate_path, root_ca_path):
        if not path.is_file():
            raise SystemExit(f'Installed device identity is incomplete: {path}')

    metadata = dict(config.get('firmware') or {})
    metadata['firmware_version'] = detected_version(project, build)
    required = (
        'ota_ecosystem', 'device_model', 'product_role', 'firmware_product',
        'hardware_revision', 'chip_family', 'flash_size', 'firmware_channel',
        'firmware_version',
    )
    missing = [key for key in required if not str(metadata.get(key) or '').strip()]
    if missing:
        raise SystemExit('Firmware publish metadata missing: ' + ', '.join(missing))
    metadata.setdefault('secure_version', 0)
    metadata.setdefault('active', True)

    firmware_filename = str(config.get('firmware_filename') or f"{metadata['firmware_product']}.bin")
    digest = sha256(bin_path)
    metadata_bytes = json.dumps(metadata, separators=(',', ':'), sort_keys=True).encode('utf-8')
    metadata_b64 = b64url(metadata_bytes)
    canonical = (
        PUBLISH_DOMAIN
        + firmware_filename.encode('utf-8') + b'|'
        + digest.encode('ascii') + b'|'
        + metadata_b64.encode('ascii')
    )

    private_key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise SystemExit('Installed device private key is not EC.')
    signature = private_key.sign(canonical, ec.ECDSA(hashes.SHA256()))

    ota_url = str(config.get('publish_url') or '').rstrip('/')
    if not ota_url:
        raise SystemExit('publish_url is missing in .jarzem_ota/project.json')
    request = urllib.request.Request(
        ota_url + '/api/firmware/publish',
        data=bin_path.read_bytes(),
        headers={
            'Content-Type': 'application/octet-stream',
            'X-Firmware-Filename': firmware_filename,
            'X-Firmware-SHA256': digest,
            'X-Firmware-Metadata': metadata_b64,
            'X-Publisher-Certificate': b64url(certificate_path.read_bytes()),
            'X-Publisher-Signature': b64url(signature),
        },
        method='POST',
    )
    context = ssl.create_default_context(cafile=str(root_ca_path))
    try:
        with urllib.request.urlopen(request, timeout=120, context=context) as response:
            result = json.loads(response.read().decode('utf-8'))
    except Exception as exc:
        raise SystemExit(f'Firmware publish failed: {exc}') from exc

    if result.get('status') != 'PUBLISHED':
        raise SystemExit(f'Firmware publish rejected: {result}')
    print(f"JarZem OTA firmware published: {firmware_filename} version={metadata['firmware_version']} sha256={digest[:12]}")


if __name__ == '__main__':
    main()
