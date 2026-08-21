#!/usr/bin/env python3
"""Adopt an already provisioned ESP identity without changing any key or certificate."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

REQUIRED = (
    'device_private.pem',
    'device_cert.pem',
    'root_ca_cert.pem',
    'ota_server_cert.pem',
)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def adopt_existing_identity(project: Path) -> dict:
    project = project.resolve()
    credential_dir = project / 'device_credentials'
    manifest_path = project / '.jarzem_ota' / 'identity.json'

    if manifest_path.exists():
        return json.loads(manifest_path.read_text(encoding='utf-8'))

    missing = [name for name in REQUIRED if not (credential_dir / name).is_file()]
    if missing:
        raise RuntimeError(
            'Cannot adopt partial identity. Missing: ' + ', '.join(missing) +
            '. Restore the original files; no key will be generated or replaced.'
        )

    key = serialization.load_pem_private_key(
        (credential_dir / 'device_private.pem').read_bytes(), password=None
    )
    cert = x509.load_pem_x509_certificate((credential_dir / 'device_cert.pem').read_bytes())
    if key.public_key().public_numbers() != cert.public_key().public_numbers():
        raise RuntimeError('Existing device_private.pem does not match device_cert.pem')

    root = x509.load_pem_x509_certificate((credential_dir / 'root_ca_cert.pem').read_bytes())
    if cert.issuer != root.subject:
        raise RuntimeError('Existing device certificate is not issued by the installed Root CA')

    serial_values = cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
    if not serial_values:
        raise RuntimeError('Existing device certificate does not contain the Zigbee IEEE serialNumber')
    device_id = serial_values[0].value.strip().lower()

    manifest = {
        'schema': 1,
        'device_id': device_id,
        'certificate_sha256': cert.fingerprint(hashes.SHA256()).hex(),
        'files': {name: sha256_file(credential_dir / name) for name in REQUIRED},
        'adopted_existing_identity': True,
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(f'Existing OTA identity adopted without modification: {device_id}')
    return manifest


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument('--project', type=Path, required=True)
    args = p.parse_args()
    adopt_existing_identity(args.project)


if __name__ == '__main__':
    main()
