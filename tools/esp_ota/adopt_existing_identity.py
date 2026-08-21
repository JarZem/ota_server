#!/usr/bin/env python3
"""Adopt an already provisioned ESP identity without changing any key or certificate."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import urllib.parse
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID, ExtensionOID

REQUIRED = (
    'device_private.pem',
    'device_cert.pem',
    'root_ca_cert.pem',
    'ota_server_cert.pem',
)
PKI_URI_PREFIX = 'urn:jarzem:esp:pki:'


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def cert_metadata(cert: x509.Certificate) -> dict[str, str]:
    result: dict[str, str] = {}
    org = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    if org:
        result['ota_ecosystem'] = org[0].value
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    except x509.ExtensionNotFound:
        san = None
    if san is not None:
        mapping = {
            'model:': 'device_model',
            'product-role:': 'product_role',
            'hardware:': 'hardware_revision',
            'chip:': 'chip_family',
            'flash:': 'flash_size',
        }
        for uri in san.get_values_for_type(x509.UniformResourceIdentifier):
            if not uri.startswith(PKI_URI_PREFIX):
                continue
            tail = uri[len(PKI_URI_PREFIX):]
            for prefix, key in mapping.items():
                if tail.startswith(prefix):
                    result[key] = urllib.parse.unquote(tail[len(prefix):])
    return result


def detect_project_name(project: Path) -> str:
    cmake = project / 'CMakeLists.txt'
    if cmake.is_file():
        match = re.search(r'(?m)^\s*project\s*\(\s*([^\s\)]+)', cmake.read_text(encoding='utf-8', errors='ignore'))
        if match:
            return match.group(1)
    return project.name


def ensure_project_manifest(project: Path, cert: x509.Certificate, publish_url: str | None) -> None:
    path = project / '.jarzem_ota' / 'project.json'
    if path.is_file():
        return
    if not publish_url:
        return
    meta = cert_metadata(cert)
    required = ('ota_ecosystem', 'device_model', 'product_role', 'hardware_revision', 'chip_family', 'flash_size')
    missing = [key for key in required if not meta.get(key)]
    if missing:
        raise RuntimeError('Cannot derive project metadata from existing device certificate: ' + ', '.join(missing))
    product = detect_project_name(project)
    data = {
        'schema': 1,
        'publish_url': publish_url.rstrip('/'),
        'firmware_filename': product + '.bin',
        'firmware': {
            **meta,
            'firmware_product': product,
            'firmware_channel': 'stable',
            'secure_version': 0,
            'active': True,
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(f'OTA project publish manifest created without changing identity: {path}')


def adopt_existing_identity(project: Path, publish_url: str | None = None) -> dict:
    project = project.resolve()
    credential_dir = project / 'device_credentials'
    manifest_path = project / '.jarzem_ota' / 'identity.json'

    missing = [name for name in REQUIRED if not (credential_dir / name).is_file()]
    if missing:
        raise RuntimeError(
            'Cannot adopt partial identity. Missing: ' + ', '.join(missing) +
            '. Restore the original files; no key will be generated or replaced.'
        )

    cert = x509.load_pem_x509_certificate((credential_dir / 'device_cert.pem').read_bytes())
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        ensure_project_manifest(project, cert, publish_url)
        return manifest

    key = serialization.load_pem_private_key(
        (credential_dir / 'device_private.pem').read_bytes(), password=None
    )
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
    ensure_project_manifest(project, cert, publish_url)
    return manifest


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument('--project', type=Path, required=True)
    p.add_argument('--publish-url')
    args = p.parse_args()
    adopt_existing_identity(args.project, args.publish_url)


if __name__ == '__main__':
    main()
