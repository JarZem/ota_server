#!/usr/bin/env python3
"""Create one immutable CA-signed ESP identity and register only its public certificate with OTA."""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import ssl
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT_CA_CERT_NAME = 'root_ca_cert.pem'
ROOT_CA_KEY_NAME = 'root_ca_private.pem'
DEVICE_CERT_NAME = 'device_cert.pem'
DEVICE_KEY_NAME = 'device_private.pem'
OTA_CERT_NAME = 'ota_server_cert.pem'
OTA_PUBLIC_NAME = 'ota_server_public.pem'
PKI_URI_PREFIX = 'urn:jarzem:esp:pki:'
ROLE_URI = PKI_URI_PREFIX + 'role:device'


def ask(prompt: str, default: str | None = None) -> str:
    suffix = f' [{default}]' if default is not None else ''
    value = input(f'{prompt}{suffix}: ').strip()
    return value or (default or '')


def normalize_device_id(value: str) -> tuple[str, str]:
    compact = value.strip().lower().replace('0x', '').replace(':', '').replace('-', '')
    if len(compact) != 16 or any(ch not in '0123456789abcdef' for ch in compact):
        raise ValueError('device id must be an 8-byte Zigbee IEEE address')
    colon = ':'.join(compact[i:i + 2] for i in range(0, 16, 2))
    return compact, colon


def uri_value(value: str) -> str:
    return urllib.parse.quote(value, safe='-._~')


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def assert_identity_absent(project: Path) -> tuple[Path, Path]:
    output = project / 'device_credentials'
    manifest = project / '.jarzem_ota' / 'identity.json'
    if manifest.exists():
        raise RuntimeError(f'Identity already installed: {manifest}. It will never be regenerated automatically.')
    if output.exists():
        existing = [p.name for p in output.iterdir()]
        raise RuntimeError(
            f'{output} already exists ({", ".join(existing) or "empty directory"}). '
            'Remove it only if this project has never represented a real device; otherwise restore/use the existing identity.'
        )
    return output, manifest


def load_ca(ca_dir: Path) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    cert_path = ca_dir / ROOT_CA_CERT_NAME
    key_path = ca_dir / ROOT_CA_KEY_NAME
    if not cert_path.is_file() or not key_path.is_file():
        raise RuntimeError('Offline CA directory must contain root_ca_cert.pem and root_ca_private.pem')
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    print('The Root CA private key is used locally only to sign this new device certificate.')
    password_text = getpass.getpass('Password protecting root_ca_private.pem (empty only if unencrypted): ')
    password = password_text.encode('utf-8') if password_text else None
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=password)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise RuntimeError('Root CA private key is not EC')
    if cert.public_key().public_numbers() != key.public_key().public_numbers():
        raise RuntimeError('Root CA certificate/private key mismatch')
    return cert, key


def make_device_certificate(
    ca_cert: x509.Certificate,
    ca_key: ec.EllipticCurvePrivateKey,
    ecosystem: str,
    device_id: str,
    compact_id: str,
    device_group: str,
    device_model: str,
    product_role: str,
    hardware_revision: str,
    chip_family: str,
    flash_size: str,
    days: int,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    device_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ecosystem),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, device_group),
        x509.NameAttribute(NameOID.COMMON_NAME, f'ESP Device {device_id}'),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, device_id),
    ])
    uris = [
        ROLE_URI,
        f'{PKI_URI_PREFIX}device:{compact_id}',
        f'{PKI_URI_PREFIX}group:{uri_value(device_group)}',
        f'{PKI_URI_PREFIX}model:{uri_value(device_model)}',
        f'{PKI_URI_PREFIX}product-role:{uri_value(product_role)}',
        f'{PKI_URI_PREFIX}hardware:{uri_value(hardware_revision)}',
        f'{PKI_URI_PREFIX}chip:{uri_value(chip_family)}',
        f'{PKI_URI_PREFIX}flash:{uri_value(flash_size)}',
    ]
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(device_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=True, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri) for uri in uris]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(device_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return device_key, cert


def https_context(root_ca_path: Path) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=str(root_ca_path))


def ota_get(ota_base: str, endpoint: str, root_ca_path: Path) -> bytes:
    req = urllib.request.Request(f'{ota_base.rstrip("/")}{endpoint}')
    with urllib.request.urlopen(req, timeout=20, context=https_context(root_ca_path)) as response:
        return response.read()


def register_with_ota(ota_base: str, root_ca_path: Path, certificate_pem: bytes) -> dict:
    body = json.dumps({'device_certificate_pem': certificate_pem.decode('ascii')}).encode('utf-8')
    req = urllib.request.Request(
        f'{ota_base.rstrip("/")}/api/manufacturing/register-device',
        data=body,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    with urllib.request.urlopen(req, timeout=20, context=https_context(root_ca_path)) as response:
        return json.loads(response.read().decode('utf-8'))


def install_identity(
    project: Path,
    device_id_raw: str,
    device_group: str,
    device_model: str,
    product_role: str,
    hardware_revision: str,
    chip_family: str,
    flash_size: str,
    ecosystem: str,
    ca_dir: Path,
    manufacturing_url: str,
    days: int = 3650,
) -> dict:
    project = project.resolve()
    output_dir, manifest_path = assert_identity_absent(project)
    compact_id, device_id = normalize_device_id(device_id_raw)
    ca_cert, ca_key = load_ca(ca_dir.resolve())
    device_key, cert = make_device_certificate(
        ca_cert, ca_key, ecosystem, device_id, compact_id, device_group, device_model,
        product_role, hardware_revision, chip_family, flash_size, days,
    )

    output_dir.mkdir(parents=True, exist_ok=False)
    try:
        cert_path = output_dir / DEVICE_CERT_NAME
        key_path = output_dir / DEVICE_KEY_NAME
        root_ca_path = output_dir / ROOT_CA_CERT_NAME
        ota_cert_path = output_dir / OTA_CERT_NAME
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        cert_path.write_bytes(cert_pem)
        key_path.write_bytes(device_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        root_ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
        try:
            key_path.chmod(0o600)
        except OSError:
            pass

        registration = register_with_ota(manufacturing_url, root_ca_path, cert_pem)
        status = str(registration.get('status') or '')
        if status not in {'REGISTERED', 'UNCHANGED'}:
            raise RuntimeError(
                f'OTA registration returned {status!r}. Refusing to replace an existing device identity automatically: {registration}'
            )
        ota_cert_path.write_bytes(ota_get(manufacturing_url, '/api/manufacturing/ota-server.pem', root_ca_path))
        (output_dir / OTA_PUBLIC_NAME).write_bytes(ota_get(manufacturing_url, '/api/manufacturing/ota-public.pem', root_ca_path))

        manifest = {
            'schema': 1,
            'device_id': device_id,
            'certificate_sha256': cert.fingerprint(hashes.SHA256()).hex(),
            'files': {
                name: sha256_file(output_dir / name)
                for name in (DEVICE_KEY_NAME, DEVICE_CERT_NAME, ROOT_CA_CERT_NAME, OTA_CERT_NAME)
            },
        }
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        return manifest
    except Exception:
        # Identity was never committed to the manifest, so an interrupted first install must be cleaned manually.
        # Never perform automatic cleanup here: preserving any generated private key is safer than accidentally deleting identity material.
        raise


def main() -> None:
    p = argparse.ArgumentParser(description='One-time JarZem Secure OTA device identity installation.')
    p.add_argument('--project', type=Path, required=True)
    p.add_argument('--device-id')
    p.add_argument('--group')
    p.add_argument('--device-model')
    p.add_argument('--product-role')
    p.add_argument('--hardware-revision')
    p.add_argument('--chip-family', default='ESP32-C6')
    p.add_argument('--flash-size', default='16MB')
    p.add_argument('--ecosystem', default='JaroslavZemanESP')
    p.add_argument('--ca-dir', type=Path)
    p.add_argument('--manufacturing-url')
    p.add_argument('--days', type=int, default=3650)
    args = p.parse_args()

    manifest = install_identity(
        args.project,
        args.device_id or ask('Device Zigbee IEEE'),
        args.group or ask('Device group/family'),
        args.device_model or ask('Device model'),
        args.product_role or ask('Product role/function'),
        args.hardware_revision or ask('Hardware revision', 'RevA'),
        args.chip_family,
        args.flash_size,
        args.ecosystem,
        (args.ca_dir or Path(ask('Offline CA directory'))).expanduser(),
        args.manufacturing_url or ask('OTA manufacturing HTTPS URL', 'https://192.168.2.120:8451'),
        args.days,
    )
    print(f"Device identity installed and locked by manifest: {manifest['device_id']}")
    print('Future builds only validate and use this identity; they never regenerate it.')


if __name__ == '__main__':
    main()
