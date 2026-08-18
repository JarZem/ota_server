#!/usr/bin/env python3
"""Live integration test for the OTA manufacturing API.

Run this from a workstation that can reach the OTA manufacturing HTTPS service
and has access to the real offline Root CA certificate/private key. The test
simulates the certificate-related part of the ESP device provisioning client.

It intentionally registers one stable test identity in the OTA registry:
02:00:00:00:00:00:00:01 / group=manufacturing-test.
"""

from __future__ import annotations

import argparse
import getpass
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

ROOT_CA_CERT_NAME = 'root_ca_cert.pem'
ROOT_CA_KEY_NAME = 'root_ca_private.pem'
TEST_DEVICE_ID = '02:00:00:00:00:00:00:01'
TEST_DEVICE_COMPACT = '0200000000000001'
TEST_GROUP = 'manufacturing-test'
TEST_MODEL = 'ESP32-C6-TEST'
TEST_PRODUCT_ROLE = 'integration-test'
TEST_HARDWARE = 'TEST-REV'
TEST_CHIP = 'ESP32-C6'
TEST_FLASH = '16MB'
PKI_URI_PREFIX = 'urn:jarzem:esp:pki:'
ROLE_DEVICE_URI = PKI_URI_PREFIX + 'role:device'
ROLE_OTA_URI = PKI_URI_PREFIX + 'role:ota-server'


def fail(message: str) -> None:
    raise AssertionError(message)


def load_ca(ca_dir: Path) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey, Path]:
    cert_path = ca_dir / ROOT_CA_CERT_NAME
    key_path = ca_dir / ROOT_CA_KEY_NAME
    if not cert_path.is_file() or not key_path.is_file():
        raise FileNotFoundError(f'Missing {cert_path} or {key_path}')

    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    password_text = getpass.getpass('Root CA private key password (empty only if unencrypted): ')
    password = password_text.encode('utf-8') if password_text else None
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=password)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        fail('Root CA private key is not EC')
    if cert.public_key().public_numbers() != key.public_key().public_numbers():
        fail('Root CA certificate/private key mismatch')
    return cert, key, cert_path


def context(root_ca_path: Path) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=str(root_ca_path))


def get_bytes(base: str, endpoint: str, root_ca_path: Path) -> bytes:
    with urllib.request.urlopen(
        urllib.request.Request(base.rstrip('/') + endpoint),
        timeout=15,
        context=context(root_ca_path),
    ) as response:
        if response.status != 200:
            fail(f'GET {endpoint} returned HTTP {response.status}')
        return response.read()


def post_certificate(base: str, root_ca_path: Path, cert_pem: bytes) -> tuple[int, dict]:
    body = json.dumps({'device_certificate_pem': cert_pem.decode('ascii')}).encode('utf-8')
    request = urllib.request.Request(
        base.rstrip('/') + '/api/manufacturing/register-device',
        data=body,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    try:
        with urllib.request.urlopen(request, timeout=15, context=context(root_ca_path)) as response:
            return response.status, json.loads(response.read().decode('utf-8'))
    except urllib.error.HTTPError as exc:
        payload = json.loads(exc.read().decode('utf-8'))
        return exc.code, payload


def san_uri_values(cert: x509.Certificate) -> list[str]:
    san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    return san.get_values_for_type(x509.UniformResourceIdentifier)


def verify_signed_by_root(cert: x509.Certificate, root: x509.Certificate) -> None:
    if cert.issuer != root.subject:
        fail('certificate issuer does not match Root CA subject')
    root_key = root.public_key()
    if not isinstance(root_key, ec.EllipticCurvePublicKey):
        fail('Root CA public key is not EC')
    root_key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))


def build_device_cert(ca_cert: x509.Certificate,
                      ca_key: ec.EllipticCurvePrivateKey,
                      ecosystem: str,
                      role_uri: str = ROLE_DEVICE_URI,
                      client_auth: bool = True) -> x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ecosystem),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, TEST_GROUP),
        x509.NameAttribute(NameOID.COMMON_NAME, f'ESP Device {TEST_DEVICE_ID}'),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, TEST_DEVICE_ID),
    ])
    uris = [
        role_uri,
        f'{PKI_URI_PREFIX}device:{TEST_DEVICE_COMPACT}',
        f'{PKI_URI_PREFIX}group:{TEST_GROUP}',
        f'{PKI_URI_PREFIX}model:{TEST_MODEL}',
        f'{PKI_URI_PREFIX}product-role:{TEST_PRODUCT_ROLE}',
        f'{PKI_URI_PREFIX}hardware:{TEST_HARDWARE}',
        f'{PKI_URI_PREFIX}chip:{TEST_CHIP}',
        f'{PKI_URI_PREFIX}flash:{TEST_FLASH}',
    ]
    eku = [ExtendedKeyUsageOID.CLIENT_AUTH] if client_auth else [ExtendedKeyUsageOID.SERVER_AUTH]
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage(eku), critical=False)
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri) for uri in uris]),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )


def build_self_signed_invalid_cert(ecosystem: str) -> x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ecosystem),
        x509.NameAttribute(NameOID.COMMON_NAME, 'Untrusted Test Device'),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, TEST_DEVICE_ID),
    ])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([
            x509.UniformResourceIdentifier(ROLE_DEVICE_URI),
            x509.UniformResourceIdentifier(f'{PKI_URI_PREFIX}device:{TEST_DEVICE_COMPACT}'),
        ]), critical=False)
        .sign(key, hashes.SHA256())
    )


def main() -> None:
    parser = argparse.ArgumentParser(description='Live end-to-end test of OTA manufacturing endpoints used by ESP device provisioning.')
    parser.add_argument('--ota-url', default='https://192.168.2.120:8451')
    parser.add_argument('--ca-dir', type=Path, required=True)
    parser.add_argument('--ecosystem', default='JaroslavZemanESP')
    args = parser.parse_args()

    ca_dir = args.ca_dir.expanduser().resolve()
    ca_cert, ca_key, root_ca_path = load_ca(ca_dir)
    base = args.ota_url.rstrip('/')

    print(f'TEST OTA manufacturing API: {base}')

    health = json.loads(get_bytes(base, '/api/manufacturing/health', root_ca_path).decode('utf-8'))
    if health.get('status') != 'OK':
        fail(f'health endpoint returned {health}')
    print('PASS health endpoint + TLS validation')

    remote_root = x509.load_pem_x509_certificate(get_bytes(base, '/api/manufacturing/root-ca.pem', root_ca_path))
    if remote_root.fingerprint(hashes.SHA256()) != ca_cert.fingerprint(hashes.SHA256()):
        fail('OTA root-ca.pem does not match the local offline Root CA')
    print('PASS OTA exposes the expected Root CA')

    ota_cert = x509.load_pem_x509_certificate(get_bytes(base, '/api/manufacturing/ota-server.pem', root_ca_path))
    verify_signed_by_root(ota_cert, ca_cert)
    eku = ota_cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    if ExtendedKeyUsageOID.SERVER_AUTH not in eku:
        fail('OTA certificate does not contain serverAuth EKU')
    if ROLE_OTA_URI not in san_uri_values(ota_cert):
        fail(f'OTA certificate does not contain expected role URI {ROLE_OTA_URI}')
    print('PASS OTA server certificate chain, EKU and existing JarZem role URI')

    ota_public_endpoint = serialization.load_pem_public_key(
        get_bytes(base, '/api/manufacturing/ota-public.pem', root_ca_path)
    )
    cert_public = ota_cert.public_key()
    if not isinstance(ota_public_endpoint, ec.EllipticCurvePublicKey) or not isinstance(cert_public, ec.EllipticCurvePublicKey):
        fail('OTA public key is not EC')
    if ota_public_endpoint.public_numbers() != cert_public.public_numbers():
        fail('ota-public.pem does not match ota-server.pem public key')
    print('PASS OTA public-key endpoint matches OTA certificate')

    valid_cert = build_device_cert(ca_cert, ca_key, args.ecosystem)
    valid_pem = valid_cert.public_bytes(serialization.Encoding.PEM)
    expected_fp = valid_cert.fingerprint(hashes.SHA256()).hex()

    status, registration = post_certificate(base, root_ca_path, valid_pem)
    if status != 200 or registration.get('status') != 'REGISTERED':
        fail(f'valid device registration failed HTTP={status} response={registration}')
    expected = {
        'device_id': TEST_DEVICE_ID,
        'certificate_fingerprint': expected_fp,
        'device_group': TEST_GROUP,
        'device_model': TEST_MODEL,
        'product_role': TEST_PRODUCT_ROLE,
        'hardware_revision': TEST_HARDWARE,
        'chip_family': TEST_CHIP,
        'flash_size': TEST_FLASH,
        'ecosystem': args.ecosystem,
    }
    for key, value in expected.items():
        if registration.get(key) != value:
            fail(f'registration metadata mismatch {key}: {registration.get(key)!r} != {value!r}')
    print('PASS valid CA-signed device certificate registration + metadata extraction')

    status2, registration2 = post_certificate(base, root_ca_path, valid_pem)
    if status2 != 200 or registration2.get('certificate_fingerprint') != expected_fp:
        fail(f'idempotent re-registration failed HTTP={status2} response={registration2}')
    print('PASS idempotent re-registration of the same device certificate')

    untrusted = build_self_signed_invalid_cert(args.ecosystem)
    status3, response3 = post_certificate(base, root_ca_path, untrusted.public_bytes(serialization.Encoding.PEM))
    if status3 != 400 or response3.get('status') != 'ERROR':
        fail(f'untrusted certificate was not rejected HTTP={status3} response={response3}')
    print('PASS self-signed/untrusted device certificate rejected')

    wrong_role = build_device_cert(ca_cert, ca_key, args.ecosystem, role_uri=ROLE_OTA_URI)
    status4, response4 = post_certificate(base, root_ca_path, wrong_role.public_bytes(serialization.Encoding.PEM))
    if status4 != 400 or response4.get('status') != 'ERROR':
        fail(f'wrong-role certificate was not rejected HTTP={status4} response={response4}')
    print('PASS CA-signed certificate with wrong role rejected')

    wrong_eku = build_device_cert(ca_cert, ca_key, args.ecosystem, client_auth=False)
    status5, response5 = post_certificate(base, root_ca_path, wrong_eku.public_bytes(serialization.Encoding.PEM))
    if status5 != 400 or response5.get('status') != 'ERROR':
        fail(f'wrong-EKU certificate was not rejected HTTP={status5} response={response5}')
    print('PASS CA-signed certificate without clientAuth rejected')

    print('\nALL MANUFACTURING API TESTS PASSED')
    print(f'Registry test identity: {TEST_DEVICE_ID} ({TEST_GROUP})')


if __name__ == '__main__':
    main()
