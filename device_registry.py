from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

from database import db_connect

ROOT_CA_PATH = Path('/share/ota_server/cert/root_ca_cert.pem')
URI_PREFIX = 'urn:jarzem:esp:pki:'


def normalize_device_id(value: str) -> str:
    compact = value.strip().lower().replace('0x', '').replace(':', '')
    if len(compact) != 16 or any(ch not in '0123456789abcdef' for ch in compact):
        raise ValueError('device_id must be an 8-byte IEEE address')
    return ':'.join(compact[i:i + 2] for i in range(0, 16, 2))


def _subject_value(cert: x509.Certificate, oid, default: str = '') -> str:
    values = cert.subject.get_attributes_for_oid(oid)
    return values[0].value if values else default


def _san_metadata(cert: x509.Certificate) -> dict[str, str]:
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    except x509.ExtensionNotFound:
        raise ValueError('device certificate has no SubjectAlternativeName')

    result: dict[str, str] = {}
    for uri in san.get_values_for_type(x509.UniformResourceIdentifier):
        if not uri.startswith(URI_PREFIX):
            continue
        rest = uri[len(URI_PREFIX):]
        if ':' not in rest:
            continue
        key, value = rest.split(':', 1)
        result[key] = unquote(value)
    return result


def verify_and_extract_device_certificate(certificate_pem: bytes) -> dict:
    root = x509.load_pem_x509_certificate(ROOT_CA_PATH.read_bytes())
    cert = x509.load_pem_x509_certificate(certificate_pem)

    if cert.issuer != root.subject:
        raise ValueError('certificate issuer does not match configured Root CA')
    if not isinstance(root.public_key(), ec.EllipticCurvePublicKey):
        raise ValueError('Root CA public key is not EC')
    root.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))

    now = datetime.now(timezone.utc)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    if now < not_before or now > not_after:
        raise ValueError('device certificate is outside its validity period')

    constraints = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
    if constraints.ca:
        raise ValueError('device certificate must have CA:FALSE')

    key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    if not key_usage.digital_signature:
        raise ValueError('device certificate must allow digitalSignature')

    eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    if ExtendedKeyUsageOID.CLIENT_AUTH not in eku:
        raise ValueError('device certificate must contain clientAuth EKU')

    public_key = cert.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, ec.SECP256R1):
        raise ValueError('device certificate must use P-256 public key')

    meta = _san_metadata(cert)
    if meta.get('role') != 'device':
        raise ValueError('certificate role is not device')
    if 'device' not in meta:
        raise ValueError('certificate does not contain device id')

    device_id = normalize_device_id(meta['device'])
    serial = _subject_value(cert, NameOID.SERIAL_NUMBER)
    if serial and normalize_device_id(serial) != device_id:
        raise ValueError('certificate serialNumber does not match device id')

    ecosystem = _subject_value(cert, NameOID.ORGANIZATION_NAME)
    group = meta.get('group') or _subject_value(cert, NameOID.ORGANIZATIONAL_UNIT_NAME)

    public_key_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_key_uncompressed = public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )

    return {
        'device_id': device_id,
        'ecosystem': ecosystem,
        'device_group': group,
        'device_model': meta.get('model', ''),
        'product_role': meta.get('product-role', ''),
        'hardware_revision': meta.get('hardware', ''),
        'chip_family': meta.get('chip', ''),
        'flash_size': meta.get('flash', ''),
        'certificate_pem': certificate_pem.decode('ascii'),
        'certificate_fingerprint': cert.fingerprint(hashes.SHA256()).hex(),
        'public_key_der': public_key_der,
        'public_key_uncompressed': public_key_uncompressed,
        'certificate_not_before': int(not_before.timestamp()),
        'certificate_not_after': int(not_after.timestamp()),
        'certificate_subject': cert.subject.rfc4514_string(),
        'certificate_issuer': cert.issuer.rfc4514_string(),
    }


def register_device_certificate(certificate_pem: bytes) -> dict:
    record = verify_and_extract_device_certificate(certificate_pem)
    now = int(datetime.now(timezone.utc).timestamp())

    with db_connect() as conn:
        existing = conn.execute(
            'SELECT certificate_fingerprint, registered_at FROM device_certificates WHERE device_id = ?',
            (record['device_id'],),
        ).fetchone()

        if existing is None:
            action = 'REGISTERED'
            registered_at = now
            conn.execute(
                '''
                INSERT INTO device_certificates (
                    device_id, ecosystem, device_group, device_model, product_role,
                    hardware_revision, chip_family, flash_size, certificate_pem,
                    certificate_fingerprint, public_key_der, public_key_uncompressed,
                    certificate_not_before, certificate_not_after, certificate_subject,
                    certificate_issuer, last_hello_counter, registered_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                ''',
                (
                    record['device_id'], record['ecosystem'], record['device_group'],
                    record['device_model'], record['product_role'], record['hardware_revision'],
                    record['chip_family'], record['flash_size'], record['certificate_pem'],
                    record['certificate_fingerprint'], record['public_key_der'],
                    record['public_key_uncompressed'], record['certificate_not_before'],
                    record['certificate_not_after'], record['certificate_subject'],
                    record['certificate_issuer'], registered_at, now,
                ),
            )
        elif existing['certificate_fingerprint'] == record['certificate_fingerprint']:
            action = 'UNCHANGED'
            registered_at = int(existing['registered_at'])
            conn.execute(
                'UPDATE device_certificates SET updated_at = ? WHERE device_id = ?',
                (now, record['device_id']),
            )
        else:
            action = 'REPLACED'
            registered_at = int(existing['registered_at'])
            conn.execute(
                '''
                UPDATE device_certificates SET
                    ecosystem=?, device_group=?, device_model=?, product_role=?,
                    hardware_revision=?, chip_family=?, flash_size=?, certificate_pem=?,
                    certificate_fingerprint=?, public_key_der=?, public_key_uncompressed=?,
                    certificate_not_before=?, certificate_not_after=?, certificate_subject=?,
                    certificate_issuer=?, last_hello_counter=0, updated_at=?
                WHERE device_id=?
                ''',
                (
                    record['ecosystem'], record['device_group'], record['device_model'],
                    record['product_role'], record['hardware_revision'], record['chip_family'],
                    record['flash_size'], record['certificate_pem'], record['certificate_fingerprint'],
                    record['public_key_der'], record['public_key_uncompressed'],
                    record['certificate_not_before'], record['certificate_not_after'],
                    record['certificate_subject'], record['certificate_issuer'], now,
                    record['device_id'],
                ),
            )

    record['registration_action'] = action
    record['registered_at'] = registered_at
    record['updated_at'] = now
    return record


def get_registered_device(device_id: str) -> dict | None:
    normalized = normalize_device_id(device_id)
    with db_connect() as conn:
        row = conn.execute(
            'SELECT * FROM device_certificates WHERE device_id=?',
            (normalized,),
        ).fetchone()
    return dict(row) if row else None


def list_registered_devices() -> list[dict]:
    with db_connect() as conn:
        rows = conn.execute(
            '''
            SELECT device_id, ecosystem, device_group, device_model, product_role,
                   hardware_revision, chip_family, flash_size, certificate_fingerprint,
                   certificate_not_before, certificate_not_after, last_hello_counter,
                   registered_at, updated_at
            FROM device_certificates
            ORDER BY device_id
            '''
        ).fetchall()
    return [dict(row) for row in rows]


def accept_hello_counter(device_id: str, counter: int) -> bool:
    normalized = normalize_device_id(device_id)
    with db_connect() as conn:
        row = conn.execute(
            'SELECT last_hello_counter FROM device_certificates WHERE device_id=?',
            (normalized,),
        ).fetchone()
        if row is None or counter <= int(row['last_hello_counter']):
            return False
        conn.execute(
            'UPDATE device_certificates SET last_hello_counter=?, updated_at=? WHERE device_id=?',
            (counter, int(datetime.now(timezone.utc).timestamp()), normalized),
        )
    return True
