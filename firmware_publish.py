from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

FIRMWARE_DIR = Path('/share/ota_server/firmware')
ROOT_CA_CERT = Path('/share/ota_server/cert/root_ca_cert.pem')
MAX_FIRMWARE_BYTES = 16 * 1024 * 1024
PUBLISH_DOMAIN = b'JaroslavZemanESP|firmware-publish-v1|'
_FILENAME_RE = re.compile(r'^[A-Za-z0-9_.-]{1,128}\.bin$')
_SHA_RE = re.compile(r'^[0-9a-f]{64}$')


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text.encode('ascii') + b'=' * ((-len(text)) % 4))


def _send_json(handler, status: int, payload: dict) -> None:
    body = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    handler.send_response(status)
    handler.send_header('Content-Type', 'application/json')
    handler.send_header('Content-Length', str(len(body)))
    handler.send_header('Connection', 'close')
    handler.end_headers()
    handler.wfile.write(body)
    handler.wfile.flush()
    handler.close_connection = True


def _verified_device_certificate(encoded_cert: str) -> x509.Certificate:
    if not ROOT_CA_CERT.is_file():
        raise ValueError('root_ca_missing')
    cert = x509.load_pem_x509_certificate(_b64url_decode(encoded_cert))
    root = x509.load_pem_x509_certificate(ROOT_CA_CERT.read_bytes())
    if cert.issuer != root.subject:
        raise ValueError('certificate_issuer_mismatch')
    root_key = root.public_key()
    if not isinstance(root_key, ec.EllipticCurvePublicKey):
        raise ValueError('root_key_not_ec')
    root_key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
    now = datetime.now(timezone.utc)
    not_before = getattr(cert, 'not_valid_before_utc', cert.not_valid_before.replace(tzinfo=timezone.utc))
    not_after = getattr(cert, 'not_valid_after_utc', cert.not_valid_after.replace(tzinfo=timezone.utc))
    if now < not_before or now > not_after:
        raise ValueError('certificate_expired_or_not_yet_valid')
    constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    if constraints.ca:
        raise ValueError('publisher_certificate_is_ca')
    if not isinstance(cert.public_key(), ec.EllipticCurvePublicKey):
        raise ValueError('publisher_key_not_ec')
    return cert


def _validate_metadata(metadata: dict, sha256_hex: str, size: int) -> dict:
    if not isinstance(metadata, dict):
        raise ValueError('metadata_not_object')
    required = (
        'ota_ecosystem', 'device_model', 'product_role', 'firmware_product',
        'hardware_revision', 'chip_family', 'flash_size', 'firmware_channel',
        'firmware_version',
    )
    result = {}
    for key in required:
        value = str(metadata.get(key) or '').strip()
        if not value or len(value) > 96:
            raise ValueError(f'invalid_metadata_{key}')
        result[key] = value
    result['secure_version'] = int(metadata.get('secure_version', 0))
    result['active'] = 1 if bool(metadata.get('active', True)) else 0
    result['sha256'] = sha256_hex
    result['size'] = int(size)
    return result


def handle_publish(handler) -> None:
    try:
        filename = str(handler.headers.get('X-Firmware-Filename') or '')
        expected_sha = str(handler.headers.get('X-Firmware-SHA256') or '').lower()
        metadata_b64 = str(handler.headers.get('X-Firmware-Metadata') or '')
        certificate_b64 = str(handler.headers.get('X-Publisher-Certificate') or '')
        signature_b64 = str(handler.headers.get('X-Publisher-Signature') or '')
        if not _FILENAME_RE.fullmatch(filename) or os.path.basename(filename) != filename:
            raise ValueError('invalid_filename')
        if not _SHA_RE.fullmatch(expected_sha):
            raise ValueError('invalid_sha256')
        try:
            length = int(handler.headers.get('Content-Length', '0'))
        except ValueError as exc:
            raise ValueError('invalid_content_length') from exc
        if length <= 0 or length > MAX_FIRMWARE_BYTES:
            raise ValueError('invalid_firmware_size')
        metadata_raw = _b64url_decode(metadata_b64)
        metadata = json.loads(metadata_raw.decode('utf-8'))
        cert = _verified_device_certificate(certificate_b64)
        signature = _b64url_decode(signature_b64)
        canonical = (
            PUBLISH_DOMAIN
            + filename.encode('utf-8') + b'|'
            + expected_sha.encode('ascii') + b'|'
            + metadata_b64.encode('ascii')
        )
        cert.public_key().verify(signature, canonical, ec.ECDSA(hashlib_to_crypto_sha256()))

        FIRMWARE_DIR.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix='.publish-', suffix='.bin', dir=FIRMWARE_DIR)
        digest = hashlib.sha256()
        remaining = length
        try:
            with os.fdopen(fd, 'wb') as out:
                while remaining:
                    block = handler.rfile.read(min(64 * 1024, remaining))
                    if not block:
                        raise ValueError('truncated_firmware_body')
                    out.write(block)
                    digest.update(block)
                    remaining -= len(block)
                out.flush()
                os.fsync(out.fileno())
            actual_sha = digest.hexdigest()
            if actual_sha != expected_sha:
                raise ValueError('firmware_sha256_mismatch')
            release = _validate_metadata(metadata, actual_sha, length)
            target = FIRMWARE_DIR / filename
            release_path = FIRMWARE_DIR / (target.stem + '.release.json')
            release_temp = release_path.with_suffix(release_path.suffix + '.tmp')
            release_temp.write_text(json.dumps(release, indent=2, sort_keys=True) + '\n', encoding='utf-8')
            os.replace(temp_name, target)
            os.replace(release_temp, release_path)
        except Exception:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise

        print(f'Firmware publish accepted filename={filename} bytes={length} sha256={expected_sha[:12]}', flush=True)
        _send_json(handler, 201, {'status': 'PUBLISHED', 'filename': filename, 'sha256': expected_sha, 'size': length})
    except Exception as exc:
        print(f'Firmware publish rejected: {exc}', flush=True)
        _send_json(handler, 400, {'status': 'ERROR', 'error': str(exc)})


def hashlib_to_crypto_sha256():
    from cryptography.hazmat.primitives import hashes
    return hashes.SHA256()
