from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from activity import record_firmware_publish
from device_registry import get_registered_device, verify_and_extract_device_certificate

FIRMWARE_DIR = Path('/share/ota_server/firmware')
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


def _validated_publisher(encoded_cert: str) -> tuple[x509.Certificate, dict, dict]:
    certificate_pem = _b64url_decode(encoded_cert)
    extracted = verify_and_extract_device_certificate(certificate_pem)
    registered = get_registered_device(extracted['device_id'])
    if registered is None:
        raise ValueError('publisher_device_not_registered')
    if str(registered.get('certificate_fingerprint') or '').lower() != extracted['certificate_fingerprint'].lower():
        raise ValueError('publisher_certificate_not_current_registered_certificate')

    cert = x509.load_pem_x509_certificate(certificate_pem)
    if not isinstance(cert.public_key(), ec.EllipticCurvePublicKey):
        raise ValueError('publisher_key_not_ec')
    return cert, extracted, registered


def _validate_metadata(metadata: dict, sha256_hex: str, size: int,
                       publisher: dict, registered: dict) -> dict:
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

    bindings = {
        'ota_ecosystem': ('ecosystem', 'ecosystem'),
        'device_model': ('device_model', 'device_model'),
        'product_role': ('product_role', 'product_role'),
        'hardware_revision': ('hardware_revision', 'hardware_revision'),
        'chip_family': ('chip_family', 'chip_family'),
        'flash_size': ('flash_size', 'flash_size'),
    }
    for metadata_key, (publisher_key, registered_key) in bindings.items():
        value = result[metadata_key]
        cert_value = str(publisher.get(publisher_key) or '').strip()
        db_value = str(registered.get(registered_key) or '').strip()
        if cert_value and value != cert_value:
            raise ValueError(f'publisher_certificate_metadata_mismatch_{metadata_key}')
        if db_value and value != db_value:
            raise ValueError(f'publisher_registry_metadata_mismatch_{metadata_key}')

    result['secure_version'] = int(metadata.get('secure_version', 0))
    result['active'] = 1 if bool(metadata.get('active', True)) else 0
    result['sha256'] = sha256_hex
    result['size'] = int(size)
    result['publisher_device_id'] = publisher['device_id']
    result['publisher_certificate_fingerprint'] = publisher['certificate_fingerprint']
    return result


def _receive_firmware_body(handler, length: int) -> tuple[str, str]:
    """Consume the complete accepted-size POST body before validating headers.

    This is deliberate: closing the HTTPS socket while the Windows client is still
    uploading a ~MB firmware body hides the useful HTTP 400 response behind
    WinError 10053/connection reset.  Once the body is consumed, any certificate,
    metadata or signature error can be returned to the build as normal JSON.
    """
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
        return temp_name, digest.hexdigest()
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def handle_publish(handler) -> None:
    temp_name = None
    try:
        try:
            length = int(handler.headers.get('Content-Length', '0'))
        except ValueError as exc:
            raise ValueError('invalid_content_length') from exc
        if length <= 0 or length > MAX_FIRMWARE_BYTES:
            raise ValueError('invalid_firmware_size')

        # For a sane firmware size always drain the full request first.  This
        # guarantees that later validation failures reach urllib as HTTP errors
        # instead of aborting an in-progress upload socket on Windows.
        temp_name, actual_sha = _receive_firmware_body(handler, length)

        filename = str(handler.headers.get('X-Firmware-Filename') or '')
        expected_sha = str(handler.headers.get('X-Firmware-SHA256') or '').lower()
        metadata_b64 = str(handler.headers.get('X-Firmware-Metadata') or '')
        certificate_b64 = str(handler.headers.get('X-Publisher-Certificate') or '')
        signature_b64 = str(handler.headers.get('X-Publisher-Signature') or '')

        if not _FILENAME_RE.fullmatch(filename) or os.path.basename(filename) != filename:
            raise ValueError('invalid_filename')
        if not _SHA_RE.fullmatch(expected_sha):
            raise ValueError('invalid_sha256')
        if actual_sha != expected_sha:
            raise ValueError('firmware_sha256_mismatch')

        metadata_raw = _b64url_decode(metadata_b64)
        metadata = json.loads(metadata_raw.decode('utf-8'))
        cert, publisher, registered = _validated_publisher(certificate_b64)
        signature = _b64url_decode(signature_b64)
        canonical = (
            PUBLISH_DOMAIN
            + filename.encode('utf-8') + b'|'
            + expected_sha.encode('ascii') + b'|'
            + metadata_b64.encode('ascii')
        )
        cert.public_key().verify(signature, canonical, ec.ECDSA(hashes.SHA256()))
        release = _validate_metadata(metadata, expected_sha, length, publisher, registered)

        target = FIRMWARE_DIR / filename
        release_path = FIRMWARE_DIR / (target.stem + '.release.json')
        release_temp = release_path.with_suffix(release_path.suffix + '.tmp')
        release_temp.write_text(json.dumps(release, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        os.replace(temp_name, target)
        temp_name = None
        os.replace(release_temp, release_path)

        record_firmware_publish(
            version=release['firmware_version'], filename=filename, sha256=expected_sha,
            size=length, publisher_device_id=publisher['device_id'],
            certificate_fingerprint=publisher['certificate_fingerprint'],
        )
        print(
            f"Firmware publish accepted device_id={publisher['device_id']} filename={filename} "
            f"bytes={length} sha256={expected_sha[:12]}", flush=True,
        )
        _send_json(handler, 201, {
            'status': 'PUBLISHED', 'publisher_device_id': publisher['device_id'],
            'filename': filename, 'sha256': expected_sha, 'size': length,
        })
    except Exception as exc:
        if temp_name:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
        print(f'Firmware publish rejected: {exc}', flush=True)
        try:
            _send_json(handler, 400, {'status': 'ERROR', 'error': str(exc)})
        except (BrokenPipeError, ConnectionResetError, OSError) as send_exc:
            print(f'Firmware publish error response could not be sent: {send_exc}', flush=True)
