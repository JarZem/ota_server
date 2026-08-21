from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time
from dataclasses import dataclass

from database import db_connect
from device_registry import get_registered_device, normalize_device_id
from secure_transport import derive_session_key

CHECK_KEY_DOMAIN = b"JaroslavZemanESP|ota-check-key-v1|"
TOKEN_KEY_DOMAIN = b"JaroslavZemanESP|ota-download-token-key-v1|"
CHECK_MAC_DOMAIN = b"JaroslavZemanESP|ota-check-v1|"
TOKEN_DOMAIN = b"JaroslavZemanESP|ota-download-token-v1|"
GRANT_RANDOM_LEN = 8
CHECK_MAC_LEN = 16
DOWNLOAD_TOKEN_LEN = 16
DOWNLOAD_TTL_SECONDS = 300


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * ((-len(value)) % 4))


def _derive_subkey(session_key: bytes, domain: bytes) -> bytes:
    return hmac.new(session_key, domain, hashlib.sha256).digest()


def _check_canonical(version: str, code: str, grant_random: bytes) -> bytes:
    return CHECK_MAC_DOMAIN + version.encode("utf-8") + b"|" + code.encode("ascii") + b"|" + grant_random


def _token_canonical(device_id: str, version: str, code: str, grant_random: bytes) -> bytes:
    return (
        TOKEN_DOMAIN
        + normalize_device_id(device_id).encode("ascii")
        + b"|"
        + version.encode("utf-8")
        + b"|"
        + code.encode("ascii")
        + b"|"
        + grant_random
    )


def save_provisioning_context(device_id: str, counter: int, random8: bytes) -> None:
    if counter <= 0 or len(random8) != 8:
        raise ValueError("invalid provisioning context")
    normalized = normalize_device_id(device_id)
    now = int(time.time())
    with db_connect() as conn:
        result = conn.execute(
            """
            UPDATE device_certificates
            SET provision_counter=?, provision_random=?, provision_context_updated_at=?, updated_at=?
            WHERE device_id=?
            """,
            (counter, random8, now, now, normalized),
        )
        if result.rowcount != 1:
            raise ValueError(f"device certificate not registered: {normalized}")


def load_provisioning_context(device_id: str) -> dict:
    normalized = normalize_device_id(device_id)
    with db_connect() as conn:
        row = conn.execute(
            """
            SELECT device_id, public_key_der, provision_counter, provision_random
            FROM device_certificates
            WHERE device_id=?
            """,
            (normalized,),
        ).fetchone()
    if not row:
        raise ValueError(f"device certificate not registered: {normalized}")
    result = dict(row)
    random8 = bytes(result.get("provision_random") or b"")
    counter = int(result.get("provision_counter") or 0)
    if counter <= 0 or len(random8) != 8:
        raise ValueError(f"device has no completed provisioning context: {normalized}")
    result["provision_random"] = random8
    result["provision_counter"] = counter
    return result


def derive_persisted_session_key(device_id: str) -> bytes:
    ctx = load_provisioning_context(device_id)
    return derive_session_key(
        bytes(ctx["public_key_der"]),
        ctx["device_id"],
        ctx["provision_counter"],
        ctx["provision_random"],
    )


@dataclass(frozen=True)
class OtaCheckGrant:
    device_id: str
    version: str
    code: str
    sha256: str
    grant_random: bytes
    token: str
    check_wire: str
    created_at: int
    expires_at: int


def create_ota_check_grant(device_id: str, version: str, code: str, sha256_hex: str) -> OtaCheckGrant:
    device_id = normalize_device_id(device_id)
    version = str(version).strip()
    code = str(code).strip()
    sha256_hex = str(sha256_hex).lower().strip()
    if not version or "|" in version or len(version.encode("utf-8")) > 32:
        raise ValueError("OTA CHECK version must be 1..32 bytes and cannot contain '|'")
    if len(code) != 3 or not code.isalnum():
        raise ValueError("OTA CHECK code must be exactly 3 alphanumeric characters")
    if len(sha256_hex) != 64 or any(ch not in "0123456789abcdef" for ch in sha256_hex):
        raise ValueError("invalid firmware SHA256")

    session_key = derive_persisted_session_key(device_id)
    check_key = _derive_subkey(session_key, CHECK_KEY_DOMAIN)
    token_key = _derive_subkey(session_key, TOKEN_KEY_DOMAIN)
    grant_random = os.urandom(GRANT_RANDOM_LEN)

    check_mac = hmac.new(
        check_key,
        _check_canonical(version, code, grant_random),
        hashlib.sha256,
    ).digest()[:CHECK_MAC_LEN]
    token_raw = hmac.new(
        token_key,
        _token_canonical(device_id, version, code, grant_random),
        hashlib.sha256,
    ).digest()[:DOWNLOAD_TOKEN_LEN]
    token = b64u(token_raw)
    check_wire = f"C|{version}|{code}|{b64u(grant_random)}|{b64u(check_mac)}"
    if len(check_wire.encode("utf-8")) > 100:
        raise ValueError("OTA CHECK exceeds Zigbee 100-byte protocol limit")

    now = int(time.time())
    expires_at = now + DOWNLOAD_TTL_SECONDS
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    with db_connect() as conn:
        conn.execute(
            """
            INSERT INTO download_grants
                (device_id, code, version, sha256, grant_random, token_hash, created_at, expires_at, consumed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
            """,
            (device_id, code, version, sha256_hex, grant_random, token_hash, now, expires_at),
        )

    return OtaCheckGrant(
        device_id=device_id,
        version=version,
        code=code,
        sha256=sha256_hex,
        grant_random=grant_random,
        token=token,
        check_wire=check_wire,
        created_at=now,
        expires_at=expires_at,
    )


def validate_download_token(token: str, code: str, device_id: str, sha256_hex: str) -> bool:
    try:
        device_id = normalize_device_id(device_id)
    except Exception:
        return False
    token_hash = hashlib.sha256(str(token).encode("ascii", "ignore")).hexdigest()
    now = int(time.time())
    with db_connect() as conn:
        row = conn.execute(
            """
            SELECT id
            FROM download_grants
            WHERE device_id=? AND code=? AND sha256=? AND token_hash=?
              AND consumed_at IS NULL AND expires_at>=?
            ORDER BY id DESC
            LIMIT 1
            """,
            (device_id, code, str(sha256_hex).lower(), token_hash, now),
        ).fetchone()
    return row is not None


def consume_download_grant(device_id: str, grant_random: bytes) -> bool:
    if len(grant_random) != GRANT_RANDOM_LEN:
        return False
    try:
        device_id = normalize_device_id(device_id)
    except Exception:
        return False
    now = int(time.time())
    with db_connect() as conn:
        result = conn.execute(
            """
            UPDATE download_grants
            SET consumed_at=?
            WHERE device_id=? AND grant_random=? AND consumed_at IS NULL AND expires_at>=?
            """,
            (now, device_id, grant_random, now),
        )
    return result.rowcount == 1


def consume_download_grant_b64(device_id: str, grant_random_b64: str) -> bool:
    try:
        grant_random = b64u_decode(grant_random_b64)
    except Exception:
        return False
    return consume_download_grant(device_id, grant_random)
