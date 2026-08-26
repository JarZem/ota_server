from __future__ import annotations

import hashlib
import json
import os
import threading
import time

from database import db_connect
from device_registry import normalize_device_id
from ota_check_security import (
    create_ota_check_grant,
    load_provisioning_context,
    validate_download_token,
)

NOOP_PROVISION_PAYLOAD = "__OTA_PROVISIONING_ALREADY_SECURE__"
OPTIONS_PATH = "/data/options.json"
_pending = {}
_lock = threading.Lock()


def _firmware_for_code(code: str, sha256_hex: str) -> dict:
    with db_connect() as conn:
        row = conn.execute(
            """
            SELECT i.filename, i.version, i.sha256
            FROM firmware_alias a
            JOIN firmware_images i ON i.filename=a.filename
            WHERE a.code=? AND i.sha256=? AND i.active=1
            LIMIT 1
            """,
            (code, sha256_hex),
        ).fetchone()
    if not row:
        raise ValueError(f"active firmware not found for code={code} sha256={sha256_hex}")
    return dict(row)


def ensure_secure_dispatch_device(device_id: str) -> dict:
    try:
        return load_provisioning_context(device_id)
    except Exception as exc:
        raise PermissionError(f"OTA_CHECK_DENIED_NO_SECURE_PROVISIONING: {exc}") from exc


def create_dispatch_token(code: str, device_id: str, sha256_hex: str, *_args, **_kwargs) -> str:
    ensure_secure_dispatch_device(device_id)
    image = _firmware_for_code(code, sha256_hex)
    version = str(image.get("version") or "").strip()
    if not version:
        raise ValueError(f"firmware {image['filename']} has no version for OTA CHECK")
    grant = create_ota_check_grant(device_id, version, code, sha256_hex)
    with _lock:
        _pending[grant.token] = grant.check_wire
    return grant.token


def make_check_payload(token: str) -> str:
    with _lock:
        wire = _pending.pop(token, None)
    if not wire:
        raise ValueError("OTA CHECK grant is missing or already dispatched")
    return wire


def make_noop_provision_payload(*_args, **_kwargs) -> str:
    return NOOP_PROVISION_PAYLOAD


def should_skip_payload(payload: str) -> bool:
    return payload == NOOP_PROVISION_PAYLOAD


def validate_dispatch_token(token: str, code: str, device_id: str, sha256_hex: str, *_args, **_kwargs) -> bool:
    return validate_download_token(token, code, device_id, sha256_hex)


def consume_dispatch_token(token: str, device_id: str, sha256_hex: str) -> bool:
    try:
        device_id = normalize_device_id(device_id)
    except Exception:
        return False
    token_hash = hashlib.sha256(str(token).encode("ascii", "ignore")).hexdigest()
    now = int(time.time())
    with db_connect() as conn:
        result = conn.execute(
            """
            UPDATE download_grants
            SET consumed_at=?
            WHERE device_id=? AND sha256=? AND token_hash=?
              AND consumed_at IS NULL AND expires_at>=?
            """,
            (now, device_id, str(sha256_hex).lower(), token_hash, now),
        )
    return result.rowcount == 1


def secure_provisioning_ui_state(device_id: str) -> dict | None:
    """Return UI provisioning state from the same durable context used by OTA CHECK."""
    try:
        normalized = normalize_device_id(device_id)
    except Exception:
        return None

    with db_connect() as conn:
        row = conn.execute(
            """
            SELECT provision_counter, provision_random, provision_context_updated_at
            FROM device_certificates
            WHERE device_id=?
            """,
            (normalized,),
        ).fetchone()
    if not row:
        return None

    counter = int(row.get("provision_counter") or 0)
    random8 = bytes(row.get("provision_random") or b"")
    if counter <= 0 or len(random8) != 8:
        return None

    options = {}
    try:
        if os.path.isfile(OPTIONS_PATH):
            with open(OPTIONS_PATH, "r", encoding="utf-8") as f:
                options = json.load(f)
    except Exception:
        options = {}

    return {
        "device_id": normalized,
        "status": "PROVISIONED",
        "wifi_ssid": str(options.get("wifi_ssid") or ""),
        "wifi_security": str(options.get("wifi_security") or ""),
        "wifi_channel": int(options.get("wifi_channel") or 0),
        "ota_host": str(options.get("ota_host") or ""),
        "ota_port": int(options.get("ota_port") or 8443),
        "firmware_filename": None,
        "firmware_sha256": None,
        "transport": "secure-zigbee",
        "error": None,
        "updated_at": int(row.get("provision_context_updated_at") or 0),
        "provision_counter": counter,
    }


# server_mysql imports this module only after server.py is loaded. Override the
# legacy UI getter here so the ESP table reflects the secure durable context,
# not the obsolete device_provisioning table.
try:
    import server as _server
    _server.get_device_provisioning = secure_provisioning_ui_state
except Exception:
    pass
