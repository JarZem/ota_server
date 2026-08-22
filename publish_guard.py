from __future__ import annotations

from database import db_connect
from device_registry import normalize_device_id


def require_verified_firmware_publication(version: str, publisher_device_id: str) -> dict:
    publisher_device_id = normalize_device_id(publisher_device_id)
    with db_connect() as conn:
        row = conn.execute(
            """
            SELECT * FROM artifact_publications
            WHERE firmware_version=? AND publisher_device_id=? AND bin_verified=1
            ORDER BY published_at DESC LIMIT 1
            """,
            (str(version), publisher_device_id),
        ).fetchone()
    if not row:
        raise ValueError('mjs_publish_requires_verified_matching_bin')
    return dict(row)
