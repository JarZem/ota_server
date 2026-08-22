from __future__ import annotations

import html
import time
from database import db_connect
from device_registry import normalize_device_id


def _now() -> int:
    return int(time.time())


def record_firmware_publish(*, version: str, filename: str, sha256: str, size: int,
                            publisher_device_id: str, certificate_fingerprint: str) -> None:
    now = _now()
    with db_connect() as conn:
        conn.execute(
            """
            INSERT INTO artifact_publications
                (firmware_version, firmware_filename, firmware_sha256, firmware_size,
                 publisher_device_id, publisher_certificate_fingerprint,
                 bin_verified, mjs_verified, z2m_loaded, published_at, last_error)
            VALUES (?, ?, ?, ?, ?, ?, 1, 0, 0, ?, NULL)
            ON CONFLICT (firmware_version, firmware_filename) DO UPDATE SET
                firmware_sha256=excluded.firmware_sha256,
                firmware_size=excluded.firmware_size,
                publisher_device_id=excluded.publisher_device_id,
                publisher_certificate_fingerprint=excluded.publisher_certificate_fingerprint,
                bin_verified=1,
                published_at=excluded.published_at,
                last_error=NULL
            """,
            (version, filename, sha256, int(size), normalize_device_id(publisher_device_id),
             certificate_fingerprint, now),
        )


def record_converter_publish(*, version: str, project: str, filename: str, sha256: str,
                             publisher_device_id: str, loaded: bool, error: str | None = None) -> None:
    now = _now()
    with db_connect() as conn:
        row = conn.execute(
            "SELECT id FROM artifact_publications WHERE firmware_version=? AND publisher_device_id=? ORDER BY published_at DESC LIMIT 1",
            (version, normalize_device_id(publisher_device_id)),
        ).fetchone()
        if row:
            conn.execute(
                """
                UPDATE artifact_publications
                SET converter_project=?, converter_filename=?, converter_sha256=?,
                    mjs_verified=?, z2m_loaded=?, converter_published_at=?, last_error=?
                WHERE id=?
                """,
                (project, filename, sha256, 1 if not error else 0, 1 if loaded else 0,
                 now, error, row['id']),
            )


def provisioning_state(device_id: str, counter: int, state: str, error: str | None = None) -> None:
    now = _now()
    device_id = normalize_device_id(device_id)
    with db_connect() as conn:
        conn.execute(
            """
            INSERT INTO provisioning_attempts
                (device_id, counter, state, started_at, updated_at, error)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (device_id, counter) DO UPDATE SET
                state=excluded.state, updated_at=excluded.updated_at, error=excluded.error
            """,
            (device_id, int(counter), state, now, now, error),
        )
        if state == 'CHALLENGE_SENT':
            conn.execute("UPDATE provisioning_attempts SET challenge_sent_at=?, updated_at=?, state=?, error=? WHERE device_id=? AND counter=?", (now, now, state, error, device_id, int(counter)))
        elif state == 'PROVISIONING_SENT':
            # P is emitted only after the main state machine has verified R.
            conn.execute("UPDATE provisioning_attempts SET response_verified_at=COALESCE(response_verified_at, ?), provisioning_sent_at=?, updated_at=?, state=?, error=? WHERE device_id=? AND counter=?", (now, now, now, state, error, device_id, int(counter)))
        elif state in ('COMPLETED', 'TIMEOUT', 'ERROR'):
            conn.execute("UPDATE provisioning_attempts SET completed_at=?, updated_at=?, state=?, error=? WHERE device_id=? AND counter=?", (now, now, state, error, device_id, int(counter)))


def firmware_device_state(*, device_id: str, sha256: str, filename: str, version: str,
                          code: str | None, state: str, token_expires_at: int | None = None,
                          error: str | None = None) -> None:
    now = _now()
    timestamp_columns = {
        'CHECK_CREATED': 'check_created_at',
        'CHECK_SENT': 'check_sent_at',
        'DOWNLOAD_STARTED': 'download_started_at',
        'DOWNLOAD_COMPLETED': 'download_finished_at',
        'DOWNLOAD_FAILED': 'download_failed_at',
        'DEVICE_CONFIRMED': 'grant_consumed_at',
        'SKIPPED': 'download_finished_at',
    }
    device_id = normalize_device_id(device_id)
    sha256 = str(sha256).lower()
    with db_connect() as conn:
        conn.execute(
            """
            INSERT INTO device_firmware_status
                (device_id, firmware_sha256, firmware_filename, firmware_version,
                 firmware_code, state, token_expires_at, last_error, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (device_id, firmware_sha256) DO UPDATE SET
                firmware_filename=excluded.firmware_filename,
                firmware_version=excluded.firmware_version,
                firmware_code=excluded.firmware_code,
                state=excluded.state,
                token_expires_at=COALESCE(excluded.token_expires_at, token_expires_at),
                last_error=excluded.last_error,
                updated_at=excluded.updated_at
            """,
            (device_id, sha256, filename, version, code, state, token_expires_at, error, now),
        )
        column = timestamp_columns.get(state)
        if column:
            conn.execute(
                f"UPDATE device_firmware_status SET {column}=?, state=?, last_error=?, updated_at=? WHERE device_id=? AND firmware_sha256=?",
                (now, state, error, now, device_id, sha256),
            )


def _fmt(ts) -> str:
    if not ts:
        return ''
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(ts)))


def _e(value) -> str:
    return html.escape(str(value or ''))


def render_ingress_tables() -> str:
    with db_connect() as conn:
        artifacts = conn.execute("SELECT * FROM artifact_publications ORDER BY published_at DESC LIMIT 50").fetchall()
        provisioning = conn.execute("SELECT * FROM provisioning_attempts ORDER BY updated_at DESC LIMIT 100").fetchall()
        device_fw = conn.execute("SELECT * FROM device_firmware_status ORDER BY updated_at DESC LIMIT 200").fetchall()

    artifact_rows = ''.join(
        '<tr><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>'.format(
            _e(r['firmware_version']), _e(r['firmware_filename']), _e(str(r['firmware_sha256'])[:12]),
            _e(r['converter_filename']), _e(str(r['converter_sha256'] or '')[:12]),
            'OK' if r['bin_verified'] else 'NO', 'OK' if r['mjs_verified'] else 'NO',
            'OK' if r['z2m_loaded'] else 'NO', _e(_fmt(r['converter_published_at'] or r['published_at'])),
            _e(str(r['publisher_certificate_fingerprint'] or '')[:12]))
        for r in artifacts
    ) or '<tr><td colspan="10">No published artifact records yet.</td></tr>'

    provisioning_rows = ''.join(
        '<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>'.format(
            _e(r['device_id']), _e(r['counter']), _e(r['state']), _e(_fmt(r['started_at'])),
            _e(_fmt(r['challenge_sent_at'])), _e(_fmt(r['response_verified_at'])),
            _e(_fmt(r['provisioning_sent_at'])), _e(_fmt(r['completed_at'])), _e(r['error']))
        for r in provisioning
    ) or '<tr><td colspan="9">No provisioning attempts recorded yet.</td></tr>'

    firmware_rows = ''.join(
        '<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>'.format(
            _e(r['device_id']), _e(r['firmware_version']), _e(r['firmware_filename']),
            _e(str(r['firmware_sha256'])[:12]), _e(r['firmware_code']), _e(r['state']),
            _e(_fmt(r['check_sent_at'] or r['check_created_at'])), _e(_fmt(r['download_started_at'])),
            _e(_fmt(r['download_finished_at'])), _e(_fmt(r['token_expires_at'])), _e(r['last_error']))
        for r in device_fw
    ) or '<tr><td colspan="11">No ESP × firmware activity recorded yet.</td></tr>'

    return f'''
<h3>Published BIN + Zigbee2MQTT converter</h3>
<div class="table-wrap"><table><thead><tr><th>Build</th><th>BIN</th><th>BIN SHA</th><th>MJS</th><th>MJS SHA</th><th>BIN verified</th><th>MJS verified</th><th>Z2M loaded</th><th>Time</th><th>Publisher cert</th></tr></thead><tbody>{artifact_rows}</tbody></table></div>
<h3>Provisioning attempts</h3>
<div class="table-wrap"><table><thead><tr><th>ESP</th><th>Counter</th><th>State</th><th>HELLO seen</th><th>Challenge sent</th><th>Response verified</th><th>Provision sent</th><th>Finished</th><th>Error</th></tr></thead><tbody>{provisioning_rows}</tbody></table></div>
<h3>ESP × firmware OTA state</h3>
<div class="table-wrap"><table><thead><tr><th>ESP</th><th>Build</th><th>BIN</th><th>SHA</th><th>Code</th><th>State</th><th>CHECK</th><th>Download start</th><th>Download finish</th><th>Token expires</th><th>Error</th></tr></thead><tbody>{firmware_rows}</tbody></table></div>
'''
