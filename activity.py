from __future__ import annotations

import html
import time
from database import db_connect
from device_registry import normalize_device_id


def _now() -> int:
    return int(time.time())


def record_activity(category: str, action: str, *, device_id: str | None = None,
                    detail: str | None = None, severity: str = 'INFO') -> None:
    category = str(category or 'OTHER').upper()[:16]
    severity = str(severity or 'INFO').upper()[:8]
    action = str(action or '')[:96]
    normalized = normalize_device_id(device_id) if device_id else None
    with db_connect() as conn:
        conn.execute(
            "INSERT INTO activity_log (created_at, category, severity, device_id, action, detail) VALUES (?, ?, ?, ?, ?, ?)",
            (_now(), category, severity, normalized, action, str(detail or '')[:1024]),
        )


def record_firmware_publish(*, version: str, filename: str, sha256: str, size: int,
                            publisher_device_id: str, certificate_fingerprint: str) -> None:
    now = _now()
    device_id = normalize_device_id(publisher_device_id)
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
                bin_verified=1, published_at=excluded.published_at, last_error=NULL
            """,
            (version, filename, sha256, int(size), device_id, certificate_fingerprint, now),
        )
    record_activity('BIN', 'BIN registered and signature verified', device_id=device_id,
                    detail=f'{filename} build={version} sha={str(sha256)[:12]} bytes={int(size)}')


def record_converter_publish(*, version: str, project: str, filename: str, sha256: str,
                             publisher_device_id: str, loaded: bool, error: str | None = None) -> None:
    now = _now()
    device_id = normalize_device_id(publisher_device_id)
    with db_connect() as conn:
        row = conn.execute(
            "SELECT id FROM artifact_publications WHERE firmware_version=? AND publisher_device_id=? ORDER BY published_at DESC LIMIT 1",
            (version, device_id),
        ).fetchone()
        if row:
            conn.execute(
                """UPDATE artifact_publications SET converter_project=?, converter_filename=?, converter_sha256=?,
                   mjs_verified=?, z2m_loaded=?, converter_published_at=?, last_error=? WHERE id=?""",
                (project, filename, sha256, 1 if not error else 0, 1 if loaded else 0, now, error, row['id']),
            )
    record_activity('MJS', 'Converter verified and loaded' if loaded and not error else 'Converter publish failed',
                    device_id=device_id, detail=f'{filename} build={version} sha={str(sha256)[:12]}' + (f' error={error}' if error else ''),
                    severity='ERROR' if error else 'INFO')


def provisioning_state(device_id: str, counter: int, state: str, error: str | None = None) -> None:
    now = _now(); device_id = normalize_device_id(device_id)
    with db_connect() as conn:
        conn.execute(
            """INSERT INTO provisioning_attempts (device_id, counter, state, started_at, updated_at, error)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT (device_id, counter) DO UPDATE SET state=excluded.state, updated_at=excluded.updated_at, error=excluded.error""",
            (device_id, int(counter), state, now, now, error),
        )
        if state == 'CHALLENGE_SENT':
            conn.execute("UPDATE provisioning_attempts SET challenge_sent_at=?, updated_at=?, state=?, error=? WHERE device_id=? AND counter=?", (now, now, state, error, device_id, int(counter)))
        elif state == 'PROVISIONING_SENT':
            conn.execute("UPDATE provisioning_attempts SET response_verified_at=COALESCE(response_verified_at, ?), provisioning_sent_at=?, updated_at=?, state=?, error=? WHERE device_id=? AND counter=?", (now, now, now, state, error, device_id, int(counter)))
        elif state in ('COMPLETED', 'TIMEOUT', 'ERROR'):
            conn.execute("UPDATE provisioning_attempts SET completed_at=?, updated_at=?, state=?, error=? WHERE device_id=? AND counter=?", (now, now, state, error, device_id, int(counter)))
    record_activity('PROV', state, device_id=device_id, detail=f'counter={counter}' + (f' error={error}' if error else ''),
                    severity='ERROR' if error or state in ('ERROR','TIMEOUT') else 'INFO')


def firmware_device_state(*, device_id: str, sha256: str, filename: str, version: str,
                          code: str | None, state: str, token_expires_at: int | None = None,
                          error: str | None = None) -> None:
    now = _now(); device_id = normalize_device_id(device_id); sha256 = str(sha256).lower()
    timestamp_columns = {'CHECK_CREATED':'check_created_at','CHECK_SENT':'check_sent_at','DOWNLOAD_STARTED':'download_started_at',
                         'DOWNLOAD_COMPLETED':'download_finished_at','DOWNLOAD_FAILED':'download_failed_at','DEVICE_CONFIRMED':'grant_consumed_at','SKIPPED':'download_finished_at'}
    with db_connect() as conn:
        conn.execute(
            """INSERT INTO device_firmware_status
               (device_id, firmware_sha256, firmware_filename, firmware_version, firmware_code, state, token_expires_at, last_error, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT (device_id, firmware_sha256) DO UPDATE SET firmware_filename=excluded.firmware_filename,
               firmware_version=excluded.firmware_version, firmware_code=excluded.firmware_code, state=excluded.state,
               token_expires_at=COALESCE(excluded.token_expires_at, token_expires_at), last_error=excluded.last_error, updated_at=excluded.updated_at""",
            (device_id, sha256, filename, version, code, state, token_expires_at, error, now),
        )
        column = timestamp_columns.get(state)
        if column:
            conn.execute(f"UPDATE device_firmware_status SET {column}=?, state=?, last_error=?, updated_at=? WHERE device_id=? AND firmware_sha256=?",
                         (now, state, error, now, device_id, sha256))
    category = 'DOWNLOAD' if state.startswith('DOWNLOAD_') or state == 'DEVICE_CONFIRMED' else 'CHECK'
    record_activity(category, state, device_id=device_id,
                    detail=f'{filename} build={version} sha={sha256[:12]}' + (f' code={code}' if code else '') + (f' error={error}' if error else ''),
                    severity='ERROR' if error or state == 'DOWNLOAD_FAILED' else 'INFO')


def _compact_time(ts) -> str:
    if not ts: return ''
    value = int(ts); now = time.time()
    today = time.localtime(now); event = time.localtime(value)
    today_mid = int(time.mktime((today.tm_year,today.tm_mon,today.tm_mday,0,0,0,today.tm_wday,today.tm_yday,today.tm_isdst)))
    event_mid = int(time.mktime((event.tm_year,event.tm_mon,event.tm_mday,0,0,0,event.tm_wday,event.tm_yday,event.tm_isdst)))
    days = max(0, (today_mid-event_mid)//86400)
    prefix = 'T' if days == 0 else f'-{days}'
    return f'{prefix} {time.strftime("%H:%M:%S", event)}'


def _e(value) -> str:
    return html.escape(str(value or ''))


def render_ingress_tables() -> str:
    with db_connect() as conn:
        events = conn.execute("SELECT * FROM activity_log ORDER BY created_at DESC, id DESC LIMIT 100").fetchall()
        artifacts = conn.execute("SELECT * FROM artifact_publications ORDER BY published_at DESC, id DESC LIMIT 100").fetchall()
        provisioning = conn.execute("SELECT * FROM provisioning_attempts ORDER BY updated_at DESC, id DESC LIMIT 100").fetchall()
        device_fw = conn.execute("SELECT * FROM device_firmware_status ORDER BY updated_at DESC LIMIT 100").fetchall()

    event_rows = ''.join(
        '<tr class="ota-event ota-cat-{cat} ota-sev-{sev}" data-cat="{cat}"><td class="ota-time">{time}</td><td><span class="ota-badge">{cat}</span></td><td>{action}</td><td><code>{dev}</code></td><td>{detail}</td></tr>'.format(
            cat=_e(str(r['category']).upper()), sev=_e(str(r['severity']).lower()), time=_e(_compact_time(r['created_at'])),
            action=_e(r['action']), dev=_e(r['device_id']), detail=_e(r['detail'])) for r in events
    ) or '<tr><td colspan="5">No activity yet.</td></tr>'

    artifact_rows = ''.join('<tr><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>'.format(
        _e(_compact_time(r['converter_published_at'] or r['published_at'])), _e(r['firmware_version']), _e(str(r['firmware_sha256'])[:12]),
        'OK' if r['bin_verified'] else 'NO', 'OK' if r['mjs_verified'] else 'NO', 'OK' if r['z2m_loaded'] else 'NO') for r in artifacts) or '<tr><td colspan="6">No artifacts.</td></tr>'
    provisioning_rows = ''.join('<tr><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>'.format(
        _e(_compact_time(r['updated_at'])), _e(r['device_id']), _e(r['counter']), _e(r['state']), _e(r['error'])) for r in provisioning) or '<tr><td colspan="5">No provisioning.</td></tr>'
    firmware_rows = ''.join('<tr><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>'.format(
        _e(_compact_time(r['updated_at'])), _e(r['device_id']), _e(r['firmware_version']), _e(r['firmware_filename']),
        _e(str(r['firmware_sha256'])[:12]), _e(r['state']), _e(r['last_error'])) for r in device_fw) or '<tr><td colspan="7">No ESP × firmware activity.</td></tr>'

    return f'''
<style>
.ota-tabs{{display:flex;flex-wrap:wrap;gap:6px;margin:14px 0 10px;border-bottom:1px solid #666;padding-bottom:6px}}
.ota-tab{{border:1px solid #666;border-radius:4px 4px 0 0;padding:6px 10px;background:#222;color:#ddd;cursor:pointer}}
.ota-tab.active{{background:#ddd;color:#111}}
.ota-tab-panel{{display:none}}
.ota-tab-panel.active{{display:block}}
.ota-log-toolbar{{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0 10px}}
.ota-filter{{border:1px solid #666;border-radius:4px;padding:3px 8px;background:#222;color:#ddd;cursor:pointer}}
.ota-filter.active{{background:#ddd;color:#111}}
.ota-log table{{font-size:12px}}
.ota-log td{{padding:3px 6px;vertical-align:top}}
.ota-time{{white-space:nowrap;font-family:monospace}}
.ota-badge{{font-weight:700}}
.ota-cat-REG .ota-badge{{color:#6cf}}
.ota-cat-BIN .ota-badge{{color:#7ee787}}
.ota-cat-MJS .ota-badge{{color:#d2a8ff}}
.ota-cat-PROV .ota-badge{{color:#ffa657}}
.ota-cat-CHECK .ota-badge{{color:#79c0ff}}
.ota-cat-DOWNLOAD .ota-badge{{color:#3fb950}}
.ota-cat-MQTT .ota-badge{{color:#a5d6ff}}
.ota-sev-error td{{background:rgba(248,81,73,.16)}}
</style>
<div class="ota-tabs">
<button type="button" class="ota-tab active" data-tab="activity">OTA activity</button>
<button type="button" class="ota-tab" data-tab="artifacts">Published BIN / MJS detail</button>
<button type="button" class="ota-tab" data-tab="provisioning">Provisioning detail</button>
<button type="button" class="ota-tab" data-tab="firmware">ESP × firmware detail</button>
</div>

<section class="ota-tab-panel active" data-panel="activity">
<h3>OTA activity — posledních 100</h3>
<div class="ota-log-toolbar">
<button type="button" class="ota-filter active" data-filter="ALL">ALL</button><button type="button" class="ota-filter" data-filter="REG">REG</button>
<button type="button" class="ota-filter" data-filter="BIN">BIN</button><button type="button" class="ota-filter" data-filter="MJS">MJS</button>
<button type="button" class="ota-filter" data-filter="PROV">PROV</button><button type="button" class="ota-filter" data-filter="CHECK">CHECK</button>
<button type="button" class="ota-filter" data-filter="DOWNLOAD">DOWNLOAD</button><button type="button" class="ota-filter" data-filter="MQTT">MQTT</button>
</div>
<div class="table-wrap ota-log"><table><thead><tr><th>Time</th><th>What</th><th>Event</th><th>ESP</th><th>Detail</th></tr></thead><tbody>{event_rows}</tbody></table></div>
<script>
if (!window.__otaLiveRefreshInstalled) {{
  window.__otaLiveRefreshInstalled = true;
  window.__otaActivityFilter = window.__otaActivityFilter || 'ALL';

  function otaApplyActivityFilter(root, filter) {{
    if (!root || !filter) return;
    root.querySelectorAll('.ota-filter').forEach(x => x.classList.toggle('active', x.dataset.filter === filter));
    root.querySelectorAll('.ota-event').forEach(row => {{
      row.style.display = (filter === 'ALL' || row.dataset.cat === filter) ? '' : 'none';
    }});
  }}

  document.addEventListener('click', event => {{
    const button = event.target.closest('.ota-filter');
    if (!button) return;
    window.__otaActivityFilter = button.dataset.filter || 'ALL';
    const panel = button.closest('.ota-main-panel') || document;
    otaApplyActivityFilter(panel, window.__otaActivityFilter);
  }});

  async function otaRefreshVisiblePanel() {{
    if (document.hidden) return;
    const current = document.querySelector('.ota-main-panel.active');
    if (!current || !current.dataset.mainPanel) return;
    const name = current.dataset.mainPanel;
    const focused = document.activeElement;
    if (focused && current.contains(focused) && /^(INPUT|SELECT|TEXTAREA)$/.test(focused.tagName)) return;

    const pageX = window.scrollX;
    const pageY = window.scrollY;
    const wraps = Array.from(current.querySelectorAll('.table-wrap')).map(w => ({{left:w.scrollLeft, top:w.scrollTop}}));

    try {{
      const response = await fetch(window.location.href, {{cache:'no-store', credentials:'same-origin'}});
      if (!response.ok) return;
      const text = await response.text();
      const freshDoc = new DOMParser().parseFromString(text, 'text/html');
      const fresh = freshDoc.querySelector('.ota-main-panel[data-main-panel="' + CSS.escape(name) + '"]');
      if (!fresh) return;
      current.innerHTML = fresh.innerHTML;
      if (name === 'activity') otaApplyActivityFilter(current, window.__otaActivityFilter || 'ALL');
      current.querySelectorAll('.table-wrap').forEach((w, i) => {{
        if (wraps[i]) {{ w.scrollLeft = wraps[i].left; w.scrollTop = wraps[i].top; }}
      }});
      window.scrollTo(pageX, pageY);
    }} catch (_) {{}}
  }}

  window.setInterval(otaRefreshVisiblePanel, 1500);
}}
</script>
</section>

<section class="ota-tab-panel" data-panel="artifacts">
<h3>Published BIN / MJS detail — posledních 100</h3>
<div class="table-wrap"><table><thead><tr><th>Time</th><th>Build</th><th>BIN SHA</th><th>BIN</th><th>MJS</th><th>Z2M</th></tr></thead><tbody>{artifact_rows}</tbody></table></div>
</section>

<section class="ota-tab-panel" data-panel="provisioning">
<h3>Provisioning detail — posledních 100</h3>
<div class="table-wrap"><table><thead><tr><th>Time</th><th>ESP</th><th>Counter</th><th>State</th><th>Error</th></tr></thead><tbody>{provisioning_rows}</tbody></table></div>
</section>

<section class="ota-tab-panel" data-panel="firmware">
<h3>ESP × firmware detail — posledních 100</h3>
<div class="table-wrap"><table><thead><tr><th>Time</th><th>ESP</th><th>Build</th><th>BIN</th><th>SHA</th><th>State</th><th>Error</th></tr></thead><tbody>{firmware_rows}</tbody></table></div>
</section>
'''
