from __future__ import annotations

import os
import re
from datetime import datetime
from zoneinfo import ZoneInfo

import activity
import server
from activity import firmware_device_state, render_ingress_tables
from database import assert_schema_current, database_summary, db_connect
from device_registry import list_registered_devices
from firmware_publish import handle_publish
from zigbee2mqtt_publish import handle_zigbee2mqtt_publish
from ota_check_runtime import (
    consume_dispatch_token,
    create_dispatch_token,
    ensure_secure_dispatch_device,
    make_check_payload,
    make_noop_provision_payload,
    should_skip_payload,
    validate_dispatch_token,
)


DISPLAY_TIMEZONE = ZoneInfo('Europe/Prague')


def _compact_time_prague(ts) -> str:
    if not ts:
        return ''
    value = int(ts)
    now = datetime.now(DISPLAY_TIMEZONE)
    event = datetime.fromtimestamp(value, DISPLAY_TIMEZONE)
    days = max(0, (now.date() - event.date()).days)
    prefix = 'T' if days == 0 else f'-{days}'
    return f'{prefix} {event:%H:%M:%S}'


activity._compact_time = _compact_time_prague


def init_mysql_runtime() -> None:
    assert_schema_current()
    print(f'OTA database ready: {database_summary()}', flush=True)


server.db_connect = db_connect
server.init_db = init_mysql_runtime
server.ensure_device_can_receive_provisioning = ensure_secure_dispatch_device
server.ota_create_token = create_dispatch_token
server.ota_validate_token = validate_dispatch_token
server.make_provision_payload = make_noop_provision_payload
server.make_ota_check_payload = make_check_payload


def get_ota_devices_from_ha():
    devices = server.ha_ws_command({"type": "config/device_registry/list"})
    result = []
    for device in devices:
        if not server.device_matches_model(device):
            continue
        transport = None
        ieee = None
        mqtt_topic_name = None
        for identifier in device.get("identifiers", []):
            if not isinstance(identifier, (list, tuple)) or len(identifier) < 2:
                continue
            domain = str(identifier[0]).lower()
            value = str(identifier[1])
            if domain == "zha":
                candidate = server.normalize_ieee(value)
                if re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){7}", candidate):
                    transport = server.TRANSPORT_ZHA
                    ieee = candidate
                    break
            if domain == "mqtt" and value.startswith("zigbee2mqtt_"):
                topic_name = value[len("zigbee2mqtt_"):]
                candidate = server.normalize_ieee(topic_name)
                if re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){7}", candidate):
                    transport = server.TRANSPORT_ZIGBEE2MQTT
                    ieee = candidate
                    mqtt_topic_name = server.ieee_to_z2m_topic_name(topic_name)
                    break
        if not ieee:
            continue
        model = str(device.get("model") or "")
        model_id = str(device.get("model_id") or "")
        result.append({
            "device_id": device.get("id"), "ieee": ieee,
            "name": str(device.get("name_by_user") or device.get("name") or model_id or model or ieee),
            "model": model, "model_id": model_id,
            "manufacturer": str(device.get("manufacturer") or ""),
            "hw_version": str(device.get("hw_version") or ""),
            "sw_version": str(device.get("sw_version") or ""),
            "serial_number": str(device.get("serial_number") or ""),
            "transport": transport, "mqtt_topic_name": mqtt_topic_name,
        })
    result.sort(key=lambda x: (x["name"].lower(), x["transport"] or "", x["ieee"]))
    return result


server.get_ota_devices = get_ota_devices_from_ha
server.get_zha_devices = get_ota_devices_from_ha


def merged_device_records():
    ha_map = {d["ieee"]: d for d in get_ota_devices_from_ha()}
    cert_map = {d["device_id"]: d for d in list_registered_devices()}
    result = []
    for device_id in sorted(set(ha_map) | set(cert_map)):
        ha = ha_map.get(device_id, {})
        cert = cert_map.get(device_id, {})
        last_hello = int(cert.get("last_hello_counter") or 0)
        state = server.DEVICE_STATE_AUTHENTICATED if cert and last_hello > 0 else ("CERT_REGISTERED" if cert else server.DEVICE_STATE_DISCOVERED)
        result.append({
            "device_id": device_id,
            "zigbee_ieee": device_id,
            "state": state,
            "ota_ecosystem": cert.get("ecosystem") or server.runtime_config["ota"]["ecosystem"],
            "device_model": ha.get("model_id") or ha.get("model") or cert.get("device_model") or "unknown",
            "product_role": cert.get("product_role") or "unknown",
            "hardware_revision": ha.get("hw_version") or cert.get("hardware_revision") or "unknown",
            "chip_family": cert.get("chip_family") or "unknown",
            "flash_size": cert.get("flash_size") or "unknown",
            "firmware_version": cert.get("running_firmware_version") or ha.get("sw_version") or "",
            "firmware_product": ha.get("model_id") or ha.get("model") or cert.get("device_model") or "unknown",
            "firmware_channel": "stable",
            "device_public_key_fingerprint": cert.get("certificate_fingerprint") or "",
            "enrollment_counter": last_hello,
        })
    return result


server.list_device_records = merged_device_records
_original_write_ota_payload_to_zigbee = server.write_ota_payload_to_zigbee


def write_ota_payload_to_zigbee(device, payload):
    if should_skip_payload(payload):
        print(f"OTA dispatch: legacy provisioning write skipped for ieee={device.get('ieee')}; secure provisioning context already exists", flush=True)
        return {"secure_provisioning": "already-completed"}
    return _original_write_ota_payload_to_zigbee(device, payload)


server.write_ota_payload_to_zigbee = write_ota_payload_to_zigbee


def _maintenance_button(target: str, label: str, confirm: str) -> str:
    return (
        '<form method="post" action="" class="ota-maint-form" '
        f"onsubmit='return confirm({server.json.dumps(confirm)})'>"
        '<input type="hidden" name="maintenance_action" value="clear">'
        f'<input type="hidden" name="target" value="{server.html.escape(target)}">'
        f'<button type="submit" class="ota-danger">{server.html.escape(label)}</button>'
        '</form>'
    )


def _rowcount(result) -> int:
    return max(0, int(result.rowcount or 0))


def _delete_for_ids(conn, table: str, column: str, device_ids: list[str]) -> int:
    if not device_ids:
        return 0
    placeholders = ','.join('?' for _ in device_ids)
    return _rowcount(conn.execute(
        f'DELETE FROM {table} WHERE {column} IN ({placeholders})', tuple(device_ids)))


def _clear_test_data(conn) -> int:
    rows = conn.execute(
        "SELECT device_id FROM device_certificates "
        "WHERE device_group=? OR product_role=? OR device_model=?",
        ('ota-e2e-live', 'integration-test', 'ESP32-C6-E2E')
    ).fetchall()
    device_ids = sorted({str(row['device_id']) for row in rows})
    removed = 0

    # Every OTA table which can contain an E2E device or ota-e2e-* artifact is
    # cleaned here. Keep child/history tables first and identity/artifact roots last.
    for table, column in (
        ('device_firmware_status', 'device_id'),
        ('provisioning_attempts', 'device_id'),
        ('device_provisioning', 'device_id'),
        ('download_grants', 'device_id'),
        ('ota_dispatch', 'ieee'),
        ('artifact_publications', 'publisher_device_id'),
        ('activity_log', 'device_id'),
        ('devices', 'device_id'),
    ):
        removed += _delete_for_ids(conn, table, column, device_ids)

    # The legacy devices table can also carry the same identity in zigbee_ieee.
    removed += _delete_for_ids(conn, 'devices', 'zigbee_ieee', device_ids)

    # Firmware-related test rows are identifiable even after a previous partial
    # cleanup removed the test certificate/device registry.
    for sql in (
        "DELETE FROM device_firmware_status WHERE firmware_filename LIKE 'ota-e2e-%'",
        "DELETE FROM device_provisioning WHERE firmware_filename LIKE 'ota-e2e-%'",
        "DELETE FROM ota_dispatch WHERE filename LIKE 'ota-e2e-%'",
        "DELETE FROM artifact_publications WHERE firmware_filename LIKE 'ota-e2e-%' OR converter_project LIKE 'ota-e2e-%' OR converter_filename LIKE 'ota-e2e-%'",
        "DELETE FROM firmware_alias WHERE filename LIKE 'ota-e2e-%'",
        "DELETE FROM firmware_history WHERE filename LIKE 'ota-e2e-%'",
        "DELETE FROM firmware_images WHERE filename LIKE 'ota-e2e-%'",
        "DELETE FROM activity_log WHERE detail LIKE '%ota-e2e-%'",
        "DELETE FROM command_counters WHERE scope LIKE '%ota-e2e-%'",
    ):
        removed += _rowcount(conn.execute(sql))

    # A counter scope may contain the normalized virtual device id rather than
    # the project name. Remove only scopes containing one of our E2E identities.
    for device_id in device_ids:
        removed += _rowcount(conn.execute(
            "DELETE FROM command_counters WHERE scope LIKE ?",
            (f'%{device_id}%',)
        ))

    removed += _rowcount(conn.execute(
        "DELETE FROM device_certificates "
        "WHERE device_group=? OR product_role=? OR device_model=?",
        ('ota-e2e-live', 'integration-test', 'ESP32-C6-E2E')
    ))

    try:
        for name in os.listdir(server.FIRMWARE_DIR):
            if name.startswith('ota-e2e-'):
                path = os.path.join(server.FIRMWARE_DIR, name)
                if os.path.isfile(path):
                    os.remove(path)
    except OSError as exc:
        print(f'OTA maintenance: E2E file cleanup warning: {exc}', flush=True)
    return removed


def clear_maintenance_target(target: str) -> str:
    target = str(target or '').strip().lower()
    labels = {
        'activity': 'OTA activity', 'artifacts': 'BIN / MJS detail',
        'provisioning': 'Provisioning detail', 'firmware': 'ESP × firmware detail',
        'esp': 'OTA ESP registry', 'images': 'Images metadata', 'tests': 'E2E test data',
    }
    if target not in labels:
        raise ValueError('Unknown maintenance target')
    removed = 0
    with db_connect() as conn:
        if target == 'activity':
            removed = _rowcount(conn.execute('DELETE FROM activity_log'))
        elif target == 'artifacts':
            removed = _rowcount(conn.execute('DELETE FROM artifact_publications'))
        elif target == 'provisioning':
            removed = _rowcount(conn.execute('DELETE FROM provisioning_attempts'))
        elif target == 'firmware':
            removed = _rowcount(conn.execute('DELETE FROM device_firmware_status'))
        elif target == 'esp':
            # Reset only ESP/device-side OTA state; HA/Z2M device registry is untouched.
            for table in (
                'device_firmware_status', 'provisioning_attempts', 'device_provisioning',
                'download_grants', 'ota_dispatch', 'devices', 'device_certificates',
            ):
                removed += _rowcount(conn.execute(f'DELETE FROM {table}'))
            removed += _rowcount(conn.execute(
                "DELETE FROM activity_log WHERE device_id IS NOT NULL AND device_id <> ''"))
        elif target == 'images':
            for table in (
                'device_firmware_status', 'download_grants', 'artifact_publications',
                'ota_dispatch', 'firmware_alias', 'firmware_history', 'firmware_images',
            ):
                removed += _rowcount(conn.execute(f'DELETE FROM {table}'))
        elif target == 'tests':
            removed = _clear_test_data(conn)
    print(f'OTA maintenance: cleared target={target} rows={removed}', flush=True)
    return f'{labels[target]}: odstraněno {removed} záznamů.'


_original_page_html = server.page_html


def _lifecycle_parts(section: str):
    style_match = re.search(r'<style>(.*?)</style>', section, re.DOTALL)
    style = style_match.group(1) if style_match else ''
    panels = {name: content.strip() for name, content in re.findall(
        r'<section class="ota-tab-panel(?: active)?" data-panel="([^"]+)">(.*?)</section>', section, re.DOTALL)}
    return style, panels


def _tab_message(target: str, message: str, error: bool = False) -> str:
    if not message:
        return ''
    cls = 'ota-tab-message error' if error else 'ota-tab-message'
    return f'<div class="{cls}">{server.html.escape(message)}</div>'


def page_html(message="", maintenance_target="", maintenance_message="", maintenance_error=False):
    # Ordinary OTA/send messages retain the original behavior. Maintenance
    # messages are deliberately kept out of the global message area.
    body = _original_page_html(message)
    try:
        lifecycle = render_ingress_tables()
        lifecycle_style, lifecycle_panels = _lifecycle_parts(lifecycle)
    except Exception as exc:
        lifecycle_style = ''
        lifecycle_panels = {'activity': f'<h3>OTA lifecycle</h3><p class="error">Cannot read OTA lifecycle tables: {server.html.escape(str(exc))}</p>'}

    panel_messages = {key: '' for key in ('images', 'esp', 'activity', 'artifacts', 'provisioning', 'firmware')}
    if maintenance_target == 'tests':
        # E2E cleanup is intentionally on the first Images page.
        panel_messages['images'] = _tab_message('images', maintenance_message, maintenance_error)
    elif maintenance_target in panel_messages:
        panel_messages[maintenance_target] = _tab_message(maintenance_target, maintenance_message, maintenance_error)

    # Maintenance controls belong at the TOP of their own tab, never below tables.
    lifecycle_panels['activity'] = (
        '<div class="ota-tab-tools">' + _maintenance_button('activity', 'Smazat OTA activity', 'Opravdu smazat celý OTA activity log?') + '</div>' +
        panel_messages['activity'] + lifecycle_panels.get('activity', '')
    )
    lifecycle_panels['artifacts'] = (
        '<div class="ota-tab-tools">' + _maintenance_button('artifacts', 'Smazat BIN / MJS detail', 'Opravdu smazat historii publikovaných BIN / MJS?') + '</div>' +
        panel_messages['artifacts'] + lifecycle_panels.get('artifacts', '')
    )
    lifecycle_panels['provisioning'] = (
        '<div class="ota-tab-tools">' + _maintenance_button('provisioning', 'Smazat provisioning detail', 'Opravdu smazat historii provisioning pokusů?') + '</div>' +
        panel_messages['provisioning'] + lifecycle_panels.get('provisioning', '')
    )
    lifecycle_panels['firmware'] = (
        '<div class="ota-tab-tools">' + _maintenance_button('firmware', 'Smazat ESP × firmware detail', 'Opravdu smazat historii ESP × firmware?') + '</div>' +
        panel_messages['firmware'] + lifecycle_panels.get('firmware', '')
    )

    labels = [('images', 'Images'), ('esp', 'ESP'), ('activity', 'OTA activity'), ('artifacts', 'BIN / MJS'), ('provisioning', 'Provisioning'), ('firmware', 'ESP × firmware')]
    active_tab = 'images' if maintenance_target in ('', 'tests', 'images') else maintenance_target
    if active_tab not in {key for key, _ in labels}:
        active_tab = 'images'
    nav = '<nav class="ota-main-tabs">' + ''.join(
        f'<button type="button" class="ota-main-tab{" active" if key == active_tab else ""}" data-main-tab="{key}">{label}</button>'
        for key, label in labels) + '</nav>'

    top_style = f'''<style>
{lifecycle_style}
.ota-main-tabs {{display:flex;flex-wrap:wrap;gap:6px;margin:12px 0 8px;border-bottom:1px solid #888;padding-bottom:6px}}
.ota-main-tab {{margin:0;padding:7px 12px;border:1px solid #777;border-radius:4px 4px 0 0;background:#222;color:#ddd;cursor:pointer}}
.ota-main-tab.active {{background:#ddd;color:#111}}
.ota-main-panel {{display:none}}
.ota-main-panel.active {{display:block}}
.ota-maint-form {{display:inline-block;margin:0 8px 0 0}}
.ota-tab-tools {{display:flex;flex-wrap:wrap;gap:8px;margin:8px 0 10px}}
.ota-danger {{margin:0;border:1px solid #c44;background:#3a1717;color:#ffd7d7;border-radius:4px;padding:6px 10px;cursor:pointer}}
.ota-tab-message {{margin:8px 0 12px;padding:9px 10px;border:1px solid #777}}
.ota-tab-message.error {{border-color:#b00020;color:#b00020}}
</style>'''
    body = body.replace('</head>', top_style + '\n</head>', 1)
    body = body.replace('<h2>ESP OTA Server</h2>', '<h2>ESP OTA Server</h2>\n' + nav, 1)

    images_tools = '<div class="ota-tab-tools">' + ''.join((
        _maintenance_button('images', 'Smazat metadata Images', 'Opravdu smazat metadata firmware Images? BIN soubory na disku zůstanou zachovány.'),
        _maintenance_button('tests', 'Smazat E2E testovací data', 'Smazat E2E testovací zařízení a všechna ota-e2e-* data ze všech OTA tabulek? Normální ESP a firmware zůstanou zachovány.'),
    )) + '</div>' + panel_messages['images']
    esp_tools = '<div class="ota-tab-tools">' + _maintenance_button(
        'esp', 'Resetovat OTA ESP registry', 'POZOR: smaže OTA certifikační registry, provisioning a OTA stav zařízení. Home Assistant/Zigbee zařízení se nesmažou. Pokračovat?') + '</div>' + panel_messages['esp']

    body = body.replace(
        '<h3>Firmware biny</h3>',
        f'<section class="ota-main-panel{" active" if active_tab == "images" else ""}" data-main-panel="images">\n<h3>Firmware biny</h3>' + images_tools,
        1
    )
    body = body.replace(
        '<h3>Registrované ESP moduly</h3>',
        f'</section>\n<section class="ota-main-panel{" active" if active_tab == "esp" else ""}" data-main-panel="esp">\n<h3>Registrované ESP moduly</h3>' + esp_tools,
        1
    )

    extra_panels = []
    for key in ('activity', 'artifacts', 'provisioning', 'firmware'):
        content = lifecycle_panels.get(key)
        if content:
            active = ' active' if active_tab == key else ''
            extra_panels.append(f'<section class="ota-main-panel{active}" data-main-panel="{key}">{content}</section>')

    script = '''
<script>
document.querySelectorAll('.ota-main-tab').forEach(button => button.addEventListener('click', () => {
    const name = button.dataset.mainTab;
    document.querySelectorAll('.ota-main-tab').forEach(x => x.classList.toggle('active', x === button));
    document.querySelectorAll('.ota-main-panel').forEach(panel => panel.classList.toggle('active', panel.dataset.mainPanel === name));
}));
document.querySelectorAll('.ota-filter').forEach(button => button.addEventListener('click', () => {
    const filter = button.dataset.filter;
    document.querySelectorAll('.ota-filter').forEach(x => x.classList.toggle('active', x === button));
    document.querySelectorAll('.ota-event').forEach(row => row.style.display = (filter === 'ALL' || row.dataset.cat === filter) ? '' : 'none');
}));
</script>
'''
    body = body.replace('</body>', '</section>\n' + '\n'.join(extra_panels) + script + '\n</body>', 1)
    return body


server.page_html = page_html


class MaintenanceUIHandler(server.UIHandler):
    def do_POST(self):
        parsed = server.urllib.parse.urlparse(self.path)

        # Maintenance uses the CURRENT ingress page as action target. This avoids
        # HA ingress path-prefix problems and eliminates the old /maintenance/clear 404.
        if parsed.path.rstrip('/') in ('', '/index.html') or parsed.path == '/':
            try:
                length = int(self.headers.get('Content-Length') or 0)
            except ValueError:
                length = 0
            if 0 < length <= 4096:
                raw = self.rfile.read(length).decode('utf-8')
                values = server.urllib.parse.parse_qs(raw, keep_blank_values=True)
                if (values.get('maintenance_action') or [''])[0] == 'clear':
                    target = (values.get('target') or [''])[0]
                    try:
                        message = clear_maintenance_target(target)
                        self.send_html(page_html('', target, message, False))
                    except Exception as exc:
                        self.send_html(page_html('', target, f'Mazání selhalo: {exc}', True), status=400)
                    return
                # Not maintenance: delegate with the consumed body impossible.
                # The ordinary OTA form posts to /send, so root POST is reserved
                # exclusively for maintenance forms.
                self.send_error(400, 'Unknown root form action')
                return

        # Backward compatibility for an already-open old page: accept the old
        # path too, but new HTML never emits it.
        if parsed.path.rstrip('/') == '/maintenance/clear':
            try:
                length = int(self.headers.get('Content-Length') or 0)
                if length <= 0 or length > 4096:
                    raise ValueError('Invalid maintenance request')
                values = server.urllib.parse.parse_qs(self.rfile.read(length).decode('utf-8'), keep_blank_values=True)
                target = (values.get('target') or [''])[0]
                message = clear_maintenance_target(target)
                self.send_html(page_html('', target, message, False))
            except Exception as exc:
                target = locals().get('target', 'images')
                self.send_html(page_html('', target, f'Mazání selhalo: {exc}', True), status=400)
            return

        return super().do_POST()


server.UIHandler = MaintenanceUIHandler


class SecureOTAHandler(server.OTAHandler):
    activity_device_id = None
    activity_image = None
    activity_code = None

    def do_GET(self):
        parsed = server.urllib.parse.urlparse(self.path)
        code = server.os.path.basename(parsed.path)
        image = server.resolve_image_code(code)
        auth = self.headers.get("Authorization") or ""
        device_id = self.headers.get("X-Device-ID") or ""
        if image and auth.startswith("Bearer ") and device_id:
            token = auth[7:].strip()
            if validate_dispatch_token(token, code, device_id, image["sha256"]):
                self.activity_device_id = device_id
                self.activity_image = image
                self.activity_code = code
                firmware_device_state(device_id=device_id, sha256=image["sha256"], filename=image["filename"], version=str(image.get("version") or "unknown"), code=code, state="DOWNLOAD_STARTED")
                print(f"OTA download started device_id={device_id} filename={image['filename']} sha256={image['sha256'][:12]}", flush=True)
        return super().do_GET()

    def copyfile(self, source, outputfile):
        completed = False
        transfer_error = None
        try:
            while True:
                block = source.read(64 * 1024)
                if not block:
                    break
                outputfile.write(block)
            outputfile.flush()
            completed = True
        except (BrokenPipeError, ConnectionResetError) as exc:
            transfer_error = type(exc).__name__
        finally:
            image = self.activity_image
            device_id = self.activity_device_id
            if image and device_id:
                if completed:
                    firmware_device_state(device_id=device_id, sha256=image["sha256"], filename=image["filename"], version=str(image.get("version") or "unknown"), code=self.activity_code, state="DOWNLOAD_COMPLETED")
                elif transfer_error:
                    firmware_device_state(device_id=device_id, sha256=image["sha256"], filename=image["filename"], version=str(image.get("version") or "unknown"), code=self.activity_code, state="DOWNLOAD_FAILED", error=transfer_error)
            if completed and self.ota_sha256:
                auth = self.headers.get("Authorization") or ""
                device_id = self.headers.get("X-Device-ID") or ""
                if auth.startswith("Bearer ") and device_id:
                    token = auth[7:].strip()
                    consumed = consume_dispatch_token(token, device_id, self.ota_sha256)
                    print(f"OTA download grant {'consumed' if consumed else 'already-consumed/expired'} device_id={device_id} sha256={self.ota_sha256[:12]}", flush=True)

    def do_POST(self):
        parsed = server.urllib.parse.urlparse(self.path)
        if parsed.path == '/api/firmware/publish':
            print(f'Firmware publish request received from {self.client_address[0]}', flush=True)
            return handle_publish(self)
        if parsed.path == '/api/zigbee2mqtt/publish':
            print(f'Zigbee2MQTT converter publish request received from {self.client_address[0]}', flush=True)
            return handle_zigbee2mqtt_publish(self)
        return super().do_POST()


server.OTAHandler = SecureOTAHandler


if __name__ == '__main__':
    print('Firmware publish HTTPS endpoint active: POST /api/firmware/publish handler=SecureOTAHandler', flush=True)
    print('Zigbee2MQTT publish HTTPS endpoint active: POST /api/zigbee2mqtt/publish', flush=True)
    print('Ingress lifecycle tables active: artifacts, provisioning attempts, ESP x firmware state', flush=True)
    server.start_servers()
