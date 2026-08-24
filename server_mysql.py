from __future__ import annotations

import re

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
    """Read live device identity from Home Assistant Device Registry.

    HA is authoritative for runtime-facing fields such as name, transport,
    model/model_id, hardware version and software version. Security identity
    remains in OTA device_certificates.
    """
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
            "device_id": device.get("id"),
            "ieee": ieee,
            "name": str(device.get("name_by_user") or device.get("name") or model_id or model or ieee),
            "model": model,
            "model_id": model_id,
            "manufacturer": str(device.get("manufacturer") or ""),
            "hw_version": str(device.get("hw_version") or ""),
            "sw_version": str(device.get("sw_version") or ""),
            "serial_number": str(device.get("serial_number") or ""),
            "transport": transport,
            "mqtt_topic_name": mqtt_topic_name,
        })

    result.sort(key=lambda x: (x["name"].lower(), x["transport"] or "", x["ieee"]))
    return result


server.get_ota_devices = get_ota_devices_from_ha
server.get_zha_devices = get_ota_devices_from_ha


def merged_device_records():
    """Merge HA live metadata with the CA-backed OTA security registry.

    Never infer a registered ESP identity from a firmware BIN. HA supplies
    model/HW/FW; device_certificates supplies role, certificate fingerprint and
    authenticated HELLO state.
    """
    ha_map = {d["ieee"]: d for d in get_ota_devices_from_ha()}
    cert_map = {d["device_id"]: d for d in list_registered_devices()}
    result = []

    for device_id in sorted(set(ha_map) | set(cert_map)):
        ha = ha_map.get(device_id, {})
        cert = cert_map.get(device_id, {})
        last_hello = int(cert.get("last_hello_counter") or 0)
        if cert:
            state = server.DEVICE_STATE_AUTHENTICATED if last_hello > 0 else "CERT_REGISTERED"
        else:
            state = server.DEVICE_STATE_DISCOVERED

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
            "firmware_version": ha.get("sw_version") or "",
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
        print(
            f"OTA dispatch: legacy provisioning write skipped for ieee={device.get('ieee')}; secure provisioning context already exists",
            flush=True,
        )
        return {"secure_provisioning": "already-completed"}
    return _original_write_ota_payload_to_zigbee(device, payload)


server.write_ota_payload_to_zigbee = write_ota_payload_to_zigbee

_original_page_html = server.page_html


def _lifecycle_parts(section: str):
    style_match = re.search(r'<style>(.*?)</style>', section, re.DOTALL)
    style = style_match.group(1) if style_match else ''
    panels = {
        name: content.strip()
        for name, content in re.findall(
            r'<section class="ota-tab-panel(?: active)?" data-panel="([^"]+)">(.*?)</section>',
            section,
            re.DOTALL,
        )
    }
    return style, panels


def page_html(message=""):
    body = _original_page_html(message)
    try:
        lifecycle = render_ingress_tables()
        lifecycle_style, lifecycle_panels = _lifecycle_parts(lifecycle)
    except Exception as exc:
        lifecycle_style = ''
        lifecycle_panels = {
            'activity': f'<h3>OTA lifecycle</h3><p class="error">Cannot read OTA lifecycle tables: {server.html.escape(str(exc))}</p>'
        }

    labels = [
        ('images', 'Images'),
        ('esp', 'ESP'),
        ('activity', 'OTA activity'),
        ('artifacts', 'BIN / MJS'),
        ('provisioning', 'Provisioning'),
        ('firmware', 'ESP × firmware'),
    ]
    nav = '<nav class="ota-main-tabs">' + ''.join(
        f'<button type="button" class="ota-main-tab{" active" if key == "images" else ""}" data-main-tab="{key}">{label}</button>'
        for key, label in labels
    ) + '</nav>'

    top_style = f'''<style>
{lifecycle_style}
.ota-main-tabs {{display:flex;flex-wrap:wrap;gap:6px;margin:12px 0 18px;border-bottom:1px solid #888;padding-bottom:6px}}
.ota-main-tab {{margin:0;padding:7px 12px;border:1px solid #777;border-radius:4px 4px 0 0;background:#222;color:#ddd;cursor:pointer}}
.ota-main-tab.active {{background:#ddd;color:#111}}
.ota-main-panel {{display:none}}
.ota-main-panel.active {{display:block}}
</style>'''

    body = body.replace('</head>', top_style + '\n</head>', 1)
    body = body.replace('<h2>ESP OTA Server</h2>', '<h2>ESP OTA Server</h2>\n' + nav, 1)
    body = body.replace('<h3>Firmware biny</h3>', '<section class="ota-main-panel active" data-main-panel="images">\n<h3>Firmware biny</h3>', 1)
    body = body.replace('<h3>Registrované ESP moduly</h3>', '</section>\n<section class="ota-main-panel" data-main-panel="esp">\n<h3>Registrované ESP moduly</h3>', 1)

    extra_panels = []
    for key in ('activity', 'artifacts', 'provisioning', 'firmware'):
        content = lifecycle_panels.get(key)
        if content:
            extra_panels.append(f'<section class="ota-main-panel" data-main-panel="{key}">{content}</section>')

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


class SecureOTAHandler(server.OTAHandler):
    """Main OTA HTTPS handler with signed publish and persistent download telemetry."""

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
