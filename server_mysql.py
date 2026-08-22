from __future__ import annotations

import server
from activity import firmware_device_state, render_ingress_tables
from database import assert_schema_current, database_summary, db_connect
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


def page_html(message=""):
    body = _original_page_html(message)
    try:
        section = render_ingress_tables()
    except Exception as exc:
        section = f'<h3>OTA lifecycle</h3><p class="error">Cannot read OTA lifecycle tables: {server.html.escape(str(exc))}</p>'
    marker = '<form method="POST" action="send">'
    return body.replace(marker, section + '\n' + marker, 1)


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
                firmware_device_state(
                    device_id=device_id, sha256=image["sha256"], filename=image["filename"],
                    version=str(image.get("version") or "unknown"), code=code,
                    state="DOWNLOAD_STARTED",
                )
                print(
                    f"OTA download started device_id={device_id} filename={image['filename']} sha256={image['sha256'][:12]}",
                    flush=True,
                )
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
                    firmware_device_state(
                        device_id=device_id, sha256=image["sha256"], filename=image["filename"],
                        version=str(image.get("version") or "unknown"), code=self.activity_code,
                        state="DOWNLOAD_COMPLETED",
                    )
                elif transfer_error:
                    firmware_device_state(
                        device_id=device_id, sha256=image["sha256"], filename=image["filename"],
                        version=str(image.get("version") or "unknown"), code=self.activity_code,
                        state="DOWNLOAD_FAILED", error=transfer_error,
                    )

            if completed and self.ota_sha256:
                auth = self.headers.get("Authorization") or ""
                device_id = self.headers.get("X-Device-ID") or ""
                if auth.startswith("Bearer ") and device_id:
                    token = auth[7:].strip()
                    consumed = consume_dispatch_token(token, device_id, self.ota_sha256)
                    print(
                        f"OTA download grant {'consumed' if consumed else 'already-consumed/expired'} "
                        f"device_id={device_id} sha256={self.ota_sha256[:12]}",
                        flush=True,
                    )

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
