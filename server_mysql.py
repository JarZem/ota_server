from __future__ import annotations

import server
from database import assert_schema_current, database_summary, db_connect
from ota_check_runtime import (
    consume_dispatch_token,
    create_dispatch_token,
    make_check_payload,
    make_noop_provision_payload,
    should_skip_payload,
    validate_dispatch_token,
)


def init_mysql_runtime() -> None:
    assert_schema_current()
    print(f'OTA database ready: {database_summary()}', flush=True)


# Keep the existing OTA application logic, but replace its legacy SQLite
# connection/schema hooks with the central SQLAlchemy/MySQL layer.
server.db_connect = db_connect
server.init_db = init_mysql_runtime

# The old UI dispatch path used to create a bearer token, put it into a legacy
# provisioning frame and then send C|token. Reuse the UI plumbing but replace
# the cryptographic operations: create_dispatch_token() creates a five-minute
# one-time grant and make_check_payload() returns the signed C|version|code|random|MAC.
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


def secure_copyfile(self, source, outputfile):
    """Stream firmware and consume the five-minute grant only after EOF and socket flush."""
    completed = False
    try:
        while True:
            block = source.read(64 * 1024)
            if not block:
                break
            outputfile.write(block)
        outputfile.flush()
        completed = True
    except (BrokenPipeError, ConnectionResetError):
        return
    finally:
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


server.OTAHandler.copyfile = secure_copyfile


if __name__ == '__main__':
    server.start_servers()
