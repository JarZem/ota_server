# OTA Server database

OTA runtime uses the existing Home Assistant MariaDB/MySQL service. SQLite is not used as runtime storage.

## Connection configuration

Home Assistant add-on options contain non-secret connection settings:

```yaml
mysql_host: core-mariadb
mysql_port: 3306
mysql_database: homeassistant
mysql_username: homeassistant
mysql_password_secret: homeassistant_mysql
```

Passwords are resolved from `/share/ota_server/secrets.json`, for example:

```json
{
  "wifi_passwords": {"main_wifi": "..."},
  "database_passwords": {"homeassistant_mysql": "..."}
}
```

`OTA_MYSQL_PASSWORD` can override the DB password for tests/non-HA deployments.

## Schema management

DDL is owned exclusively by Alembic. Runtime modules do not create or alter tables.

Startup runs:

```bash
alembic -c /share/ota_server/runtime/alembic.ini upgrade head
```

The namespaced version table is:

```text
ota_server_alembic_version
```

Current expected revision:

```text
0003_ota_observability
```

## One-time SQLite migration

`migrate_legacy_sqlite.py` can import old `/data/ota_server.db` and `/data/device_registry.db`. Successfully migrated files are renamed to `*.db.migrated`; they are never used as active runtime databases afterward.

## Core tables

```text
ota_server_firmware_images
ota_server_firmware_alias
ota_server_firmware_history
ota_server_dispatch
ota_server_device_provisioning
ota_server_devices
ota_server_command_counters
ota_server_device_certificates
ota_server_download_grants
```

`ota_server_device_certificates` stores only public device identity material and successful provisioning security context. Device private keys are never stored in MySQL.

`ota_server_download_grants` stores short-lived OTA CHECK/download grants, their expiry and consumption state.

## Build artifact audit

```text
ota_server_artifact_publications
```

One row binds a firmware build publication to its publisher ESP certificate. It stores:

```text
firmware_version
firmware_filename / firmware_sha256 / firmware_size
converter_project / converter_filename / converter_sha256
publisher_device_id
publisher_certificate_fingerprint
bin_verified
mjs_verified
z2m_loaded
published_at / converter_published_at
last_error
```

The MJS publish is accepted only after a verified BIN of the same build from the same publisher exists.

## Provisioning attempt history

```text
ota_server_provisioning_attempts
```

Unique key:

```text
(device_id, counter)
```

It preserves the timeline of one provisioning attempt:

```text
started_at
challenge_sent_at
response_verified_at
provisioning_sent_at
completed_at
state
error
```

The passive MQTT observer records transport observations. `response_verified_at` is set only when OTA emits `P`, because the authoritative state machine emits `P` only after successful R verification.

## ESP × firmware cross table

```text
ota_server_device_firmware_status
```

Primary key:

```text
(device_id, firmware_sha256)
```

This table answers the operational question "what happened when this exact ESP was offered this exact BIN?" It stores:

```text
firmware_filename
firmware_version
firmware_code
state
check_created_at
check_sent_at
token_expires_at
download_started_at
download_finished_at
download_failed_at
grant_consumed_at
last_error
updated_at
```

Typical state progression is:

```text
CHECK_SENT
DOWNLOAD_STARTED
DOWNLOAD_COMPLETED
DEVICE_CONFIRMED
```

or on failure:

```text
CHECK_SENT
DOWNLOAD_STARTED
DOWNLOAD_FAILED
```

Timestamps are intentionally retained even when the current state advances, so the ingress UI can show both start and finish times.

## Code responsibilities

- `migrations/`: schema ownership.
- `database.py`: MySQL configuration, SQLAlchemy engine and logical table mapping.
- `activity.py`: writes/reads operational lifecycle tables and renders ingress status tables.
- `mqtt_observer.py`: passive persistence of Zigbee2MQTT OTA/provisioning traffic.
- `device_registry.py`: Root-CA-validated public device identities.
- `firmware_publish.py`: signed BIN validation plus artifact audit.
- `zigbee2mqtt_publish.py`: signed MJS validation, BIN/MJS binding and Z2M runtime verification.
- `server_mysql.py`: HTTPS download telemetry and ingress integration.

When schema changes are needed, create a new Alembic revision and update `EXPECTED_SCHEMA_REVISION`. Do not add runtime `CREATE TABLE IF NOT EXISTS` logic.
