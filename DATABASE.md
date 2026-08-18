# OTA Server database

OTA runtime uses the existing Home Assistant MariaDB/MySQL service. SQLite is not used as runtime storage.

## Connection configuration

Home Assistant add-on options contain only non-secret connection settings:

```yaml
mysql_host: core-mariadb
mysql_port: 3306
mysql_database: homeassistant
mysql_username: homeassistant
mysql_password_secret: homeassistant_mysql
```

The password is deliberately not stored in Git or `config.yaml`. It is resolved from:

```text
/share/ota_server/secrets.json
```

Example structure:

```json
{
  "wifi_passwords": {
    "main_wifi": "..."
  },
  "database_passwords": {
    "homeassistant_mysql": "..."
  }
}
```

`OTA_MYSQL_PASSWORD` can override the password for tests or non-HA deployments.

## Schema management

DDL is owned exclusively by Alembic. Application Python modules must not execute `CREATE TABLE`, `ALTER TABLE` or schema migrations.

At add-on startup `run.sh` executes:

```bash
alembic -c /alembic.ini upgrade head
```

Only after Alembic completes are `manufacturing_api.py`, `mqtt_listener.py` and the OTA server started.

The Alembic version table is deliberately namespaced:

```text
ota_server_alembic_version
```

This avoids collisions with another application using Alembic in the shared `homeassistant` database.

## Table names

All OTA tables are namespaced in the shared database:

```text
ota_server_firmware_images
ota_server_firmware_alias
ota_server_firmware_history
ota_server_dispatch
ota_server_device_provisioning
ota_server_devices
ota_server_command_counters
ota_server_device_certificates
```

Application code accesses them through `database.py`; logical legacy names are translated centrally so SQL dialect/configuration details are not spread through the server.

## Responsibilities

- `migrations/`: database structure and future schema changes.
- `database.py`: MySQL configuration, SQLAlchemy engine, transactions and runtime SQL adaptation.
- `device_registry.py`: device certificate SELECT/INSERT/UPDATE only.
- `manufacturing_api.py`: HTTP API only; never creates tables.
- `server_mysql.py`: activates the MySQL database layer for the existing OTA application.

When schema changes are needed, create a new Alembic revision. Do not add runtime `CREATE TABLE IF NOT EXISTS` logic to application modules.
