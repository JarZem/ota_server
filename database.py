from __future__ import annotations

import json
import os
import re
import threading
from contextlib import AbstractContextManager
from pathlib import Path
from urllib.parse import quote_plus

from sqlalchemy import create_engine, inspect
from sqlalchemy.engine import Engine

OPTIONS_PATH = Path('/data/options.json')
SECRETS_PATH = Path('/share/ota_server/secrets.json')
ALEMBIC_VERSION_TABLE = 'ota_server_alembic_version'
EXPECTED_SCHEMA_REVISION = '0003_ota_observability'

TABLE_MAP = {
    'firmware_images': 'ota_server_firmware_images',
    'firmware_alias': 'ota_server_firmware_alias',
    'firmware_history': 'ota_server_firmware_history',
    'ota_dispatch': 'ota_server_dispatch',
    'device_provisioning': 'ota_server_device_provisioning',
    'devices': 'ota_server_devices',
    'command_counters': 'ota_server_command_counters',
    'device_certificates': 'ota_server_device_certificates',
    'download_grants': 'ota_server_download_grants',
    'artifact_publications': 'ota_server_artifact_publications',
    'provisioning_attempts': 'ota_server_provisioning_attempts',
    'device_firmware_status': 'ota_server_device_firmware_status',
}

_engine: Engine | None = None
_engine_lock = threading.Lock()


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding='utf-8')) if path.is_file() else {}
    except Exception as exc:
        raise RuntimeError(f'cannot read JSON config {path}: {exc}') from exc


def _secret(name: str) -> str:
    if not name:
        return ''
    data = _read_json(SECRETS_PATH)
    for bucket_name in ('database_passwords', 'mysql_passwords', 'secrets'):
        bucket = data.get(bucket_name)
        if isinstance(bucket, dict) and name in bucket:
            return str(bucket[name])
    value = data.get(name)
    return str(value) if value is not None else ''


def database_config() -> dict:
    options = _read_json(OPTIONS_PATH)
    secret_name = str(options.get('mysql_password_secret') or 'homeassistant_mysql').strip()
    password = os.environ.get('OTA_MYSQL_PASSWORD', '') or _secret(secret_name)
    if not password:
        raise RuntimeError(
            f'MySQL password secret {secret_name!r} is missing. '
            f'Add it to {SECRETS_PATH} under database_passwords.'
        )
    return {
        'host': str(options.get('mysql_host') or 'core-mariadb').strip(),
        'port': int(options.get('mysql_port') or 3306),
        'database': str(options.get('mysql_database') or 'homeassistant').strip(),
        'username': str(options.get('mysql_username') or 'homeassistant').strip(),
        'password': password,
        'password_secret': secret_name,
    }


def database_url(mask_password: bool = False) -> str:
    cfg = database_config()
    password = '***' if mask_password else quote_plus(cfg['password'])
    username = quote_plus(cfg['username'])
    database = quote_plus(cfg['database'])
    return f"mysql+pymysql://{username}:{password}@{cfg['host']}:{cfg['port']}/{database}?charset=utf8mb4"


def get_engine() -> Engine:
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = create_engine(
                database_url(),
                pool_pre_ping=True,
                pool_recycle=1800,
                future=True,
            )
        return _engine


def _translate_tables(sql: str) -> str:
    for logical, physical in sorted(TABLE_MAP.items(), key=lambda item: -len(item[0])):
        sql = re.sub(rf'\b{re.escape(logical)}\b', physical, sql)
    return sql


def _translate_sql(sql: str) -> str:
    sql = _translate_tables(sql)
    sql = re.sub(
        r'ON\s+CONFLICT\s*\([^)]*\)\s+DO\s+UPDATE\s+SET',
        'ON DUPLICATE KEY UPDATE',
        sql,
        flags=re.IGNORECASE | re.DOTALL,
    )
    sql = re.sub(r'\bexcluded\.([A-Za-z_][A-Za-z0-9_]*)', r'VALUES(\1)', sql, flags=re.IGNORECASE)
    sql = sql.replace("X''", "CAST('' AS BINARY)")
    sql = sql.replace('?', '%s')
    return sql


class QueryResult:
    def __init__(self, result):
        self._result = result
        self.rowcount = result.rowcount

    def fetchone(self):
        if not self._result.returns_rows:
            return None
        return self._result.mappings().fetchone()

    def fetchall(self):
        if not self._result.returns_rows:
            return []
        return list(self._result.mappings().fetchall())


class DatabaseConnection(AbstractContextManager):
    def __init__(self):
        self._ctx = None
        self._conn = None

    def __enter__(self):
        self._ctx = get_engine().begin()
        self._conn = self._ctx.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        return self._ctx.__exit__(exc_type, exc, tb)

    def execute(self, sql: str, params=()):
        translated = _translate_sql(sql)
        result = self._conn.exec_driver_sql(translated, tuple(params or ()))
        return QueryResult(result)


def db_connect() -> DatabaseConnection:
    return DatabaseConnection()


def assert_schema_current() -> None:
    engine = get_engine()
    inspector = inspect(engine)
    if ALEMBIC_VERSION_TABLE not in inspector.get_table_names():
        raise RuntimeError(
            'OTA MySQL schema is not initialized. Run Alembic migration: alembic -c /alembic.ini upgrade head'
        )
    with engine.connect() as conn:
        revision = conn.exec_driver_sql(
            f'SELECT version_num FROM {ALEMBIC_VERSION_TABLE} LIMIT 1'
        ).scalar_one_or_none()
    if revision != EXPECTED_SCHEMA_REVISION:
        raise RuntimeError(
            f'OTA MySQL schema revision mismatch: database={revision!r} expected={EXPECTED_SCHEMA_REVISION!r}. '
            'Run Alembic migration.'
        )


def database_summary() -> str:
    cfg = database_config()
    return (
        f"mysql={cfg['host']}:{cfg['port']}/{cfg['database']} "
        f"user={cfg['username']} password_source=secret:{cfg['password_secret']}"
    )
