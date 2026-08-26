from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from sqlalchemy import inspect

from database import TABLE_MAP, get_engine

LEGACY_DATABASES = (
    (Path('/data/ota_server.db'), (
        'firmware_images',
        'firmware_alias',
        'firmware_history',
        'ota_dispatch',
        'device_provisioning',
        'devices',
        'command_counters',
    )),
    (Path('/data/device_registry.db'), ('device_certificates',)),
)


def import_table(sqlite_conn, source_table: str) -> int:
    physical_table = TABLE_MAP[source_table]
    engine = get_engine()
    inspector = inspect(engine)
    target_columns = {column['name'] for column in inspector.get_columns(physical_table)}

    source_info = sqlite_conn.execute(f'PRAGMA table_info({source_table})').fetchall()
    source_columns = [row[1] for row in source_info if row[1] in target_columns]
    if not source_columns:
        return 0

    quoted_source = ','.join(f'"{name}"' for name in source_columns)
    rows = sqlite_conn.execute(f'SELECT {quoted_source} FROM {source_table}').fetchall()
    if not rows:
        return 0

    target_names = ','.join(f'`{name}`' for name in source_columns)
    placeholders = ','.join(['%s'] * len(source_columns))
    statement = f'INSERT IGNORE INTO `{physical_table}` ({target_names}) VALUES ({placeholders})'

    imported = 0
    with engine.begin() as connection:
        for row in rows:
            result = connection.exec_driver_sql(statement, tuple(row))
            if result.rowcount > 0:
                imported += 1
    return imported


def migrate_database(path: Path, tables: tuple[str, ...]) -> bool:
    if not path.is_file():
        return False

    print(f'Legacy SQLite migration found {path}', flush=True)
    connection = sqlite3.connect(path)
    try:
        existing_tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        total = 0
        for table in tables:
            if table not in existing_tables:
                continue
            count = import_table(connection, table)
            total += count
            print(f'Legacy SQLite migration table={table} imported={count}', flush=True)
    finally:
        connection.close()

    migrated_path = path.with_suffix(path.suffix + '.migrated')
    if migrated_path.exists():
        migrated_path.unlink()
    os.replace(path, migrated_path)
    print(f'Legacy SQLite migration complete rows={total} archived={migrated_path}', flush=True)
    return True


def main() -> None:
    migrated_any = False
    for path, tables in LEGACY_DATABASES:
        migrated_any = migrate_database(path, tables) or migrated_any
    if not migrated_any:
        print('Legacy SQLite migration: no active SQLite databases found', flush=True)


if __name__ == '__main__':
    main()
