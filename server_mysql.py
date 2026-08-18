from __future__ import annotations

import server
from database import assert_schema_current, database_summary, db_connect


def init_mysql_runtime() -> None:
    assert_schema_current()
    print(f'OTA database ready: {database_summary()}', flush=True)


# Keep the existing OTA application logic, but replace its legacy SQLite
# connection/schema hooks with the central SQLAlchemy/MySQL layer.
server.db_connect = db_connect
server.init_db = init_mysql_runtime


if __name__ == '__main__':
    server.start_servers()
