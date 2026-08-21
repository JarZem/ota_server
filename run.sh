#!/bin/sh
set -e

mkdir -p /share/ota_server/firmware

echo "Starting OTA Server"

ls -la /share/ota_server/cert
ls -la /share/ota_server/firmware

echo "esptool:"
esptool version

echo "Applying OTA database migrations with Alembic"
alembic -c /alembic.ini upgrade head

echo "Database schema ready"

python3 /migrate_legacy_sqlite.py

python3 /manufacturing_api.py &
MANUFACTURING_PID=$!

python3 /mqtt_listener.py &
MQTT_PID=$!

sleep 2
if ! kill -0 "$MQTT_PID" 2>/dev/null; then
    echo "FATAL: mqtt_listener.py terminated during startup" >&2
    wait "$MQTT_PID" || true
    kill "$MANUFACTURING_PID" 2>/dev/null || true
    exit 1
fi

echo "MQTT listener running pid=$MQTT_PID"

exec python3 /server_mysql.py
