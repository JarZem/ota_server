#!/bin/sh
set -eu

RUNTIME_DIR="${OTA_RUNTIME_DIR:-/share/ota_server/runtime}"
export OTA_RUNTIME_DIR="$RUNTIME_DIR"
export PYTHONPATH="$RUNTIME_DIR${PYTHONPATH:+:$PYTHONPATH}"
cd "$RUNTIME_DIR"

mkdir -p /share/ota_server/firmware

echo "Starting OTA Server"
echo "Runtime scripts: $RUNTIME_DIR"

ls -la /share/ota_server/cert
ls -la /share/ota_server/firmware

echo "esptool:"
esptool version

echo "Applying OTA database migrations with Alembic"
alembic -c "$RUNTIME_DIR/alembic.ini" upgrade head

echo "Database schema ready"

python3 "$RUNTIME_DIR/migrate_legacy_sqlite.py"

python3 "$RUNTIME_DIR/manufacturing_api.py" &
MANUFACTURING_PID=$!

python3 "$RUNTIME_DIR/mqtt_listener.py" &
MQTT_PID=$!

sleep 2
if ! kill -0 "$MQTT_PID" 2>/dev/null; then
    echo "FATAL: mqtt_listener.py terminated during startup" >&2
    wait "$MQTT_PID" || true
    kill "$MANUFACTURING_PID" 2>/dev/null || true
    exit 1
fi

echo "MQTT listener running pid=$MQTT_PID"

exec python3 "$RUNTIME_DIR/server_mysql.py"
