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

python3 "$RUNTIME_DIR/mqtt_observer.py" &
OBSERVER_PID=$!

sleep 2
if ! kill -0 "$MQTT_PID" 2>/dev/null; then
    echo "FATAL: mqtt_listener.py terminated during startup" >&2
    wait "$MQTT_PID" || true
    kill "$MANUFACTURING_PID" "$OBSERVER_PID" 2>/dev/null || true
    exit 1
fi
if ! kill -0 "$OBSERVER_PID" 2>/dev/null; then
    echo "FATAL: mqtt_observer.py terminated during startup" >&2
    wait "$OBSERVER_PID" || true
    kill "$MANUFACTURING_PID" "$MQTT_PID" 2>/dev/null || true
    exit 1
fi

echo "MQTT listener running pid=$MQTT_PID"
echo "MQTT activity observer running pid=$OBSERVER_PID"

python3 "$RUNTIME_DIR/server_mysql.py" &
SERVER_PID=$!

# Supervisor can write commands to the add-on stdin. Keeping diagnostics inside
# this container means they use this add-on's own SUPERVISOR_TOKEN and therefore
# the same dynamically-issued MQTT service credentials as production runtime.
(
    while IFS= read -r command; do
        case "$command" in
            MQTT_DEBUG)
                echo "STDIN: running MQTT service diagnostic inside OTA add-on"
                python3 "$RUNTIME_DIR/tests/debug_mqtt_service.py" || true
                ;;
            RUN_E2E)
                echo "STDIN: starting live OTA E2E test inside OTA add-on"
                python3 "$RUNTIME_DIR/tests/test_ota_e2e_live.py" || true
                ;;
            "")
                ;;
            *)
                echo "STDIN: unknown command: $command" >&2
                ;;
        esac
    done
) &
STDIN_PID=$!

wait "$SERVER_PID"
STATUS=$?
kill "$STDIN_PID" "$MANUFACTURING_PID" "$MQTT_PID" "$OBSERVER_PID" 2>/dev/null || true
wait "$STDIN_PID" "$MANUFACTURING_PID" "$MQTT_PID" "$OBSERVER_PID" 2>/dev/null || true
exit "$STATUS"
