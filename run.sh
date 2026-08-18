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

python3 /manufacturing_api.py &
python3 /mqtt_listener.py &

exec python3 /server_mysql.py
