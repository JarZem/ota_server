#!/bin/sh

mkdir -p /share/ota_server/firmware

echo "Starting OTA Server"

ls -la /share/ota_server/cert
ls -la /share/ota_server/firmware

echo "esptool:"
esptool version

python3 /manufacturing_api.py &
python3 /mqtt_listener.py &

exec python3 /server.py
