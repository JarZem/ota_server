#!/bin/sh

mkdir -p /share/ota_server/firmware

echo "Starting OTA Server"

ls -la /share/ota_server/cert
ls -la /share/ota_server/firmware

echo "esptool:"
esptool version

exec python3 /server.py
