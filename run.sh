#!/bin/sh

mkdir -p /share/esp_ota/firmware

echo "Starting ESP OTA HTTPS Server"

ls -la /share/esp_ota/cert
ls -la /share/esp_ota/firmware

echo "esptool:"
esptool version

exec python3 /server.py
