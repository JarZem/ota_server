#!/bin/bash
set -e

APP="local_ota_server"

echo "Zastavuji $APP..."
ha apps stop "$APP" 2>/dev/null || true

echo "Odinstalovavam $APP..."
ha apps uninstall "$APP" 2>/dev/null || true

echo "Obnovuji informace o Apps..."
ha supervisor reload

echo "Instaluji $APP..."
ha apps install "$APP"

echo "Spoustim $APP..."
ha apps start "$APP"

echo "Hotovo."
ha apps info "$APP"