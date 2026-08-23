#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
VENV="$ROOT_DIR/.venv-test"
REQ="$SCRIPT_DIR/requirements-test.txt"

echo "JarZem OTA E2E test environment"
echo "Project: $ROOT_DIR"

if [ ! -x "$VENV/bin/python" ]; then
    echo "Creating virtual environment: $VENV"
    python3 -m venv "$VENV"
fi

echo "Installing/updating test dependencies..."
"$VENV/bin/python" -m pip install --disable-pip-version-check -r "$REQ"

echo "Starting OTA live E2E test..."
exec "$VENV/bin/python" "$SCRIPT_DIR/run_ota_e2e_live.py"
