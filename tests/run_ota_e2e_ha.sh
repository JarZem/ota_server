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

if [ -z "${SUPERVISOR_TOKEN:-}" ]; then
    echo "SUPERVISOR_TOKEN is missing. Run this from the Home Assistant SSH add-on with Supervisor API access." >&2
    exit 1
fi

SLUG="$(SUPERVISOR_TOKEN="$SUPERVISOR_TOKEN" "$VENV/bin/python" - <<'PY'
import json, os, urllib.request
req = urllib.request.Request(
    'http://supervisor/addons',
    headers={'Authorization': f"Bearer {os.environ['SUPERVISOR_TOKEN']}"},
)
with urllib.request.urlopen(req, timeout=20) as response:
    payload = json.loads(response.read().decode('utf-8'))
items = (payload.get('data') or {}).get('addons') or payload.get('addons') or []
matches = []
for item in items:
    slug = str(item.get('slug') or '')
    name = str(item.get('name') or '')
    if slug == 'ota_server' or slug.endswith('_ota_server') or name.strip().lower() == 'ota server':
        matches.append(slug)
if len(matches) != 1:
    raise SystemExit('Cannot uniquely identify OTA add-on: ' + (', '.join(matches) or 'none'))
print(matches[0])
PY
)"

echo "OTA add-on: $SLUG"
echo "Starting live E2E inside OTA add-on..."
# The actual E2E process runs inside the OTA add-on. That add-on has the MQTT
# service credentials and production dependencies, so the SSH add-on no longer
# needs the forbidden Supervisor /services/mqtt endpoint.
exec "$VENV/bin/python" "$SCRIPT_DIR/run_ota_e2e_supervisor.py" --slug "$SLUG"
