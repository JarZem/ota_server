#!/bin/sh
set -eu

# Deploy the current /addons/ota_server checkout into the persistent runtime
# used by the OTA add-on, then restart only the OTA add-on through Supervisor.
# Intended to be run from Home Assistant SSH after git pull.

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
RUNTIME_DIR="/share/ota_server/runtime"

if [ ! -f "$SCRIPT_DIR/server.py" ] || [ ! -f "$SCRIPT_DIR/run.sh" ]; then
    echo "This script must be run from the ota_server git checkout (expected server.py and run.sh next to it)." >&2
    exit 1
fi

if [ -z "${SUPERVISOR_TOKEN:-}" ]; then
    echo "SUPERVISOR_TOKEN is not available. Run this from the Home Assistant SSH add-on with Supervisor API access." >&2
    exit 1
fi

mkdir -p "$RUNTIME_DIR"

echo "[1/3] Deploying current OTA scripts to $RUNTIME_DIR"

# Root Python runtime files are fully managed by git. Remove stale managed
# Python files first so deleted/renamed modules cannot survive a deployment.
rm -f "$RUNTIME_DIR"/*.py
for file in "$SCRIPT_DIR"/*.py; do
    [ -f "$file" ] && cp "$file" "$RUNTIME_DIR/"
done

cp "$SCRIPT_DIR/alembic.ini" "$RUNTIME_DIR/alembic.ini"
cp "$SCRIPT_DIR/run.sh" "$RUNTIME_DIR/run.sh"
cp "$SCRIPT_DIR/restart.sh" "$RUNTIME_DIR/restart.sh"

rm -rf "$RUNTIME_DIR/migrations" "$RUNTIME_DIR/tests"
cp -R "$SCRIPT_DIR/migrations" "$RUNTIME_DIR/migrations"
cp -R "$SCRIPT_DIR/tests" "$RUNTIME_DIR/tests"

chmod a+x "$RUNTIME_DIR/run.sh" "$RUNTIME_DIR/restart.sh" "$RUNTIME_DIR/ota_tool.py" 2>/dev/null || true

# Stamp with the git revision if available. This is informational and also
# prevents bootstrap from treating the runtime as an accidentally incomplete
# copy on the next ordinary restart.
if command -v git >/dev/null 2>&1; then
    REV="$(git -C "$SCRIPT_DIR" rev-parse HEAD 2>/dev/null || true)"
    [ -n "$REV" ] && printf '%s\n' "$REV" > "$RUNTIME_DIR/.git-deployed-revision"
fi

echo "[2/3] Locating OTA add-on"

python3 - <<'PY'
import json
import os
import urllib.error
import urllib.request

token = os.environ["SUPERVISOR_TOKEN"]
headers = {"Authorization": f"Bearer {token}"}
base = "http://supervisor"


def request(path: str, method: str = "GET"):
    req = urllib.request.Request(
        base + path,
        data=b"" if method == "POST" else None,
        headers=headers,
        method=method,
    )
    with urllib.request.urlopen(req, timeout=20) as response:
        body = response.read().decode("utf-8", errors="replace")
        return response.status, json.loads(body) if body else {}

_, payload = request("/addons")
items = (payload.get("data") or {}).get("addons") or payload.get("addons") or []
matches = []
for item in items:
    slug = str(item.get("slug") or "")
    name = str(item.get("name") or "")
    if slug == "ota_server" or slug.endswith("_ota_server") or name.strip().lower() == "ota server":
        matches.append((slug, name))

if len(matches) != 1:
    shown = ", ".join(f"{slug} ({name})" for slug, name in matches) or "none"
    raise SystemExit(f"OTA add-on was not identified uniquely; matches: {shown}")

slug, name = matches[0]
print(f"OTA add-on: {name} [{slug}]")
print("[3/3] Restarting OTA add-on")
try:
    status, result = request(f"/addons/{slug}/restart", method="POST")
except urllib.error.HTTPError as exc:
    detail = exc.read().decode("utf-8", errors="replace")
    raise SystemExit(f"OTA restart rejected HTTP {exc.code}: {detail}") from exc

print(f"OTA restart accepted HTTP {status}: {json.dumps(result, ensure_ascii=False)}")
PY

echo "Done. Current git scripts were deployed and OTA was restarted."
