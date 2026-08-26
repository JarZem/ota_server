#!/bin/sh
set -eu

if [ -z "${SUPERVISOR_TOKEN:-}" ]; then
    echo "SUPERVISOR_TOKEN is not available; run this from a Home Assistant add-on shell with Supervisor access." >&2
    exit 1
fi

python3 - <<'PY'
import json
import os
import urllib.error
import urllib.request

TOKEN = os.environ["SUPERVISOR_TOKEN"]
BASE = "http://supervisor"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}


def request_json(path: str, method: str = "GET"):
    req = urllib.request.Request(
        BASE + path,
        data=b"" if method == "POST" else None,
        headers=HEADERS,
        method=method,
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        body = response.read().decode("utf-8", errors="replace")
        return response.status, json.loads(body) if body else {}


_, payload = request_json("/addons")
addons = (payload.get("data") or {}).get("addons") or []
matches = []
for addon in addons:
    slug = str(addon.get("slug") or "")
    name = str(addon.get("name") or "")
    if slug == "ota_server" or slug.endswith("_ota_server") or name.strip().lower() == "ota server":
        matches.append((slug, name))

if len(matches) != 1:
    rendered = ", ".join(f"{slug} ({name})" for slug, name in matches) or "none"
    raise SystemExit(f"Refusing to restart anything: OTA add-on was not identified uniquely. Matches: {rendered}")

slug, name = matches[0]
print(f"Restarting OTA add-on only: {name} [{slug}]")
status, result = request_json(f"/addons/{slug}/restart", method="POST")
print(f"OTA restart accepted HTTP {status}: {json.dumps(result, ensure_ascii=False)}")
PY
