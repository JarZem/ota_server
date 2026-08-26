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
HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json",
}


def request_json(path: str, method: str = "GET", payload=None):
    data = None
    if method == "POST":
        data = json.dumps(payload if payload is not None else {}).encode("utf-8")
    req = urllib.request.Request(
        BASE + path,
        data=data,
        headers=HEADERS,
        method=method,
    )
    with urllib.request.urlopen(req, timeout=300) as response:
        body = response.read().decode("utf-8", errors="replace")
        return response.status, json.loads(body) if body else {}


try:
    _, payload = request_json("/addons")
except Exception as exc:
    raise SystemExit(f"Cannot read Home Assistant add-on list: {exc}") from exc

addons = (payload.get("data") or {}).get("addons") or []

matches = []
for addon in addons:
    slug = str(addon.get("slug") or "")
    name = str(addon.get("name") or "")
    if slug == "ota_server" or slug.endswith("_ota_server") or name.strip().lower() == "ota server":
        matches.append((slug, name, bool(addon.get("build"))))

if len(matches) != 1:
    rendered = ", ".join(f"{slug} ({name})" for slug, name, _ in matches) or "none"
    raise SystemExit(
        "Refusing to rebuild anything: OTA add-on was not identified uniquely. "
        f"Matches: {rendered}"
    )

slug, name, local_build = matches[0]
print(f"OTA add-on selected: {name} [{slug}]")

if not local_build:
    print("Supervisor does not mark this add-on as a local build; trying forced rebuild anyway.")

try:
    status, result = request_json(f"/addons/{slug}/rebuild", method="POST", payload={"force": True})
except urllib.error.HTTPError as exc:
    detail = exc.read().decode("utf-8", errors="replace")
    raise SystemExit(f"OTA rebuild rejected HTTP {exc.code}: {detail}") from exc
except Exception as exc:
    raise SystemExit(f"OTA rebuild failed: {exc}") from exc

print(f"OTA rebuild accepted HTTP {status}: {json.dumps(result, ensure_ascii=False)}")
print("The rebuilt add-on is started by Supervisor; no second plain restart is needed.")
PY
