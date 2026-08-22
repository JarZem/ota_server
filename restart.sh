#!/bin/sh
set -eu

if [ -z "${SUPERVISOR_TOKEN:-}" ]; then
    echo "SUPERVISOR_TOKEN is not available; run this script inside the OTA add-on." >&2
    exit 1
fi

echo "Requesting OTA add-on restart through Home Assistant Supervisor..."

python3 - <<'PY'
import http.client
import os
import urllib.error
import urllib.request

request = urllib.request.Request(
    "http://supervisor/addons/self/restart",
    data=b"",
    headers={"Authorization": f"Bearer {os.environ['SUPERVISOR_TOKEN']}"},
    method="POST",
)
try:
    with urllib.request.urlopen(request, timeout=15) as response:
        body = response.read().decode("utf-8", errors="replace")
        print(f"Supervisor restart accepted HTTP {response.status}: {body}")
except http.client.RemoteDisconnected:
    # The container can disappear before the HTTP response is fully returned.
    print("Supervisor restart request sent; OTA container is restarting.")
except urllib.error.HTTPError as exc:
    detail = exc.read().decode("utf-8", errors="replace")
    raise SystemExit(f"OTA restart rejected HTTP {exc.code}: {detail}") from exc
PY
