#!/bin/sh
set -eu

SEED_DIR="/opt/ota_server_seed"
RUNTIME_DIR="/share/ota_server/runtime"
STAMP_FILE="$RUNTIME_DIR/.seed.sha256"

mkdir -p "$RUNTIME_DIR"

seed_hash="$({
    find "$SEED_DIR" -type f | sort | while IFS= read -r file; do
        sha256sum "$file"
    done
} | sha256sum | awk '{print $1}')"

old_hash=""
if [ -f "$STAMP_FILE" ]; then
    old_hash="$(cat "$STAMP_FILE" 2>/dev/null || true)"
fi

if [ "$old_hash" != "$seed_hash" ]; then
    echo "Updating persistent OTA runtime: $RUNTIME_DIR"
    cp -R "$SEED_DIR"/. "$RUNTIME_DIR"/
    printf '%s\n' "$seed_hash" > "$STAMP_FILE"
else
    # Keep local edits across ordinary restarts, but restore accidentally
    # deleted managed files from the image seed.
    find "$SEED_DIR" -type f | while IFS= read -r source; do
        relative="${source#$SEED_DIR/}"
        target="$RUNTIME_DIR/$relative"
        if [ ! -f "$target" ]; then
            mkdir -p "$(dirname "$target")"
            cp "$source" "$target"
        fi
    done
fi

chmod a+x "$RUNTIME_DIR/run.sh" "$RUNTIME_DIR/restart.sh" "$RUNTIME_DIR/ota_tool.py"
ln -sf "$RUNTIME_DIR/ota_tool.py" /usr/local/bin/ota-tool

export OTA_RUNTIME_DIR="$RUNTIME_DIR"
export PYTHONPATH="$RUNTIME_DIR${PYTHONPATH:+:$PYTHONPATH}"

exec "$RUNTIME_DIR/run.sh"
