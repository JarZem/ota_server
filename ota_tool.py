#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sqlite3
import stat
import sys
import urllib.request

from device_enrollment import derive_device_auth_secret, normalize_device_id

DB_PATH = os.environ.get("OTA_SERVER_DB", "/data/ota_server.db")
SERVER_DEVICE_MASTER_SECRET_PATH = os.environ.get(
    "SERVER_DEVICE_MASTER_SECRET_PATH",
    "/data/server_device_master_secret.bin",
)


def read_master_secret() -> bytes:
    with open(SERVER_DEVICE_MASTER_SECRET_PATH, "rb") as f:
        secret = f.read()
    if len(secret) < 32:
        raise SystemExit("SERVER_DEVICE_MASTER_SECRET is invalid")
    return secret


def prepare_device_auth(args: argparse.Namespace) -> None:
    device_id = normalize_device_id(args.device_id)
    secret = derive_device_auth_secret(read_master_secret(), device_id)
    out_path = args.out
    fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(secret)
    try:
        os.chmod(out_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass

    print(f"DEVICE_ID: {device_id}")
    print(f"Secret binary: {out_path}")
    print("Recommended ESP32-C6 eFuse purpose: HMAC upstream for esp_hmac_calculate()")
    print("Do not burn eFuse automatically from this tool.")
    print("Example shape:")
    print(f"  espefuse.py --chip esp32c6 burn_key BLOCK_KEY0 {out_path} HMAC_UP")


def rows() -> list[sqlite3.Row]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute("SELECT * FROM devices ORDER BY device_id").fetchall()
    finally:
        conn.close()


def list_devices(_: argparse.Namespace) -> None:
    for row in rows():
        print(
            f"{row['device_id']} state={row['state']} hw={row['hardware_revision']} "
            f"role={row['product_role']} pkfp={row['device_public_key_fingerprint'] or 'missing'}"
        )


def show_device(args: argparse.Namespace) -> None:
    device_id = normalize_device_id(args.device_id)
    for row in rows():
        if row["device_id"] == device_id:
            for key in row.keys():
                value = row[key]
                if key == "device_enc_public_key" and value:
                    value = f"<{len(value)} bytes>"
                print(f"{key}: {value}")
            return
    raise SystemExit(f"device not found: {device_id}")


def request_auth(args: argparse.Namespace) -> None:
    device_id = normalize_device_id(args.device_id)
    url = args.server.rstrip("/") + "/api/device/challenge"
    body = ("{\"device_id\":\"" + device_id + "\"}").encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        print(response.read().decode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(prog="ota-tool")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("prepare-device-auth")
    p.add_argument("device_id")
    p.add_argument("--out", required=True)
    p.set_defaults(func=prepare_device_auth)

    p = sub.add_parser("devices")
    p.set_defaults(func=list_devices)

    p = sub.add_parser("pending-devices")
    p.set_defaults(func=list_devices)

    p = sub.add_parser("device")
    p.add_argument("device_id")
    p.set_defaults(func=show_device)

    p = sub.add_parser("auth")
    p.add_argument("device_id")
    p.add_argument("--server", default="https://127.0.0.1:8443")
    p.set_defaults(func=request_auth)

    args = parser.parse_args()
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
