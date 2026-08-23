#!/usr/bin/env python3
"""Run test_ota_e2e_live.py inside the OTA add-on using a temporary JSON input bundle."""
from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path

import test_ota_e2e_live as e2e


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('bundle')
    args = parser.parse_args()

    bundle_path = Path(args.bundle)
    data = json.loads(bundle_path.read_text(encoding='utf-8'))
    cert = str(data['root_ca_cert_pem']).rstrip('\r\n') + '\n'
    key = str(data['root_ca_private_key_pem']).rstrip('\r\n') + '\n'
    password = str(data.get('root_ca_private_key_password') or '')

    try:
        bundle_path.unlink()
    except FileNotFoundError:
        pass

    def read_pem(label: str, _end_marker: str) -> bytes:
        return (cert if 'certificate' in label.lower() else key).encode('ascii')

    e2e.read_pem = read_pem
    getpass.getpass = lambda _prompt='': password

    # Keep secrets only in this process memory from this point on.
    data.clear()
    e2e.main()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
