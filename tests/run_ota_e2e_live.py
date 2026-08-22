#!/usr/bin/env python3
"""Interactive launcher for test_ota_e2e_live.py.

Accepts both encrypted and unencrypted PEM private keys pasted directly into the
Home Assistant add-on terminal without putting CA secrets on a command line.
"""
from __future__ import annotations

import test_ota_e2e_live as e2e


def read_pem_any(label: str, _end_marker: str) -> bytes:
    if 'certificate' in label.lower():
        endings = {'-----END CERTIFICATE-----'}
    else:
        endings = {
            '-----END PRIVATE KEY-----',
            '-----END ENCRYPTED PRIVATE KEY-----',
            '-----END EC PRIVATE KEY-----',
        }
    e2e.say(f"\nPaste {label}. The PEM END line finishes input:")
    lines: list[str] = []
    while True:
        line = input()
        lines.append(line)
        if line.strip() in endings:
            return ('\n'.join(lines) + '\n').encode('ascii')


e2e.read_pem = read_pem_any

if __name__ == '__main__':
    e2e.main()
