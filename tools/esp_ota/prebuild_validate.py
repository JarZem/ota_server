#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

RESERVED_ENDPOINTS = {10: "secure OTA transport", 11: "OTA control/status"}
RESERVED_CLUSTERS = {0xFC00: "secure OTA transport", 0xFC01: "Enable OTA", 0xFC02: "OTA status"}
SKIP_DIRS = {'.git', 'build', 'build_full', 'managed_components', '.idea', '.vscode', '__pycache__'}
CREDENTIALS = ('device_private.pem', 'device_cert.pem', 'root_ca_cert.pem', 'ota_server_cert.pem')


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def validate_identity(project: Path) -> None:
    manifest_path = project / '.jarzem_ota' / 'identity.json'
    if not manifest_path.is_file():
        raise SystemExit('JarZem OTA identity manifest is missing. Run the OTA installer once; build will never generate a device identity.')
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    expected = manifest.get('files') or {}
    credential_dir = project / 'device_credentials'
    for name in CREDENTIALS:
        path = credential_dir / name
        if not path.is_file():
            raise SystemExit(f'Installed OTA identity is incomplete: {path} is missing. Restore the original file; do not regenerate it.')
        actual = sha256(path)
        wanted = expected.get(name)
        if not wanted or actual.lower() != wanted.lower():
            raise SystemExit(f'Installed OTA identity changed: {name} SHA256 does not match .jarzem_ota/identity.json. Build stopped.')


def iter_sources(project: Path, submodule_path: Path):
    suffixes = {'.c', '.cc', '.cpp', '.h', '.hpp', '.mjs', '.js'}
    submodule_path = submodule_path.resolve()
    for path in project.rglob('*'):
        if not path.is_file() or path.suffix.lower() not in suffixes:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            if path.resolve().is_relative_to(submodule_path):
                continue
        except AttributeError:
            if str(path.resolve()).startswith(str(submodule_path)):
                continue
        yield path


def parse_int(text: str) -> int | None:
    try:
        return int(text, 0)
    except ValueError:
        return None


def validate_collisions(project: Path, submodule_path: Path) -> None:
    problems: list[str] = []
    endpoint_patterns = [
        re.compile(r'\b[A-Za-z0-9_]*ENDPOINT[A-Za-z0-9_]*\s+(0x[0-9a-fA-F]+|\d+)'),
        re.compile(r'\.endpoint\s*=\s*(0x[0-9a-fA-F]+|\d+)'),
        re.compile(r'\bendpoint\s*:\s*(0x[0-9a-fA-F]+|\d+)'),
    ]
    cluster_patterns = [
        re.compile(r'\b[A-Za-z0-9_]*CLUSTER[A-Za-z0-9_]*\s+(0x[0-9a-fA-F]+|\d+)'),
        re.compile(r'\.cluster(?:_id|ID)?\s*=\s*(0x[0-9a-fA-F]+|\d+)'),
        re.compile(r'\bcluster(?:Id|ID|_id)?\s*:\s*(0x[0-9a-fA-F]+|\d+)'),
    ]
    for path in iter_sources(project, submodule_path):
        try:
            lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
        except OSError:
            continue
        for lineno, line in enumerate(lines, 1):
            low = line.lower()
            if 'endpoint' in low:
                for pattern in endpoint_patterns:
                    for match in pattern.finditer(line):
                        value = parse_int(match.group(1))
                        if value in RESERVED_ENDPOINTS:
                            problems.append(f'{path.relative_to(project)}:{lineno}: endpoint {value} is reserved by OTA ({RESERVED_ENDPOINTS[value]})')
            if 'cluster' in low:
                for pattern in cluster_patterns:
                    for match in pattern.finditer(line):
                        value = parse_int(match.group(1))
                        if value in RESERVED_CLUSTERS:
                            problems.append(f'{path.relative_to(project)}:{lineno}: cluster 0x{value:04X} is reserved by OTA ({RESERVED_CLUSTERS[value]})')
    if problems:
        raise SystemExit('JarZem OTA Zigbee resource collision:\n  ' + '\n  '.join(sorted(set(problems))))


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument('--project', type=Path, required=True)
    p.add_argument('--submodule', type=Path, required=True)
    args = p.parse_args()
    project = args.project.resolve()
    validate_identity(project)
    validate_collisions(project, args.submodule.resolve())
    print('JarZem OTA pre-build validation OK: immutable identity and Zigbee resources verified')


if __name__ == '__main__':
    main()
