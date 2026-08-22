#!/usr/bin/env python3
"""Create one self-contained deployable Zigbee2MQTT converter from project + OTA code."""
from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path

LEGACY_OTA_MARKERS = (
    'enable_ota_ota_control', 'ota_status_ota_control',
    ".withEndpoint('ota_control')", '.withEndpoint("ota_control")',
)
PROJECT_OTA_MARKERS = (
    'jarzemOta', 'OTA_CLUSTER_ID', 'OTA_CONTROL_ENDPOINT',
    'enable_ota', 'ota_status', 'ota_command',
)


def _version(project: Path) -> str:
    try:
        return subprocess.check_output(
            ['git', '-C', str(project), 'describe', '--tags', '--always', '--dirty'],
            text=True, stderr=subprocess.DEVNULL, timeout=5,
        ).strip()
    except Exception:
        return 'unknown'


def _validate_project_only(path: Path, text: str) -> None:
    found = [m for m in PROJECT_OTA_MARKERS if m in text]
    if found:
        raise SystemExit(f'Project-only converter {path} contains OTA implementation: {", ".join(found)}')


def _validate_ota_module(path: Path, text: str) -> None:
    found = [m for m in LEGACY_OTA_MARKERS if m in text]
    if found:
        raise SystemExit(f'OTA module {path} contains legacy endpoint-suffixed names: {", ".join(found)}')
    missing = [m for m in ('enable_ota', 'ota_status', 'ota_transport') if m not in text]
    if missing:
        raise SystemExit(f'OTA module {path} is incomplete, missing: {", ".join(missing)}')


def _remove_imports(text: str) -> str:
    return re.sub(r'^import\s+.*?;\s*$', '', text, flags=re.MULTILINE)


def _make_monolith(project_text: str, ota_text: str, version: str) -> str:
    # The project converter contract intentionally uses exposes alias `e`.
    # OTA owns the common imports so the deployed file has no local imports.
    project_body = _remove_imports(project_text)
    project_body, count = re.subn(r'export\s+default\s+definition\s*;', 'const projectDefinition=definition;', project_body)
    if count != 1:
        raise SystemExit('Project converter must end with `export default definition;`')

    ota_body = _remove_imports(ota_text)
    ota_body = re.sub(r'\bexport\s+const\s+', 'const ', ota_body)

    imports = """import {presets as e, access as ea} from 'zigbee-herdsman-converters/lib/exposes';
import * as m from 'zigbee-herdsman-converters/lib/modernExtend';
import {Zcl} from 'zigbee-herdsman';
"""
    glue = """
const jarzemOtaAugment=(definition)=>({
    ...definition,
    extend:[...(definition.extend??[]),...extend],
    fromZigbee:[...(definition.fromZigbee??[]),...fromZigbee],
    toZigbee:[...(definition.toZigbee??[]),...toZigbee],
    exposes:[...(definition.exposes??[]),...exposes],
    endpoint:(device)=>({...(typeof definition.endpoint==='function'?definition.endpoint(device):{}),...endpointMap}),
    configure:async(device,coordinatorEndpoint,logger)=>{
        if(definition.configure)await definition.configure(device,coordinatorEndpoint,logger);
        await configure(device,coordinatorEndpoint,logger);
    },
    meta:{...(definition.meta??{}),multiEndpoint:true},
});

export default Array.isArray(projectDefinition)?projectDefinition.map(jarzemOtaAugment):jarzemOtaAugment(projectDefinition);
"""
    return f'// JarZem firmware build: {version}\n// Generated file: project converter + JarZem Secure OTA; do not edit in Home Assistant.\n{imports}\n{project_body.strip()}\n\n{ota_body.strip()}\n{glue}'


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument('--project', type=Path, required=True)
    p.add_argument('--submodule', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()

    project = args.project.resolve()
    submodule = args.submodule.resolve()
    output = args.output.resolve()
    source_dir = project / 'zigbee2mqtt'
    project_parts = sorted(source_dir.glob('*.project.mjs'))
    if len(project_parts) != 1:
        raise SystemExit(f'Expected exactly one *.project.mjs in {source_dir}, found {len(project_parts)}')

    project_part = project_parts[0]
    ota_part = submodule / 'zigbee2mqtt' / 'jarzem_secure_ota.mjs'
    if not ota_part.is_file():
        raise SystemExit(f'Missing OTA Zigbee2MQTT module: {ota_part}')

    project_text = project_part.read_text(encoding='utf-8')
    ota_text = ota_part.read_text(encoding='utf-8')
    _validate_project_only(project_part, project_text)
    _validate_ota_module(ota_part, ota_text)

    version = _version(project)
    base_name = project_part.name[:-len('.project.mjs')]
    output.mkdir(parents=True, exist_ok=True)
    for old in output.glob('*.mjs'):
        old.unlink()

    target = output / f'{base_name}.mjs'
    target.write_text(_make_monolith(project_text, ota_text, version), encoding='utf-8')
    generated = target.read_text(encoding='utf-8')
    if any(marker in generated for marker in LEGACY_OTA_MARKERS):
        raise SystemExit('Generated converter unexpectedly contains legacy OTA endpoint suffixes')
    if f'// JarZem firmware build: {version}' not in generated:
        raise SystemExit('Generated converter build marker missing')

    print(f'Zigbee2MQTT converter ready: {target}')
    print(f'  firmware build: {version}')
    print('  single-file deployment: yes')
    print('  OTA HA entities: enable_ota, ota_status (no endpoint suffix)')


if __name__ == '__main__':
    main()
