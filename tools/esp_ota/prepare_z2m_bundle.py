#!/usr/bin/env python3
"""Create one self-contained deployable Zigbee2MQTT converter from project + OTA code."""
from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path

LEGACY_OTA_MARKERS = (
    'enable_ota_ota_control', 'ota_status_ota_control',
)
PROJECT_OTA_MARKERS = (
    'jarzemOta', 'OTA_CLUSTER_ID', 'OTA_CONTROL_ENDPOINT',
    'enable_ota', 'ota_status', 'ota_command',
)
OTA_MULTI_ENDPOINT_SKIP = ('enable_ota', 'ota_status', 'ota_transport', 'ota_command')


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
    if "e.binary('enable_ota',ea.ALL" not in text:
        raise SystemExit('OTA module enable_ota must expose STATE+SET+GET access')
    if ".withEndpoint('ota_control')" not in text and '.withEndpoint("ota_control")' not in text:
        raise SystemExit('OTA module controls must be explicitly bound to endpoint ota_control')
    if 'endpointMap={ota_control:OTA_CONTROL_ENDPOINT}' not in text:
        raise SystemExit('OTA module must map ota_control to OTA_CONTROL_ENDPOINT')
    if ".withCategory('config')" in text or '.withCategory("config")' in text:
        raise SystemExit('OTA module enable_ota must be a normal control, not a disabled/config-category HA entity')


def _remove_imports(text: str) -> str:
    return re.sub(r'^import\s+.*?;\s*$', '', text, flags=re.MULTILINE)


def _make_monolith(project_text: str, ota_text: str, version: str) -> str:
    project_body = _remove_imports(project_text)
    project_body, count = re.subn(
        r'export\s+default\s+definition\s*;',
        'return definition;',
        project_body,
    )
    if count != 1:
        raise SystemExit('Project converter must end with `export default definition;`')

    ota_body = _remove_imports(ota_text)
    ota_body = re.sub(r'\bexport\s+const\s+', 'const ', ota_body)

    imports = """import {presets as e, access as ea} from 'zigbee-herdsman-converters/lib/exposes';
import * as m from 'zigbee-herdsman-converters/lib/modernExtend';
import {Zcl} from 'zigbee-herdsman';
"""

    project_scope = f"""
const projectDefinition=(()=>{{
{project_body.strip()}
}})();
"""

    ota_scope = f"""
const jarzemOta=(()=>{{
{ota_body.strip()}
return {{extend,fromZigbee,toZigbee,exposes,endpointMap,configure}};
}})();
"""

    skip_values = ','.join(repr(v) for v in OTA_MULTI_ENDPOINT_SKIP)
    glue = f"""
const jarzemOtaAugment=(definition)=>({{
    ...definition,
    extend:[...(definition.extend??[]),...jarzemOta.extend],
    fromZigbee:[...(definition.fromZigbee??[]),...jarzemOta.fromZigbee],
    toZigbee:[...(definition.toZigbee??[]),...jarzemOta.toZigbee],
    exposes:[...(definition.exposes??[]),...jarzemOta.exposes],
    endpoint:(device)=>({{...(typeof definition.endpoint==='function'?definition.endpoint(device):{{}}),...jarzemOta.endpointMap}}),
    configure:async(device,coordinatorEndpoint,logger)=>{{
        if(definition.configure)await definition.configure(device,coordinatorEndpoint,logger);
        await jarzemOta.configure(device,coordinatorEndpoint,logger);
    }},
    meta:{{
        ...(definition.meta??{{}}),
        multiEndpoint:true,
        multiEndpointSkip:[...new Set([...(definition.meta?.multiEndpointSkip??[]),{skip_values}])],
    }},
}});

export default Array.isArray(projectDefinition)?projectDefinition.map(jarzemOtaAugment):jarzemOtaAugment(projectDefinition);
"""
    return (
        f'// JarZem firmware build: {version}\n'
        '// Generated file: project converter + JarZem Secure OTA; do not edit in Home Assistant.\n'
        f'{imports}\n{project_scope}\n{ota_scope}\n{glue}'
    )


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
    if 'const projectDefinition=(()=>{' not in generated or 'const jarzemOta=(()=>{' not in generated:
        raise SystemExit('Generated converter lexical scope isolation missing')
    if "e.binary('enable_ota',ea.ALL" not in generated:
        raise SystemExit('Generated converter enable_ota is not writable')
    if ".withEndpoint('ota_control')" not in generated and '.withEndpoint("ota_control")' not in generated:
        raise SystemExit('Generated converter enable_ota is not bound to endpoint 11')
    if 'multiEndpointSkip:' not in generated or "'enable_ota'" not in generated:
        raise SystemExit('Generated converter does not suppress OTA endpoint suffixes')
    if ".withCategory('config')" in generated or '.withCategory("config")' in generated:
        raise SystemExit('Generated converter enable_ota is incorrectly marked as config-category')

    print(f'Zigbee2MQTT converter ready: {target}')
    print(f'  firmware build: {version}')
    print('  single-file deployment: yes')
    print('  project/OTA lexical scope isolation: yes')
    print('  OTA HA enable_ota: endpoint 11, STATE+SET+GET, unsuffixed')


if __name__ == '__main__':
    main()
