#!/usr/bin/env python3
"""Create a deployable Zigbee2MQTT bundle from project-only code + pinned OTA module."""
from __future__ import annotations

import argparse
import shutil
from pathlib import Path

WRAPPER_TEMPLATE = """import projectDefinition from './{project_name}';
import * as ota from './{ota_name}';

const augment=(definition)=>({{
    ...definition,
    extend:[...(definition.extend??[]),...ota.extend],
    fromZigbee:[...(definition.fromZigbee??[]),...ota.fromZigbee],
    toZigbee:[...(definition.toZigbee??[]),...ota.toZigbee],
    exposes:[...(definition.exposes??[]),...ota.exposes],
    endpoint:(device)=>({{...(typeof definition.endpoint==='function'?definition.endpoint(device):{{}}),...ota.endpointMap}}),
    configure:async(device,coordinatorEndpoint,logger)=>{{
        if(definition.configure)await definition.configure(device,coordinatorEndpoint,logger);
        await ota.configure(device,coordinatorEndpoint,logger);
    }},
    meta:{{...(definition.meta??{{}}),multiEndpoint:true}},
}});

export default Array.isArray(projectDefinition)?projectDefinition.map(augment):augment(projectDefinition);
"""

LEGACY_OTA_MARKERS = (
    'enable_ota_ota_control',
    'ota_status_ota_control',
    ".withEndpoint('ota_control')",
    '.withEndpoint("ota_control")',
)

PROJECT_OTA_MARKERS = (
    'jarzemOta',
    'OTA_CLUSTER_ID',
    'OTA_CONTROL_ENDPOINT',
    'enable_ota',
    'ota_status',
    'ota_command',
)


def _validate_project_only(path: Path, text: str) -> None:
    found = [marker for marker in PROJECT_OTA_MARKERS if marker in text]
    if found:
        raise SystemExit(
            f'Project-only Zigbee2MQTT converter {path} contains OTA implementation: {", ".join(found)}. '
            'OTA code must live only in the ota_server submodule.'
        )


def _validate_ota_module(path: Path, text: str) -> None:
    found = [marker for marker in LEGACY_OTA_MARKERS if marker in text]
    if found:
        raise SystemExit(
            f'OTA Zigbee2MQTT module {path} contains legacy HA endpoint-suffixed names: {", ".join(found)}'
        )
    required = ('enable_ota', 'ota_status', 'ota_transport')
    missing = [marker for marker in required if marker not in text]
    if missing:
        raise SystemExit(f'OTA Zigbee2MQTT module {path} is incomplete, missing: {", ".join(missing)}')


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
        raise SystemExit(
            f'Expected exactly one project-only Zigbee2MQTT converter (*.project.mjs) in {source_dir}, '
            f'found {len(project_parts)}'
        )

    project_part = project_parts[0]
    ota_part = submodule / 'zigbee2mqtt' / 'jarzem_secure_ota.mjs'
    if not ota_part.is_file():
        raise SystemExit(f'Missing OTA Zigbee2MQTT module: {ota_part}')

    project_text = project_part.read_text(encoding='utf-8')
    ota_text = ota_part.read_text(encoding='utf-8')
    _validate_project_only(project_part, project_text)
    _validate_ota_module(ota_part, ota_text)

    base_name = project_part.name[:-len('.project.mjs')]
    wrapper_name = base_name + '.mjs'
    ota_name = base_name + '.ota.mjs'

    output.mkdir(parents=True, exist_ok=True)
    for old in output.glob('*.mjs'):
        old.unlink()

    shutil.copy2(project_part, output / project_part.name)
    shutil.copy2(ota_part, output / ota_name)
    wrapper_path = output / wrapper_name
    wrapper_path.write_text(
        WRAPPER_TEMPLATE.format(project_name=project_part.name, ota_name=ota_name),
        encoding='utf-8',
    )

    # Final guard: never publish a legacy monolithic converter again.
    wrapper_text = wrapper_path.read_text(encoding='utf-8')
    if any(marker in wrapper_text for marker in LEGACY_OTA_MARKERS):
        raise SystemExit('Generated Zigbee2MQTT wrapper unexpectedly contains legacy OTA endpoint suffixes')

    print(f'Zigbee2MQTT bundle ready: {output}')
    print('  OTA HA entities: enable_ota, ota_status (no endpoint suffix)')
    for path in sorted(output.glob('*.mjs')):
        print(' ', path.name)


if __name__ == '__main__':
    main()
