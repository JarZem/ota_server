#!/usr/bin/env python3
"""Create a deployable Zigbee2MQTT bundle from project-only code + pinned OTA module."""
from __future__ import annotations

import argparse
import shutil
from pathlib import Path

WRAPPER_TEMPLATE = """import projectDefinition from './{project_name}';
import * as ota from './jarzem_secure_ota.mjs';

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

    base_name = project_part.name[:-len('.project.mjs')]
    wrapper_name = base_name + '.mjs'

    output.mkdir(parents=True, exist_ok=True)
    for old in output.glob('*.mjs'):
        old.unlink()

    shutil.copy2(project_part, output / project_part.name)
    shutil.copy2(ota_part, output / ota_part.name)
    (output / wrapper_name).write_text(
        WRAPPER_TEMPLATE.format(project_name=project_part.name),
        encoding='utf-8',
    )

    print(f'Zigbee2MQTT bundle ready: {output}')
    for path in sorted(output.glob('*.mjs')):
        print(' ', path.name)


if __name__ == '__main__':
    main()
