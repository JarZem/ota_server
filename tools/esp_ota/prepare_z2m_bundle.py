#!/usr/bin/env python3
"""Create a deployable Zigbee2MQTT converter bundle from project code + OTA module."""
from __future__ import annotations

import argparse
import shutil
from pathlib import Path


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

    wrappers = [p for p in source_dir.glob('*.mjs') if not p.name.endswith('.project.mjs') and p.name != 'jarzem_secure_ota.mjs']
    if len(wrappers) != 1:
        raise SystemExit(f'Expected exactly one project Zigbee2MQTT wrapper in {source_dir}, found {len(wrappers)}')

    wrapper = wrappers[0]
    project_part = wrapper.with_name(wrapper.stem + '.project.mjs')
    ota_part = submodule / 'zigbee2mqtt' / 'jarzem_secure_ota.mjs'
    for path in (wrapper, project_part, ota_part):
        if not path.is_file():
            raise SystemExit(f'Missing Zigbee2MQTT converter input: {path}')

    output.mkdir(parents=True, exist_ok=True)
    for old in output.glob('*.mjs'):
        old.unlink()
    shutil.copy2(wrapper, output / wrapper.name)
    shutil.copy2(project_part, output / project_part.name)
    shutil.copy2(ota_part, output / ota_part.name)
    print(f'Zigbee2MQTT bundle ready: {output}')
    for path in sorted(output.glob('*.mjs')):
        print(' ', path.name)


if __name__ == '__main__':
    main()
