#!/usr/bin/env python3
"""Integrate JarZem Secure OTA into an ESP-IDF Zigbee project without hand-editing project code."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from create_device_identity import ask, install_identity  # noqa: E402

SUBMODULE_PATH = Path('external/ota_server')
SUBMODULE_URL = 'https://github.com/JarZem/ota_server.git'
BEGIN_PRE = '# BEGIN JARZEM SECURE OTA - generated, do not edit'
END_PRE = '# END JARZEM SECURE OTA - generated'


def run(args: list[str], cwd: Path) -> None:
    print('+', ' '.join(args))
    subprocess.run(args, cwd=cwd, check=True)


def ensure_git_project(project: Path) -> None:
    if not (project / '.git').exists():
        raise RuntimeError(f'{project} is not a Git working tree')
    if not (project / 'CMakeLists.txt').is_file():
        raise RuntimeError(f'{project} does not look like an ESP-IDF project')


def ensure_submodule(project: Path, ref: str) -> Path:
    target = project / SUBMODULE_PATH
    gitmodules = project / '.gitmodules'
    if not target.exists():
        run(['git', 'submodule', 'add', SUBMODULE_URL, str(SUBMODULE_PATH).replace('\\', '/')], project)
    elif not gitmodules.is_file() or 'external/ota_server' not in gitmodules.read_text(encoding='utf-8', errors='ignore'):
        raise RuntimeError(f'{target} exists but is not registered as the JarZem OTA Git submodule')
    run(['git', 'fetch', 'origin'], target)
    run(['git', 'checkout', ref], target)
    return target


def patch_root_cmake(project: Path) -> None:
    path = project / 'CMakeLists.txt'
    text = path.read_text(encoding='utf-8')
    if BEGIN_PRE in text:
        return
    idf_include = 'include($ENV{IDF_PATH}/tools/cmake/project.cmake)'
    if idf_include not in text:
        raise RuntimeError('Top-level CMakeLists.txt does not contain the standard ESP-IDF project.cmake include')
    pre = (
        f'{BEGIN_PRE}\n'
        'include("${CMAKE_CURRENT_LIST_DIR}/external/ota_server/esp_component/jarzem_secure_ota/bootstrap.cmake")\n'
        f'{END_PRE}\n\n'
    )
    text = text.replace(idf_include, pre + idf_include, 1)
    project_match = re.search(r'(?m)^\s*project\s*\([^\n]+\)\s*$', text)
    if not project_match:
        raise RuntimeError('Top-level CMakeLists.txt does not contain project(...)')
    post = (
        '\n' + f'{BEGIN_PRE} POST\n'
        'include("${CMAKE_CURRENT_LIST_DIR}/external/ota_server/esp_component/jarzem_secure_ota/post_project.cmake")\n'
        f'{END_PRE} POST'
    )
    text = text[:project_match.end()] + post + text[project_match.end():]
    path.write_text(text, encoding='utf-8')


def patch_zigbee_sources(project: Path, submodule: Path) -> list[Path]:
    patched: list[Path] = []
    for path in project.rglob('*.c'):
        if str(path.resolve()).startswith(str(submodule.resolve())) or 'build' in path.parts:
            continue
        text = path.read_text(encoding='utf-8', errors='ignore')
        original = text
        if 'esp_zb_device_register(' in text:
            text = text.replace('esp_zb_device_register(', 'jarzem_ota_device_register(')
        if 'esp_zb_core_action_handler_register(' in text:
            text = text.replace('esp_zb_core_action_handler_register(', 'jarzem_ota_action_handler_register(')
        if text != original:
            if '#include "jarzem_secure_ota.h"' not in text:
                includes = list(re.finditer(r'(?m)^#include[^\n]*$', text))
                if not includes:
                    raise RuntimeError(f'Cannot insert OTA include into {path}')
                pos = includes[-1].end()
                text = text[:pos] + '\n#include "jarzem_secure_ota.h"' + text[pos:]
            path.write_text(text, encoding='utf-8')
            patched.append(path)
    if not patched:
        raise RuntimeError('No esp_zb_device_register/esp_zb_core_action_handler_register calls found. Cannot integrate Zigbee OTA automatically.')
    return patched


def add_project_hooks(project: Path) -> None:
    status_header = project / 'main' / 'status_led.h'
    if not status_header.is_file():
        return
    hook = project / 'main' / 'jarzem_ota_project_hooks.c'
    hook.write_text(
        '#include "jarzem_secure_ota.h"\n'
        '#include "status_led.h"\n\n'
        'void jarzem_ota_hook_rx_from_ha(void) { status_led_indicate_ha_command(); }\n'
        'void jarzem_ota_hook_provision_step(void) { status_led_indicate_provision_step(); }\n',
        encoding='utf-8',
    )
    cmake = project / 'main' / 'CMakeLists.txt'
    if not cmake.is_file():
        raise RuntimeError('main/status_led.h exists but main/CMakeLists.txt is missing')
    text = cmake.read_text(encoding='utf-8')
    if 'jarzem_ota_project_hooks.c' not in text:
        text, count = re.subn(r'(?m)^(\s*SRCS\s*)$', r'\1\n            "jarzem_ota_project_hooks.c"', text)
        if count == 0:
            raise RuntimeError('Could not add jarzem_ota_project_hooks.c to main CMake SRCS')
        cmake.write_text(text, encoding='utf-8')


def compose_converter(project: Path, converter: Path | None) -> None:
    if converter is None:
        candidates = sorted((project / 'zigbee2mqtt').glob('*.mjs')) if (project / 'zigbee2mqtt').is_dir() else []
        if len(candidates) == 1:
            converter = candidates[0]
        else:
            return
    converter = converter if converter.is_absolute() else project / converter
    if not converter.is_file():
        raise RuntimeError(f'Zigbee2MQTT converter not found: {converter}')
    project_only = converter.with_name(converter.stem + '.project.mjs')
    if project_only.exists():
        return
    converter.rename(project_only)
    ota_import = '../../external/ota_server/zigbee2mqtt/jarzem_secure_ota.mjs'
    converter.write_text(
        f"import projectDefinition from './{project_only.name}';\n"
        f"import * as ota from '{ota_import}';\n\n"
        "const augment=(definition)=>({\n"
        "  ...definition,\n"
        "  extend:[...(definition.extend??[]),...ota.extend],\n"
        "  fromZigbee:[...(definition.fromZigbee??[]),...ota.fromZigbee],\n"
        "  toZigbee:[...(definition.toZigbee??[]),...ota.toZigbee],\n"
        "  exposes:[...(definition.exposes??[]),...ota.exposes],\n"
        "  endpoint:(device)=>({...(typeof definition.endpoint==='function'?definition.endpoint(device):{}),...ota.endpointMap}),\n"
        "  configure:async(device,coordinatorEndpoint,logger)=>{\n"
        "    if(definition.configure)await definition.configure(device,coordinatorEndpoint,logger);\n"
        "    await ota.configure(device,coordinatorEndpoint,logger);\n"
        "  },\n"
        "  meta:{...(definition.meta??{}),multiEndpoint:true},\n"
        "});\n\n"
        "export default Array.isArray(projectDefinition)?projectDefinition.map(augment):augment(projectDefinition);\n",
        encoding='utf-8',
    )


def write_project_manifest(project: Path, values: dict) -> None:
    path = project / '.jarzem_ota' / 'project.json'
    if path.exists():
        existing = json.loads(path.read_text(encoding='utf-8'))
        if existing != values:
            raise RuntimeError(f'{path} already exists with different settings; installer will not silently rewrite an integrated project')
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(values, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def main() -> None:
    p = argparse.ArgumentParser(description='One-time complete JarZem Secure OTA integration for an ESP-IDF Zigbee project.')
    p.add_argument('project', type=Path)
    p.add_argument('--ref', default='main', help='OTA git branch/tag/commit to pin in the submodule')
    p.add_argument('--converter', type=Path)
    p.add_argument('--device-id')
    p.add_argument('--ca-dir', type=Path)
    p.add_argument('--manufacturing-url')
    p.add_argument('--publish-url')
    args = p.parse_args()

    project = args.project.resolve()
    ensure_git_project(project)
    submodule = ensure_submodule(project, args.ref)
    patch_root_cmake(project)
    patched = patch_zigbee_sources(project, submodule)
    add_project_hooks(project)
    compose_converter(project, args.converter)

    identity_manifest = project / '.jarzem_ota' / 'identity.json'
    credential_dir = project / 'device_credentials'
    new_identity = not identity_manifest.exists() and not credential_dir.exists()
    if new_identity:
        group = ask('Device group/family')
        model = ask('Device model')
        role = ask('Product role/function')
        hardware = ask('Hardware revision', 'RevA')
        chip = ask('Chip family', 'ESP32-C6')
        flash = ask('Flash size', '16MB')
        ecosystem = ask('Ecosystem', 'JaroslavZemanESP')
        manufacturing = args.manufacturing_url or ask('OTA manufacturing HTTPS URL', 'https://192.168.2.120:8451')
        install_identity(
            project,
            args.device_id or ask('Device Zigbee IEEE'),
            group, model, role, hardware, chip, flash, ecosystem,
            (args.ca_dir or Path(ask('Offline CA directory'))).expanduser(),
            manufacturing,
        )
    elif not identity_manifest.is_file() or not credential_dir.is_dir():
        raise RuntimeError('Partial OTA identity found. Installer refuses to regenerate or repair keys automatically; restore the original identity files.')
    else:
        print('Existing immutable OTA identity detected; no key/certificate operation performed.')
        # Metadata is requested below only when project manifest is absent.
        group=model=role=hardware=chip=flash=ecosystem=''

    project_manifest = project / '.jarzem_ota' / 'project.json'
    if not project_manifest.exists():
        if not new_identity:
            ecosystem = ask('Ecosystem', 'JaroslavZemanESP')
            model = ask('Device model')
            role = ask('Product role/function')
            hardware = ask('Hardware revision', 'RevA')
            chip = ask('Chip family', 'ESP32-C6')
            flash = ask('Flash size', '16MB')
        firmware_product = ask('Firmware product name')
        channel = ask('Firmware channel', 'stable')
        publish_url = args.publish_url or ask('OTA firmware HTTPS URL', 'https://192.168.2.120:8443')
        write_project_manifest(project, {
            'schema': 1,
            'publish_url': publish_url,
            'firmware_filename': firmware_product + '.bin',
            'firmware': {
                'ota_ecosystem': ecosystem,
                'device_model': model,
                'product_role': role,
                'firmware_product': firmware_product,
                'hardware_revision': hardware,
                'chip_family': chip,
                'flash_size': flash,
                'firmware_channel': channel,
                'secure_version': 0,
                'active': True,
            },
        })

    print('JarZem Secure OTA integration complete.')
    print('Patched Zigbee source files:')
    for path in patched:
        print(' ', path.relative_to(project))
    print('The submodule commit is now part of the ESP project history; builds never update it automatically.')
    print('Next: git add . && git commit, then idf.py fullclean && idf.py build')


if __name__ == '__main__':
    main()
