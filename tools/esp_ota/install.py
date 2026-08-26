#!/usr/bin/env python3
"""One-time, repeatable integration of JarZem Secure OTA into an ESP-IDF Zigbee project."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from adopt_existing_identity import adopt_existing_identity  # noqa: E402
from create_device_identity import ask, install_identity  # noqa: E402

SUBMODULE_PATH = Path('external/ota_server')
SUBMODULE_URL = 'https://github.com/JarZem/ota_server.git'
BEGIN = '# BEGIN JARZEM SECURE OTA - generated, do not edit'
END = '# END JARZEM SECURE OTA - generated'


def run(args: list[str], cwd: Path) -> None:
    print('+', ' '.join(args))
    subprocess.run(args, cwd=cwd, check=True)


def ensure_project(project: Path) -> None:
    if not (project / '.git').exists():
        raise RuntimeError(f'{project} is not a Git working tree')
    if not (project / 'CMakeLists.txt').is_file():
        raise RuntimeError(f'{project} is not an ESP-IDF project')


def ensure_submodule(project: Path, ref: str) -> Path:
    target = project / SUBMODULE_PATH
    modules = project / '.gitmodules'
    registered = modules.is_file() and SUBMODULE_PATH.as_posix() in modules.read_text(encoding='utf-8', errors='ignore')

    if not target.exists():
        if registered:
            run(['git', 'submodule', 'update', '--init', '--recursive', SUBMODULE_PATH.as_posix()], project)
        else:
            run(['git', 'submodule', 'add', SUBMODULE_URL, SUBMODULE_PATH.as_posix()], project)
    elif not registered:
        raise RuntimeError(f'{target} exists but is not the registered OTA submodule')

    run(['git', 'fetch', 'origin'], target)
    run(['git', 'checkout', ref], target)
    return target


def patch_cmake(project: Path) -> None:
    path = project / 'CMakeLists.txt'
    text = path.read_text(encoding='utf-8')
    if BEGIN in text:
        return
    idf = 'include($ENV{IDF_PATH}/tools/cmake/project.cmake)'
    if idf not in text:
        raise RuntimeError('Top-level CMakeLists.txt does not contain the standard ESP-IDF project.cmake include')
    project_match = re.search(r'(?m)^\s*project\s*\([^\n]+\)\s*$', text)
    if not project_match:
        raise RuntimeError('Top-level CMakeLists.txt does not contain project(...)')
    pre = (
        f'{BEGIN}\n'
        'set(EXTRA_COMPONENT_DIRS\n'
        '    "${CMAKE_CURRENT_LIST_DIR}/external/ota_server/esp_component"\n'
        '    ${EXTRA_COMPONENT_DIRS}\n'
        ')\n'
        'include("${CMAKE_CURRENT_LIST_DIR}/external/ota_server/esp_component/jarzem_secure_ota/bootstrap.cmake")\n'
        f'{END}\n'
    )
    text = text.replace(idf, pre + idf, 1)
    project_match = re.search(r'(?m)^\s*project\s*\([^\n]+\)\s*$', text)
    post = (
        f'\n{BEGIN} POST\n'
        'include("${CMAKE_CURRENT_LIST_DIR}/external/ota_server/esp_component/jarzem_secure_ota/post_project.cmake")\n'
        f'{END} POST'
    )
    text = text[:project_match.end()] + post + text[project_match.end():]
    path.write_text(text, encoding='utf-8')


def ensure_project_component_dependency(project: Path) -> None:
    path = project / 'main' / 'CMakeLists.txt'
    if not path.is_file():
        return
    text = path.read_text(encoding='utf-8')
    if 'jarzem_secure_ota' in text:
        return
    matches = list(re.finditer(r'(?m)^(\s*REQUIRES\s*)$', text))
    if not matches:
        return
    shift = 0
    for match in matches:
        pos = match.end() + shift
        insertion = '\n            jarzem_secure_ota'
        text = text[:pos] + insertion + text[pos:]
        shift += len(insertion)
    path.write_text(text, encoding='utf-8')


def ensure_project_converter(project: Path, requested: Path | None) -> None:
    directory = project / 'zigbee2mqtt'
    if not directory.is_dir() and requested is None:
        return
    directory.mkdir(parents=True, exist_ok=True)

    existing_project_parts = sorted(directory.glob('*.project.mjs'))
    if existing_project_parts:
        if len(existing_project_parts) != 1:
            raise RuntimeError('Expected exactly one *.project.mjs converter')
        return

    if requested is not None:
        source = requested if requested.is_absolute() else project / requested
    else:
        candidates = [p for p in directory.glob('*.mjs') if p.name != 'jarzem_secure_ota.mjs']
        if len(candidates) != 1:
            return
        source = candidates[0]
    if not source.is_file():
        raise RuntimeError(f'Zigbee2MQTT project converter not found: {source}')

    target = source.with_name(source.stem + '.project.mjs')
    source.rename(target)
    print(f'Project-only Zigbee2MQTT converter: {target.relative_to(project)}')
    print('OTA converter and combined wrapper will be supplied only in build/zigbee2mqtt/.')


def ensure_identity(project: Path, args) -> None:
    manifest = project / '.jarzem_ota' / 'identity.json'
    credentials = project / 'device_credentials'
    if manifest.is_file():
        if not credentials.is_dir():
            raise RuntimeError('Identity manifest exists but device_credentials is missing; restore the original identity')
        print('Existing immutable OTA identity detected; keys/certificates are untouched.')
        return
    if credentials.is_dir():
        print('Existing device_credentials found; adopting identity without changing any key/certificate.')
        adopt_existing_identity(project)
        return
    install_identity(
        project,
        args.device_id or ask('Device Zigbee IEEE'),
        ask('Device group/family'),
        ask('Device model'),
        ask('Product role/function'),
        ask('Hardware revision', 'RevA'),
        ask('Chip family', 'ESP32-C6'),
        ask('Flash size', '16MB'),
        ask('Ecosystem', 'JaroslavZemanESP'),
        (args.ca_dir or Path(ask('Offline CA directory'))).expanduser(),
        args.manufacturing_url or ask('OTA manufacturing HTTPS URL', 'https://192.168.2.120:8451'),
    )


def ensure_project_manifest(project: Path, publish_url: str | None) -> None:
    path = project / '.jarzem_ota' / 'project.json'
    if path.is_file():
        return
    firmware_product = ask('Firmware product name')
    data = {
        'schema': 1,
        'publish_url': publish_url or ask('OTA firmware HTTPS URL', 'https://192.168.2.120:8443'),
        'firmware_filename': firmware_product + '.bin',
        'firmware': {
            'ota_ecosystem': ask('Ecosystem', 'JaroslavZemanESP'),
            'device_model': ask('Device model'),
            'product_role': ask('Product role/function'),
            'firmware_product': firmware_product,
            'hardware_revision': ask('Hardware revision', 'RevA'),
            'chip_family': ask('Chip family', 'ESP32-C6'),
            'flash_size': ask('Flash size', '16MB'),
            'firmware_channel': ask('Firmware channel', 'stable'),
            'secure_version': 0,
            'active': True,
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def main() -> None:
    p = argparse.ArgumentParser(description='Install JarZem Secure OTA into an ESP-IDF Zigbee project.')
    p.add_argument('project', type=Path)
    p.add_argument('--ref', default='main', help='OTA branch/tag/commit to pin in the Git submodule')
    p.add_argument('--converter', type=Path)
    p.add_argument('--device-id')
    p.add_argument('--ca-dir', type=Path)
    p.add_argument('--manufacturing-url')
    p.add_argument('--publish-url')
    args = p.parse_args()

    project = args.project.resolve()
    ensure_project(project)
    ensure_submodule(project, args.ref)
    patch_cmake(project)
    ensure_project_component_dependency(project)
    ensure_project_converter(project, args.converter)
    ensure_identity(project, args)
    ensure_project_manifest(project, args.publish_url)

    print('JarZem Secure OTA integration complete.')
    print('Application Zigbee source code was not modified.')
    print('Builds validate but never regenerate installed identity files.')
    print('OTA source revision is pinned by the Git submodule commit.')
    print('Run: git add . && git commit, then idf.py fullclean && idf.py build')


if __name__ == '__main__':
    main()
