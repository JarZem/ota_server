from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import tempfile
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from firmware_publish import _b64url_decode, _send_json, _validated_publisher

MAX_BODY_BYTES = 512 * 1024
PUBLISH_DOMAIN = b'JaroslavZemanESP|z2m-publish-v1|'
ADDON_CONFIGS_ROOT = Path('/addon_configs')
_FILE_RE = re.compile(r'^[A-Za-z0-9_.-]{1,128}\.mjs$')
_PROJECT_RE = re.compile(r'^[A-Za-z0-9_.-]{1,96}$')


def _find_zigbee2mqtt_config_dir() -> Path:
    if not ADDON_CONFIGS_ROOT.is_dir():
        raise ValueError('all_addon_configs_not_mounted')

    candidates = []
    for path in ADDON_CONFIGS_ROOT.iterdir():
        if not path.is_dir():
            continue
        name = path.name.lower()
        if name == 'zigbee2mqtt' or name.endswith('_zigbee2mqtt') or 'zigbee2mqtt' in name:
            candidates.append(path)

    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        raise ValueError('zigbee2mqtt_addon_config_not_found')
    raise ValueError('multiple_zigbee2mqtt_addon_configs_found')


def _restart_zigbee2mqtt() -> None:
    token = os.environ.get('SUPERVISOR_TOKEN', '')
    if not token:
        raise ValueError('supervisor_token_missing_for_zigbee2mqtt_restart')

    request = urllib.request.Request(
        'http://supervisor/addons',
        headers={'Authorization': f'Bearer {token}'},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        payload = json.loads(response.read().decode('utf-8'))

    addons = payload.get('data', {}).get('addons', []) if isinstance(payload, dict) else []
    matches = []
    for addon in addons:
        slug = str(addon.get('slug') or '')
        name = str(addon.get('name') or '')
        if slug == 'zigbee2mqtt' or slug.endswith('_zigbee2mqtt') or name.lower() == 'zigbee2mqtt':
            matches.append(slug)

    if len(matches) != 1:
        raise ValueError('zigbee2mqtt_supervisor_addon_not_found_or_ambiguous')

    restart = urllib.request.Request(
        f'http://supervisor/addons/{matches[0]}/restart',
        data=b'',
        headers={'Authorization': f'Bearer {token}'},
        method='POST',
    )
    with urllib.request.urlopen(restart, timeout=30) as response:
        response.read()


def handle_zigbee2mqtt_publish(handler) -> None:
    try:
        try:
            length = int(handler.headers.get('Content-Length', '0'))
        except ValueError as exc:
            raise ValueError('invalid_content_length') from exc
        if length <= 0 or length > MAX_BODY_BYTES:
            raise ValueError('invalid_zigbee2mqtt_bundle_size')

        raw = handler.rfile.read(length)
        if len(raw) != length:
            raise ValueError('truncated_zigbee2mqtt_bundle')
        request = json.loads(raw.decode('utf-8'))

        project = str(request.get('project') or '')
        if not _PROJECT_RE.fullmatch(project):
            raise ValueError('invalid_project_name')

        files = request.get('files')
        if not isinstance(files, dict) or len(files) != 3:
            raise ValueError('invalid_zigbee2mqtt_file_set')

        normalized = {}
        for filename, encoded in files.items():
            filename = str(filename)
            if not _FILE_RE.fullmatch(filename) or os.path.basename(filename) != filename:
                raise ValueError('invalid_zigbee2mqtt_filename')
            data = base64.b64decode(str(encoded), validate=True)
            if len(data) > 256 * 1024:
                raise ValueError('zigbee2mqtt_file_too_large')
            normalized[filename] = data

        expected_names = {
            f'{project}.mjs',
            f'{project}.project.mjs',
            f'{project}.ota.mjs',
        }
        if set(normalized) != expected_names:
            raise ValueError('zigbee2mqtt_file_names_do_not_match_project')

        bundle_digest = hashlib.sha256()
        for filename in sorted(normalized):
            bundle_digest.update(filename.encode('utf-8'))
            bundle_digest.update(b'\0')
            bundle_digest.update(normalized[filename])
            bundle_digest.update(b'\0')
        digest_hex = bundle_digest.hexdigest()

        cert, publisher, _registered = _validated_publisher(str(request.get('certificate') or ''))
        signature = _b64url_decode(str(request.get('signature') or ''))
        canonical = PUBLISH_DOMAIN + project.encode('utf-8') + b'|' + digest_hex.encode('ascii')
        cert.public_key().verify(signature, canonical, ec.ECDSA(hashes.SHA256()))

        config_dir = _find_zigbee2mqtt_config_dir()
        target_dir = config_dir / 'external_converters'
        target_dir.mkdir(parents=True, exist_ok=True)

        changed = False
        for filename, data in normalized.items():
            target = target_dir / filename
            if target.is_file() and target.read_bytes() == data:
                continue
            fd, temp_name = tempfile.mkstemp(prefix='.' + filename + '.', dir=target_dir)
            try:
                with os.fdopen(fd, 'wb') as out:
                    out.write(data)
                    out.flush()
                    os.fsync(out.fileno())
                os.replace(temp_name, target)
            except Exception:
                try:
                    os.unlink(temp_name)
                except OSError:
                    pass
                raise
            changed = True

        if changed:
            _restart_zigbee2mqtt()

        print(
            f"Zigbee2MQTT converter publish accepted device_id={publisher['device_id']} "
            f"project={project} changed={int(changed)} dir={target_dir}",
            flush=True,
        )
        _send_json(handler, 201, {
            'status': 'PUBLISHED',
            'project': project,
            'changed': changed,
            'directory': str(target_dir),
        })
    except Exception as exc:
        print(f'Zigbee2MQTT converter publish rejected: {exc}', flush=True)
        _send_json(handler, 400, {'status': 'ERROR', 'error': str(exc)})
