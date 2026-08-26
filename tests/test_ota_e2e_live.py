#!/usr/bin/env python3
"""Live black-box-ish OTA integration test run inside the Home Assistant OTA add-on.

The OTA server has no test mode and no test-only endpoint. This program creates a
fresh virtual ESP identity, registers it through the normal manufacturing API,
uses the normal MQTT provisioning wire protocol, publishes a signed BIN and MJS
through the production HTTPS APIs, creates a temporary Home Assistant MQTT
registry device so the normal ingress /send path can dispatch the OTA CHECK,
downloads the BIN through the normal one-time HTTPS token and finally sends the
same F confirmation as a real ESP.

Root CA certificate/private key are pasted interactively and are never written
to disk. Successful runs clean their synthetic device/artifacts from OTA/HA/Z2M.
Diagnostic logs remain under /share/ota_server/test-results/<run-id>/.
"""
from __future__ import annotations

import base64
import getpass
import hashlib
import hmac
import json
import os
import queue
import re
import ssl
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import paho.mqtt.client as mqtt
import websocket
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

# Runtime production modules. They are used only for database inspection and
# cleanup; protocol messages themselves go through the real network endpoints.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from database import db_connect  # noqa: E402

OPTIONS_PATH = Path('/data/options.json')
INSTALLED_ROOT_CA = Path('/share/ota_server/cert/root_ca_cert.pem')
RESULT_ROOT = Path('/share/ota_server/test-results')
FIRMWARE_DIR = Path('/share/ota_server/firmware')
SUPERVISOR_TOKEN = os.environ.get('SUPERVISOR_TOKEN', '')

PUBLISH_DOMAIN = b'JaroslavZemanESP|firmware-publish-v1|'
Z2M_PUBLISH_DOMAIN = b'JaroslavZemanESP|z2m-publish-v1|'
KDF_DOMAIN = b'JaroslavZemanESP|provisioning-v1|'
NONCE_DOMAIN = b'JaroslavZemanESP|provisioning-nonce-v1|'
CHECK_KEY_DOMAIN = b'JaroslavZemanESP|ota-check-key-v1|'
TOKEN_KEY_DOMAIN = b'JaroslavZemanESP|ota-download-token-key-v1|'
CHECK_MAC_DOMAIN = b'JaroslavZemanESP|ota-check-v1|'
TOKEN_DOMAIN = b'JaroslavZemanESP|ota-download-token-v1|'
PKI = 'urn:jarzem:esp:pki:'


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def b64ud(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + '=' * ((-len(text)) % 4))


def raw64(signature_der: bytes) -> bytes:
    r, s = decode_dss_signature(signature_der)
    return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')


def der64(signature: bytes) -> bytes:
    if len(signature) != 64:
        raise AssertionError(f'expected 64-byte P-256 signature, got {len(signature)}')
    return encode_dss_signature(int.from_bytes(signature[:32], 'big'), int.from_bytes(signature[32:], 'big'))


def say(text: str) -> None:
    print(text, flush=True)


def step(text: str) -> None:
    say(f'\nTEST  {text}')


def passed(text: str) -> None:
    say(f'PASS  {text}')


def fail(text: str) -> None:
    raise AssertionError(text)


def read_pem(label: str, end_marker: str) -> bytes:
    say(f'\nPaste {label}. Finish with {end_marker}:')
    lines: list[str] = []
    while True:
        line = input()
        lines.append(line)
        if line.strip() == end_marker:
            break
    return ('\n'.join(lines) + '\n').encode('ascii')


def load_options() -> dict:
    return json.loads(OPTIONS_PATH.read_text(encoding='utf-8'))


def tls_context(root_pem: bytes) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cadata=root_pem.decode('ascii'))
    # Calls are made to 127.0.0.1 from inside the add-on. Chain validation is
    # still active; hostname is validated independently from the OTA cert SAN.
    ctx.check_hostname = False
    return ctx


def http_json(url: str, *, ctx: ssl.SSLContext | None = None, data: bytes | None = None,
              headers: dict | None = None, method: str | None = None,
              expected: int = 200) -> dict:
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60, context=ctx) as response:
            body = response.read()
            if response.status != expected:
                fail(f'{url} HTTP {response.status}, expected {expected}: {body[:500]!r}')
            return json.loads(body.decode('utf-8')) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode('utf-8', 'replace')
        if exc.code == expected:
            try:
                return json.loads(body) if body else {}
            except Exception:
                return {'raw': body}
        fail(f'{url} HTTP {exc.code}, expected {expected}: {body}')


def supervisor_get(path: str) -> bytes:
    if not SUPERVISOR_TOKEN:
        raise RuntimeError('SUPERVISOR_TOKEN is missing')
    req = urllib.request.Request(
        'http://supervisor' + path,
        headers={'Authorization': f'Bearer {SUPERVISOR_TOKEN}'},
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        return response.read()


def mqtt_service() -> dict:
    payload = json.loads(supervisor_get('/services/mqtt').decode('utf-8'))
    data = payload.get('data', payload)
    return {
        'host': data['host'], 'port': int(data['port']),
        'username': data.get('username') or '', 'password': data.get('password') or '',
    }


def issue_device_cert(ca_cert: x509.Certificate, ca_key: ec.EllipticCurvePrivateKey,
                      device_key: ec.EllipticCurvePrivateKey, device_id: str,
                      compact: str, ecosystem: str, model: str, product_role: str,
                      hardware: str) -> x509.Certificate:
    now = datetime.now(timezone.utc)
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ecosystem),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'ota-e2e-live'),
        x509.NameAttribute(NameOID.COMMON_NAME, f'ESP Device {device_id}'),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, device_id),
    ])
    uris = [
        PKI + 'role:device', PKI + 'device:' + compact,
        PKI + 'group:ota-e2e-live', PKI + 'model:' + model,
        PKI + 'product-role:' + product_role, PKI + 'hardware:' + hardware,
        PKI + 'chip:ESP32-C6', PKI + 'flash:16MB',
    ]
    return (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(ca_cert.subject)
        .public_key(device_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([
            x509.UniformResourceIdentifier(v) for v in uris]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )


class VirtualEsp:
    def __init__(self, base_topic: str, topic_device: str, device_id: str,
                 device_key: ec.EllipticCurvePrivateKey, ota_cert: x509.Certificate,
                 service: dict):
        self.base_topic = base_topic
        self.topic_device = topic_device
        self.device_id = device_id
        self.device_key = device_key
        self.ota_cert = ota_cert
        self.commands: queue.Queue[str] = queue.Queue()
        self.transcript: list[str] = []
        self.connected = threading.Event()
        try:
            self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f'ota-e2e-{topic_device[-8:]}')
        except (AttributeError, TypeError):
            self.client = mqtt.Client(client_id=f'ota-e2e-{topic_device[-8:]}')
        if service['username']:
            self.client.username_pw_set(service['username'], service['password'])
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        self.client.connect(service['host'], service['port'], keepalive=30)
        self.client.loop_start()
        if not self.connected.wait(10):
            fail('MQTT virtual ESP did not connect')

    @property
    def state_topic(self) -> str:
        return f'{self.base_topic}/{self.topic_device}'

    @property
    def set_topic(self) -> str:
        return f'{self.base_topic}/{self.topic_device}/set'

    def _on_connect(self, client, userdata, flags, reason_code, properties=None):
        code = int(reason_code) if hasattr(reason_code, '__int__') else reason_code
        if code == 0:
            client.subscribe(self.set_topic, qos=0)
            self.connected.set()

    def _on_message(self, client, userdata, msg):
        try:
            body = json.loads(msg.payload.decode('utf-8'))
            wire = body.get('ota_command') if isinstance(body, dict) else None
        except Exception:
            wire = None
        if isinstance(wire, str):
            self.transcript.append(f'OTA -> ESP {wire}')
            self.commands.put(wire)

    def send(self, wire: str) -> None:
        self.transcript.append(f'ESP -> OTA {wire}')
        body = json.dumps({'ota_transport': wire}, separators=(',', ':'))
        result = self.client.publish(self.state_topic, body, qos=1, retain=False)
        result.wait_for_publish(timeout=10)
        if result.rc != mqtt.MQTT_ERR_SUCCESS:
            fail(f'MQTT publish failed rc={result.rc}')

    def expect(self, prefix: str, timeout: int = 15) -> str:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                wire = self.commands.get(timeout=min(1, deadline - time.monotonic()))
            except queue.Empty:
                continue
            if wire.startswith(prefix):
                return wire
        fail(f'timeout waiting for OTA command {prefix}')

    def stop(self):
        try:
            self.client.disconnect()
        finally:
            self.client.loop_stop()


def wait_db(sql: str, params: tuple, predicate, timeout: int = 20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with db_connect() as conn:
            row = conn.execute(sql, params).fetchone()
        if row and predicate(dict(row)):
            return dict(row)
        time.sleep(0.3)
    return None


def verify_and_decrypt_provisioning(wire: str, device_key, ota_cert, device_id: str,
                                    counter: int, random8: bytes) -> tuple[bytes, dict]:
    shared = device_key.exchange(ec.ECDH(), ota_cert.public_key())
    material = KDF_DOMAIN + device_id.encode('ascii') + struct.pack('>Q', counter) + random8
    session_key = hmac.new(shared, material, hashlib.sha256).digest()
    nonce_material = NONCE_DOMAIN + device_id.encode('ascii') + struct.pack('>Q', counter) + random8
    nonce = hmac.new(session_key, nonce_material, hashlib.sha256).digest()[:12]
    aad = f'P|{device_id}|{counter}|'.encode('ascii') + random8
    encrypted = b64ud(wire.split('|', 1)[1])
    plain = AESGCM(session_key).decrypt(nonce, encrypted, aad)
    if len(plain) < 9:
        fail('provisioning plaintext too short')
    proto, security, channel, ssid_len, pass_len, host_type, host_len = plain[:7]
    pos = 7
    ssid = plain[pos:pos+ssid_len].decode(); pos += ssid_len
    password = plain[pos:pos+pass_len].decode(); pos += pass_len
    host_raw = plain[pos:pos+host_len]; pos += host_len
    host = '.'.join(str(x) for x in host_raw) if host_type == 1 else host_raw.decode()
    port = struct.unpack('>H', plain[pos:pos+2])[0]
    return session_key, {
        'protocol': proto, 'security': security, 'channel': channel,
        'ssid': ssid, 'password': password, 'host': host, 'port': port,
    }


def publish_firmware(base: str, ctx: ssl.SSLContext, cert_pem: bytes, key,
                     filename: str, blob: bytes, metadata: dict) -> str:
    digest = hashlib.sha256(blob).hexdigest()
    meta_b64 = b64u(json.dumps(metadata, separators=(',', ':'), sort_keys=True).encode())
    canonical = PUBLISH_DOMAIN + filename.encode() + b'|' + digest.encode() + b'|' + meta_b64.encode()
    sig = key.sign(canonical, ec.ECDSA(hashes.SHA256()))
    headers = {
        'Content-Type': 'application/octet-stream', 'X-Firmware-Filename': filename,
        'X-Firmware-SHA256': digest, 'X-Firmware-Metadata': meta_b64,
        'X-Publisher-Certificate': b64u(cert_pem), 'X-Publisher-Signature': b64u(sig),
    }
    result = http_json(base + '/api/firmware/publish', ctx=ctx, data=blob,
                       headers=headers, method='POST', expected=201)
    if result.get('status') != 'PUBLISHED' or result.get('sha256') != digest:
        fail(f'firmware publish response invalid: {result}')
    return digest


def publish_converter(base: str, ctx: ssl.SSLContext, cert_pem: bytes, key,
                      project: str, version: str) -> tuple[str, str]:
    filename = project + '.mjs'
    code = (
        f'// JarZem firmware build: {version}\n'
        "const definition={zigbeeModel:['JARZEM_OTA_E2E_NEVER'],model:'JARZEM_OTA_E2E_NEVER',vendor:'JarZem',description:'OTA E2E temporary converter'};\n"
        'export default definition;\n'
    ).encode()
    digest = hashlib.sha256(filename.encode() + b'\0' + code + b'\0').hexdigest()
    sig = key.sign(Z2M_PUBLISH_DOMAIN + project.encode() + b'|' + digest.encode(), ec.ECDSA(hashes.SHA256()))
    body = json.dumps({
        'schema': 2, 'project': project, 'firmware_version': version,
        'files': {filename: base64.b64encode(code).decode()},
        'certificate': b64u(cert_pem), 'signature': b64u(sig),
    }, separators=(',', ':')).encode()
    result = http_json(base + '/api/zigbee2mqtt/publish', ctx=ctx, data=body,
                       headers={'Content-Type': 'application/json'}, method='POST', expected=201)
    if result.get('status') != 'PUBLISHED':
        fail(f'MJS publish response invalid: {result}')
    return filename, hashlib.sha256(code).hexdigest()


def mqtt_request(service: dict, request_topic: str, response_topic: str, body: dict, timeout=15) -> dict:
    q: queue.Queue[dict] = queue.Queue()
    transaction = int(time.time_ns() & 0x7fffffff)
    body = dict(body); body['transaction'] = transaction
    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f'ota-e2e-admin-{transaction}')
    except (AttributeError, TypeError):
        client = mqtt.Client(client_id=f'ota-e2e-admin-{transaction}')
    if service['username']:
        client.username_pw_set(service['username'], service['password'])
    def on_message(_c, _u, msg):
        try:
            value = json.loads(msg.payload.decode())
            if value.get('transaction') == transaction:
                q.put(value)
        except Exception:
            pass
    client.on_message = on_message
    client.connect(service['host'], service['port'], 30)
    client.subscribe(response_topic)
    client.loop_start()
    try:
        client.publish(request_topic, json.dumps(body, separators=(',', ':')), qos=1).wait_for_publish(10)
        response = q.get(timeout=timeout)
        if response.get('status') != 'ok':
            fail(f'MQTT bridge request failed: {response}')
        return response
    finally:
        client.disconnect(); client.loop_stop()


def publish_discovery(client, compact: str, present: bool) -> str:
    topic = f'homeassistant/sensor/jarzem_ota_e2e_{compact}/config'
    if present:
        payload = json.dumps({
            'name': f'JarZem OTA E2E {compact[-6:]}',
            'unique_id': f'jarzem_ota_e2e_{compact}',
            'state_topic': f'jarzem_ota_e2e/{compact}/state',
            'device': {
                'identifiers': [f'zigbee2mqtt_0x{compact}'],
                'name': f'JarZem OTA E2E {compact[-6:]}',
                'model': 'ESP32-C6-E2E', 'manufacturer': 'JarZem',
            },
        }, separators=(',', ':'))
    else:
        payload = ''
    result = client.publish(topic, payload, qos=1, retain=True)
    result.wait_for_publish(10)
    return topic


def ha_registry_contains(compact: str) -> bool:
    if not SUPERVISOR_TOKEN:
        return False
    ws = websocket.create_connection('ws://supervisor/core/websocket', timeout=10)
    try:
        if json.loads(ws.recv()).get('type') != 'auth_required':
            return False
        ws.send(json.dumps({'type': 'auth', 'access_token': SUPERVISOR_TOKEN}))
        if json.loads(ws.recv()).get('type') != 'auth_ok':
            return False
        ws.send(json.dumps({'id': 1, 'type': 'config/device_registry/list'}))
        while True:
            msg = json.loads(ws.recv())
            if msg.get('id') != 1 or msg.get('type') != 'result':
                continue
            for device in msg.get('result') or []:
                for identifier in device.get('identifiers') or []:
                    if len(identifier) >= 2 and str(identifier[0]).lower() == 'mqtt' and str(identifier[1]) == f'zigbee2mqtt_0x{compact}':
                        return True
            return False
    finally:
        ws.close()


def wait_ha_registry(compact: str, present: bool, timeout=30) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if ha_registry_contains(compact) == present:
            return
        time.sleep(1)
    fail(f'HA MQTT discovery registry present={present} timeout for {compact}')


def trigger_ingress_dispatch(filename: str, device_id: str) -> None:
    form = urllib.parse.urlencode([('file', filename), ('ssid', ''), ('password', ''), ('ieee', device_id)]).encode()
    req = urllib.request.Request('http://127.0.0.1:8099/send', data=form,
                                 headers={'Content-Type': 'application/x-www-form-urlencoded'}, method='POST')
    with urllib.request.urlopen(req, timeout=45) as response:
        text = response.read().decode('utf-8', 'replace')
        if response.status != 200 or 'ota_check' not in text:
            fail(f'ingress dispatch did not report OTA check success: HTTP={response.status}')


def download(url: str, ctx: ssl.SSLContext, headers: dict, expected: int) -> tuple[int, bytes, dict]:
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60, context=ctx) as response:
            return response.status, response.read(), dict(response.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers)


def addon_logs() -> tuple[str, dict[str, str]]:
    logs: dict[str, str] = {}
    try:
        logs['ota'] = supervisor_get('/addons/self/logs').decode('utf-8', 'replace')
    except Exception as exc:
        logs['ota'] = f'LOG FETCH FAILED: {exc}'
    try:
        addons = json.loads(supervisor_get('/addons').decode())
        items = (addons.get('data') or {}).get('addons') or addons.get('addons') or []
        for item in items:
            slug = str(item.get('slug') or '')
            name = str(item.get('name') or '').lower()
            key = None
            if 'zigbee2mqtt' in slug.lower() or 'zigbee2mqtt' in name:
                key = 'zigbee2mqtt'
            elif 'mosquitto' in slug.lower() or 'mosquitto' in name:
                key = 'mosquitto'
            if key and key not in logs:
                try:
                    logs[key] = supervisor_get(f'/addons/{slug}/logs').decode('utf-8', 'replace')
                except Exception as exc:
                    logs[key] = f'LOG FETCH FAILED: {exc}'
    except Exception as exc:
        logs['addons'] = f'ADDON DISCOVERY FAILED: {exc}'
    return logs.get('ota', ''), logs


def cleanup_db(device_id: str, filename: str, version: str, sha256_hex: str) -> None:
    statements = [
        ('DELETE FROM device_firmware_status WHERE device_id=? OR firmware_sha256=?', (device_id, sha256_hex)),
        ('DELETE FROM provisioning_attempts WHERE device_id=?', (device_id,)),
        ('DELETE FROM download_grants WHERE device_id=?', (device_id,)),
        ('DELETE FROM ota_dispatch WHERE ieee=? OR filename=?', (device_id, filename)),
        ('DELETE FROM device_provisioning WHERE device_id=?', (device_id,)),
        ('DELETE FROM artifact_publications WHERE publisher_device_id=? OR firmware_version=?', (device_id, version)),
        ('DELETE FROM firmware_alias WHERE filename=?', (filename,)),
        ('DELETE FROM firmware_history WHERE filename=?', (filename,)),
        ('DELETE FROM firmware_images WHERE filename=?', (filename,)),
        ('DELETE FROM devices WHERE device_id=?', (device_id,)),
        ('DELETE FROM device_certificates WHERE device_id=?', (device_id,)),
    ]
    with db_connect() as conn:
        for sql, params in statements:
            conn.execute(sql, params)
    for path in (FIRMWARE_DIR / filename, FIRMWARE_DIR / (Path(filename).stem + '.release.json')):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def main() -> None:
    options = load_options()
    ecosystem = str(options.get('ota_ecosystem') or 'JaroslavZemanESP')
    base_topic = str(options.get('mqtt_base_topic') or 'zigbee2mqtt')
    ota_https = 'https://127.0.0.1:' + str(options.get('ota_port') or 8443)
    manufacturing = 'https://127.0.0.1:8451'

    say('JarZem OTA live E2E test')
    say('The OTA server is used exactly as in production; no test mode is enabled.')
    root_pem = read_pem('Root CA certificate PEM', '-----END CERTIFICATE-----')
    key_pem = read_pem('Root CA private key PEM', '-----END ENCRYPTED PRIVATE KEY-----' if 'ENCRYPTED' in '' else '-----END PRIVATE KEY-----')
    # If an encrypted key was pasted, the preceding helper may have stopped on
    # END PRIVATE KEY only. Accept both formats by reading a second form cleanly
    # is awkward in terminals, so detect and explain before parsing.
    password_text = getpass.getpass('Root CA private key password (empty if key is unencrypted): ')
    password = password_text.encode() if password_text else None

    ca_cert = x509.load_pem_x509_certificate(root_pem)
    try:
        ca_key = serialization.load_pem_private_key(key_pem, password=password)
    except Exception as exc:
        fail(f'cannot load pasted Root CA private key: {exc}. For encrypted PKCS#8 paste through END ENCRYPTED PRIVATE KEY.')
    if not isinstance(ca_key, ec.EllipticCurvePrivateKey):
        fail('Root CA private key is not EC')
    if ca_key.public_key().public_numbers() != ca_cert.public_key().public_numbers():
        fail('pasted Root CA certificate/private key do not match')
    installed = x509.load_pem_x509_certificate(INSTALLED_ROOT_CA.read_bytes())
    if installed.fingerprint(hashes.SHA256()) != ca_cert.fingerprint(hashes.SHA256()):
        fail('pasted Root CA does not match the Root CA installed in OTA')
    passed('pasted offline Root CA matches OTA trust anchor')

    run_id = datetime.now().strftime('%Y%m%d%H%M%S') + '-' + os.urandom(2).hex()
    compact = '02' + os.urandom(7).hex()
    device_id = ':'.join(compact[i:i+2] for i in range(0, 16, 2))
    topic_device = '0x' + compact
    model = 'ESP32-C6-E2E'
    product_role = 'integration-test'
    hardware = 'E2E-REV'
    project = 'ota-e2e-' + run_id.replace('-', '')
    version = 'e2e-' + run_id[-9:]
    filename = project + '.bin'
    firmware_product = project
    result_dir = RESULT_ROOT / run_id
    result_dir.mkdir(parents=True, exist_ok=True)
    success = False
    discovery_created = False
    converter_name = project + '.mjs'
    esp: VirtualEsp | None = None
    admin_client = None

    try:
        step('create a brand-new virtual ESP key and CA-signed certificate')
        device_key = ec.generate_private_key(ec.SECP256R1())
        device_cert = issue_device_cert(ca_cert, ca_key, device_key, device_id, compact,
                                        ecosystem, model, product_role, hardware)
        cert_pem = device_cert.public_bytes(serialization.Encoding.PEM)
        passed(f'virtual ESP identity created device_id={device_id}')

        ctx = tls_context(root_pem)
        step('verify OTA manufacturing TLS identity and register the new certificate')
        ota_cert_pem = urllib.request.urlopen(manufacturing + '/api/manufacturing/ota-server.pem', context=ctx, timeout=20).read()
        ota_cert = x509.load_pem_x509_certificate(ota_cert_pem)
        ca_cert.public_key().verify(ota_cert.signature, ota_cert.tbs_certificate_bytes,
                                    ec.ECDSA(ota_cert.signature_hash_algorithm))
        registration = http_json(
            manufacturing + '/api/manufacturing/register-device', ctx=ctx,
            data=json.dumps({'device_certificate_pem': cert_pem.decode()}).encode(),
            headers={'Content-Type': 'application/json'}, method='POST', expected=200)
        if registration.get('status') not in ('REGISTERED', 'REPLACED', 'UNCHANGED'):
            fail(f'device registration failed: {registration}')
        if registration.get('device_id') != device_id:
            fail(f'registration returned wrong device: {registration}')
        passed('OTA accepted only the CA-signed public device certificate')

        service = mqtt_service()
        esp = VirtualEsp(base_topic, topic_device, device_id, device_key, ota_cert, service)

        step('run real H -> A -> R -> P provisioning over MQTT transport')
        counter = int(time.time())
        hsig = raw64(device_key.sign(f'H|{device_id}|{counter}'.encode('ascii'), ec.ECDSA(hashes.SHA256())))
        esp.send(f'H|{counter}|{b64u(hsig)}')
        awire = esp.expect('A|')
        apart = awire.split('|')
        if len(apart) != 3:
            fail(f'malformed A: {awire}')
        random8 = b64ud(apart[1])
        ota_cert.public_key().verify(
            der64(b64ud(apart[2])), f'A|{device_id}|{counter}|'.encode('ascii') + random8,
            ec.ECDSA(hashes.SHA256()))
        passed('A challenge signature verified with Root-CA-signed OTA certificate')

        rcanonical = f'R|{device_id}|{counter}|'.encode('ascii') + random8 + b'|OK'
        rsig = raw64(device_key.sign(rcanonical, ec.ECDSA(hashes.SHA256())))
        esp.send('R|' + b64u(rsig))
        pwire = esp.expect('P|')
        session_key, provisioning = verify_and_decrypt_provisioning(
            pwire, device_key, ota_cert, device_id, counter, random8)
        if provisioning['ssid'] != str(options.get('wifi_ssid') or ''):
            fail(f'provisioned SSID mismatch: {provisioning}')
        if provisioning['host'] != str(options.get('ota_host') or '') or provisioning['port'] != int(options.get('ota_port') or 8443):
            fail(f'provisioned OTA address mismatch: {provisioning}')
        passed(f"P decrypted: ssid={provisioning['ssid']} ota={provisioning['host']}:{provisioning['port']}")
        esp.send('T|0|42')
        ctxrow = wait_db(
            'SELECT provision_counter FROM device_certificates WHERE device_id=?', (device_id,),
            lambda r: int(r.get('provision_counter') or 0) == counter)
        if not ctxrow:
            fail('OTA did not persist successful provisioning context')
        passed('provisioning completion persisted in OTA database')

        step('publish a new signed synthetic BIN through the production build API')
        blob = b'JARZEM-OTA-E2E\0' + os.urandom(128 * 1024)
        metadata = {
            'ota_ecosystem': ecosystem, 'device_model': model,
            'product_role': product_role, 'firmware_product': firmware_product,
            'hardware_revision': hardware, 'chip_family': 'ESP32-C6', 'flash_size': '16MB',
            'firmware_channel': 'stable', 'firmware_version': version,
            'secure_version': 0, 'active': True,
        }
        firmware_sha = publish_firmware(ota_https, ctx, cert_pem, device_key, filename, blob, metadata)
        passed(f'BIN signature/certificate/SHA accepted sha256={firmware_sha[:12]}')

        step('publish build-matched signed MJS and require Zigbee2MQTT hot-load')
        converter_name, converter_sha = publish_converter(ota_https, ctx, cert_pem, device_key, project, version)
        passed(f'MJS signed and hot-loaded file={converter_name} sha256={converter_sha[:12]}')

        # Force the real running ingress server to scan the just-published BIN
        # and allocate its normal three-character alias.
        urllib.request.urlopen('http://127.0.0.1:8099/', timeout=30).read()
        alias = wait_db('SELECT code FROM firmware_alias WHERE filename=?', (filename,), lambda r: bool(r.get('code')))
        if not alias:
            fail('firmware alias was not created by running OTA server')
        code = alias['code']

        step('create a temporary normal HA MQTT device and dispatch CHECK through real ingress /send')
        try:
            admin_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f'ota-e2e-discovery-{compact[-6:]}')
        except (AttributeError, TypeError):
            admin_client = mqtt.Client(client_id=f'ota-e2e-discovery-{compact[-6:]}')
        if service['username']:
            admin_client.username_pw_set(service['username'], service['password'])
        admin_client.connect(service['host'], service['port'], 30); admin_client.loop_start()
        publish_discovery(admin_client, compact, True); discovery_created = True
        wait_ha_registry(compact, True)
        passed('virtual ESP appeared in normal Home Assistant MQTT device registry')
        trigger_ingress_dispatch(filename, device_id)
        cwire = esp.expect('C|', timeout=20)
        passed('normal OTA ingress generated and transmitted secure CHECK')

        step('verify CHECK MAC and independently derive the same one-time download token')
        parts = cwire.split('|')
        if len(parts) != 5 or parts[1] != version or parts[2] != code:
            fail(f'CHECK fields mismatch: {cwire}')
        grant_random = b64ud(parts[3]); received_mac = b64ud(parts[4])
        check_key = hmac.new(session_key, CHECK_KEY_DOMAIN, hashlib.sha256).digest()
        expected_mac = hmac.new(
            check_key, CHECK_MAC_DOMAIN + version.encode() + b'|' + code.encode() + b'|' + grant_random,
            hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(received_mac, expected_mac):
            fail('CHECK MAC verification failed')
        tampered = bytearray(received_mac); tampered[0] ^= 1
        if hmac.compare_digest(bytes(tampered), expected_mac):
            fail('tampered CHECK unexpectedly verified')
        token_key = hmac.new(session_key, TOKEN_KEY_DOMAIN, hashlib.sha256).digest()
        token_raw = hmac.new(
            token_key,
            TOKEN_DOMAIN + device_id.encode() + b'|' + version.encode() + b'|' + code.encode() + b'|' + grant_random,
            hashlib.sha256).digest()[:12]
        token = b64u(token_raw)
        passed('CHECK authenticates; modified CHECK does not; download token derived locally')

        firmware_url = ota_https + '/' + code
        step('prove BIN cannot be downloaded by URL alone or with a fake token')
        status, _, _ = download(firmware_url, ctx, {'X-Device-ID': device_id}, 401)
        if status != 401: fail(f'URL-only download returned {status}')
        status, _, _ = download(firmware_url, ctx, {'X-Device-ID': device_id, 'Authorization': 'Bearer AAAAAAAAAAAAAAAA'}, 401)
        if status != 401: fail(f'fake-token download returned {status}')
        passed('unauthorized and fake-token downloads rejected')

        step('download the BIN with the derived one-time token and verify SHA')
        status, downloaded, headers = download(
            firmware_url, ctx, {'X-Device-ID': device_id, 'Authorization': 'Bearer ' + token}, 200)
        if status != 200 or downloaded != blob:
            fail(f'authorized firmware bytes mismatch status={status} bytes={len(downloaded)}')
        if hashlib.sha256(downloaded).hexdigest() != firmware_sha:
            fail('downloaded SHA mismatch')
        if str(headers.get('X-Firmware-SHA256') or '').lower() != firmware_sha:
            fail('server X-Firmware-SHA256 header mismatch')
        state = wait_db(
            'SELECT * FROM device_firmware_status WHERE device_id=? AND firmware_sha256=?',
            (device_id, firmware_sha), lambda r: r.get('state') == 'DOWNLOAD_COMPLETED')
        if not state:
            fail('database did not reach DOWNLOAD_COMPLETED')
        passed('HTTPS download completed and server persisted DOWNLOAD_COMPLETED')

        step('prove the one-time token cannot download the BIN twice')
        status, _, _ = download(
            firmware_url, ctx, {'X-Device-ID': device_id, 'Authorization': 'Bearer ' + token}, 401)
        if status != 401: fail(f'reused token returned HTTP {status}')
        passed('download grant is one-time')

        step('send ESP F confirmation only after verified/write-complete download')
        esp.send('F|' + b64u(grant_random))
        confirmed = wait_db(
            'SELECT * FROM device_firmware_status WHERE device_id=? AND firmware_sha256=?',
            (device_id, firmware_sha), lambda r: r.get('state') == 'DEVICE_CONFIRMED')
        if not confirmed:
            fail('database did not reach DEVICE_CONFIRMED after F')
        passed('OTA accepted F only after the completed HTTPS transfer')

        step('verify persistent lifecycle tables contain every major block')
        with db_connect() as conn:
            artifact = conn.execute(
                'SELECT * FROM artifact_publications WHERE firmware_version=? AND publisher_device_id=?',
                (version, device_id)).fetchone()
            prov = conn.execute(
                'SELECT * FROM provisioning_attempts WHERE device_id=? AND counter=?',
                (device_id, counter)).fetchone()
            fwstate = conn.execute(
                'SELECT * FROM device_firmware_status WHERE device_id=? AND firmware_sha256=?',
                (device_id, firmware_sha)).fetchone()
        if not artifact or not artifact['bin_verified'] or not artifact['mjs_verified'] or not artifact['z2m_loaded']:
            fail(f'artifact lifecycle incomplete: {dict(artifact) if artifact else None}')
        if not prov or prov['state'] != 'COMPLETED':
            fail(f'provisioning lifecycle incomplete: {dict(prov) if prov else None}')
        if not fwstate or fwstate['state'] != 'DEVICE_CONFIRMED':
            fail(f'ESP x firmware lifecycle incomplete: {dict(fwstate) if fwstate else None}')
        passed('artifact, provisioning and ESP x BIN lifecycle tables are complete')

        step('collect OTA, Zigbee2MQTT, Mosquitto and exact MQTT transcript logs')
        ota_log, logs = addon_logs()
        (result_dir / 'mqtt_transcript.log').write_text('\n'.join(esp.transcript) + '\n', encoding='utf-8')
        for name, text in logs.items():
            (result_dir / f'{name}.log').write_text(text, encoding='utf-8')
        required = [
            f'H CA/certificate/ECDSA/counter OK device_id={device_id}',
            f'provisioning completed device_id={device_id}',
            f'Firmware publish accepted device_id={device_id}',
            f'file={converter_name} build={version}',
            f'OTA download started device_id={device_id}',
            f'OTA firmware confirmed by ESP device_id={device_id}',
        ]
        missing = [marker for marker in required if marker not in ota_log]
        if missing:
            fail('OTA supervisor log is missing expected production events: ' + '; '.join(missing))
        transcript = '\n'.join(esp.transcript)
        for kind in ('ESP -> OTA H|', 'OTA -> ESP A|', 'ESP -> OTA R|', 'OTA -> ESP P|', 'OTA -> ESP C|', 'ESP -> OTA F|'):
            if kind not in transcript:
                fail(f'MQTT transcript missing {kind}')
        passed(f'logs verified and stored in {result_dir}')

        success = True
        say('\nALL OTA E2E TESTS PASSED')
    finally:
        if admin_client is not None:
            try:
                if discovery_created:
                    publish_discovery(admin_client, compact, False)
                admin_client.disconnect(); admin_client.loop_stop()
            except Exception as exc:
                say(f'WARN cleanup HA discovery: {exc}')
        if esp is not None:
            esp.stop()
        try:
            service = mqtt_service()
            mqtt_request(
                service,
                f'{base_topic}/bridge/request/converter/remove',
                f'{base_topic}/bridge/response/converter/remove',
                {'name': converter_name}, timeout=10)
        except Exception as exc:
            say(f'WARN cleanup converter {converter_name}: {exc}')
        if success:
            try:
                cleanup_db(device_id, filename, version, locals().get('firmware_sha', ''))
                passed('successful test artifacts cleaned from OTA/HA/Zigbee2MQTT; result logs retained')
            except Exception as exc:
                say(f'WARN cleanup database/files: {exc}')
        else:
            say(f'FAILED run evidence intentionally retained in {result_dir} and OTA database for diagnosis')


if __name__ == '__main__':
    main()
