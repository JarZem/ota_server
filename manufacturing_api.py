from __future__ import annotations

import http.server
import json
import ssl
from pathlib import Path
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from database import assert_schema_current, database_summary
from device_registry import list_registered_devices, register_device_certificate

PORT = 8451
CERT_DIR = Path('/share/ota_server/cert')
OTA_CERT_PATH = CERT_DIR / 'ota_server_cert.pem'
OTA_KEY_PATH = CERT_DIR / 'ota_server_private.pem'
ROOT_CA_PATH = CERT_DIR / 'root_ca_cert.pem'
MAX_REGISTER_BODY = 16 * 1024


def public_key_pem_from_certificate(cert_path: Path) -> bytes:
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    return cert.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


class ManufacturingHandler(http.server.BaseHTTPRequestHandler):
    server_version = 'OTA-Manufacturing/4'

    def log_message(self, fmt, *args):
        print(f'MANUFACTURING {self.address_string()} - {fmt % args}', flush=True)

    def send_bytes(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status: int, payload: dict) -> None:
        self.send_bytes(status, json.dumps(payload, separators=(',', ':')).encode('utf-8'), 'application/json')

    def do_GET(self):
        path = urlparse(self.path).path
        if path == '/api/manufacturing/root-ca.pem':
            return self.send_bytes(200, ROOT_CA_PATH.read_bytes(), 'application/x-pem-file')
        if path == '/api/manufacturing/ota-server.pem':
            return self.send_bytes(200, OTA_CERT_PATH.read_bytes(), 'application/x-pem-file')
        if path == '/api/manufacturing/ota-public.pem':
            return self.send_bytes(200, public_key_pem_from_certificate(OTA_CERT_PATH), 'application/x-pem-file')
        if path == '/api/manufacturing/health':
            return self.send_json(200, {'status': 'OK', 'database': 'mysql'})
        if path == '/api/manufacturing/devices':
            devices = list_registered_devices()
            return self.send_json(200, {'status': 'OK', 'count': len(devices), 'devices': devices})
        self.send_error(404, 'Not found')

    def do_POST(self):
        path = urlparse(self.path).path
        if path != '/api/manufacturing/register-device':
            self.send_error(404, 'Not found')
            return

        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_REGISTER_BODY:
            self.send_json(400, {'status': 'ERROR', 'error': 'invalid_request_size'})
            return

        try:
            request = json.loads(self.rfile.read(length).decode('utf-8'))
            certificate_pem = str(request['device_certificate_pem']).encode('ascii')
            record = register_device_certificate(certificate_pem)
        except Exception as exc:
            print(f'MANUFACTURING certificate verification FAILED reason={exc}', flush=True)
            self.send_json(400, {'status': 'ERROR', 'error': str(exc)})
            return

        print(
            'MANUFACTURING certificate verification OK '
            f"device_id={record['device_id']} root_ca_signature=OK validity=OK "
            f"ca=FALSE digital_signature=OK eku=clientAuth key=P-256 role=device "
            f"identity=OK cert_sha256={record['certificate_fingerprint']}",
            flush=True,
        )
        action = record['registration_action']
        print(
            f'MANUFACTURING device {action} '
            f"device_id={record['device_id']} ecosystem={record['ecosystem']} "
            f"group={record['device_group']} model={record['device_model']} "
            f"role={record['product_role']} hw={record['hardware_revision']} "
            f"chip={record['chip_family']} flash={record['flash_size']}",
            flush=True,
        )
        self.send_json(200, {
            'status': action,
            'device_id': record['device_id'],
            'certificate_fingerprint': record['certificate_fingerprint'],
            'device_group': record['device_group'],
            'device_model': record['device_model'],
            'product_role': record['product_role'],
            'hardware_revision': record['hardware_revision'],
            'chip_family': record['chip_family'],
            'flash_size': record['flash_size'],
            'ecosystem': record['ecosystem'],
        })


def main() -> None:
    for path in (OTA_CERT_PATH, OTA_KEY_PATH, ROOT_CA_PATH):
        if not path.is_file():
            raise RuntimeError(f'missing manufacturing credential: {path}')

    assert_schema_current()
    print(f'Manufacturing database ready: {database_summary()}', flush=True)

    server = http.server.ThreadingHTTPServer(('0.0.0.0', PORT), ManufacturingHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(OTA_CERT_PATH), str(OTA_KEY_PATH))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f'Manufacturing HTTPS API running on port {PORT}', flush=True)
    print('Manufacturing bootstrap, registry read and CA-validated device registration endpoints are available', flush=True)
    server.serve_forever()


if __name__ == '__main__':
    main()
