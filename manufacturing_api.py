from __future__ import annotations

import hmac
import http.server
import json
import os
import ssl
from pathlib import Path
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from device_registry import init_registry, register_device_certificate

PORT = 8451
CERT_DIR = Path('/share/ota_server/cert')
OTA_CERT_PATH = CERT_DIR / 'ota_server_cert.pem'
OTA_KEY_PATH = CERT_DIR / 'ota_server_private.pem'
ROOT_CA_PATH = CERT_DIR / 'root_ca_cert.pem'
MANUFACTURING_TOKEN_PATH = CERT_DIR / 'manufacturing_token.txt'
MAX_REGISTER_BODY = 16 * 1024


def load_token() -> str:
    token = MANUFACTURING_TOKEN_PATH.read_text(encoding='utf-8').strip()
    if len(token) < 32:
        raise RuntimeError('manufacturing token is missing or too short')
    return token


def public_key_pem_from_certificate(cert_path: Path) -> bytes:
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    return cert.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


class ManufacturingHandler(http.server.BaseHTTPRequestHandler):
    server_version = 'OTA-Manufacturing/1'

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

    def authorized(self) -> bool:
        header = self.headers.get('Authorization', '')
        expected = f'Bearer {load_token()}'
        return hmac.compare_digest(header, expected)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == '/api/manufacturing/root-ca.pem':
            return self.send_bytes(200, ROOT_CA_PATH.read_bytes(), 'application/x-pem-file')
        if path == '/api/manufacturing/ota-server.pem':
            return self.send_bytes(200, OTA_CERT_PATH.read_bytes(), 'application/x-pem-file')
        if path == '/api/manufacturing/ota-public.pem':
            return self.send_bytes(200, public_key_pem_from_certificate(OTA_CERT_PATH), 'application/x-pem-file')
        if path == '/api/manufacturing/health':
            return self.send_json(200, {'status': 'OK'})
        self.send_error(404, 'Not found')

    def do_POST(self):
        path = urlparse(self.path).path
        if path != '/api/manufacturing/register-device':
            self.send_error(404, 'Not found')
            return
        if not self.authorized():
            self.send_json(401, {'status': 'ERROR', 'error': 'unauthorized'})
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
            print(f'MANUFACTURING device certificate rejected: {exc}', flush=True)
            self.send_json(400, {'status': 'ERROR', 'error': str(exc)})
            return

        print(
            'MANUFACTURING device registered '
            f"device_id={record['device_id']} ecosystem={record['ecosystem']} "
            f"group={record['device_group']} model={record['device_model']} "
            f"role={record['product_role']} hw={record['hardware_revision']} "
            f"chip={record['chip_family']} flash={record['flash_size']} "
            f"cert_sha256={record['certificate_fingerprint']}",
            flush=True,
        )
        self.send_json(200, {
            'status': 'REGISTERED',
            'device_id': record['device_id'],
            'certificate_fingerprint': record['certificate_fingerprint'],
            'device_group': record['device_group'],
            'device_model': record['device_model'],
            'product_role': record['product_role'],
        })


def main() -> None:
    for path in (OTA_CERT_PATH, OTA_KEY_PATH, ROOT_CA_PATH, MANUFACTURING_TOKEN_PATH):
        if not path.is_file():
            raise RuntimeError(f'missing manufacturing credential: {path}')

    init_registry()
    server = http.server.ThreadingHTTPServer(('0.0.0.0', PORT), ManufacturingHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(OTA_CERT_PATH), str(OTA_KEY_PATH))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f'Manufacturing HTTPS API running on port {PORT}', flush=True)
    print('Manufacturing public bootstrap endpoints are available; device registration requires bearer token', flush=True)
    server.serve_forever()


if __name__ == '__main__':
    main()
