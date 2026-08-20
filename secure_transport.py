from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import os
import struct
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KDF_DOMAIN = b"JaroslavZemanESP|provisioning-v1|"
NONCE_DOMAIN = b"JaroslavZemanESP|provisioning-nonce-v1|"

OTA_SERVER_KEY_PATH = "/share/ota_server/cert/ota_server_private.pem"
OTA_SERVER_CERT_PATH = "/share/ota_server/cert/ota_server_cert.pem"
ROOT_CA_CERT_PATH = "/share/ota_server/cert/root_ca_cert.pem"

SECURITY_MAP = {"OPEN": 0, "WPA2": 1, "WPA3": 2, "WPA2_WPA3": 3}


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * ((-len(value)) % 4))


def raw64_from_der(signature_der: bytes) -> bytes:
    r, s = decode_dss_signature(signature_der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def der_from_raw64(signature: bytes) -> bytes:
    if len(signature) != 64:
        raise ValueError("P-256 raw signature must be 64 bytes")
    return encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))


def _load_server_identity():
    server_cert = x509.load_pem_x509_certificate(open(OTA_SERVER_CERT_PATH, "rb").read())
    root_cert = x509.load_pem_x509_certificate(open(ROOT_CA_CERT_PATH, "rb").read())
    private_key = serialization.load_pem_private_key(open(OTA_SERVER_KEY_PATH, "rb").read(), password=None)
    if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(private_key.curve, ec.SECP256R1):
        raise ValueError("OTA server private key must be P-256")
    if private_key.public_key().public_numbers() != server_cert.public_key().public_numbers():
        raise ValueError("OTA server private key does not match certificate")
    root_public = root_cert.public_key()
    if not isinstance(root_public, ec.EllipticCurvePublicKey):
        raise ValueError("root CA public key is not EC")
    root_public.verify(server_cert.signature, server_cert.tbs_certificate_bytes,
                       ec.ECDSA(server_cert.signature_hash_algorithm))
    if server_cert.issuer != root_cert.subject:
        raise ValueError("OTA certificate issuer mismatch")
    return server_cert, private_key


_SERVER_CERT, _SERVER_PRIVATE = _load_server_identity()


def challenge_canonical(device_id: str, counter: int, random8: bytes) -> bytes:
    return f"A|{device_id}|{counter}|".encode("ascii") + random8


def response_canonical(device_id: str, counter: int, random8: bytes) -> bytes:
    return f"R|{device_id}|{counter}|".encode("ascii") + random8 + b"|OK"


def derive_session_key(device_public_key_der: bytes, device_id: str, counter: int, random8: bytes) -> bytes:
    device_public = serialization.load_der_public_key(device_public_key_der)
    if not isinstance(device_public, ec.EllipticCurvePublicKey) or not isinstance(device_public.curve, ec.SECP256R1):
        raise ValueError("device public key must be P-256")
    shared = _SERVER_PRIVATE.exchange(ec.ECDH(), device_public)
    material = KDF_DOMAIN + device_id.encode("ascii") + struct.pack(">Q", counter) + random8
    return hmac.new(shared, material, hashlib.sha256).digest()


@dataclass
class SecureSession:
    device_id: str
    topic_device: str
    counter: int
    random8: bytes
    device_public_key_der: bytes
    session_key: bytes
    challenge_wire: str
    created_mono: float
    state: str = "WAIT_RESPONSE"


def build_challenge(device_id: str, topic_device: str, counter: int,
                    device_public_key_der: bytes, created_mono: float) -> SecureSession:
    random8 = os.urandom(8)
    signature = raw64_from_der(_SERVER_PRIVATE.sign(
        challenge_canonical(device_id, counter, random8), ec.ECDSA(hashes.SHA256())))
    wire = f"A|{b64u(random8)}|{b64u(signature)}"
    if len(wire.encode("utf-8")) > 100:
        raise ValueError(f"A exceeds 100-byte Zigbee limit: {len(wire)}")
    return SecureSession(
        device_id=device_id,
        topic_device=topic_device,
        counter=counter,
        random8=random8,
        device_public_key_der=device_public_key_der,
        session_key=derive_session_key(device_public_key_der, device_id, counter, random8),
        challenge_wire=wire,
        created_mono=created_mono,
    )


def verify_response(session: SecureSession, payload: str) -> bool:
    if session.state != "WAIT_RESPONSE" or not payload.startswith("R|"):
        return False
    parts = payload.split("|")
    if len(parts) != 2:
        return False
    try:
        raw_sig = b64u_decode(parts[1])
        public = serialization.load_der_public_key(session.device_public_key_der)
        public.verify(der_from_raw64(raw_sig),
                      response_canonical(session.device_id, session.counter, session.random8),
                      ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def encode_provision_plain(ssid: str, password: str, host: str, port: int,
                           security: str, channel: int) -> bytes:
    ssid_b = ssid.encode("utf-8")
    password_b = password.encode("utf-8")
    if not 1 <= len(ssid_b) <= 32 or len(password_b) > 64:
        raise ValueError("SSID/password length invalid")
    if not 0 <= channel <= 14 or not 1 <= int(port) <= 65535:
        raise ValueError("channel/port invalid")
    security_code = SECURITY_MAP.get(str(security).upper())
    if security_code is None:
        raise ValueError(f"unsupported WiFi security={security}")
    try:
        ip = ipaddress.ip_address(host)
        if ip.version != 4:
            raise ValueError
        host_type, host_b = 1, ip.packed
    except ValueError:
        host_type, host_b = 0, host.encode("utf-8")
        if not 1 <= len(host_b) <= 64:
            raise ValueError("OTA host length invalid")
    return bytes([1, security_code, channel, len(ssid_b), len(password_b), host_type, len(host_b)]) + \
        ssid_b + password_b + host_b + struct.pack(">H", int(port))


def build_provisioning(session: SecureSession, *, ssid: str, password: str,
                       host: str, port: int, security: str, channel: int) -> str:
    nonce_material = NONCE_DOMAIN + session.device_id.encode("ascii") + \
        struct.pack(">Q", session.counter) + session.random8
    nonce = hmac.new(session.session_key, nonce_material, hashlib.sha256).digest()[:12]
    aad = f"P|{session.device_id}|{session.counter}|".encode("ascii") + session.random8
    encrypted = AESGCM(session.session_key).encrypt(
        nonce, encode_provision_plain(ssid, password, host, port, security, channel), aad)
    wire = "P|" + b64u(encrypted)
    if len(wire.encode("utf-8")) > 100:
        raise ValueError(f"P is {len(wire.encode('utf-8'))} bytes; exceeds 100-byte Zigbee limit")
    return wire
