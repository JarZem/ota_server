from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import os
import struct
import zlib
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SESSION_DOMAIN = b"JaroslavZemanESP-SESSION-v1"
CHALLENGE_DOMAIN = b"JaroslavZemanESP-CHALLENGE-v1"
RESPONSE_DOMAIN = b"JaroslavZemanESP-CHALLENGE-OK-v1"
PROVISION_KEY_DOMAIN = b"JaroslavZemanESP-PROVISION-KEY-v1"
PROVISION_NONCE_DOMAIN = b"JaroslavZemanESP-PROVISION-NONCE-v1"
PROVISION_AAD_DOMAIN = b"JaroslavZemanESP-PROVISION-AAD-v1"

OTA_SERVER_KEY_PATH = "/share/ota_server/cert/ota_server_private.pem"
OTA_SERVER_CERT_PATH = "/share/ota_server/cert/ota_server_cert.pem"
ROOT_CA_CERT_PATH = "/share/ota_server/cert/root_ca_cert.pem"

SECURITY_MAP = {
    "OPEN": 0,
    "WPA2": 1,
    "WPA3": 2,
    "WPA2_WPA3": 3,
}


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * ((-len(value)) % 4))


def _verify_server_certificate_and_key():
    with open(OTA_SERVER_CERT_PATH, "rb") as f:
        server_cert = x509.load_pem_x509_certificate(f.read())
    with open(ROOT_CA_CERT_PATH, "rb") as f:
        root_cert = x509.load_pem_x509_certificate(f.read())
    with open(OTA_SERVER_KEY_PATH, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise ValueError("OTA server private key is not EC")
    if not isinstance(private_key.curve, ec.SECP256R1):
        raise ValueError("OTA server private key is not P-256")
    if private_key.public_key().public_numbers() != server_cert.public_key().public_numbers():
        raise ValueError("OTA server private key does not match OTA certificate")

    # Verify direct server-cert -> offline-root signature. The project currently
    # has a single offline root and no intermediate CA.
    root_public = root_cert.public_key()
    if not isinstance(root_public, ec.EllipticCurvePublicKey):
        raise ValueError("root CA public key is not EC")
    root_public.verify(
        server_cert.signature,
        server_cert.tbs_certificate_bytes,
        ec.ECDSA(server_cert.signature_hash_algorithm),
    )
    if server_cert.issuer != root_cert.subject:
        raise ValueError("OTA server certificate issuer does not match root CA subject")
    return server_cert, private_key


_SERVER_CERT, _SERVER_PRIVATE = _verify_server_certificate_and_key()


def derive_session_key(device_public_key_der: bytes, device_id: str, counter: int, random16: bytes) -> bytes:
    device_public = serialization.load_der_public_key(device_public_key_der)
    if not isinstance(device_public, ec.EllipticCurvePublicKey):
        raise ValueError("device public key is not EC")
    if not isinstance(device_public.curve, ec.SECP256R1):
        raise ValueError("device public key is not P-256")
    shared = _SERVER_PRIVATE.exchange(ec.ECDH(), device_public)
    material = SESSION_DOMAIN + device_id.encode("ascii") + struct.pack(">Q", counter) + random16
    return hmac.new(shared, material, hashlib.sha256).digest()


def auth_material(domain: bytes, device_id: str, counter: int, random16: bytes, crc32: int) -> bytes:
    return domain + device_id.encode("ascii") + struct.pack(">Q", counter) + random16 + struct.pack(">I", crc32)


@dataclass
class SecureSession:
    device_id: str
    topic_device: str
    counter: int
    random16: bytes
    crc32: int
    session_key: bytes
    challenge_wire: str
    expected_response_wire: str
    created_mono: float


def build_challenge(device_id: str, topic_device: str, counter: int,
                    device_public_key_der: bytes, created_mono: float) -> SecureSession:
    random16 = os.urandom(16)
    crc = zlib.crc32(struct.pack(">Q", counter) + random16) & 0xFFFFFFFF
    key = derive_session_key(device_public_key_der, device_id, counter, random16)
    challenge_mac = hmac.new(
        key,
        auth_material(CHALLENGE_DOMAIN, device_id, counter, random16, crc),
        hashlib.sha256,
    ).digest()
    response_mac = hmac.new(
        key,
        auth_material(RESPONSE_DOMAIN, device_id, counter, random16, crc),
        hashlib.sha256,
    ).digest()
    challenge_wire = f"A1|{counter}|{b64u(random16)}|{crc:08x}|{b64u(challenge_mac)}"
    expected_response = f"R1|{counter}|{b64u(response_mac)}"
    if len(challenge_wire.encode("utf-8")) > 100:
        raise ValueError(f"challenge exceeds 100-byte Zigbee wire limit: {len(challenge_wire)}")
    return SecureSession(
        device_id=device_id,
        topic_device=topic_device,
        counter=counter,
        random16=random16,
        crc32=crc,
        session_key=key,
        challenge_wire=challenge_wire,
        expected_response_wire=expected_response,
        created_mono=created_mono,
    )


def verify_response(session: SecureSession, payload: str) -> bool:
    return hmac.compare_digest(session.expected_response_wire, payload)


def encode_provision_plain(ssid: str, password: str, host: str, port: int,
                           security: str, channel: int) -> bytes:
    ssid_b = ssid.encode("utf-8")
    password_b = password.encode("utf-8")
    if not 1 <= len(ssid_b) <= 32:
        raise ValueError("SSID must encode to 1..32 bytes")
    if len(password_b) > 64:
        raise ValueError("WiFi password must encode to <=64 bytes")
    if not 0 <= channel <= 14:
        raise ValueError("WiFi channel must be 0..14")
    if not 1 <= int(port) <= 65535:
        raise ValueError("OTA port invalid")
    security_code = SECURITY_MAP.get(str(security).upper())
    if security_code is None:
        raise ValueError(f"unsupported WiFi security={security}")

    try:
        ip = ipaddress.ip_address(host)
        if ip.version != 4:
            raise ValueError
        host_type = 1
        host_b = ip.packed
    except ValueError:
        host_type = 0
        host_b = host.encode("utf-8")
        if not 1 <= len(host_b) <= 64:
            raise ValueError("OTA host must encode to 1..64 bytes")

    return bytes([
        1,
        security_code,
        channel,
        len(ssid_b),
        len(password_b),
        host_type,
        len(host_b),
    ]) + ssid_b + password_b + host_b + struct.pack(">H", int(port))


def build_provisioning(session: SecureSession, *, ssid: str, password: str,
                       host: str, port: int, security: str, channel: int) -> str:
    key = hmac.new(session.session_key, PROVISION_KEY_DOMAIN, hashlib.sha256).digest()
    nonce_material = PROVISION_NONCE_DOMAIN + struct.pack(">Q", session.counter) + session.random16
    nonce = hmac.new(session.session_key, nonce_material, hashlib.sha256).digest()[:12]
    aad = (
        PROVISION_AAD_DOMAIN
        + session.device_id.encode("ascii")
        + struct.pack(">Q", session.counter)
        + session.random16
        + struct.pack(">I", session.crc32)
    )
    plain = encode_provision_plain(ssid, password, host, port, security, channel)
    encrypted = AESGCM(key).encrypt(nonce, plain, aad)
    wire = "P1|" + b64u(encrypted)
    if len(wire.encode("utf-8")) > 100:
        raise ValueError(
            f"secure provisioning is {len(wire.encode('utf-8'))} bytes; exceeds proven 100-byte single-frame limit"
        )
    return wire
