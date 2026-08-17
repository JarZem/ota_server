from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Dict, Optional

DEVICE_ENROLLMENT_CANONICAL_DOMAIN = b"JaroslavZemanESP-DEVICE-ENROLL-v1"
DEVICE_AUTH_SECRET_DOMAIN = b"JaroslavZemanESP-DEVICE-AUTH-KEY-v1"
DEVICE_AUTH_CHALLENGE_LEN = 32
DEVICE_ENC_PUBLIC_KEY_LEN = 65
DEVICE_AUTH_HMAC_LEN = 32
DEVICE_ENROLLMENT_PROTOCOL_VERSION = 1


def _u8(value: int) -> bytes:
    return value.to_bytes(1, "big")


def _u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def _u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def _len_bytes(value: bytes) -> bytes:
    if len(value) > 0xFFFF:
        raise ValueError("canonical field too large")
    return _u16(len(value)) + value


def _field(value: str | bytes) -> bytes:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return _len_bytes(value)


def normalize_device_id(device_id: str) -> str:
    compact = device_id.strip().lower().replace("0x", "").replace(":", "")
    if len(compact) != 16 or any(ch not in "0123456789abcdef" for ch in compact):
        raise ValueError("DEVICE_ID must be an 8-byte IEEE address")
    return ":".join(compact[i : i + 2] for i in range(0, 16, 2))


def canonical_auth_secret_message(device_id: str) -> bytes:
    return _field(DEVICE_AUTH_SECRET_DOMAIN) + _field(normalize_device_id(device_id))


def derive_device_auth_secret(master_secret: bytes, device_id: str) -> bytes:
    if len(master_secret) < 32:
        raise ValueError("server device master secret must have at least 32 bytes")
    return hmac.new(master_secret, canonical_auth_secret_message(device_id), hashlib.sha256).digest()


def canonical_enrollment(fields: dict) -> bytes:
    public_key = bytes.fromhex(fields["device_enc_public_key"])
    challenge = bytes.fromhex(fields["challenge"])
    if len(public_key) != DEVICE_ENC_PUBLIC_KEY_LEN or public_key[0] != 0x04:
        raise ValueError("DEVICE_ENC_PUBLIC_KEY must be uncompressed P-256 public key")
    if len(challenge) != DEVICE_AUTH_CHALLENGE_LEN:
        raise ValueError("challenge must be 32 bytes")

    parts = [
        _field(DEVICE_ENROLLMENT_CANONICAL_DOMAIN),
        _u8(int(fields["protocol_version"])),
        _field(str(fields["message_id"])),
        _len_bytes(challenge),
        _u64(int(fields["enrollment_counter"])),
        _field(normalize_device_id(fields["device_id"])),
        _field(normalize_device_id(fields["zigbee_ieee"])),
        _field(str(fields["ota_ecosystem"])),
        _field(str(fields["device_model"])),
        _field(str(fields["product_role"])),
        _field(str(fields["hardware_revision"])),
        _field(str(fields["chip_family"])),
        _field(str(fields["flash_size"])),
        _field(str(fields["firmware_version"])),
        _field(str(fields["firmware_channel"])),
        _u16(int(fields["device_enc_key_id"])),
        _len_bytes(public_key),
    ]
    return b"".join(parts)


def enrollment_hmac(device_auth_secret: bytes, fields: dict) -> bytes:
    return hmac.new(device_auth_secret, canonical_enrollment(fields), hashlib.sha256).digest()


def public_key_fingerprint_hex(public_key_hex: str) -> str:
    public_key = bytes.fromhex(public_key_hex)
    if len(public_key) != DEVICE_ENC_PUBLIC_KEY_LEN or public_key[0] != 0x04:
        raise ValueError("DEVICE_ENC_PUBLIC_KEY must be uncompressed P-256 public key")
    return hashlib.sha256(public_key).hexdigest()


@dataclass
class Challenge:
    device_id: str
    message_id: str
    challenge: bytes
    expires_at: float


class ChallengeStore:
    def __init__(self, ttl_seconds: int = 60) -> None:
        self.ttl_seconds = ttl_seconds
        self._items: Dict[str, Challenge] = {}

    def create(self, device_id: str) -> Challenge:
        normalized = normalize_device_id(device_id)
        challenge = Challenge(
            device_id=normalized,
            message_id=secrets.token_hex(8),
            challenge=secrets.token_bytes(DEVICE_AUTH_CHALLENGE_LEN),
            expires_at=time.time() + self.ttl_seconds,
        )
        self._items[challenge.message_id] = challenge
        return challenge

    def consume(self, device_id: str, message_id: str, challenge_hex: str) -> Optional[Challenge]:
        challenge = self._items.pop(message_id, None)
        if challenge is None:
            return None
        if challenge.expires_at < time.time():
            return None
        if challenge.device_id != normalize_device_id(device_id):
            return None
        try:
            received = bytes.fromhex(challenge_hex)
        except ValueError:
            return None
        if not hmac.compare_digest(challenge.challenge, received):
            return None
        return challenge


def fixed_test_vector() -> tuple[bytes, dict, str, str, str]:
    master = bytes.fromhex("10" * 32)
    public_key = "04" + ("21" * 32) + ("42" * 32)
    fields = {
        "protocol_version": 1,
        "message_id": "msg-0001",
        "challenge": "33" * 32,
        "enrollment_counter": 7,
        "device_id": "20:6e:f1:ff:fe:0d:45:94",
        "zigbee_ieee": "20:6e:f1:ff:fe:0d:45:94",
        "ota_ecosystem": "JaroslavZemanESP",
        "device_model": "remotecontrol7-encoder",
        "product_role": "six-strip-cct-led-controller",
        "hardware_revision": "ESP32-C6",
        "chip_family": "ESP32-C6",
        "flash_size": "16MB",
        "firmware_version": "1",
        "firmware_channel": "stable",
        "device_enc_key_id": 1,
        "device_enc_public_key": public_key,
    }
    secret = derive_device_auth_secret(master, fields["device_id"])
    canonical_sha = hashlib.sha256(canonical_enrollment(fields)).hexdigest()
    auth_hmac = enrollment_hmac(secret, fields).hex()
    return master, fields, secret.hex(), canonical_sha, auth_hmac

