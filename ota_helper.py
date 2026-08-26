"""
Shared OTA token and firmware helper for server and test.

This module extracts token creation/validation logic and firmware code
generation from server.py to avoid duplication.
"""

import base64
import hashlib
import hmac
import os
import re
import secrets
import time

# Token constants
TOKEN_BUCKET_SECONDS = 300
TOKEN_BYTES = 12
BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def normalize_ieee(value):
    """Normalize IEEE address to aa:bb:cc:dd:ee:ff:00:11 format."""
    if value is None:
        return ""

    value = str(value).strip().lower().replace("-", ":")

    if value.startswith("0x"):
        raw = re.sub(r"[^0-9a-f]", "", value[2:])
    else:
        raw = re.sub(r"[^0-9a-f]", "", value)

    if len(raw) == 16:
        return ":".join(raw[i:i + 2] for i in range(0, 16, 2))

    return value


def get_token_secret(token_secret_path="/data/ota_token_secret.bin"):
    """
    Read or create token secret.
    
    Args:
        token_secret_path: Path to token secret file (default: server path)
    
    Returns:
        32-byte token secret
    
    Raises:
        FileNotFoundError: If token secret cannot be created/read
    """
    if os.path.isfile(token_secret_path):
        with open(token_secret_path, "rb") as f:
            secret = f.read()
            if len(secret) >= 32:
                return secret[:32]

    # Attempt to create if doesn't exist
    try:
        secret = secrets.token_bytes(32)
        directory = os.path.dirname(token_secret_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        
        fd = os.open(
            token_secret_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600
        )
        with os.fdopen(fd, "wb") as f:
            f.write(secret)
        return secret
    except FileExistsError:
        # File was created by another process
        with open(token_secret_path, "rb") as f:
            secret = f.read()
            if len(secret) >= 32:
                return secret[:32]
        raise
    except Exception as e:
        raise FileNotFoundError(
            f"Cannot read/create token secret at {token_secret_path}: {e}"
        )


def _token_for_bucket(device_id, code, sha256_hex, bucket, token_secret):
    """
    Create HMAC token for specific time bucket.
    
    Args:
        device_id: IEEE address normalized
        code: 3-char firmware code
        sha256_hex: SHA256 hex string
        bucket: Time bucket (int(time.time()) // TOKEN_BUCKET_SECONDS)
        token_secret: 32-byte token secret
    
    Returns:
        Base64url-encoded token
    """
    msg = f"{bucket}|{normalize_ieee(device_id)}|{code}|{sha256_hex}".encode("utf-8")
    digest = hmac.new(token_secret, msg, hashlib.sha256).digest()[:TOKEN_BYTES]
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def create_token(code, device_id, sha256_hex, token_secret_path="/data/ota_token_secret.bin"):
    """
    Create valid OTA download token for current time bucket.
    
    Args:
        code: 3-char firmware code
        device_id: IEEE address (will be normalized)
        sha256_hex: SHA256 of firmware hex string
        token_secret_path: Path to token secret
    
    Returns:
        Base64url token string
    """
    token_secret = get_token_secret(token_secret_path)
    bucket = int(time.time()) // TOKEN_BUCKET_SECONDS
    return _token_for_bucket(device_id, code, sha256_hex, bucket, token_secret)


def validate_token(token, code, device_id, sha256_hex, token_secret_path="/data/ota_token_secret.bin"):
    """
    Validate OTA download token (accepts current and previous bucket).
    
    Args:
        token: Token to validate
        code: 3-char firmware code
        device_id: IEEE address (will be normalized)
        sha256_hex: SHA256 of firmware hex string
        token_secret_path: Path to token secret
    
    Returns:
        True if token is valid
    """
    try:
        token_secret = get_token_secret(token_secret_path)
    except FileNotFoundError:
        return False

    device_id = normalize_ieee(device_id)
    bucket = int(time.time()) // TOKEN_BUCKET_SECONDS

    for candidate_bucket in (bucket, bucket - 1):
        expected = _token_for_bucket(device_id, code, sha256_hex, candidate_bucket, token_secret)
        if secrets.compare_digest(token, expected):
            return True

    return False


def _base62_3(value):
    """Encode value as 3-char base62 string."""
    value %= (62 ** 3)
    return (
        BASE62[(value // (62 * 62)) % 62]
        + BASE62[(value // 62) % 62]
        + BASE62[value % 62]
    )


def generate_firmware_code_candidates(filename):
    """
    Generate candidate firmware codes for a filename.
    
    Server uses deterministic code generation from filename SHA256.
    This generates the candidates in order that server would check.
    
    Args:
        filename: Firmware filename
    
    Yields:
        3-char base62 codes in order
    """
    seed = int.from_bytes(
        hashlib.sha256(filename.encode("utf-8")).digest()[:4],
        "big"
    )

    for offset in range(62 ** 3):
        code = _base62_3(seed + offset)
        yield code


def compute_firmware_sha256(bin_data_or_path):
    """
    Compute SHA256 of firmware binary.
    
    Args:
        bin_data_or_path: Either bytes or path to .bin file
    
    Returns:
        SHA256 hex string
    """
    sha = hashlib.sha256()
    
    if isinstance(bin_data_or_path, bytes):
        # Direct bytes
        sha.update(bin_data_or_path)
    else:
        # File path
        with open(bin_data_or_path, "rb") as f:
            while True:
                data = f.read(1024 * 1024)
                if not data:
                    break
                sha.update(data)
    
    return sha.hexdigest()


def get_firmware_size(bin_path):
    """Get firmware binary size in bytes."""
    return os.path.getsize(bin_path)
