import base64
import hashlib
import hmac
import html
import http.server
import json
import os
import re
import secrets
import sqlite3
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import websocket
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from device_enrollment import (
    ChallengeStore,
    canonical_enrollment,
    derive_device_auth_secret,
    enrollment_hmac,
    normalize_device_id,
    public_key_fingerprint_hex,
)
from ota_helper import (
    create_token as ota_create_token,
    validate_token as ota_validate_token,
    get_token_secret,
    normalize_ieee,
)


HTTPS_PORT = 8443
UI_PORT = 8099

FIRMWARE_DIR = "/share/ota_server/firmware"
DB_PATH = "/data/ota_server.db"
ADDON_OPTIONS_PATH = "/data/options.json"
SECRETS_PATH = "/share/ota_server/secrets.json"

TOKEN_TTL = 300
TOKEN_BUCKET_SECONDS = 300
TOKEN_BYTES = 12
OTA_HOST = "192.168.2.120"
TOKEN_SECRET_PATH = "/data/ota_token_secret.bin"
SERVER_DEVICE_MASTER_SECRET_PATH = "/data/server_device_master_secret.bin"
SERVER_SIGN_KEY_ID = 1
SERVER_SIGN_PRIVATE_KEY_PATH = "/data/server_sign_p256.pem"
SERVER_SIGN_PUBLIC_KEY_PATH = "/data/server_sign_p256.pub"

CERT_FILE="/share/ota_server/cert/ota_server_cert.pem"
KEY_FILE="/share/ota_server/cert/ota_server_private.pem"

DEVICE_MODEL_PREFIX = "ESP32-C6-"
DEFAULT_OTA_ECOSYSTEM = "JaroslavZemanESP"
UNKNOWN_RELEASE_VALUE = "unknown"
DEFAULT_SECURE_VERSION = 0
DEFAULT_FIRMWARE_ACTIVE = 1

TRANSPORT_ZHA = "zha"
TRANSPORT_ZIGBEE2MQTT = "zigbee2mqtt"
Z2M_TOPIC_PREFIX = "zigbee2mqtt"
Z2M_OTA_PROPERTY = "ota_command"
INSECURE_LEGACY_PROVISIONING = os.environ.get("INSECURE_LEGACY_PROVISIONING", "") == "1"

DEVICE_STATE_DISCOVERED = "DISCOVERED"
DEVICE_STATE_AUTH_CHALLENGE_PENDING = "AUTH_CHALLENGE_PENDING"
DEVICE_STATE_AUTHENTICATED = "AUTHENTICATED"
DEVICE_STATE_AUTH_FAILED = "AUTH_FAILED"
DEVICE_STATE_REKEY_REQUIRED = "REKEY_REQUIRED"

ZIGBEE_ENDPOINT = 1
ZIGBEE_CLUSTER_ID = 0xFC00
ZIGBEE_ATTRIBUTE_ID = 0x0001
ZIGBEE_CLUSTER_TYPE = "in"

HA_REST = "http://supervisor/core/api"
HA_WS = "ws://supervisor/core/websocket"

SUPERVISOR_TOKEN = os.environ.get("SUPERVISOR_TOKEN", "")

tokens = {}
tokens_lock = threading.Lock()
db_lock = threading.Lock()
device_challenges = ChallengeStore(ttl_seconds=60)
device_challenges_lock = threading.Lock()

os.makedirs(FIRMWARE_DIR, exist_ok=True)
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
os.chdir(FIRMWARE_DIR)


# ----------------------------------------------------------------------
# Runtime config
# ----------------------------------------------------------------------

runtime_config = {
    "wifi": {
        "ssid": "",
        "password": "",
        "password_secret": "main_wifi",
        "password_source": "missing",
        "security": "WPA2",
        "channel": 0,
    },
    "ota": {
        "ecosystem": DEFAULT_OTA_ECOSYSTEM,
        "host": OTA_HOST,
        "port": HTTPS_PORT,
    },
    "mqtt": {
        "host": "core-mosquitto",
        "port": 1883,
        "base_topic": Z2M_TOPIC_PREFIX,
    },
}


def _option_str(options, key, default=""):
    value = options.get(key, default)
    if value is None:
        return default
    return str(value).strip()


def _option_int(options, key, default):
    value = options.get(key, default)
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def load_secret(name):
    if not name or not os.path.isfile(SECRETS_PATH):
        return ""

    try:
        with open(SECRETS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Runtime config: cannot read secret store: {e}", flush=True)
        return ""

    wifi_passwords = data.get("wifi_passwords") or {}
    value = wifi_passwords.get(name)
    if value is None:
        return ""
    return str(value)


def load_runtime_config():
    global OTA_HOST, HTTPS_PORT, Z2M_TOPIC_PREFIX

    options = {}
    if os.path.isfile(ADDON_OPTIONS_PATH):
        try:
            with open(ADDON_OPTIONS_PATH, "r", encoding="utf-8") as f:
                options = json.load(f)
        except Exception as e:
            print(f"Runtime config: cannot read add-on options: {e}", flush=True)
            options = {}

    runtime_config["wifi"]["ssid"] = _option_str(options, "wifi_ssid")
    runtime_config["wifi"]["password_secret"] = _option_str(options, "wifi_password_secret", "main_wifi") or "main_wifi"

    legacy_password = _option_str(options, "wifi_password")
    secret_password = load_secret(runtime_config["wifi"]["password_secret"])
    if secret_password:
        runtime_config["wifi"]["password"] = secret_password
        runtime_config["wifi"]["password_source"] = "secret"
    elif legacy_password:
        runtime_config["wifi"]["password"] = legacy_password
        runtime_config["wifi"]["password_source"] = "legacy-option"
    else:
        runtime_config["wifi"]["password"] = ""
        runtime_config["wifi"]["password_source"] = "missing"

    runtime_config["wifi"]["security"] = _option_str(options, "wifi_security", "WPA2") or "WPA2"
    runtime_config["wifi"]["channel"] = _option_int(options, "wifi_channel", 0)

    runtime_config["ota"]["ecosystem"] = _option_str(options, "ota_ecosystem", DEFAULT_OTA_ECOSYSTEM) or DEFAULT_OTA_ECOSYSTEM
    runtime_config["ota"]["host"] = _option_str(options, "ota_host", OTA_HOST) or OTA_HOST
    runtime_config["ota"]["port"] = _option_int(options, "ota_port", HTTPS_PORT)

    runtime_config["mqtt"]["host"] = _option_str(options, "mqtt_host", "core-mosquitto") or "core-mosquitto"
    runtime_config["mqtt"]["port"] = _option_int(options, "mqtt_port", 1883)
    runtime_config["mqtt"]["base_topic"] = _option_str(options, "mqtt_base_topic", Z2M_TOPIC_PREFIX) or Z2M_TOPIC_PREFIX

    OTA_HOST = runtime_config["ota"]["host"]
    HTTPS_PORT = runtime_config["ota"]["port"]
    Z2M_TOPIC_PREFIX = runtime_config["mqtt"]["base_topic"]

    print(
        "Runtime config loaded: "
        f"ecosystem={runtime_config['ota']['ecosystem']} "
        f"wifi_ssid={'configured' if runtime_config['wifi']['ssid'] else 'missing'} "
        f"wifi_password={'configured' if runtime_config['wifi']['password'] else 'missing'} "
        f"wifi_password_source={runtime_config['wifi']['password_source']} "
        f"ota_host={runtime_config['ota']['host']} ota_port={runtime_config['ota']['port']} "
        f"mqtt={runtime_config['mqtt']['host']}:{runtime_config['mqtt']['port']} base_topic={runtime_config['mqtt']['base_topic']}",
        flush=True,
    )


# ----------------------------------------------------------------------
# SQLite
# ----------------------------------------------------------------------

def db_connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db_lock:
        with db_connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS firmware_images (
                    filename       TEXT PRIMARY KEY,
                    ota_ecosystem  TEXT NOT NULL DEFAULT 'JaroslavZemanESP',
                    sha256         TEXT NOT NULL,
                    size           INTEGER NOT NULL,
                    version        TEXT,
                    revision       INTEGER NOT NULL DEFAULT 1,
                    device_family  TEXT NOT NULL DEFAULT 'unknown',
                    device_model   TEXT NOT NULL DEFAULT 'unknown',
                    product_role   TEXT NOT NULL DEFAULT 'unknown',
                    product        TEXT NOT NULL DEFAULT 'unknown',
                    hardware_revision TEXT NOT NULL DEFAULT 'unknown',
                    chip_family    TEXT NOT NULL DEFAULT 'ESP32-C6',
                    flash_size     TEXT NOT NULL DEFAULT '16MB',
                    channel        TEXT NOT NULL DEFAULT 'stable',
                    secure_version INTEGER NOT NULL DEFAULT 0,
                    active         INTEGER NOT NULL DEFAULT 1,
                    first_seen     INTEGER NOT NULL,
                    last_seen      INTEGER NOT NULL,
                    changed_at     INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS firmware_alias (
                    filename       TEXT PRIMARY KEY,
                    code           TEXT NOT NULL UNIQUE,
                    created_at     INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS firmware_history (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename       TEXT NOT NULL,
                    sha256         TEXT NOT NULL,
                    size           INTEGER NOT NULL,
                    version        TEXT,
                    revision       INTEGER NOT NULL,
                    detected_at    INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS ota_dispatch (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    ieee           TEXT NOT NULL,
                    filename       TEXT NOT NULL,
                    sha256         TEXT NOT NULL,
                    revision       INTEGER NOT NULL,
                    sent_at        INTEGER NOT NULL,
                    success        INTEGER NOT NULL,
                    error          TEXT
                );

                CREATE TABLE IF NOT EXISTS device_provisioning (
                    device_id      TEXT PRIMARY KEY,
                    wifi_ssid      TEXT NOT NULL,
                    wifi_security  TEXT NOT NULL,
                    wifi_channel   INTEGER NOT NULL DEFAULT 0,
                    ota_host       TEXT NOT NULL,
                    ota_port       INTEGER NOT NULL,
                    firmware_filename TEXT,
                    firmware_sha256 TEXT,
                    transport      TEXT,
                    status         TEXT NOT NULL,
                    error          TEXT,
                    updated_at     INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS devices (
                    device_id             TEXT PRIMARY KEY,
                    device_enc_public_key BLOB NOT NULL,
                    device_key_id         INTEGER NOT NULL DEFAULT 1,
                    device_public_key_fingerprint TEXT,
                    zigbee_ieee           TEXT,
                    ota_ecosystem         TEXT NOT NULL DEFAULT 'JaroslavZemanESP',
                    device_model          TEXT NOT NULL DEFAULT 'unknown',
                    firmware_product      TEXT NOT NULL DEFAULT 'unknown',
                    product_role          TEXT NOT NULL,
                    hardware_revision     TEXT NOT NULL,
                    chip_family           TEXT NOT NULL DEFAULT 'ESP32-C6',
                    flash_size            TEXT,
                    firmware_version      TEXT,
                    firmware_channel      TEXT NOT NULL DEFAULT 'stable',
                    enrollment_counter    INTEGER NOT NULL DEFAULT 0,
                    state                 TEXT NOT NULL DEFAULT 'DISCOVERED',
                    last_message_id       TEXT,
                    last_challenge        TEXT,
                    auth_failed_reason    TEXT,
                    created_at            INTEGER NOT NULL,
                    updated_at            INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS command_counters (
                    scope                 TEXT PRIMARY KEY,
                    provision_counter     INTEGER NOT NULL DEFAULT 0,
                    ota_counter           INTEGER NOT NULL DEFAULT 0,
                    updated_at            INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS ix_ota_dispatch_ieee_file
                    ON ota_dispatch (ieee, filename, sent_at);
                """
            )

            existing_columns = {
                row[1]
                for row in conn.execute("PRAGMA table_info(firmware_images)")
            }
            migrations = {
                "ota_ecosystem": "TEXT NOT NULL DEFAULT 'JaroslavZemanESP'",
                "device_family": "TEXT NOT NULL DEFAULT 'unknown'",
                "device_model": "TEXT NOT NULL DEFAULT 'unknown'",
                "product_role": "TEXT NOT NULL DEFAULT 'unknown'",
                "product": "TEXT NOT NULL DEFAULT 'unknown'",
                "hardware_revision": "TEXT NOT NULL DEFAULT 'unknown'",
                "chip_family": "TEXT NOT NULL DEFAULT 'ESP32-C6'",
                "flash_size": "TEXT NOT NULL DEFAULT '16MB'",
                "channel": "TEXT NOT NULL DEFAULT 'stable'",
                "secure_version": "INTEGER NOT NULL DEFAULT 0",
                "active": "INTEGER NOT NULL DEFAULT 1",
            }
            for column, definition in migrations.items():
                if column not in existing_columns:
                    conn.execute(
                        f"ALTER TABLE firmware_images ADD COLUMN {column} {definition}"
                    )

            existing_device_columns = {
                row[1]
                for row in conn.execute("PRAGMA table_info(devices)")
            }
            device_migrations = {
                "device_public_key_fingerprint": "TEXT",
                "zigbee_ieee": "TEXT",
                "ota_ecosystem": "TEXT NOT NULL DEFAULT 'JaroslavZemanESP'",
                "device_model": "TEXT NOT NULL DEFAULT 'unknown'",
                "firmware_product": "TEXT NOT NULL DEFAULT 'unknown'",
                "firmware_version": "TEXT",
                "enrollment_counter": "INTEGER NOT NULL DEFAULT 0",
                "state": "TEXT NOT NULL DEFAULT 'DISCOVERED'",
                "last_message_id": "TEXT",
                "last_challenge": "TEXT",
                "auth_failed_reason": "TEXT",
            }
            for column, definition in device_migrations.items():
                if column not in existing_device_columns:
                    conn.execute(
                        f"ALTER TABLE devices ADD COLUMN {column} {definition}"
                    )


# ----------------------------------------------------------------------
# Device enrollment
# ----------------------------------------------------------------------

def get_server_device_master_secret():
    directory = os.path.dirname(SERVER_DEVICE_MASTER_SECRET_PATH)
    os.makedirs(directory, exist_ok=True)
    if not os.path.isfile(SERVER_DEVICE_MASTER_SECRET_PATH):
        secret = secrets.token_bytes(32)
        fd = os.open(
            SERVER_DEVICE_MASTER_SECRET_PATH,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600
        )
        with os.fdopen(fd, "wb") as f:
            f.write(secret)
        print("Device enrollment master secret created in secure local file", flush=True)

    with open(SERVER_DEVICE_MASTER_SECRET_PATH, "rb") as f:
        secret = f.read()
    if len(secret) < 32:
        raise RuntimeError("SERVER_DEVICE_MASTER_SECRET is invalid")
    try:
        os.chmod(SERVER_DEVICE_MASTER_SECRET_PATH, 0o600)
    except OSError:
        pass
    return secret


def get_authenticated_device(device_id):
    normalized = normalize_device_id(device_id)
    with db_lock:
        with db_connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM devices
                WHERE device_id = ?
                  AND state = ?
                  AND device_enc_public_key IS NOT NULL
                  AND length(device_enc_public_key) = 65
                """,
                (normalized, DEVICE_STATE_AUTHENTICATED)
            ).fetchone()
    return dict(row) if row is not None else None


def get_device_record(device_id):
    normalized = normalize_device_id(device_id)
    with db_lock:
        with db_connect() as conn:
            row = conn.execute(
                "SELECT * FROM devices WHERE device_id = ?",
                (normalized,)
            ).fetchone()
    return dict(row) if row is not None else None


def list_device_records():
    with db_lock:
        with db_connect() as conn:
            rows = conn.execute(
                "SELECT * FROM devices ORDER BY device_id"
            ).fetchall()
    return [dict(row) for row in rows]


def get_device_provisioning(device_id):
    normalized = normalize_device_id(device_id)
    with db_lock:
        with db_connect() as conn:
            row = conn.execute(
                "SELECT * FROM device_provisioning WHERE device_id = ?",
                (normalized,)
            ).fetchone()
    return dict(row) if row is not None else None


def save_device_provisioning(device, image, status, error=None, ssid=None):
    device_id = normalize_device_id(device.get("ieee"))
    now = int(time.time())
    with db_lock:
        with db_connect() as conn:
            conn.execute(
                """
                INSERT INTO device_provisioning (
                    device_id,
                    wifi_ssid,
                    wifi_security,
                    wifi_channel,
                    ota_host,
                    ota_port,
                    firmware_filename,
                    firmware_sha256,
                    transport,
                    status,
                    error,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    wifi_ssid = excluded.wifi_ssid,
                    wifi_security = excluded.wifi_security,
                    wifi_channel = excluded.wifi_channel,
                    ota_host = excluded.ota_host,
                    ota_port = excluded.ota_port,
                    firmware_filename = excluded.firmware_filename,
                    firmware_sha256 = excluded.firmware_sha256,
                    transport = excluded.transport,
                    status = excluded.status,
                    error = excluded.error,
                    updated_at = excluded.updated_at
                """,
                (
                    device_id,
                    ssid if ssid is not None else runtime_config["wifi"]["ssid"],
                    runtime_config["wifi"]["security"],
                    int(runtime_config["wifi"]["channel"] or 0),
                    runtime_config["ota"]["host"],
                    int(runtime_config["ota"]["port"]),
                    image["filename"] if image else None,
                    image["sha256"] if image else None,
                    device.get("transport") or "",
                    status,
                    error,
                    now,
                )
            )


def record_device_state(device_id, state, reason=""):
    normalized = normalize_device_id(device_id)
    now = int(time.time())
    with db_lock:
        with db_connect() as conn:
            conn.execute(
                """
                INSERT INTO devices (
                    device_id,
                    device_enc_public_key,
                    device_key_id,
                    product_role,
                    hardware_revision,
                    chip_family,
                    flash_size,
                    firmware_channel,
                    state,
                    auth_failed_reason,
                    created_at,
                    updated_at
                )
                VALUES (?, X'', 1, 'unknown', 'unknown', 'ESP32-C6', '16MB', 'stable', ?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    state = excluded.state,
                    auth_failed_reason = excluded.auth_failed_reason,
                    updated_at = excluded.updated_at
                """,
                (normalized, state, reason, now, now)
            )


def create_device_auth_challenge(device_id):
    with device_challenges_lock:
        challenge = device_challenges.create(device_id)
    now = int(time.time())
    with db_lock:
        with db_connect() as conn:
            conn.execute(
                """
                INSERT INTO devices (
                    device_id,
                    device_enc_public_key,
                    device_key_id,
                    product_role,
                    hardware_revision,
                    chip_family,
                    flash_size,
                    firmware_channel,
                    state,
                    last_message_id,
                    last_challenge,
                    created_at,
                    updated_at
                )
                VALUES (?, X'', 1, 'unknown', 'unknown', 'ESP32-C6', '16MB', 'stable', ?, ?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    state = excluded.state,
                    last_message_id = excluded.last_message_id,
                    last_challenge = excluded.last_challenge,
                    updated_at = excluded.updated_at
                """,
                (
                    challenge.device_id,
                    DEVICE_STATE_AUTH_CHALLENGE_PENDING,
                    challenge.message_id,
                    challenge.challenge.hex(),
                    now,
                    now,
                )
            )
    return challenge


def validate_device_enrollment(enrollment):
    fields = dict(enrollment)
    fields["device_id"] = normalize_device_id(fields["device_id"])
    fields["zigbee_ieee"] = normalize_device_id(fields["zigbee_ieee"])
    if fields["ota_ecosystem"] != runtime_config["ota"]["ecosystem"]:
        raise ValueError("ota ecosystem mismatch")

    with device_challenges_lock:
        challenge = device_challenges.consume(
            fields["device_id"],
            str(fields["message_id"]),
            str(fields["challenge"])
        )
    if challenge is None:
        record_device_state(fields["device_id"], DEVICE_STATE_AUTH_FAILED, "invalid_or_expired_challenge")
        raise ValueError("invalid or expired challenge")

    device_auth_secret = derive_device_auth_secret(
        get_server_device_master_secret(),
        fields["device_id"]
    )
    expected_hmac = enrollment_hmac(device_auth_secret, fields)
    received_hmac = bytes.fromhex(str(fields["device_auth_hmac"]))
    if not hmac.compare_digest(expected_hmac, received_hmac):
        record_device_state(fields["device_id"], DEVICE_STATE_AUTH_FAILED, "hmac_mismatch")
        raise ValueError("device auth hmac mismatch")

    public_key = bytes.fromhex(fields["device_enc_public_key"])
    fingerprint = public_key_fingerprint_hex(fields["device_enc_public_key"])
    counter = int(fields["enrollment_counter"])
    now = int(time.time())

    with db_lock:
        with db_connect() as conn:
            row = conn.execute(
                "SELECT enrollment_counter, device_public_key_fingerprint FROM devices WHERE device_id = ?",
                (fields["device_id"],)
            ).fetchone()
            if row is not None and int(row["enrollment_counter"] or 0) >= counter:
                raise ValueError("enrollment counter is not monotonic")
            if row is not None and row["device_public_key_fingerprint"] and row["device_public_key_fingerprint"] != fingerprint:
                state = DEVICE_STATE_REKEY_REQUIRED
            else:
                state = DEVICE_STATE_AUTHENTICATED

            conn.execute(
                """
                INSERT INTO devices (
                    device_id,
                    device_enc_public_key,
                    device_key_id,
                    device_public_key_fingerprint,
                    zigbee_ieee,
                    ota_ecosystem,
                    device_model,
                    firmware_product,
                    product_role,
                    hardware_revision,
                    chip_family,
                    flash_size,
                    firmware_version,
                    firmware_channel,
                    enrollment_counter,
                    state,
                    last_message_id,
                    last_challenge,
                    auth_failed_reason,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    device_enc_public_key = excluded.device_enc_public_key,
                    device_key_id = excluded.device_key_id,
                    device_public_key_fingerprint = excluded.device_public_key_fingerprint,
                    zigbee_ieee = excluded.zigbee_ieee,
                    ota_ecosystem = excluded.ota_ecosystem,
                    device_model = excluded.device_model,
                    firmware_product = excluded.firmware_product,
                    product_role = excluded.product_role,
                    hardware_revision = excluded.hardware_revision,
                    chip_family = excluded.chip_family,
                    flash_size = excluded.flash_size,
                    firmware_version = excluded.firmware_version,
                    firmware_channel = excluded.firmware_channel,
                    enrollment_counter = excluded.enrollment_counter,
                    state = excluded.state,
                    last_message_id = excluded.last_message_id,
                    last_challenge = excluded.last_challenge,
                    auth_failed_reason = '',
                    updated_at = excluded.updated_at
                """,
                (
                    fields["device_id"],
                    public_key,
                    int(fields["device_enc_key_id"]),
                    fingerprint,
                    fields["zigbee_ieee"],
                    fields["ota_ecosystem"],
                    fields["device_model"],
                    fields.get("firmware_product", fields.get("product", "unknown")),
                    fields["product_role"],
                    fields["hardware_revision"],
                    fields["chip_family"],
                    fields["flash_size"],
                    fields["firmware_version"],
                    fields["firmware_channel"],
                    counter,
                    state,
                    fields["message_id"],
                    fields["challenge"],
                    now,
                    now,
                )
            )
    return {
        "status": state,
        "device_id": fields["device_id"],
        "public_key_fingerprint": fingerprint,
        "canonical_sha256": hashlib.sha256(canonical_enrollment(fields)).hexdigest(),
    }


def ensure_device_can_receive_provisioning(device_id):
    device = get_authenticated_device(device_id)
    if device is None:
        raise PermissionError("PROVISIONING_DENIED_NOT_AUTHENTICATED")
    if not INSECURE_LEGACY_PROVISIONING:
        raise PermissionError("INSECURE_LEGACY_PROVISIONING_DISABLED")
    return device


# ----------------------------------------------------------------------
# Firmware
# ----------------------------------------------------------------------

def get_sha256(path):
    sha = hashlib.sha256()

    with open(path, "rb") as f:
        while True:
            data = f.read(1024 * 1024)
            if not data:
                break
            sha.update(data)

    return sha.hexdigest()


def sha256_b64url(hex_sha):
    return base64.urlsafe_b64encode(
        bytes.fromhex(hex_sha)
    ).decode().rstrip("=")


def get_firmware_version(path):
    try:
        result = subprocess.run(
            ["esptool", "image-info", path],
            capture_output=True,
            text=True,
            timeout=10
        )

        output = result.stdout + "\n" + result.stderr

        for pattern in (
            r"App version:\s*(.+)",
            r"Project version:\s*(.+)",
            r"Version:\s*(.+)"
        ):
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                return match.group(1).strip()

    except Exception as e:
        print(f"Version read error: {e}", flush=True)

    return "unknown"



def release_metadata_filename(filename):
    base, _ = os.path.splitext(filename)
    return base + ".release.json"


def load_release_metadata(filename, sha256, size, detected_version):
    metadata_path = os.path.join(FIRMWARE_DIR, release_metadata_filename(filename))
    metadata = {}

    if os.path.isfile(metadata_path):
        try:
            with open(metadata_path, "r", encoding="utf-8") as f:
                metadata = json.load(f)
        except Exception as e:
            print(f"Release metadata read error {metadata_path}: {e}", flush=True)
            metadata = {}
    else:
        print(f"Release metadata missing for {filename}: expected {release_metadata_filename(filename)}", flush=True)

    def meta_str(key, fallback=UNKNOWN_RELEASE_VALUE):
        value = metadata.get(key, fallback)
        if value is None:
            value = fallback
        return str(value).strip() or fallback

    def meta_int(key, fallback):
        try:
            return int(metadata.get(key, fallback))
        except (TypeError, ValueError):
            return fallback

    file_sha = meta_str("sha256", sha256)
    if file_sha != sha256:
        print(f"Release metadata SHA mismatch for {filename}; using actual SHA256", flush=True)

    file_size = meta_int("size", size)
    if file_size != size:
        print(f"Release metadata size mismatch for {filename}; using actual size", flush=True)

    return {
        "ota_ecosystem": meta_str("ota_ecosystem", runtime_config["ota"]["ecosystem"]),
        "device_family": meta_str("ota_ecosystem", runtime_config["ota"]["ecosystem"]),
        "device_model": meta_str("device_model"),
        "product_role": meta_str("product_role"),
        "product": meta_str("firmware_product"),
        "hardware_revision": meta_str("hardware_revision"),
        "chip_family": meta_str("chip_family"),
        "flash_size": meta_str("flash_size"),
        "channel": meta_str("firmware_channel", "stable"),
        "version": meta_str("firmware_version", detected_version or "unknown"),
        "secure_version": meta_int("secure_version", DEFAULT_SECURE_VERSION),
        "active": meta_int("active", DEFAULT_FIRMWARE_ACTIVE),
    }


def scan_firmware_images():
    """
    Skenuje *.bin a v SQLite drzi revize.
    Projektova/release metadata bere z <bin>.release.json vedle binarky.
    revision se zvysi pouze tehdy, pokud se zmenil SHA256.
    """
    now = int(time.time())
    result = []

    for filename in sorted(os.listdir(FIRMWARE_DIR)):
        if not filename.lower().endswith(".bin"):
            continue

        path = os.path.join(FIRMWARE_DIR, filename)

        if not os.path.isfile(path):
            continue

        size = os.path.getsize(path)
        sha256 = get_sha256(path)
        detected_version = get_firmware_version(path)
        firmware_metadata = load_release_metadata(filename, sha256, size, detected_version)
        version = firmware_metadata["version"]

        with db_lock:
            with db_connect() as conn:
                row = conn.execute(
                    """
                    SELECT *
                    FROM firmware_images
                    WHERE filename = ?
                    """,
                    (filename,)
                ).fetchone()

                changed_now = False

                if row is None:
                    revision = 1
                    changed_now = True

                    conn.execute(
                        """
                        INSERT INTO firmware_images
                            (filename, ota_ecosystem, sha256, size, version, revision,
                             device_family, device_model, product_role, product,
                             hardware_revision, chip_family, flash_size, channel,
                             secure_version, active,
                             first_seen, last_seen, changed_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            filename, firmware_metadata["ota_ecosystem"], sha256, size, version, revision,
                            firmware_metadata["device_family"],
                            firmware_metadata["device_model"],
                            firmware_metadata["product_role"],
                            firmware_metadata["product"],
                            firmware_metadata["hardware_revision"],
                            firmware_metadata["chip_family"],
                            firmware_metadata["flash_size"],
                            firmware_metadata["channel"],
                            firmware_metadata["secure_version"], firmware_metadata["active"],
                            now, now, now
                        )
                    )

                    conn.execute(
                        """
                        INSERT INTO firmware_history
                            (filename, sha256, size, version, revision, detected_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (filename, sha256, size, version, revision, now)
                    )

                elif row["sha256"] != sha256:
                    revision = row["revision"] + 1
                    changed_now = True

                    conn.execute(
                        """
                        UPDATE firmware_images
                        SET ota_ecosystem = ?,
                            sha256 = ?,
                            size = ?,
                            version = ?,
                            revision = ?,
                            device_family = ?,
                            device_model = ?,
                            product_role = ?,
                            product = ?,
                            hardware_revision = ?,
                            chip_family = ?,
                            flash_size = ?,
                            channel = ?,
                            secure_version = ?,
                            active = ?,
                            last_seen = ?,
                            changed_at = ?
                        WHERE filename = ?
                        """,
                        (
                            firmware_metadata["ota_ecosystem"], sha256, size, version, revision,
                            firmware_metadata["device_family"],
                            firmware_metadata["device_model"],
                            firmware_metadata["product_role"],
                            firmware_metadata["product"],
                            firmware_metadata["hardware_revision"],
                            firmware_metadata["chip_family"],
                            firmware_metadata["flash_size"],
                            firmware_metadata["channel"],
                            firmware_metadata["secure_version"], firmware_metadata["active"],
                            now, now, filename
                        )
                    )

                    conn.execute(
                        """
                        INSERT INTO firmware_history
                            (filename, sha256, size, version, revision, detected_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (filename, sha256, size, version, revision, now)
                    )

                else:
                    revision = row["revision"]

                    conn.execute(
                        """
                        UPDATE firmware_images
                        SET ota_ecosystem = ?,
                            size = ?,
                            version = ?,
                            device_family = ?,
                            device_model = ?,
                            product_role = ?,
                            product = ?,
                            hardware_revision = ?,
                            chip_family = ?,
                            flash_size = ?,
                            channel = ?,
                            secure_version = ?,
                            active = ?,
                            last_seen = ?
                        WHERE filename = ?
                        """,
                        (
                            firmware_metadata["ota_ecosystem"], size, version,
                            firmware_metadata["device_family"],
                            firmware_metadata["device_model"],
                            firmware_metadata["product_role"],
                            firmware_metadata["product"],
                            firmware_metadata["hardware_revision"],
                            firmware_metadata["chip_family"],
                            firmware_metadata["flash_size"],
                            firmware_metadata["channel"],
                            firmware_metadata["secure_version"], firmware_metadata["active"],
                            now, filename
                        )
                    )

                current = conn.execute(
                    """
                    SELECT *
                    FROM firmware_images
                    WHERE filename = ?
                    """,
                    (filename,)
                ).fetchone()

        result.append({
            "filename": current["filename"],
            "ota_ecosystem": current["ota_ecosystem"],
            "sha256": current["sha256"],
            "size": current["size"],
            "version": current["version"],
            "revision": current["revision"],
            "device_family": current["device_family"],
            "device_model": current["device_model"],
            "product_role": current["product_role"],
            "product": current["product"],
            "hardware_revision": current["hardware_revision"],
            "chip_family": current["chip_family"],
            "flash_size": current["flash_size"],
            "channel": current["channel"],
            "secure_version": current["secure_version"],
            "active": bool(current["active"]),
            "changed_at": current["changed_at"],
            "changed_now": changed_now,
        })

    return result


def get_image(filename):
    filename = os.path.basename(filename)

    scan_firmware_images()

    with db_lock:
        with db_connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM firmware_images
                WHERE filename = ?
                """,
                (filename,)
            ).fetchone()

    if row is None:
        return None

    path = os.path.join(FIRMWARE_DIR, filename)

    if not os.path.isfile(path):
        return None

    return dict(row)


def version_key(value):
    if not value or value == "unknown":
        return ()

    parts = []
    for item in re.findall(r"\d+|[A-Za-z]+", str(value)):
        if item.isdigit():
            parts.append((1, int(item)))
        else:
            parts.append((0, item.lower()))
    return tuple(parts)


def compare_versions(left, right):
    left_key = version_key(left)
    right_key = version_key(right)
    if not left_key or not right_key:
        return 0 if left == right else 1
    return (left_key > right_key) - (left_key < right_key)


def validate_metadata_value(name, value, max_len=64):
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    if not value or len(value) > max_len:
        raise ValueError(f"{name} length is invalid")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", value):
        raise ValueError(f"{name} contains invalid characters")
    return value


def latest_compatible_firmware(product, hardware_revision, channel, current_version):
    scan_firmware_images()

    with db_lock:
        with db_connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM firmware_images
                WHERE product = ?
                  AND hardware_revision = ?
                  AND channel = ?
                  AND active = 1
                """,
                (product, hardware_revision, channel)
            ).fetchall()

    candidates = []
    for row in rows:
        image = dict(row)
        if current_version and compare_versions(image.get("version"), current_version) <= 0:
            continue
        candidates.append(image)

    if not candidates:
        return None

    candidates.sort(
        key=lambda x: (
            version_key(x.get("version")),
            int(x.get("secure_version") or 0),
            int(x.get("revision") or 0),
            str(x.get("filename") or "")
        ),
        reverse=True
    )
    return candidates[0]


def latest_compatible_firmware_for_device(device):
    scan_firmware_images()
    device_model = str(device.get("device_model") or "")
    product_role = str(device.get("product_role") or "")
    product = str(device.get("firmware_product") or "")
    hardware_revision = str(device.get("hardware_revision") or "")
    channel = str(device.get("firmware_channel") or "stable")

    with db_lock:
        with db_connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM firmware_images
                WHERE active = 1
                  AND channel = ?
                  AND hardware_revision = ?
                  AND (
                        device_model = ?
                     OR product_role = ?
                     OR product = ?
                  )
                """,
                (channel, hardware_revision, device_model, product_role, product)
            ).fetchall()

    candidates = [dict(row) for row in rows]
    if not candidates:
        return None
    candidates.sort(
        key=lambda x: (
            version_key(x.get("version")),
            int(x.get("secure_version") or 0),
            int(x.get("revision") or 0),
            str(x.get("filename") or "")
        ),
        reverse=True
    )
    return candidates[0]


def device_update_status(device):
    if (
        (device.get("state") or DEVICE_STATE_DISCOVERED) != DEVICE_STATE_AUTHENTICATED or
        not device.get("device_model") or
        device.get("device_model") == "unknown" or
        not device.get("hardware_revision") or
        device.get("hardware_revision") == "unknown"
    ):
        return {
            "status": "ENROLLMENT_REQUIRED",
            "latest": None,
            "current_version": device.get("firmware_version") or "",
        }

    latest = latest_compatible_firmware_for_device(device)
    if latest is None:
        return {
            "status": "NO_COMPATIBLE_BIN",
            "latest": None,
            "current_version": device.get("firmware_version") or "",
        }

    current_version = device.get("firmware_version") or ""
    compare = compare_versions(latest.get("version"), current_version)
    if not current_version:
        status = "UNKNOWN_CURRENT_VERSION"
    elif compare > 0:
        status = "UPDATE_AVAILABLE"
    else:
        status = "CURRENT"

    return {
        "status": status,
        "latest": latest,
        "current_version": current_version,
    }


def firmware_manifest(image):
    code = ensure_image_code(image["filename"])
    return {
        "protocol": 1,
        "status": "UPDATE",
        "product": image["product"],
        "hardware_revision": image["hardware_revision"],
        "channel": image["channel"],
        "version": image["version"],
        "secure_version": int(image["secure_version"] or 0),
        "size": int(image["size"]),
        "sha256": image["sha256"],
        "url": f"https://{OTA_HOST}:{HTTPS_PORT}/{code}",
        "mandatory": False,
    }


BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _base62_3(value):
    value %= (62 ** 3)
    return (
        BASE62[(value // (62 * 62)) % 62]
        + BASE62[(value // 62) % 62]
        + BASE62[value % 62]
    )


def ensure_image_code(filename):
    with db_lock:
        with db_connect() as conn:
            row = conn.execute(
                "SELECT code FROM firmware_alias WHERE filename = ?",
                (filename,)
            ).fetchone()

            if row:
                return row["code"]

            seed = int.from_bytes(
                hashlib.sha256(filename.encode("utf-8")).digest()[:4],
                "big"
            )

            for offset in range(62 ** 3):
                code = _base62_3(seed + offset)
                exists = conn.execute(
                    "SELECT 1 FROM firmware_alias WHERE code = ?",
                    (code,)
                ).fetchone()

                if not exists:
                    conn.execute(
                        """
                        INSERT INTO firmware_alias (filename, code, created_at)
                        VALUES (?, ?, ?)
                        """,
                        (filename, code, int(time.time()))
                    )
                    return code

    raise RuntimeError("Nelze vytvořit 3znakový kód firmware")


def resolve_image_code(code):
    with db_lock:
        with db_connect() as conn:
            row = conn.execute(
                """
                SELECT a.code, i.*
                FROM firmware_alias a
                JOIN firmware_images i ON i.filename = a.filename
                WHERE a.code = ?
                """,
                (code,)
            ).fetchone()

    return dict(row) if row else None


# Token management moved to ota_helper.py
# get_token_secret() now imported from ota_helper

SERVER_SIGN_PRIVATE_KEY = None
SERVER_SIGN_LOCK = threading.Lock()


def b64url_encode(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def get_server_sign_private_key():
    global SERVER_SIGN_PRIVATE_KEY

    with SERVER_SIGN_LOCK:
        if SERVER_SIGN_PRIVATE_KEY is not None:
            return SERVER_SIGN_PRIVATE_KEY

        if os.path.isfile(SERVER_SIGN_PRIVATE_KEY_PATH):
            with open(SERVER_SIGN_PRIVATE_KEY_PATH, "rb") as f:
                SERVER_SIGN_PRIVATE_KEY = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                )
        else:
            SERVER_SIGN_PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())
            pem = SERVER_SIGN_PRIVATE_KEY.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            with open(SERVER_SIGN_PRIVATE_KEY_PATH, "wb") as f:
                os.chmod(SERVER_SIGN_PRIVATE_KEY_PATH, 0o600)
                f.write(pem)

        if not isinstance(SERVER_SIGN_PRIVATE_KEY, ec.EllipticCurvePrivateKey):
            raise RuntimeError("SERVER_SIGN_PRIVATE_KEY is not an EC private key")
        if SERVER_SIGN_PRIVATE_KEY.curve.name not in ("secp256r1", "prime256v1"):
            raise RuntimeError("SERVER_SIGN_PRIVATE_KEY must be ECDSA P-256")

        public_key = SERVER_SIGN_PRIVATE_KEY.public_key()
        raw_public = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        with open(SERVER_SIGN_PUBLIC_KEY_PATH, "wb") as f:
            f.write(raw_public)

        print(
            f"SERVER_SIGN key ready key_id={SERVER_SIGN_KEY_ID} public_len={len(raw_public)}",
            flush=True,
        )
        return SERVER_SIGN_PRIVATE_KEY


def sign_server_command(domain, payload):
    if not isinstance(domain, bytes) or not isinstance(payload, bytes):
        raise TypeError("domain and payload must be bytes")

    private_key = get_server_sign_private_key()
    der_signature = private_key.sign(domain + payload, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    raw_signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return {
        "key_id": SERVER_SIGN_KEY_ID,
        "signature": raw_signature,
        "signature_b64url": b64url_encode(raw_signature),
    }



# Token functions moved to ota_helper.py
# Use: ota_create_token() and ota_validate_token()


# ----------------------------------------------------------------------
# Home Assistant
# ----------------------------------------------------------------------

def require_ha_token():
    if not SUPERVISOR_TOKEN:
        raise RuntimeError(
            "SUPERVISOR_TOKEN chybi. V config.yaml musi byt homeassistant_api: true."
        )


def ha_ws_command(command):
    require_ha_token()

    ws = websocket.create_connection(
        HA_WS,
        timeout=10
    )

    try:
        hello = json.loads(ws.recv())

        if hello.get("type") != "auth_required":
            raise RuntimeError(f"Unexpected HA WS response: {hello}")

        ws.send(json.dumps({
            "type": "auth",
            "access_token": SUPERVISOR_TOKEN
        }))

        auth = json.loads(ws.recv())

        if auth.get("type") != "auth_ok":
            raise RuntimeError(
                f"Home Assistant WebSocket auth failed: {auth}"
            )

        message = dict(command)
        message["id"] = 1

        ws.send(json.dumps(message))

        while True:
            response = json.loads(ws.recv())

            if response.get("id") != 1:
                continue

            if response.get("type") != "result":
                continue

            if not response.get("success"):
                raise RuntimeError(
                    f"Home Assistant WebSocket command failed: "
                    f"{response.get('error')}"
                )

            return response.get("result")

    finally:
        ws.close()

# normalize_ieee moved to ota_helper.py (already imported above)


def ieee_to_z2m_topic_name(value):
    normalized = normalize_ieee(value)
    raw = re.sub(r"[^0-9a-f]", "", normalized)

    if len(raw) == 16:
        return "0x" + raw

    value = str(value).strip().lower()
    if value.startswith("0x"):
        return value

    return value


def device_matches_model(device):
    fields = (
        device.get("model"),
        device.get("model_id"),
        device.get("name"),
        device.get("name_by_user"),
    )
    for field in fields:
        text = str(field or "")
        if DEVICE_MODEL_PREFIX.upper() in text.upper():
            return True
    return False


def get_ota_devices():
    """
    Vrací ESP OTA zařízení z Home Assistant Device Registry.
    Podporuje ZHA i Zigbee2MQTT. Pro Zigbee2MQTT se drží MQTT topic name
    zvlášť od normalizovaného IEEE, protože token se váže na IEEE ve tvaru
    aa:bb:..., zatímco Zigbee2MQTT topic typicky používá 0x...
    """
    devices = ha_ws_command({
        "type": "config/device_registry/list"
    })

    result = []

    for device in devices:
        if not device_matches_model(device):
            continue

        transport = None
        ieee = None
        mqtt_topic_name = None

        for identifier in device.get("identifiers", []):
            if not (
                isinstance(identifier, (list, tuple))
                and len(identifier) >= 2
            ):
                continue

            domain = str(identifier[0]).lower()
            value = str(identifier[1])

            if domain == "zha":
                candidate = normalize_ieee(value)
                if re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){7}", candidate):
                    transport = TRANSPORT_ZHA
                    ieee = candidate
                    break

            if domain == "mqtt" and value.startswith("zigbee2mqtt_"):
                topic_name = value[len("zigbee2mqtt_"):]
                candidate = normalize_ieee(topic_name)
                if re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){7}", candidate):
                    transport = TRANSPORT_ZIGBEE2MQTT
                    ieee = candidate
                    mqtt_topic_name = ieee_to_z2m_topic_name(topic_name)
                    break

        if not ieee:
            continue

        model = str(device.get("model") or "")
        model_id = str(device.get("model_id") or "")
        manufacturer = str(device.get("manufacturer") or "")
        name = str(
            device.get("name_by_user")
            or device.get("name")
            or model_id
            or model
            or ieee
        )

        result.append({
            "device_id": device.get("id"),
            "ieee": ieee,
            "name": name,
            "model": model,
            "model_id": model_id,
            "manufacturer": manufacturer,
            "transport": transport,
            "mqtt_topic_name": mqtt_topic_name,
        })

    result.sort(
        key=lambda x: (
            x["name"].lower(),
            x["transport"],
            x["ieee"]
        )
    )

    return result


def get_zha_devices():
    return get_ota_devices()

def ha_post(path, data):
    require_ha_token()

    body = json.dumps(data).encode()

    request = urllib.request.Request(
        HA_REST + path,
        data=body,
        headers={
            "Authorization": f"Bearer {SUPERVISOR_TOKEN}",
            "Content-Type": "application/json"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            content = response.read()

            if not content:
                return None

            return json.loads(content.decode())

    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        raise RuntimeError(
            f"HA HTTP {e.code}: {detail}"
        ) from e


def write_ota_payload_to_zigbee(device, payload):
    """
    Jeden OTA string, dva možné transporty:
    - Zigbee2MQTT: MQTT topic zigbee2mqtt/<device>/set s ota_command
    - ZHA: přímý zápis custom clusteru 0xFC00/0x0001
    """
    if isinstance(device, str):
        device = {
            "ieee": normalize_ieee(device),
            "transport": TRANSPORT_ZHA,
            "mqtt_topic_name": None,
        }

    transport = device.get("transport") or TRANSPORT_ZHA

    if transport == TRANSPORT_ZIGBEE2MQTT:
        topic_name = device.get("mqtt_topic_name") or ieee_to_z2m_topic_name(device.get("ieee"))
        topic = f"{Z2M_TOPIC_PREFIX}/{topic_name}/set"
        mqtt_payload = json.dumps({Z2M_OTA_PROPERTY: payload}, separators=(",", ":"))
        print(f"OTA dispatch via Zigbee2MQTT topic={topic} bytes={len(payload.encode('utf-8'))}", flush=True)
        return ha_post(
            "/services/mqtt/publish",
            {
                "topic": topic,
                "payload": mqtt_payload,
                "qos": 0,
                "retain": False,
            }
        )

    print(f"OTA dispatch via ZHA ieee={device.get('ieee')} bytes={len(payload.encode('utf-8'))}", flush=True)
    return ha_post(
        "/services/zha/set_zigbee_cluster_attribute",
        {
            "ieee": normalize_ieee(device.get("ieee")),
            "endpoint_id": ZIGBEE_ENDPOINT,
            "cluster_id": ZIGBEE_CLUSTER_ID,
            "cluster_type": ZIGBEE_CLUSTER_TYPE,
            "attribute": ZIGBEE_ATTRIBUTE_ID,
            "value": payload
        }
    )


# ----------------------------------------------------------------------
# Payload
# ----------------------------------------------------------------------

def make_ota_payload(ssid, password, image, token):
    """
    Pevné pořadí:
        SSID|PASSWORD|HOST|CODE|TOKEN

    HTTPS port se přes Zigbee neposílá. ESP ho má v build configu.
    SHA256 se přes Zigbee neposílá; server ho váže do HMAC tokenu
    a zároveň vrací v HTTPS response headeru X-Firmware-SHA256.
    """
    code = ensure_image_code(image["filename"])
    fields = (ssid, password, OTA_HOST, code, token)

    for field in fields:
        if "|" in field or "\r" in field or "\n" in field or "\x00" in field:
            raise ValueError("SSID/heslo/host nesmí obsahovat |, CR, LF nebo NUL")

    return "|".join(fields)


def make_provision_payload(ssid, password, image, token):
    return "P|" + make_ota_payload(ssid, password, image, token)


def make_ota_check_payload(token):
    if not re.fullmatch(r"[0-9A-Za-z_-]{16}", token):
        raise ValueError("invalid OTA check token")
    return "C|" + token


def save_dispatch(ieee, image, success, error=None):
    with db_lock:
        with db_connect() as conn:
            conn.execute(
                """
                INSERT INTO ota_dispatch
                    (ieee, filename, sha256, revision,
                     sent_at, success, error)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    normalize_ieee(ieee),
                    image["filename"],
                    image["sha256"],
                    image["revision"],
                    int(time.time()),
                    1 if success else 0,
                    error
                )
            )


def get_last_dispatch(ieee, filename):
    with db_lock:
        with db_connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM ota_dispatch
                WHERE ieee = ?
                  AND filename = ?
                  AND success = 1
                ORDER BY sent_at DESC
                LIMIT 1
                """,
                (normalize_ieee(ieee), filename)
            ).fetchone()

    return dict(row) if row else None


# ----------------------------------------------------------------------
# HTTPS OTA server
# ----------------------------------------------------------------------

class OTAHandler(http.server.SimpleHTTPRequestHandler):

    ota_sha256 = None

    def log_message(self, fmt, *args):
        print(
            f"OTA {self.client_address[0]} - {fmt % args}",
            flush=True
        )

    def end_headers(self):
        if self.ota_sha256:
            self.send_header("X-Firmware-SHA256", self.ota_sha256)
        super().end_headers()

    def copyfile(self, source, outputfile):
        try:
            super().copyfile(source, outputfile)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def send_json(self, status, payload):
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        self.close_connection = True

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path not in ("/api/ota/check", "/api/device/challenge", "/api/device/enroll"):
            self.send_error(404, "Not found")
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_json(400, {"status": "ERROR", "error": "invalid_content_length"})
            return

        if length <= 0 or length > 8192:
            self.send_json(400, {"status": "ERROR", "error": "invalid_request_size"})
            return

        if parsed.path == "/api/device/challenge":
            try:
                request = json.loads(self.rfile.read(length).decode("utf-8"))
                device_id = normalize_device_id(request.get("device_id", ""))
                challenge = create_device_auth_challenge(device_id)
            except Exception as e:
                print(f"DEVICE_AUTH_CHALLENGE rejected: {e}", flush=True)
                self.send_json(400, {"status": "ERROR", "error": "invalid_device_id"})
                return

            self.send_json(200, {
                "protocol": 1,
                "command": "DEVICE_AUTH_CHALLENGE",
                "status": DEVICE_STATE_AUTH_CHALLENGE_PENDING,
                "device_id": challenge.device_id,
                "message_id": challenge.message_id,
                "challenge": challenge.challenge.hex(),
                "ttl_seconds": device_challenges.ttl_seconds,
            })
            return

        if parsed.path == "/api/device/enroll":
            try:
                request = json.loads(self.rfile.read(length).decode("utf-8"))
                result = validate_device_enrollment(request)
            except Exception as e:
                print(f"DEVICE_ENROLL rejected: {e}", flush=True)
                self.send_json(400, {"status": "AUTH_FAILED", "error": str(e)})
                return

            print(
                "DEVICE_ENROLL accepted "
                f"device_id={result['device_id']} status={result['status']} "
                f"pkfp={result['public_key_fingerprint']}",
                flush=True
            )
            self.send_json(200, {
                "protocol": 1,
                "command": "DEVICE_ENROLL",
                **result,
            })
            return

        try:
            request = json.loads(self.rfile.read(length).decode("utf-8"))
            device_id = validate_metadata_value("device_id", request.get("device_id"), 96)
            product = validate_metadata_value("product", request.get("product"))
            hardware_revision = validate_metadata_value("hardware_revision", request.get("hardware_revision"))
            channel = validate_metadata_value("firmware_channel", request.get("firmware_channel"))
            current_version = validate_metadata_value("firmware_version", request.get("firmware_version"), 32)
        except Exception as e:
            print(f"OTA check rejected: {e}", flush=True)
            self.send_json(400, {"status": "ERROR", "error": "invalid_metadata"})
            return

        image = latest_compatible_firmware(
            product,
            hardware_revision,
            channel,
            current_version
        )

        if image is None:
            print(
                "OTA check NO_UPDATE "
                f"device_id={device_id} product={product} "
                f"hw={hardware_revision} channel={channel} "
                f"current={current_version}",
                flush=True
            )
            self.send_json(200, {"protocol": 1, "status": "NO_UPDATE"})
            return

        print(
            "OTA check UPDATE "
            f"device_id={device_id} product={product} "
            f"hw={hardware_revision} channel={channel} "
            f"current={current_version} offer={image['version']} "
            f"filename={image['filename']}",
            flush=True
        )
        self.send_json(200, firmware_manifest(image))

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        code = os.path.basename(parsed.path)

        image = resolve_image_code(code)

        if not image:
            self.send_error(404, "Firmware code not found")
            return

        auth = self.headers.get("Authorization")

        if not auth or not auth.startswith("Bearer "):
            self.send_unauthorized()
            return

        token = auth[7:].strip()
        device_id = self.headers.get("X-Device-ID")

        if not device_id:
            self.send_unauthorized()
            return

        if not ota_validate_token(
            token,
            code,
            device_id,
            image["sha256"]
        ):
            self.send_unauthorized()
            return

        path = os.path.join(FIRMWARE_DIR, image["filename"])

        if not os.path.isfile(path):
            self.send_error(404, "Firmware not found")
            return

        self.ota_sha256 = image["sha256"]
        self.path = "/" + image["filename"]
        super().do_GET()

    def send_unauthorized(self):
        body = b"Unauthorized\n"

        self.send_response(401)
        self.send_header("WWW-Authenticate", "Bearer")
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()

        self.wfile.write(body)
        self.wfile.flush()
        self.close_connection = True


# ----------------------------------------------------------------------
# Ingress UI
# ----------------------------------------------------------------------

def fmt_time(timestamp):
    if not timestamp:
        return ""

    return time.strftime(
        "%Y-%m-%d %H:%M:%S",
        time.localtime(timestamp)
    )


def short_sha(value):
    value = str(value or "")
    return value[:12] if value else ""


def page_html(message=""):
    images = scan_firmware_images()

    try:
        devices = get_zha_devices()
        device_error = ""
    except Exception as e:
        devices = []
        device_error = str(e)

    image_options = []
    firmware_rows = []

    for image in images:
        code = ensure_image_code(image["filename"])
        active = "active" if image.get("active") else "inactive"
        label = (
            f'{code} -> {image["filename"]} | '
            f'{image.get("ota_ecosystem")}/{image["product"]}/{image["hardware_revision"]}/{image["channel"]} | '
            f'v={image["version"]} | '
            f'sv={image["secure_version"]} | '
            f'rev={image["revision"]} | '
            f'{active} | '
            f'{image["size"]} B'
        )

        image_options.append(
            '<option value="{}">{}</option>'.format(
                html.escape(image["filename"], quote=True),
                html.escape(label)
            )
        )
        firmware_rows.append(
            """
            <tr>
                <td><code>{code}</code></td>
                <td>{filename}</td>
                <td>{product}</td>
                <td>{model}</td>
                <td>{role}</td>
                <td>{hw}</td>
                <td>{channel}</td>
                <td>{version}</td>
                <td>{revision}</td>
                <td>{active}</td>
                <td>{size}</td>
                <td><code>{sha}</code></td>
            </tr>
            """.format(
                code=html.escape(code),
                filename=html.escape(image["filename"]),
                product=html.escape(image.get("product") or ""),
                model=html.escape(image.get("device_model") or ""),
                role=html.escape(image.get("product_role") or ""),
                hw=html.escape(image.get("hardware_revision") or ""),
                channel=html.escape(image.get("channel") or ""),
                version=html.escape(str(image.get("version") or "")),
                revision=html.escape(str(image.get("revision") or "")),
                active=html.escape(active),
                size=html.escape(str(image.get("size") or "")),
                sha=html.escape(short_sha(image.get("sha256"))),
            )
        )

    device_rows = []
    registered_rows = []
    update_rows = []
    project_line = (
        f"ecosystem={runtime_config['ota']['ecosystem']} | "
        "firmware identity is loaded from the selected .release.json"
    )
    ha_device_map = {device["ieee"]: device for device in devices}
    registry_map = {record["device_id"]: record for record in list_device_records()}
    all_device_ids = sorted(set(ha_device_map) | set(registry_map))

    for device_id in all_device_ids:
        ha_device = ha_device_map.get(device_id, {})
        registry = registry_map.get(device_id)
        provisioning = get_device_provisioning(device_id)
        state = (registry or {}).get("state") or DEVICE_STATE_DISCOVERED
        provision_status = "NOT_PROVISIONED"
        provision_detail = ""
        if provisioning:
            provision_status = provisioning.get("status") or "UNKNOWN"
            provision_detail = (
                f"ssid={provisioning.get('wifi_ssid') or ''} | "
                f"{provisioning.get('wifi_security') or ''} ch={provisioning.get('wifi_channel') or 0} | "
                f"ota={provisioning.get('ota_host') or ''}:{provisioning.get('ota_port') or ''} | "
                f"fw={provisioning.get('firmware_filename') or ''} | "
                f"{fmt_time(provisioning.get('updated_at'))}"
            )
            if provisioning.get("error"):
                provision_detail += f" | {provisioning.get('error')}"
        elif get_last_dispatch(device_id, "remotecontrol7andEncoder.bin"):
            provision_status = "LEGACY_UNKNOWN"
            provision_detail = "previous dispatch exists, config was not stored in registry"

        registered_rows.append(
            """
            <tr>
                <td><code>{device_id}</code></td>
                <td>{name}</td>
                <td>{transport}</td>
                <td>{state}</td>
                <td>{model}</td>
                <td>{role}</td>
                <td>{hw}</td>
                <td>{fw_version}</td>
                <td>{pkfp}</td>
                <td>{provision_status}</td>
                <td>{provision_detail}</td>
            </tr>
            """.format(
                device_id=html.escape(device_id),
                name=html.escape(ha_device.get("name") or ""),
                transport=html.escape(ha_device.get("transport") or ""),
                state=html.escape(state),
                model=html.escape((registry or {}).get("device_model") or ha_device.get("model") or ""),
                role=html.escape((registry or {}).get("product_role") or ""),
                hw=html.escape((registry or {}).get("hardware_revision") or ""),
                fw_version=html.escape((registry or {}).get("firmware_version") or ""),
                pkfp=html.escape(short_sha((registry or {}).get("device_public_key_fingerprint")) or "missing"),
                provision_status=html.escape(provision_status),
                provision_detail=html.escape(provision_detail),
            )
        )

        update = device_update_status(registry) if registry else {
            "status": "ENROLLMENT_REQUIRED",
            "latest": None,
            "current_version": "",
        }
        latest = update["latest"]
        latest_label = ""
        latest_sha = ""
        last_dispatch = None
        if latest:
            latest_label = (
                f"{latest.get('filename')} v={latest.get('version')} "
                f"rev={latest.get('revision')}"
            )
            latest_sha = short_sha(latest.get("sha256"))
            last_dispatch = get_last_dispatch(device_id, latest["filename"])
        update_rows.append(
            """
            <tr>
                <td><code>{device_id}</code></td>
                <td>{current}</td>
                <td>{latest}</td>
                <td>{status}</td>
                <td><code>{sha}</code></td>
                <td>{last_sent}</td>
            </tr>
            """.format(
                device_id=html.escape(device_id),
                current=html.escape(update["current_version"] or "unknown"),
                latest=html.escape(latest_label or "none"),
                status=html.escape(update["status"]),
                sha=html.escape(latest_sha),
                last_sent=html.escape(fmt_time((last_dispatch or {}).get("sent_at"))),
            )
        )

    for device in devices:
        registry = get_device_record(device["ieee"])
        auth_line = "enrollment=DISCOVERED"
        if registry:
            auth_line = (
                f"enrollment={registry.get('state') or DEVICE_STATE_DISCOVERED} | "
                f"hw={registry.get('hardware_revision') or 'unknown'} | "
                f"role={registry.get('product_role') or 'unknown'} | "
                f"pkfp={registry.get('device_public_key_fingerprint') or 'missing'}"
            )
        device_rows.append(
            """
            <label class="device">
                <input type="checkbox" name="ieee" value="{ieee}">
                <span>
                    <b>{name}</b><br>
                    <small>{ieee} | {transport} {topic} | {manufacturer} {model_id} {model}</small><br>
                    <small>OTA identity: {project_line}</small><br>
                    <small>Device auth: {auth_line}</small>
                </span>
            </label>
            """.format(
                ieee=html.escape(device["ieee"], quote=True),
                name=html.escape(device["name"]),
                manufacturer=html.escape(device["manufacturer"]),
                model_id=html.escape(device.get("model_id") or ""),
                model=html.escape(device["model"]),
                transport=html.escape(device.get("transport") or ""),
                topic=html.escape(device.get("mqtt_topic_name") or ""),
                project_line=html.escape(project_line),
                auth_line=html.escape(auth_line),
            )
        )

    if not image_options:
        image_options.append(
            '<option value="">Žádný .bin soubor</option>'
        )

    if not firmware_rows:
        firmware_rows.append('<tr><td colspan="12">Žádný firmware bin nebyl nalezen.</td></tr>')

    if not registered_rows:
        registered_rows.append('<tr><td colspan="11">Žádné ESP zařízení není v HA/OTA registru.</td></tr>')

    if not update_rows:
        update_rows.append('<tr><td colspan="6">Žádné registrované ESP zatím nemá enrollment metadata pro kontrolu binu.</td></tr>')

    if not device_rows:
        device_rows.append(
            "<p>Žádné zařízení ESP32-C6-* pro OTA nebylo nalezeno.</p>"
        )

    if device_error:
        device_rows.insert(
            0,
            '<p class="error">HA registry: {}</p>'.format(
                html.escape(device_error)
            )
        )

    message_html = ""

    if message:
        message_html = (
            '<div class="message">{}</div>'.format(
                message
            )
        )

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ESP OTA</title>
<style>
body {{
    font-family: sans-serif;
    margin: 24px;
    max-width: 1280px;
}}
label {{
    display: block;
    margin-top: 12px;
}}
input[type=text],
input[type=password],
select {{
    width: 100%;
    max-width: 650px;
    padding: 8px;
    box-sizing: border-box;
}}
.devices {{
    margin-top: 8px;
    border: 1px solid #aaa;
    padding: 8px 12px;
    max-width: 650px;
}}
.device {{
    display: flex;
    gap: 8px;
    align-items: flex-start;
    padding: 7px 0;
    margin: 0;
}}
button {{
    margin-top: 18px;
    padding: 9px 16px;
}}
.message {{
    margin: 12px 0;
    padding: 10px;
    border: 1px solid #888;
}}
.error {{
    color: #b00020;
}}
small {{
    opacity: .75;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    margin: 10px 0 24px;
    font-size: 13px;
}}
th,
td {{
    border: 1px solid #ccc;
    padding: 6px 8px;
    text-align: left;
    vertical-align: top;
}}
th {{
    background: #f3f3f3;
}}
code {{
    white-space: nowrap;
}}
.table-wrap {{
    overflow-x: auto;
}}
</style>
<script>
function toggleAll(source) {{
    document.querySelectorAll('input[name="ieee"]').forEach(
        x => x.checked = source.checked
    );
}}
</script>
</head>
<body>
<h2>ESP OTA Server</h2>

{message_html}

<h3>Firmware biny</h3>
<div class="table-wrap">
<table>
    <thead>
        <tr>
            <th>Code</th>
            <th>Soubor</th>
            <th>Product</th>
            <th>Model</th>
            <th>Role</th>
            <th>HW</th>
            <th>Channel</th>
            <th>Verze</th>
            <th>Rev</th>
            <th>Active</th>
            <th>Velikost</th>
            <th>SHA</th>
        </tr>
    </thead>
    <tbody>
        {''.join(firmware_rows)}
    </tbody>
</table>
</div>

<h3>Registrované ESP moduly</h3>
<div class="table-wrap">
<table>
    <thead>
        <tr>
            <th>Device ID</th>
            <th>HA název</th>
            <th>Transport</th>
            <th>Auth stav</th>
            <th>Model</th>
            <th>Role</th>
            <th>HW</th>
            <th>FW</th>
            <th>PK fp</th>
            <th>Provisioning</th>
            <th>Config</th>
        </tr>
    </thead>
    <tbody>
        {''.join(registered_rows)}
    </tbody>
</table>
</div>

<h3>Aktuálnost binů na registrovaných ESP</h3>
<div class="table-wrap">
<table>
    <thead>
        <tr>
            <th>Device ID</th>
            <th>Aktuální FW</th>
            <th>Nejnovější kompatibilní bin</th>
            <th>Stav</th>
            <th>SHA</th>
            <th>Naposledy posláno</th>
        </tr>
    </thead>
    <tbody>
        {''.join(update_rows)}
    </tbody>
</table>
</div>

<form method="POST" action="send">
    <label>Firmware:</label>
    <select name="file" required>
        {''.join(image_options)}
    </select>

    <label>Wi-Fi SSID:</label>
    <input type="text" name="ssid" autocomplete="off" placeholder="ulozeno v add-on options">

    <label>Wi-Fi heslo:</label>
    <input type="password" name="password" autocomplete="new-password" placeholder="ulozeno v add-on options">

    <h3>ESP32-C6 zařízení</h3>

    <label>
        <input type="checkbox" onclick="toggleAll(this)">
        Vybrat všechna
    </label>

    <div class="devices">
        {''.join(device_rows)}
    </div>

    <button type="submit">Poslat OTA přes Zigbee</button>
</form>
</body>
</html>
"""


class UIHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        print(
            f"UI {self.client_address[0]} - {fmt % args}",
            flush=True
        )

    def send_html(self, body, status=200):
        body = body.encode("utf-8")

        self.send_response(status)
        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8"
        )
        self.send_header(
            "Content-Length",
            str(len(body))
        )
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path in ("", "/", "/index.html"):
            self.send_html(page_html())
            return

        self.send_error(404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path not in ("/send", "send"):
            self.send_error(404)
            return

        length = int(
            self.headers.get("Content-Length", "0")
        )

        raw = self.rfile.read(length).decode("utf-8")

        form = urllib.parse.parse_qs(
            raw,
            keep_blank_values=True
        )

        filename = os.path.basename(
            form.get("file", [""])[0]
        )

        ssid = form.get("ssid", [""])[0].strip() or runtime_config["wifi"]["ssid"]
        password = form.get("password", [""])[0] or runtime_config["wifi"]["password"]

        selected_ieees = [
            normalize_ieee(x)
            for x in form.get("ieee", [])
            if x.strip()
        ]

        if not filename:
            self.send_html(
                page_html('<span class="error">Chybí firmware.</span>'),
                400
            )
            return

        if not ssid:
            self.send_html(
                page_html('<span class="error">Chybí SSID.</span>'),
                400
            )
            return

        if not selected_ieees:
            self.send_html(
                page_html(
                    '<span class="error">'
                    'Není vybrané žádné ESP32-C6.'
                    '</span>'
                ),
                400
            )
            return

        image = get_image(filename)

        if image is None:
            self.send_html(
                page_html(
                    '<span class="error">'
                    'Firmware nebyl nalezen.'
                    '</span>'
                ),
                404
            )
            return

        # Nepřijmeme IEEE, které uživatel podstrčí ručně.
        # Musí být právě v aktuálním seznamu ESP32-C6 z HA.
        try:
            allowed_devices = {
                x["ieee"]: x
                for x in get_ota_devices()
            }
        except Exception as e:
            self.send_html(
                page_html(
                    '<span class="error">'
                    f'Nelze načíst HA registry: {html.escape(str(e))}'
                    '</span>'
                ),
                500
            )
            return

        selected_devices = [
            allowed_devices[ieee]
            for ieee in selected_ieees
            if ieee in allowed_devices
        ]

        if not selected_devices:
            self.send_html(
                page_html(
                    '<span class="error">'
                    'Vybraná zařízení už nejsou dostupná v seznamu ESP32-C6.'
                    '</span>'
                ),
                400
            )
            return

        results = []

        for device in selected_devices:
            ieee = device["ieee"]
            try:
                ensure_device_can_receive_provisioning(ieee)
            except PermissionError as e:
                error = str(e)
                save_device_provisioning(device, image, "DENIED", error, ssid)
                save_dispatch(
                    ieee,
                    image,
                    False,
                    error
                )
                results.append(
                    f'<li class="error"><b>{html.escape(ieee)}</b>: '
                    f'{html.escape(error)}</li>'
                )
                continue

            code = ensure_image_code(image["filename"])
            token = ota_create_token(
                code,
                ieee,
                image["sha256"]
            )

            provision_payload = make_provision_payload(
                ssid,
                password,
                image,
                token
            )
            check_payload = make_ota_check_payload(token)

            print(
                "OTA dispatch prepared "
                f"transport={device.get('transport')} "
                f"ieee={ieee} code={code} "
                f"sha256={image['sha256']} "
                f"token_len={len(token)} "
                f"provision_len={len(provision_payload.encode('utf-8'))} "
                f"check_len={len(check_payload.encode('utf-8'))}",
                flush=True
            )

            try:
                write_ota_payload_to_zigbee(
                    device,
                    provision_payload
                )
                time.sleep(0.7)
                write_ota_payload_to_zigbee(
                    device,
                    check_payload
                )
                save_device_provisioning(device, image, "SENT", None, ssid)

                save_dispatch(
                    ieee,
                    image,
                    True
                )

                results.append(
                    f"<li><b>{html.escape(ieee)}</b>: "
                    f"provision+ota_check odesláno přes {html.escape(device.get('transport') or '')}, "
                    f"{len(provision_payload.encode('utf-8'))}+{len(check_payload.encode('utf-8'))} B</li>"
                )

            except Exception as e:
                with tokens_lock:
                    tokens.pop(token, None)

                error = str(e)

                save_dispatch(
                    ieee,
                    image,
                    False,
                    error
                )
                save_device_provisioning(device, image, "FAILED", error, ssid)

                results.append(
                    f'<li class="error"><b>{html.escape(ieee)}</b>: '
                    f'{html.escape(error)}</li>'
                )

        message = (
            "<b>Firmware:</b> "
            + html.escape(image["filename"])
            + " | code "
            + html.escape(ensure_image_code(image["filename"]))
            + " | rev "
            + str(image["revision"])
            + "<br><ul>"
            + "".join(results)
            + "</ul>"
        )

        self.send_html(
            page_html(message)
        )


# ----------------------------------------------------------------------
# Start
# ----------------------------------------------------------------------

def start_servers():
    load_runtime_config()
    init_db()
    get_server_sign_private_key()
    scan_firmware_images()

    ota_server = http.server.ThreadingHTTPServer(
        ("0.0.0.0", HTTPS_PORT),
        OTAHandler
    )

    context = ssl.SSLContext(
        ssl.PROTOCOL_TLS_SERVER
    )

    context.load_cert_chain(
        certfile=CERT_FILE,
        keyfile=KEY_FILE
    )

    ota_server.socket = context.wrap_socket(
        ota_server.socket,
        server_side=True
    )

    ui_server = http.server.ThreadingHTTPServer(
        ("0.0.0.0", UI_PORT),
        UIHandler
    )

    threading.Thread(
        target=ota_server.serve_forever,
        daemon=True
    ).start()

    print(
        f"OTA server is running on port {HTTPS_PORT}",
        flush=True
    )

    print(
        f"OTA server UI running on port {UI_PORT}",
        flush=True
    )

    ui_server.serve_forever()


if __name__ == "__main__":
    start_servers()
