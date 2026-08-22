from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import threading
import time
import urllib.request
from dataclasses import dataclass, field

import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from activity import record_converter_publish
from firmware_publish import _b64url_decode, _send_json, _validated_publisher
from publish_guard import require_verified_firmware_publication

MAX_BODY_BYTES = 512 * 1024
PUBLISH_DOMAIN = b"JaroslavZemanESP|z2m-publish-v1|"
PROJECT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,96}$")
OPTIONS_PATH = "/data/options.json"
SUPERVISOR_TOKEN = os.environ.get("SUPERVISOR_TOKEN", "")
MQTT_TIMEOUT_SECONDS = 20


def _load_options() -> dict:
    try:
        with open(OPTIONS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _mqtt_service() -> dict:
    if not SUPERVISOR_TOKEN:
        raise ValueError("supervisor_token_missing_for_mqtt_service")
    request = urllib.request.Request("http://supervisor/services/mqtt", headers={"Authorization": f"Bearer {SUPERVISOR_TOKEN}"})
    with urllib.request.urlopen(request, timeout=10) as response:
        payload = json.loads(response.read().decode("utf-8"))
    data = payload.get("data", payload)
    return {"host": data["host"], "port": int(data["port"]), "username": data.get("username") or "", "password": data.get("password") or ""}


def _new_mqtt_client(client_id: str):
    try:
        return mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
    except (AttributeError, TypeError):
        return mqtt.Client(client_id=client_id)


@dataclass
class _Z2MBridgeSession:
    base_topic: str
    service: dict
    client: mqtt.Client = field(init=False)
    connected: threading.Event = field(default_factory=threading.Event)
    converters_event: threading.Event = field(default_factory=threading.Event)
    response_event: threading.Event = field(default_factory=threading.Event)
    lock: threading.Lock = field(default_factory=threading.Lock)
    converters: dict[str, str] = field(default_factory=dict)
    response_payload: dict | None = None
    expected_transaction: int | None = None

    def __post_init__(self):
        self.client = _new_mqtt_client(f"ota-z2m-publish-{os.getpid()}-{time.time_ns() & 0xFFFF:x}")
        if self.service["username"]:
            self.client.username_pw_set(self.service["username"], self.service["password"])
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message

    @property
    def converters_topic(self) -> str:
        return f"{self.base_topic}/bridge/converters"

    def _on_connect(self, client, userdata, flags, reason_code, properties=None):
        code = int(reason_code) if hasattr(reason_code, "__int__") else reason_code
        if code != 0:
            return
        client.subscribe(self.converters_topic, qos=0)
        client.subscribe(f"{self.base_topic}/bridge/response/converter/+", qos=0)
        self.connected.set()

    def _on_message(self, client, userdata, message):
        try:
            payload = json.loads(message.payload.decode("utf-8"))
        except Exception:
            return
        if message.topic == self.converters_topic:
            found = {}
            if isinstance(payload, list):
                for item in payload:
                    if isinstance(item, dict):
                        name, code = str(item.get("name") or ""), item.get("code")
                        if name and isinstance(code, str):
                            found[name] = code
            with self.lock:
                self.converters = found
            self.converters_event.set()
            return
        prefix = f"{self.base_topic}/bridge/response/converter/"
        if not message.topic.startswith(prefix) or not isinstance(payload, dict):
            return
        with self.lock:
            if self.expected_transaction is None or payload.get("transaction") != self.expected_transaction:
                return
            self.response_payload = payload
        self.response_event.set()

    def start(self):
        self.client.connect(self.service["host"], self.service["port"], keepalive=30)
        self.client.loop_start()
        if not self.connected.wait(MQTT_TIMEOUT_SECONDS):
            self.stop()
            raise ValueError("zigbee2mqtt_mqtt_connect_timeout")
        self.converters_event.wait(3)

    def stop(self):
        try:
            self.client.disconnect()
        except Exception:
            pass
        try:
            self.client.loop_stop()
        except Exception:
            pass

    def snapshot(self):
        with self.lock:
            return dict(self.converters)

    def _request(self, action: str, body: dict):
        transaction = int(time.time_ns() & 0x7FFFFFFF)
        body = dict(body)
        body["transaction"] = transaction
        with self.lock:
            self.expected_transaction = transaction
            self.response_payload = None
        self.response_event.clear()
        result = self.client.publish(f"{self.base_topic}/bridge/request/converter/{action}", json.dumps(body, separators=(",", ":")), qos=1, retain=False)
        if result.rc != mqtt.MQTT_ERR_SUCCESS:
            raise ValueError(f"zigbee2mqtt_converter_{action}_publish_failed_rc_{result.rc}")
        if not self.response_event.wait(MQTT_TIMEOUT_SECONDS):
            raise ValueError(f"zigbee2mqtt_converter_{action}_response_timeout")
        with self.lock:
            response = dict(self.response_payload or {})
            self.expected_transaction = None
        if response.get("status") != "ok":
            raise ValueError(f"zigbee2mqtt_converter_{action}_failed:{response.get('error') or 'unknown_error'}")
        return response

    def save(self, name, code):
        return self._request("save", {"name": name, "code": code})

    def remove(self, name):
        return self._request("remove", {"name": name})

    def wait_until(self, predicate, description):
        deadline = time.monotonic() + MQTT_TIMEOUT_SECONDS
        while True:
            snapshot = self.snapshot()
            if predicate(snapshot):
                return snapshot
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError(f"zigbee2mqtt_converter_verify_timeout:{description}")
            self.converters_event.clear()
            self.converters_event.wait(min(remaining, 2))


def _deploy_via_zigbee2mqtt(base_topic, name, code, legacy_names):
    session = _Z2MBridgeSession(base_topic=base_topic, service=_mqtt_service())
    session.start()
    try:
        before = session.snapshot()
        previous_code = before.get(name)
        session.save(name, code)
        current = session.wait_until(lambda c: c.get(name) == code, f"save:{name}")
        removed = []
        for legacy in legacy_names:
            if legacy in current:
                session.remove(legacy)
                current = session.wait_until(lambda c, n=legacy: n not in c, f"remove:{legacy}")
                removed.append(legacy)
        final = session.wait_until(lambda c: c.get(name) == code and all(x not in c for x in legacy_names), f"final:{name}")
        return {"changed": previous_code != code or bool(removed), "removed": removed, "loaded_names": sorted(final), "previous_present": name in before}
    finally:
        session.stop()


def handle_zigbee2mqtt_publish(handler) -> None:
    try:
        length = int(handler.headers.get("Content-Length", "0"))
        if length <= 0 or length > MAX_BODY_BYTES:
            raise ValueError("invalid_zigbee2mqtt_bundle_size")
        raw = handler.rfile.read(length)
        if len(raw) != length:
            raise ValueError("truncated_zigbee2mqtt_bundle")
        request = json.loads(raw.decode("utf-8"))
        project = str(request.get("project") or "")
        if not PROJECT_RE.fullmatch(project):
            raise ValueError("invalid_project_name")
        if int(request.get("schema") or 0) != 2:
            raise ValueError("unsupported_zigbee2mqtt_publish_schema")
        version = str(request.get("firmware_version") or "").strip()
        files = request.get("files")
        expected_name = f"{project}.mjs"
        if not version or not isinstance(files, dict) or set(files) != {expected_name}:
            raise ValueError("invalid_single_converter_file_set")
        data = base64.b64decode(str(files[expected_name]), validate=True)
        if len(data) > 256 * 1024:
            raise ValueError("zigbee2mqtt_file_too_large")
        marker = re.search(rb"^// JarZem firmware build: (.+)$", data, re.M)
        if not marker or marker.group(1).decode().strip() != version:
            raise ValueError("zigbee2mqtt_firmware_build_marker_mismatch")
        code = data.decode("utf-8")
        digest = hashlib.sha256(expected_name.encode() + b"\0" + data + b"\0").hexdigest()
        cert, publisher, _registered = _validated_publisher(str(request.get("certificate") or ""))
        signature = _b64url_decode(str(request.get("signature") or ""))
        cert.public_key().verify(signature, PUBLISH_DOMAIN + project.encode() + b"|" + digest.encode(), ec.ECDSA(hashes.SHA256()))

        # MJS is accepted only after a signed BIN from the same build and publisher
        # has already been verified and persisted by the OTA server.
        require_verified_firmware_publication(version, publisher['device_id'])

        options = _load_options()
        base_topic = str(options.get("mqtt_base_topic") or "zigbee2mqtt")
        deploy = _deploy_via_zigbee2mqtt(base_topic, expected_name, code, [f"{project}.project.mjs", f"{project}.ota.mjs"])
        file_sha = hashlib.sha256(data).hexdigest()
        record_converter_publish(version=version, project=project, filename=expected_name, sha256=file_sha, publisher_device_id=publisher['device_id'], loaded=True)
        print(f"Zigbee2MQTT converter deployed through MQTT API file={expected_name} build={version} changed={int(deploy['changed'])} sha256={file_sha[:12]} bytes={len(data)} removed={deploy['removed']}", flush=True)
        print(f"Zigbee2MQTT bridge/converters verified file={expected_name} build_marker={version} loaded=1", flush=True)
        _send_json(handler, 201, {"status":"PUBLISHED","project":project,"firmware_version":version,"changed":deploy["changed"],"transport":"zigbee2mqtt-mqtt-api","files":{expected_name:file_sha},"removed":deploy["removed"]})
    except Exception as exc:
        print(f"Zigbee2MQTT converter publish rejected: {exc}", flush=True)
        _send_json(handler, 400, {"status":"ERROR","error":str(exc)})
