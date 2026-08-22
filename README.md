# OTA Server

Home Assistant add-on providing secure ESP firmware delivery, provisioning over Zigbee2MQTT, manufacturing PKI, automatic Zigbee2MQTT converter deployment and persistent OTA lifecycle history.

This README is the authoritative human-readable description of the trust model and the expected end-to-end workflow.

## 1. Trust model

The ecosystem uses one offline P-256 Root CA.

```text
OFFLINE CA workstation
  root_ca_cert.pem          public
  root_ca_private.pem       PRIVATE, password protected
          |
          +-- signs OTA server certificate
          +-- signs one certificate for every ESP device

HOME ASSISTANT / OTA
  /share/ota_server/cert/root_ca_cert.pem
  /share/ota_server/cert/ota_server_cert.pem
  /share/ota_server/cert/ota_server_private.pem
  /share/ota_server/cert/ota_server_public.pem
  MySQL device certificate registry

ESP
  device_private.pem        unique private P-256 key
  device_cert.pem           Root-CA-signed device certificate
  root_ca_cert.pem          public Root CA
  ota_server_cert.pem       public OTA certificate
```

The Root CA private key never goes to Home Assistant, the OTA server, an ESP firmware image or Git. Every ESP has its own private key. Compromise of one ESP key does not expose the CA or another ESP key.

During development the ESP private key may be embedded in flash. Moving the private-key backend later to eFuse/protected storage does not change the protocol.

## 2. Creating the Root CA and OTA identity

The repository contains a standalone helper:

```bash
python setup_certificates.py
```

For a new ecosystem only:

```bash
python setup_certificates.py --init-ca
```

The helper creates or reuses:

```text
<ca-dir>/root_ca_cert.pem
<ca-dir>/root_ca_private.pem
```

and issues:

```text
ota_server_cert.pem
ota_server_private.pem
ota_server_public.pem
root_ca_cert.pem
```

The OTA certificate contains:

```text
urn:jarzem:esp:pki:role:ota-server
```

When `--ssh-target` is used, only the OTA certificate material and public Root CA are copied to `/share/ota_server/cert/`. `root_ca_private.pem` is never copied.

## 3. ESP device identity

A device is represented by a Root-CA-signed certificate, not by a bare public key.

The device certificate may contain:

```text
urn:jarzem:esp:pki:role:device
urn:jarzem:esp:pki:device:<IEEE>
urn:jarzem:esp:pki:group:<group>
urn:jarzem:esp:pki:model:<model>
urn:jarzem:esp:pki:product-role:<role>
urn:jarzem:esp:pki:hardware:<revision>
urn:jarzem:esp:pki:chip:<chip>
urn:jarzem:esp:pki:flash:<size>
```

OTA validates the device certificate against `/share/ota_server/cert/root_ca_cert.pem` before trusting the public key inside it. Validation includes the Root CA signature, validity period, `CA:FALSE`, `digitalSignature`, `clientAuth`, P-256 key type, device role and IEEE identity.

The public certificate is registered through the manufacturing HTTPS service on port `8451`:

```text
GET  /api/manufacturing/root-ca.pem
GET  /api/manufacturing/ota-server.pem
GET  /api/manufacturing/ota-public.pem
GET  /api/manufacturing/health
POST /api/manufacturing/register-device
```

Runtime provisioning then proves that the ESP owns the private key corresponding to that registered certificate.

## 4. Installing OTA into a new ESP-IDF project

OTA integration is owned by this repository. Project-specific application code remains in the ESP project.

The one-time installer is:

```bash
python tools/esp_ota/install.py <ESP_PROJECT>
```

Typical explicit invocation:

```bash
python tools/esp_ota/install.py D:/Espressif/project/my-device \
  --ca-dir D:/ESP-PKI/ca \
  --manufacturing-url https://192.168.2.120:8451 \
  --publish-url https://192.168.2.120:8443
```

The installer is repeatable and performs these jobs:

1. verifies that the target is an ESP-IDF Git project;
2. installs this repository as Git submodule `external/ota_server`;
3. patches top-level CMake to load `jarzem_secure_ota`;
4. adds the OTA component dependency without modifying application Zigbee source;
5. separates the project-only Zigbee2MQTT converter into `zigbee2mqtt/*.project.mjs`;
6. creates the ESP identity if none exists;
7. registers the public device certificate with OTA;
8. downloads the public CA/OTA trust material;
9. creates `.jarzem_ota/identity.json` and `.jarzem_ota/project.json`;
10. leaves an existing device identity untouched on subsequent runs.

### Standalone ESP identity helper

The identity work is intentionally separated into:

```text
tools/esp_ota/create_device_identity.py
```

The installer calls this helper for a new project. It can also be used directly when manufacturing/debugging requires identity creation without running the complete installer.

For an existing project that already has `device_credentials/`, use:

```text
tools/esp_ota/adopt_existing_identity.py
```

Never regenerate a device identity merely because firmware changes. One physical ESP keeps the same private key and certificate across builds and OTA updates.

The resulting local ESP credential directory is:

```text
device_credentials/
  device_private.pem      PRIVATE
  device_cert.pem         public and Root-CA-signed
  root_ca_cert.pem        public
  ota_server_cert.pem     public
  ota_server_public.pem   public
```

Build validation may read these files but never regenerates or replaces them.

## 5. What CMake does on every firmware build

After installation, `idf.py build` automatically performs the OTA integration steps.

### Firmware BIN

The build produces the normal ESP-IDF `.bin` and release metadata. `tools/esp_ota/publish_firmware.py` then:

1. calculates SHA-256 of the complete BIN;
2. reads the project/device metadata;
3. creates a canonical publish message containing filename, BIN SHA-256 and metadata;
4. signs that canonical message with the ESP private P-256 key;
5. sends the BIN, metadata, ESP certificate and ECDSA signature over HTTPS to `/api/firmware/publish`.

The OTA server does not trust the supplied certificate merely because it contains a public key. It first verifies the certificate against the Root CA and against the currently registered certificate fingerprint. It then verifies the ECDSA publish signature and metadata bindings. While receiving the BIN it calculates SHA-256 again and refuses the upload if the received bytes do not match the signed digest.

Only after all checks pass is the BIN atomically installed in `/share/ota_server/firmware`.

### Zigbee2MQTT MJS

The project-only converter and OTA converter are combined during build into exactly one deployable file:

```text
build/zigbee2mqtt/<project>.mjs
```

The first line identifies the firmware build:

```javascript
// JarZem firmware build: <firmware_version>
```

BIN and MJS therefore carry the same build identity.

The build calculates the MJS SHA-256 and signs a separate canonical `z2m-publish-v1` message with the same ESP private key. The request contains the ESP certificate and is sent to `/api/zigbee2mqtt/publish`.

OTA accepts the MJS only when all of the following are true:

- its ESP certificate is valid under the configured Root CA;
- the certificate is the currently registered certificate for that ESP;
- the MJS ECDSA signature is valid;
- the MJS build marker equals `firmware_version`;
- a verified BIN with the same build and the same publisher ESP has already been accepted.

The converter is then deployed through the official Zigbee2MQTT runtime MQTT API:

```text
zigbee2mqtt/bridge/request/converter/save
```

OTA waits for the corresponding response and for `zigbee2mqtt/bridge/converters` to contain exactly the uploaded code. No Zigbee2MQTT restart is required. Legacy `<project>.project.mjs` and `<project>.ota.mjs` external converters are removed through the matching converter API.

## 6. Runtime provisioning

Provisioning starts only when the user enables `Enable OTA` in Home Assistant. The switch gates provisioning; it does not disable authenticated firmware checks.

Home Assistant is only the UI. The cryptographic transport is directly:

```text
ESP <-> Zigbee2MQTT <-> MQTT <-> OTA server
```

The protocol uses endpoint `10`, manufacturer-specific cluster `0xFC00`:

```text
ESP -> OTA   H|counter|signatureESP
OTA -> ESP   A|random8-base64url|signatureOTA
ESP -> OTA   R|signatureESP
OTA -> ESP   P|base64url(AES-256-GCM(ciphertext||tag16))
```

In human terms:

- `H`: start a new authenticated provisioning attempt;
- `A`: OTA accepted the request and returns a fresh signed challenge;
- `R`: ESP proves possession of its private key;
- `P`: OTA sends encrypted Wi-Fi and OTA configuration.

The temporary session key is derived independently by both sides from P-256 ECDH, device identity, persistent counter and the fresh 8-byte random. The session key itself is never transmitted.

Encrypted provisioning contains protocol version, Wi-Fi security/channel, SSID, Wi-Fi password, OTA host and OTA port.

The ESP writes new provisioning data only after successful authentication/decryption. A failed re-provisioning attempt leaves the previous known-good configuration and previous successful OTA security context intact.

Successful completion is reported as:

```text
T|0|42
```

Only then does the OTA server replace its durable successful `counter + random` context.

### Provisioning state rules

Messages that are not valid for the expected next state do not advance the state machine. Duplicates are harmless. A new correctly signed `H` with a strictly higher counter may replace an unfinished attempt immediately. A timeout discards only temporary attempt state, never the previous successful provisioning context.

Provisioning can therefore be started repeatedly without requiring a device reset.

## 7. Endpoint 11 status

Endpoint `11` contains provisioning enable and status.

```text
bit 7  0x80  error
bit 6  0x40  provisioning
bit 5  0x20  firmware
bit 4  0x10  verification
bit 3  0x08  skipped
bit 2  0x04  timeout
bit 1  0x02  finished
bit 0  0x01  started
```

Examples:

```text
0x00 idle
0x41 provisioning + started
0x42 provisioning + finished
0xC2 error + provisioning + finished
0xC6 error + provisioning + timeout + finished
0x21 firmware + started
0x22 firmware + finished
0xA2 error + firmware + finished
0xB2 error + firmware + verification + finished
0x2A firmware + skipped + finished
```

After boot the ESP reports `Enable OTA=false` and `Status=idle`.

## 8. OTA CHECK and five-minute download token

Firmware check is independent from the provisioning switch.

OTA sends:

```text
C|<version>|<three-character-code>|<fresh-random>|<MAC>
```

The MAC is derived from the last successfully completed provisioning context. The ESP authenticates the CHECK before comparing versions.

The fresh CHECK random also derives a unique HTTPS Bearer token. OTA and ESP calculate the same token; the token itself is not sent over Zigbee. Its maximum lifetime is five minutes and it is consumed after successful download.

The HTTPS firmware GET requires both:

```text
Authorization: Bearer <derived-token>
X-Device-ID: <ESP IEEE>
```

OTA validates token, device, firmware code and firmware SHA before serving bytes.

## 9. Persistent OTA lifecycle database and ingress

The Home Assistant ingress UI is not only a dispatch page. It also shows persistent state from MySQL.

### Published artifacts

Table:

```text
ota_server_artifact_publications
```

It records the build, BIN filename/SHA/size, MJS filename/SHA, publishing ESP identity, certificate fingerprint and whether BIN verification, MJS verification and Zigbee2MQTT runtime loading succeeded.

### Provisioning attempts

Table:

```text
ota_server_provisioning_attempts
```

One row represents one ESP + provisioning counter. It records HELLO observation, challenge sent, response verification implied by successful P generation, provisioning sent, completion/timeout and error text.

A passive `mqtt_observer.py` records the transport timeline without participating in cryptographic decisions. The main `mqtt_listener.py` remains the authoritative state machine.

### ESP × firmware cross table

Table:

```text
ota_server_device_firmware_status
```

Primary key:

```text
(device_id, firmware_sha256)
```

This is the requested cross table between a physical ESP and a concrete firmware image. It records, where applicable:

```text
CHECK sent
token expiry
download started
download completed or failed
post-download ESP confirmation
last error
```

The ingress page displays these three sections directly, so it is possible to see whether provisioning stopped at HELLO/A/R/P, which BIN/MJS build is active, and whether a particular ESP actually began and completed a firmware transfer.

## 10. Database migrations

MySQL schema is managed by Alembic. OTA startup runs:

```bash
alembic -c /share/ota_server/runtime/alembic.ini upgrade head
```

Current schema includes device certificates, successful provisioning context, download grants, firmware images/history, artifact publications, provisioning attempt history and ESP × firmware state.

See `DATABASE.md` for table-level details.

## 11. Runtime scripts outside the container

Managed runtime files live in:

```text
/share/ota_server/runtime
```

Important files include:

```text
run.sh
restart.sh
server_mysql.py
mqtt_listener.py
mqtt_observer.py
firmware_publish.py
zigbee2mqtt_publish.py
activity.py
migrations/
```

`restart.sh` restarts the OTA add-on through the Supervisor self-restart API.

Container/image changes such as Python dependencies or `config.yaml` still require rebuilding the add-on image. Ordinary runtime Python/shell changes are designed to execute from the persistent runtime location.

## 12. Main implementation files

```text
setup_certificates.py
  offline Root CA and OTA certificate preparation

tools/esp_ota/install.py
  repeatable integration into a clean ESP-IDF project

tools/esp_ota/create_device_identity.py
  unique ESP key/certificate creation and public registration

tools/esp_ota/adopt_existing_identity.py
  adopts existing credentials without changing keys

tools/esp_ota/prebuild_validate.py
  build-time identity and resource validation

tools/esp_ota/prepare_z2m_bundle.py
  creates the single build-matched external converter

tools/esp_ota/publish_firmware.py
  signs and publishes BIN and MJS

device_registry.py
  Root-CA validation and registered public device identities

mqtt_listener.py
  authoritative provisioning state machine

mqtt_observer.py
  persistent passive lifecycle observation

secure_transport.py
  OTA signatures, ECDH and AES-256-GCM provisioning

ota_check_security.py
  successful provisioning context and one-time grants

server_mysql.py
  secure HTTPS endpoints, download telemetry and ingress integration
```

## 13. Security rules

Never commit or casually copy:

```text
root_ca_private.pem
ota_server_private.pem
device_private.pem
firmware binaries containing an embedded device_private.pem
```

A bare public key is never sufficient to become a trusted publisher. OTA trusts an ESP public key only through a valid Root-CA-signed device certificate that matches the currently registered certificate for that device.

BIN and MJS are independently signed, and the MJS is additionally accepted only after the matching signed BIN from the same publisher has already been verified.

The Root CA private key remains the only authority capable of creating a new trusted OTA or ESP identity.
