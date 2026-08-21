# OTA Server

Home Assistant add-on providing HTTPS OTA firmware delivery, Zigbee2MQTT secure provisioning transport and a manufacturing PKI service for ESP devices.

This README is the primary description of the OTA/ESP trust model, device manufacturing, enrollment/provisioning protocol and the helper scripts used to prepare an ESP for flashing.

## Certificate architecture

The ecosystem uses one offline P-256 Root CA. The Root CA private key is the only CA signing authority and must never be copied to Home Assistant, OTA server, ESP firmware or Git.

The established PKI URI namespace is:

```text
urn:jarzem:esp:pki:...
```

Existing OTA and ESP certificates using this namespace remain valid and are not regenerated merely because application code changes.

```text
OFFLINE CA workstation
  root_ca_cert.pem          public
  root_ca_private.pem       PRIVATE, preferably password protected
          |
          +-- signs OTA server certificate
          +-- signs one certificate for every ESP device

HOME ASSISTANT / OTA
  /share/ota_server/cert/root_ca_cert.pem
  /share/ota_server/cert/ota_server_cert.pem
  /share/ota_server/cert/ota_server_private.pem
  /share/ota_server/cert/ota_server_public.pem
  /data/device_registry.db  public ESP certificates and metadata

ESP FLASH
  device_private.pem        unique private P-256 key for this ESP
  device_cert.pem           CA-signed public identity of this ESP
  root_ca_cert.pem          public Root CA
  ota_server_cert.pem       public OTA server certificate
```

`root_ca_private.pem` never leaves the offline CA workstation. `ota_server_private.pem` exists only on the OTA server. Every ESP has its own private key; no private key is shared between devices.

The current prototype embeds the ESP private key in flash. The protocol is intentionally independent of the eventual storage backend, so this can later be changed to protected/eFuse-backed key storage without changing the OTA wire protocol.

## 1. Root CA and OTA server certificate

Run `setup_certificates.py` on the workstation that has access to the offline CA.

Requirement:

```bash
pip install cryptography
```

Existing CA layout:

```text
<ca-dir>/root_ca_cert.pem
<ca-dir>/root_ca_private.pem
```

For an existing ecosystem the script reuses these files; it does not create a new CA. For a completely new ecosystem use `--init-ca` once.

The OTA certificate uses the established role URI:

```text
urn:jarzem:esp:pki:role:ota-server
```

When `--ssh-target` is supplied, the script creates `/share/ota_server/cert/` and copies only the files OTA actually requires. It deliberately does not copy `root_ca_private.pem`.

The OTA server certificate/private-key pair has two purposes:

1. normal HTTPS/TLS identity of the OTA/manufacturing service;
2. ECDSA authentication and P-256 ECDH in the secure Zigbee provisioning protocol.

ESP verifies the OTA identity against the same offline Root CA. OTA verifies ESP identities against that Root CA as well.

## 2. OTA manufacturing HTTPS service

OTA add-on version 0.1.18 exposes a manufacturing service on HTTPS port `8451` using the normal OTA server TLS certificate.

Public endpoints:

```text
GET  https://<ota-ip>:8451/api/manufacturing/root-ca.pem
GET  https://<ota-ip>:8451/api/manufacturing/ota-server.pem
GET  https://<ota-ip>:8451/api/manufacturing/ota-public.pem
GET  https://<ota-ip>:8451/api/manufacturing/health
POST https://<ota-ip>:8451/api/manufacturing/register-device
```

There is no manufacturing bearer token. Registration transports only a public device certificate. The security boundary is the offline Root CA: OTA accepts a device certificate only when all certificate checks pass.

Device certificate URIs use the same namespace, for example:

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

For every registration OTA verifies the CA signature, certificate validity, `CA:FALSE`, `digitalSignature`, `clientAuth`, P-256, role `device` and the device IEEE identity. Only after those checks is the public certificate written to `/data/device_registry.db`.

This registration is a manufacturing operation. It is not the same thing as runtime provisioning over Zigbee. Manufacturing establishes the permanent cryptographic identity `DEVICE_ID -> CA-signed public key`; runtime provisioning later proves possession of the matching private key and securely sends Wi-Fi/OTA configuration.

## 3. Per-device ESP certificate and helper script

The ESP project `JarZem/7button-encoder` contains:

```text
tools/create_device_credentials.py
```

The script performs the complete manufacturing preparation for one ESP:

1. loads the existing offline Root CA certificate and password-protected Root CA private key;
2. generates a new unique P-256 private key for this ESP;
3. creates a CA-signed device certificate containing the ESP IEEE and manufacturing metadata;
4. writes the ESP private key only to the local credential workspace;
5. registers only the public device certificate with the OTA manufacturing API;
6. downloads the public Root/OTA trust material needed by the firmware build.

The script creates locally:

```text
device_credentials/
  device_private.pem      PRIVATE
  device_cert.pem         public
  root_ca_cert.pem        public
  ota_server_cert.pem     public, fetched from OTA
  ota_server_public.pem   public, fetched from OTA
```

The script never uploads `device_private.pem`.

Typical interactive use is:

```bash
python tools/create_device_credentials.py
```

It can also receive explicit values such as `--device-id`, `--group`, `--device-model`, `--product-role`, `--hardware-revision`, `--chip-family`, `--flash-size`, `--ca-dir` and `--ota-url`.

The device certificate contains stable manufacturing identity: ecosystem, group/family, IEEE device id, model, product role, hardware revision, chip and flash size. These facts therefore do not need to be repeated in Zigbee HELLO.

## 4. ESP build, flash and cleanup

The ESP project's CMake invokes `tools/create_device_credentials.py` automatically when no complete device credential workspace exists. It refuses to silently regenerate an identity when only part of an existing credential set is present.

CMake embeds into firmware:

```text
device_private.pem
device_cert.pem
root_ca_cert.pem
ota_server_cert.pem
```

During the prototype phase this means the firmware binary contains the ESP private key and must itself be treated as sensitive.

After successful flashing run:

```bash
python tools/cleanup_device_credentials.py
```

The cleanup helper removes the local private-key workspace and build outputs that may contain firmware images with the embedded private key. It does not remove the public device registration from OTA.

Do not regenerate a new device identity merely because firmware changed. A device keeps its identity across normal firmware builds and OTA updates.

## 5. Runtime provisioning architecture

Provisioning is initiated by the ESP over Zigbee after the user enables provisioning from Home Assistant. Home Assistant itself does not perform the cryptographic protocol. The data path is:

```text
Home Assistant GUI
      |
      | Enable OTA / provisioning gate
      v
Zigbee2MQTT
      |
      | Zigbee endpoint 11 control/status
      v
ESP
      |
      | H / R via Zigbee endpoint 10, cluster 0xFC00
      v
Zigbee2MQTT MQTT action topic
      |
      v
OTA mqtt_listener.py
      |
      | A / P via zigbee2mqtt/<device>/set
      v
Zigbee2MQTT -> ESP
```

The OTA server subscribes directly to the Zigbee2MQTT MQTT action topic. Home Assistant is only the UI/control path for the provisioning enable flag and status; it is not a cryptographic relay.

The provisioning gate must not disable ordinary OTA `check` functionality. `Enable OTA` controls only whether a new provisioning exchange may be started/processed.

After successful provisioning the ESP automatically returns `Enable OTA` to `false` and reports that change to Zigbee2MQTT/Home Assistant. The final provisioning result remains visible in the status attribute; disabling the gate must not erase a previous success/error result.

## 6. Secure H/A/R/P provisioning protocol

Runtime provisioning uses four protocol frames:

```text
ESP -> OTA   H|counter|signatureESP
OTA -> ESP   A|random8-base64url|signatureOTA
ESP -> OTA   R|signatureESP
OTA -> ESP   P|base64url(AES-256-GCM(ciphertext||tag16))
```

The Zigbee transport is endpoint `10`, manufacturer-specific cluster `0xFC00`. The MQTT representation remains textual H/A/R/P even where the radio representation of A/P is compact binary to fit the Zigbee payload limit.

### H - signed HELLO

When provisioning is enabled, ESP starts a fresh provisioning session even if valid provisioning data already exists in NVS. Existing NVS configuration is retained as a fallback until a new authenticated `P` is successfully verified and stored.

ESP increments its persistent enrollment counter and signs the canonical value:

```text
H|<device_id>|<counter>
```

The transmitted frame is:

```text
H|<counter>|<raw-P256-signature-base64url>
```

The device id is derived by OTA from the Zigbee2MQTT topic/IEEE and is therefore not repeated in the radio frame.

OTA `mqtt_listener.py`:

1. resolves the Zigbee IEEE/device id from the MQTT topic;
2. loads the registered device certificate from the device registry;
3. checks certificate ecosystem and validity;
4. verifies the H ECDSA-P256 signature with the registered device public key;
5. rejects stale/replayed counters;
6. creates a short-lived secure session.

A device that does not already have a CA-validated public certificate in the registry is rejected. There is no per-device HMAC secret in the active H/A/R/P protocol.

### A - OTA challenge

OTA generates a fresh 8-byte random value and signs:

```text
A|<device_id>|<counter>|<random8 binary>
```

The transmitted frame is:

```text
A|<random8-base64url>|<raw-P256-signature-base64url>
```

ESP verifies the OTA signature using the trusted OTA certificate/Root CA chain. This proves that the challenge came from an authorized OTA server.

At the same time both sides derive a per-session secret using P-256 ECDH between the ESP device key and OTA server key. The final 256-bit session key is derived with HMAC-SHA256 over the ECDH shared secret and session context:

```text
JaroslavZemanESP|provisioning-v1|
+ device_id
+ counter (uint64 big endian)
+ random8
```

The session key is never sent over Zigbee or MQTT.

### R - ESP response

After accepting A, ESP signs:

```text
R|<device_id>|<counter>|<random8 binary>|OK
```

and sends:

```text
R|<raw-P256-signature-base64url>
```

OTA accepts R only for an existing session in `WAIT_RESPONSE` and verifies it with the registered ESP public key. Replayed or out-of-order R frames are rejected.

This proves that the ESP which initiated H still possesses the private key belonging to the CA-signed certificate registered for that IEEE address.

### P - encrypted provisioning

Only after a valid R does OTA build provisioning data from its configured values. Sensitive Wi-Fi information is never sent in clear text.

The current plaintext contains:

```text
protocol version
Wi-Fi security type
Wi-Fi channel
SSID
Wi-Fi password
OTA host
OTA port
```

`secure_transport.py` encrypts it with AES-256-GCM using the session key. Nonce and authenticated additional data are deterministically bound to device id, counter and random challenge so a provisioning packet cannot be moved to another session/device.

ESP authenticates/decrypts P and only then writes the new provisioning structure to NVS. If validation fails, the previous valid NVS provisioning remains available.

After successful P:

1. ESP stores the new provisioning in NVS;
2. provisioning status becomes `PROVISIONING | FINISHED`;
3. ESP automatically changes the provisioning enable attribute to `false`;
4. ESP reports both status and `Enable OTA=false` back through Zigbee2MQTT to Home Assistant.

No additional ESP protocol response after P is currently required by the OTA server.

## 7. Session state and replay protection

OTA keeps runtime sessions only in memory. The relevant OTA state progression is:

```text
IDLE --H--> WAIT_RESPONSE --R--> PROVISIONING_SENT
```

Sessions expire after 120 seconds. Unexpected H/R ordering and stale counters are rejected.

ESP has its own strict state sequence:

```text
IDLE -> WAIT_CHALLENGE -> WAIT_PROVISIONING -> PROVISIONED
```

Starting a new user-requested provisioning run must be possible even when NVS already contains valid provisioning. The old configuration is data, not permission to skip the new authentication exchange.

## 8. Endpoint 11 provisioning control and status

Endpoint `11` contains the Home Assistant/Zigbee2MQTT control/status attributes. `Enable OTA` is a provisioning gate, not a permanent OTA mode and not the stored result of the last run.

The status byte is a bit field so category/result information can be combined:

```text
bit 7  0x80  ERROR
bit 6  0x40  PROVISIONING
bit 5  0x20  FIRMWARE
bit 4  0x10  VERIFY
bit 3  0x08  SKIPPED
bit 2  0x04  TIMEOUT
bit 1  0x02  FINISHED
bit 0  0x01  STARTED
```

Current useful combinations are:

```text
0x00  idle
0x41  provisioning_started
0x42  provisioning_finished
0xC2  provisioning_error
0xC6  provisioning_timeout
0x21  firmware_update_started
0x22  firmware_update_finished
0xA2  firmware_update_error
0xB2  firmware_verify_error
0x2A  firmware_skipped
```

On a fresh boot/flash ESP initializes the control endpoint to:

```text
Enable OTA = false
Status     = idle
```

and reports these initial values after Zigbee networking is ready so Home Assistant does not retain stale UI state from the previous runtime.

Once a run has started, manually setting `Enable OTA=false` only closes the provisioning gate; it does not replace the status with `idle`. The last meaningful result remains visible. A successful provisioning run also automatically closes this gate.

If eight status bits become insufficient, the attribute can be migrated to `UINT16` while retaining the existing lower-eight-bit meanings.

## 9. OTA-side Python modules involved in provisioning

The active runtime path is split primarily across these files:

```text
mqtt_listener.py
  Zigbee2MQTT MQTT connection and H/R state machine
  certificate lookup and HELLO verification
  replay/counter checks
  sends A and P

secure_transport.py
  OTA P-256 private key/certificate loading
  A challenge signing
  P-256 ECDH session key derivation
  R signature verification
  AES-256-GCM provisioning encoding

device_registry.py
  registered CA-signed device identities
  device public keys/certificate metadata
  accepted HELLO counter persistence/replay protection

manufacturing_api.py
  HTTPS endpoints for Root/OTA public material
  CA-validated public device certificate registration

setup_certificates.py
  Root CA / OTA server certificate preparation and deployment
```

The ESP repository contains the complementary helpers/modules:

```text
tools/create_device_credentials.py
  generate/sign/register one device identity and fetch public OTA trust material

tools/cleanup_device_credentials.py
  remove local private credential/build material after successful flash

main/device_credentials.c
  embedded device key/certificate access and signing/ECDH

main/device_identity.c
  device IEEE identity and persistent enrollment counter

main/ota_secure_session.c
  ESP H/A/R/P secure state and AES-GCM validation/NVS storage

main/zigbee_ota_cluster.c
  endpoint 10 Zigbee protocol transport

main/zigbee_ota_control.c
  endpoint 11 provisioning enable/status exposed to HA/Zigbee2MQTT
```

### Legacy warning: `device_enrollment.py`

`device_enrollment.py` contains an older experimental design based on `SERVER_DEVICE_MASTER_SECRET`, derived per-device HMAC secrets, a 32-byte challenge and a separately supplied device encryption public key.

That is **not** the active secure H/A/R/P provisioning protocol described above. The current runtime uses CA-signed per-device P-256 certificates, ECDSA authentication and ECDH; it does not require a long-term per-device HMAC secret. Do not use `device_enrollment.py` as the implementation reference for new provisioning work unless the legacy module is deliberately revived/refactored.

## 10. Provisioning configuration and secrets

OTA obtains provisioning parameters from its normal options/configuration. Wi-Fi passwords are loaded from the server secrets store rather than included openly in the Zigbee protocol or device certificate.

Conceptually the server-owned provisioning values are:

```text
wifi_ssid
wifi_password (secret)
wifi_security
wifi_channel
ota_host
ota_port
```

These are network/provisioning data and are not device model metadata. Device family/model/role/hardware information belongs in the CA-signed per-device certificate/registry.

## 11. Live manufacturing API test

Run:

```bash
python tests/test_manufacturing_live.py --ota-url https://192.168.2.120:8451 --ca-dir D:/ESP-PKI/ca --ecosystem JaroslavZemanESP
```

The test validates TLS through the real Root CA, verifies the OTA certificate including `urn:jarzem:esp:pki:role:ota-server`, checks the OTA public key endpoint, registers a valid CA-signed device certificate and verifies rejection of invalid certificates.

For protocol-target testing the repository also contains:

```text
tools/test_ota_secure_target.py
```

The ESP repository contains additional device-side/test helpers for enrollment and secure-target testing. These scripts should be kept consistent with the H/A/R/P protocol above; legacy HMAC enrollment helpers must not silently become the protocol specification.

## Security rules

Never commit or copy these outside their intended secure location:

```text
root_ca_private.pem
ota_server_private.pem
device_private.pem
firmware binaries containing embedded device_private.pem
```

The Root CA private key remains offline. Home Assistant receives only the public Root CA and OTA's own private key/certificate. Each ESP receives only its own private key plus public certificates.

Compromise of one ESP private key compromises that device identity, not the Root CA and not the private keys of other ESP devices. A stolen device certificate alone is public information and is insufficient to impersonate the ESP without the corresponding private key.

A compromised OTA server private key is more serious because it can authenticate as the OTA server and participate in provisioning sessions, but it still cannot mint a new valid ESP identity or OTA certificate without the offline Root CA private key. Root CA protection is therefore the highest-priority trust boundary.
