# OTA Server

Home Assistant add-on providing HTTPS OTA firmware delivery, Zigbee2MQTT secure provisioning transport and a manufacturing PKI service for ESP devices.

This README is the primary description of the OTA/ESP trust model, device manufacturing, provisioning protocol and helper scripts used to prepare an ESP for flashing.

## Certificate architecture

The ecosystem uses one offline P-256 Root CA. The Root CA private key is the only CA signing authority and must never be copied to Home Assistant, OTA server, ESP firmware or Git.

PKI URI namespace:

```text
urn:jarzem:esp:pki:...
```

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
  /data/device_registry.db  public ESP certificates and metadata

ESP FLASH
  device_private.pem        unique private P-256 key for this ESP
  device_cert.pem           CA-signed public identity of this ESP
  root_ca_cert.pem          public Root CA
  ota_server_cert.pem       public OTA server certificate
```

`root_ca_private.pem` never leaves the offline CA workstation. `ota_server_private.pem` exists only on the OTA server. Every ESP has its own private key; private keys are never shared between devices.

During development the ESP private key is embedded in flash. The provisioning protocol does not depend on where the private key is stored, so later it can be moved to protected/eFuse-backed storage without changing the wire protocol.

## Root CA and OTA server certificate

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

For an existing ecosystem the script reuses these files. For a completely new ecosystem use `--init-ca` once.

OTA certificate role URI:

```text
urn:jarzem:esp:pki:role:ota-server
```

When `--ssh-target` is supplied, the script creates `/share/ota_server/cert/` and copies only files OTA needs. It never copies `root_ca_private.pem`.

The OTA certificate/private-key pair is used for HTTPS/TLS, ECDSA authentication and P-256 ECDH during secure provisioning.

## OTA manufacturing HTTPS service

The manufacturing service runs on HTTPS port `8451` using the OTA TLS certificate.

```text
GET  https://<ota-ip>:8451/api/manufacturing/root-ca.pem
GET  https://<ota-ip>:8451/api/manufacturing/ota-server.pem
GET  https://<ota-ip>:8451/api/manufacturing/ota-public.pem
GET  https://<ota-ip>:8451/api/manufacturing/health
POST https://<ota-ip>:8451/api/manufacturing/register-device
```

Registration transports only a public device certificate. OTA accepts it only after verification of the Root CA signature, validity period, `CA:FALSE`, `digitalSignature`, `clientAuth`, P-256 key type, device role and IEEE identity.

Device certificate URIs include for example:

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

Manufacturing registration establishes the permanent relationship `DEVICE_ID -> CA-signed public key`. Runtime provisioning later proves possession of the matching private key and sends Wi-Fi/OTA configuration securely.

## Per-device ESP credentials

The ESP project `JarZem/7button-encoder` contains:

```text
tools/create_device_credentials.py
tools/cleanup_device_credentials.py
```

`create_device_credentials.py`:

1. loads the existing offline Root CA;
2. generates one unique P-256 key for the ESP;
3. creates a CA-signed device certificate containing IEEE and manufacturing metadata;
4. stores the private key only in the local credential workspace;
5. registers only the public certificate with OTA;
6. downloads public Root/OTA trust material for the build.

Generated local workspace:

```text
device_credentials/
  device_private.pem      PRIVATE
  device_cert.pem         public
  root_ca_cert.pem        public
  ota_server_cert.pem     public
  ota_server_public.pem   public
```

The private key is never uploaded to OTA.

Typical use:

```bash
python tools/create_device_credentials.py
```

The script also accepts explicit `--device-id`, `--group`, `--device-model`, `--product-role`, `--hardware-revision`, `--chip-family`, `--flash-size`, `--ca-dir` and `--ota-url` arguments.

The device certificate contains stable manufacturing identity, so model/family/role/hardware data do not need to be repeated in Zigbee HELLO.

## ESP build, flash and cleanup

CMake embeds:

```text
device_private.pem
device_cert.pem
root_ca_cert.pem
ota_server_cert.pem
```

During the prototype phase the firmware binary therefore contains the ESP private key and must be treated as sensitive.

After successful flashing run:

```bash
python tools/cleanup_device_credentials.py
```

The cleanup helper removes the local private-key workspace and build outputs that may contain the embedded private key. It does not remove the public device registration from OTA.

Do not regenerate device identity merely because firmware changes. A device keeps its identity across firmware builds and OTA updates.

## Runtime provisioning architecture

Provisioning is initiated by ESP after the user enables provisioning from Home Assistant.

```text
Home Assistant GUI
      |
      | Enable OTA / provisioning gate
      v
Zigbee2MQTT
      |
      | endpoint 11 control/status
      v
ESP
      |
      | H / R, endpoint 10, cluster 0xFC00
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

OTA subscribes directly to Zigbee2MQTT MQTT. Home Assistant is only the UI/control path and is not part of the cryptographic protocol.

`Enable OTA` controls only provisioning. It must not disable normal OTA check functionality.

After successful provisioning ESP automatically sets `Enable OTA=false` and reports that change to Zigbee2MQTT/Home Assistant. The final provisioning status remains visible.

## Secure H/A/R/P provisioning protocol

```text
ESP -> OTA   H|counter|signatureESP
OTA -> ESP   A|random8-base64url|signatureOTA
ESP -> OTA   R|signatureESP
OTA -> ESP   P|base64url(AES-256-GCM(ciphertext||tag16))
```

Transport uses endpoint `10`, manufacturer-specific cluster `0xFC00`. MQTT representation remains textual H/A/R/P; A/P may be compact binary on radio to fit Zigbee limits.

### H - signed HELLO

When provisioning is enabled, ESP starts a fresh provisioning session even when valid provisioning data already exists in NVS. Existing NVS configuration remains valid until a new authenticated P is successfully stored.

ESP increments its persistent counter and signs:

```text
H|<device_id>|<counter>
```

Transmitted frame:

```text
H|<counter>|<raw-P256-signature-base64url>
```

OTA derives device id from the Zigbee2MQTT topic/IEEE, loads the registered certificate, verifies certificate validity and ecosystem, verifies the ECDSA-P256 signature and rejects stale/replayed counters.

A device without a CA-validated certificate in the registry is rejected. The active protocol uses no per-device HMAC secret or server master-secret enrollment mechanism.

### A - OTA challenge

OTA generates a fresh 8-byte random value and signs:

```text
A|<device_id>|<counter>|<random8 binary>
```

Transmitted frame:

```text
A|<random8-base64url>|<raw-P256-signature-base64url>
```

ESP verifies the OTA signature using its trusted OTA certificate/Root CA chain.

Both sides derive a per-session key using P-256 ECDH. The final 256-bit session key is derived with HMAC-SHA256 over the ECDH shared secret and:

```text
JaroslavZemanESP|provisioning-v1|
+ device_id
+ counter (uint64 big endian)
+ random8
```

The session key is never transmitted.

### R - ESP response

ESP signs:

```text
R|<device_id>|<counter>|<random8 binary>|OK
```

and sends:

```text
R|<raw-P256-signature-base64url>
```

OTA accepts R only for an active `WAIT_RESPONSE` session and verifies it against the registered ESP public key.

### P - encrypted provisioning

After valid R, OTA sends an AES-256-GCM encrypted provisioning structure containing:

```text
protocol version
Wi-Fi security type
Wi-Fi channel
SSID
Wi-Fi password
OTA host
OTA port
```

Nonce and authenticated data are bound to device id, counter and challenge. ESP authenticates and decrypts P and only then replaces the provisioning stored in NVS. Failed validation leaves the previous valid NVS provisioning untouched.

After successful P:

1. ESP stores the new provisioning in NVS;
2. status becomes `PROVISIONING | FINISHED`;
3. ESP sets `Enable OTA=false`;
4. ESP reports status and `Enable OTA=false` to Home Assistant.

## Session state and replay protection

OTA runtime state:

```text
IDLE --H--> WAIT_RESPONSE --R--> PROVISIONING_SENT
```

Sessions expire after 120 seconds. Unexpected ordering and stale counters are rejected.

ESP state:

```text
IDLE -> WAIT_CHALLENGE -> WAIT_PROVISIONING -> PROVISIONED
```

Stored provisioning is configuration data, not permission to skip a newly requested authenticated provisioning session.

## Endpoint 11 control and status

Endpoint `11` contains the provisioning enable and status attributes. `Enable OTA` is a provisioning gate, not the stored result of the last run.

Status is an 8-bit field:

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

Current combinations:

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

After boot/flash ESP initializes and reports:

```text
Enable OTA = false
Status     = idle
```

Manually setting `Enable OTA=false` closes only the provisioning gate; it does not erase the previous result. Successful provisioning closes the gate automatically.

If eight bits become insufficient, the attribute can be migrated to `UINT16` while preserving the lower-eight-bit meanings.

## Main implementation files

OTA side:

```text
mqtt_listener.py
  Zigbee2MQTT MQTT connection, H/R state machine, certificate lookup,
  HELLO verification, replay checks, sends A and P

secure_transport.py
  OTA key/certificate loading, A signing, P-256 ECDH,
  R verification, AES-256-GCM provisioning encoding

device_registry.py
  registered device identities, public keys/certificate metadata,
  accepted HELLO counter persistence

manufacturing_api.py
  Root/OTA public material and CA-validated device registration

setup_certificates.py
  Root CA / OTA certificate preparation and deployment
```

ESP side:

```text
tools/create_device_credentials.py
  generate/sign/register one device identity and fetch OTA trust material

tools/cleanup_device_credentials.py
  remove sensitive local build material after flashing

main/device_credentials.c
  device key/certificate access, signing and ECDH

main/device_identity.c
  device IEEE and persistent enrollment counter

main/ota_secure_session.c
  H/A/R/P secure state, AES-GCM validation and NVS storage

main/zigbee_ota_cluster.c
  endpoint 10 provisioning transport

main/zigbee_ota_control.c
  endpoint 11 provisioning enable/status
```

## Provisioning configuration and secrets

OTA-owned provisioning values are conceptually:

```text
wifi_ssid
wifi_password (secret)
wifi_security
wifi_channel
ota_host
ota_port
```

Wi-Fi password belongs in the server secrets store, not in the device certificate or clear Zigbee messages. Device family/model/role/hardware data belong in the CA-signed device certificate/registry.

## Tests

Manufacturing API test:

```bash
python tests/test_manufacturing_live.py --ota-url https://192.168.2.120:8451 --ca-dir D:/ESP-PKI/ca --ecosystem JaroslavZemanESP
```

Secure-target helper:

```text
tools/test_ota_secure_target.py
```

Tests and helpers must follow the certificate-based H/A/R/P protocol described here.

## Security rules

Never commit or copy these outside their intended secure location:

```text
root_ca_private.pem
ota_server_private.pem
device_private.pem
firmware binaries containing embedded device_private.pem
```

The Root CA private key remains offline. Home Assistant receives only the public Root CA and OTA's own private key/certificate. Each ESP receives only its own private key plus public certificates.

Compromise of one ESP private key compromises that device identity, not the Root CA or other ESP private keys. A stolen device certificate alone is public information and is insufficient to impersonate the ESP.

Compromise of the OTA private key is more serious because it allows authentication as the OTA server and participation in provisioning sessions, but it still cannot mint a new valid ESP identity or OTA certificate without the offline Root CA private key.