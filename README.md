# OTA Server

Home Assistant add-on providing HTTPS OTA firmware delivery, secure provisioning over Zigbee2MQTT and a manufacturing PKI service for ESP devices.

This README is the primary description of the trust model, certificates, manufacturing, provisioning, OTA check and recovery rules. The implementation on the OTA server and in ESP firmware is expected to follow this document.

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
  device registry          public ESP certificates and metadata

ESP FLASH
  device_private.pem        unique private P-256 key for this ESP
  device_cert.pem           CA-signed public identity of this ESP
  root_ca_cert.pem          public Root CA
  ota_server_cert.pem       public OTA server certificate
```

`root_ca_private.pem` never leaves the offline CA workstation. `ota_server_private.pem` exists only on the OTA server. Every ESP has its own private key; private keys are never shared between devices.

During development the ESP private key is embedded in flash. Later it can be moved to protected/eFuse-backed storage without changing the provisioning or OTA protocol.

## Preparing the Root CA and OTA certificate

Run:

```bash
python setup_certificates.py
```

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

When `--ssh-target` is supplied, the script creates `/share/ota_server/cert/` and copies only files needed by the OTA server. It never copies `root_ca_private.pem`.

The OTA certificate/private-key pair is used for HTTPS/TLS, ECDSA authentication and P-256 ECDH during provisioning.

## Manufacturing HTTPS service

The manufacturing service runs on HTTPS port `8451`.

```text
GET  https://<ota-ip>:8451/api/manufacturing/root-ca.pem
GET  https://<ota-ip>:8451/api/manufacturing/ota-server.pem
GET  https://<ota-ip>:8451/api/manufacturing/ota-public.pem
GET  https://<ota-ip>:8451/api/manufacturing/health
POST https://<ota-ip>:8451/api/manufacturing/register-device
```

Registration transports only a public device certificate. OTA accepts it only after verification of the Root CA signature, validity period, `CA:FALSE`, `digitalSignature`, `clientAuth`, P-256 key type, device role and IEEE identity.

Device certificate URIs can include:

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

Manufacturing registration establishes the permanent relationship between an ESP IEEE identity and its CA-signed public key. Runtime provisioning proves possession of the matching private key.

## Per-device ESP credentials

The ESP project contains:

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

Typical use:

```bash
python tools/create_device_credentials.py
```

After successful flashing:

```bash
python tools/cleanup_device_credentials.py
```

Do not regenerate device identity merely because firmware changes. A device keeps the same identity across firmware builds and OTA updates.

## Runtime provisioning architecture

Provisioning starts only when the user enables `Enable OTA` in Home Assistant. This switch controls provisioning only; it does not disable OTA firmware checks.

```text
Home Assistant
    |
    | user enables provisioning
    v
Zigbee2MQTT
    |
    v
ESP
    |
    | authenticated provisioning messages
    v
Zigbee2MQTT MQTT
    |
    v
OTA server
```

The OTA server subscribes directly to Zigbee2MQTT. Home Assistant is only the user interface and is not part of the cryptographic trust chain.

After successful provisioning the ESP automatically turns `Enable OTA` off, while the final successful status remains visible in Home Assistant.

## Provisioning messages

The wire protocol uses four main messages:

```text
ESP -> OTA   H|counter|signatureESP
OTA -> ESP   A|random8-base64url|signatureOTA
ESP -> OTA   R|signatureESP
OTA -> ESP   P|base64url(AES-256-GCM(ciphertext||tag16))
```

In plain language:

- `H` means: the ESP is asking to start a new authenticated provisioning attempt.
- `A` means: the OTA server has accepted that request and returns a fresh signed challenge.
- `R` means: the ESP proves that it owns the private key belonging to its registered certificate and accepts the challenge.
- `P` means: the OTA server sends the encrypted Wi-Fi and OTA configuration.

Transport uses endpoint `10`, manufacturer-specific cluster `0xFC00`.

## How one successful provisioning attempt works

### 1. The ESP starts a new attempt

When the user enables provisioning, the ESP increments its persistent counter and signs:

```text
H|<device_id>|<counter>
```

The transmitted message contains the counter and signature. The OTA server derives the device identity from Zigbee2MQTT, validates the registered certificate, verifies the signature and accepts the request only when the counter is newer than every previously accepted counter from that device.

The counter therefore prevents an old recorded start message from being replayed.

### 2. The OTA server sends a challenge

The server generates a fresh 8-byte random value and signs a message containing the device identity, counter and random value.

Both sides derive the same temporary session key from:

- P-256 ECDH shared secret;
- device identity;
- current counter;
- current 8-byte random value.

The session key itself is never transmitted or stored as a long-term secret.

### 3. The ESP proves possession of its private key

The ESP verifies the OTA signature and signs its response. The OTA server accepts the response only when it belongs to the currently active attempt.

### 4. The OTA server sends encrypted provisioning

The encrypted data contains:

```text
protocol version
Wi-Fi security type
Wi-Fi channel
SSID
Wi-Fi password
OTA host
OTA port
```

The OTA address is stored as host plus port received from provisioning. The firmware does not require a fixed OTA download port compiled into the binary.

The ESP authenticates and decrypts the packet before writing anything to NVS. If validation fails, the previously working provisioning remains untouched.

### 5. The ESP confirms completion

Only after the ESP has successfully authenticated, decrypted and stored the new configuration does it:

1. save the new provisioning context needed by later OTA checks;
2. set the provisioning status to finished;
3. set `Enable OTA` to off;
4. send its combined control/status message back through Zigbee2MQTT.

The successful completion message is:

```text
T|0|42
```

The OTA server does not replace its last successful `counter + random` merely because it sent the encrypted provisioning packet. It replaces that durable context only after receiving this completion confirmation from the ESP.

This is important: if a new provisioning attempt fails halfway through, both sides continue to have the previous known-good OTA security context.

## Provisioning state machine in human terms

The following states are conceptual. Internal program names may differ, but behavior must follow these rules.

### ESP side

```text
Provisioning disabled / previous configuration available
            |
            | user turns Enable OTA on
            v
Ready to start a new provisioning attempt
            |
            | ESP sends a new signed start request
            v
Waiting for a valid challenge from the OTA server
            |
            | valid challenge received and verified
            | ESP sends its signed response
            v
Waiting for encrypted provisioning data
            |
            | valid encrypted provisioning received and stored
            v
Provisioning completed
            |
            | ESP reports success and turns Enable OTA off
            v
Provisioning disabled / new configuration available
```

### OTA server side

```text
No provisioning attempt in progress
            |
            | valid signed start request with a newer counter
            v
Waiting for the ESP's signed response
            |
            | valid response received
            | server sends encrypted provisioning
            v
Waiting for the ESP to confirm that provisioning was stored
            |
            | ESP reports provisioning finished and Enable OTA off
            v
No provisioning attempt in progress
```

## Rules for duplicates, lost messages and retries

These rules are mandatory because Zigbee/MQTT delivery may be delayed, duplicated or lost.

A message that does not represent the expected next step must never move the state machine forward.

Examples:

- A challenge received when the ESP is not waiting for a challenge is ignored.
- Encrypted provisioning received when the ESP is not waiting for provisioning is ignored.
- An ESP response received when the OTA server is not waiting for that response is ignored.
- A completion notification received when the OTA server is not waiting for completion is ignored.
- A start request with an already used or older counter is ignored.

Duplicates must be harmless. Receiving the same old message twice must not restart cryptography, overwrite NVS or change the last successful OTA context.

A new correctly signed start request with a strictly higher counter has a special meaning: it is an explicit request to start a fresh provisioning attempt. The OTA server is allowed to discard an unfinished older attempt and immediately start the new one. It must not force the ESP to wait for an old 120-second timeout merely because a previous response or completion notification was lost.

If an attempt times out on the ESP while `Enable OTA` is still on, the ESP may start another attempt from the beginning using a new counter.

If an attempt times out on the OTA server, only that unfinished attempt is discarded. The last successful provisioning context remains valid.

Turning provisioning on again after a successful run must always be possible. Existing provisioning data is not a reason to refuse a new user-requested provisioning attempt.

Turning provisioning off manually stops the current provisioning attempt but does not erase the last successful configuration or OTA security context.

## Persistent data and failed attempts

Two concepts must not be mixed:

1. temporary data belonging to the provisioning attempt currently in progress;
2. the last successfully completed provisioning configuration and its `counter + random` security context.

Temporary session data may be discarded at any time after an error, timeout or new valid start request.

The last successfully completed configuration and security context must remain available until another provisioning attempt finishes successfully.

This rule allows provisioning to be attempted repeatedly without making a device unusable after one failed attempt.

## Endpoint 11 control and status

Endpoint `11` contains the provisioning enable and status attributes. `Enable OTA` is only the provisioning gate.

Status is an 8-bit field:

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
0x00  idle
0x41  provisioning + started
0x42  provisioning + finished
0xC2  error + provisioning + finished
0xC6  error + provisioning + timeout + finished
0x21  firmware + started
0x22  firmware + finished
0xA2  error + firmware + finished
0xB2  error + firmware + verification + finished
0x2A  firmware + skipped + finished
```

Zigbee2MQTT decodes the bits rather than relying on a fixed table of every possible byte value.

After boot or normal flash the ESP reports:

```text
Enable OTA = false
Status     = idle
```

The current implementation also sends a compact control/status uplink such as:

```text
T|0|00
T|1|41
T|0|42
```

This keeps Home Assistant synchronized without relying on problematic manual reporting of manufacturer-specific ZCL attributes.

## OTA firmware check and temporary download token

The firmware check is independent from `Enable OTA`.

The OTA server sends:

```text
C|<version>|<three-character-code>|<fresh-random>|<MAC>
```

The MAC is calculated from a key derived from the last successfully completed provisioning session. The provisioning session key is reconstructed from the stored device identity, successful provisioning counter, successful provisioning random value and P-256 ECDH secret. The session key itself does not need to be stored.

The ESP first authenticates the check. Only after authentication does it compare the offered firmware version with the running version.

A separate fresh random value in each firmware check is used to derive a one-time HTTPS Bearer token. OTA and ESP independently derive the same token; the token itself is not transmitted over Zigbee.

The OTA server grants the token for at most five minutes. A completed firmware download consumes the grant immediately. An expired or already consumed token is rejected.

The last successful provisioning `counter + random` is therefore long-lived context for authenticated OTA checks, while the HTTPS download token is short-lived and unique to a specific check/download attempt.

## Main implementation files

OTA side:

```text
mqtt_listener.py
  provisioning state machine, certificate verification, retries,
  challenge/provisioning transport and completion confirmation

secure_transport.py
  OTA signing, P-256 ECDH, ESP-response verification,
  AES-256-GCM provisioning encoding

ota_check_security.py
  durable successful provisioning context and one-time download grants

device_registry.py
  registered device certificates and accepted start counters

manufacturing_api.py
  CA-validated device registration and public trust material

setup_certificates.py
  Root CA / OTA certificate preparation and deployment
```

ESP side:

```text
main/ota_secure_session.c
  provisioning state machine, challenge verification,
  encrypted provisioning validation and NVS storage

main/ota_check_auth.c
  durable successful OTA context, firmware-check authentication
  and token derivation

main/zigbee_ota_cluster.c
  endpoint 10 protocol transport

main/zigbee_ota_control.c
  endpoint 11 Enable OTA and status handling

main/device_credentials.c
  device signing, certificate trust and ECDH

main/device_identity.c
  device IEEE identity and persistent increasing counter
```

## Provisioning configuration and secrets

Server-owned provisioning values are:

```text
wifi_ssid
wifi_password
wifi_security
wifi_channel
ota_host
ota_port
```

Wi-Fi password belongs in the server secret store, not in the device certificate or clear Zigbee messages. Device family/model/role/hardware metadata belong in the CA-signed certificate and registry.

## Tests

Manufacturing API test:

```bash
python tests/test_manufacturing_live.py --ota-url https://192.168.2.120:8451 --ca-dir D:/ESP-PKI/ca --ecosystem JaroslavZemanESP
```

Secure-target helper:

```text
tools/test_ota_secure_target.py
```

Tests should include repeated provisioning, duplicate/out-of-order messages, lost completion confirmation, timeout/restart and preservation of the previous successful context after a failed new attempt.

## Security rules

Never commit or copy these outside their intended secure location:

```text
root_ca_private.pem
ota_server_private.pem
device_private.pem
firmware binaries containing embedded device_private.pem
```

The Root CA private key remains offline. Home Assistant receives only the public Root CA and OTA's own private key/certificate. Each ESP receives only its own private key plus public certificates.

Compromise of one ESP private key compromises that device identity, not the Root CA or other ESP private keys. A stolen public device certificate alone is insufficient to impersonate the ESP.

Compromise of the OTA private key is more serious because it allows authentication as the OTA server and participation in provisioning sessions, but it still cannot mint a new valid ESP identity or OTA certificate without the offline Root CA private key.
