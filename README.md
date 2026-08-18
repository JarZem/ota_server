# OTA Server

Home Assistant add-on providing HTTPS OTA firmware delivery, Zigbee2MQTT enrollment transport and a small manufacturing PKI service for ESP devices.

## Certificate architecture

The ecosystem uses one offline P-256 Root CA. The Root CA private key is the only signing authority and must never be copied to Home Assistant, OTA server, ESP firmware or Git.

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
  /share/ota_server/cert/manufacturing_token.txt
  /data/device_registry.db  public ESP certificates and metadata

ESP FLASH
  device_private.pem        unique private P-256 key for this ESP
  device_cert.pem           CA-signed public identity of this ESP
  root_ca_cert.pem          public Root CA
  ota_server_cert.pem       public OTA server certificate
```

`root_ca_private.pem` never leaves the offline CA workstation.

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

Example:

```bash
python setup_certificates.py \
  --ecosystem JaroslavZemanESP \
  --ota-ip 192.168.2.120 \
  --ca-dir D:/ESP-PKI/ca \
  --out D:/ESP-PKI/ota_credentials \
  --ssh-target root@192.168.2.120 \
  --ssh-key C:/Users/<user>/.ssh/id_ed25519
```

The script asks for the Root CA private-key password and creates:

```text
ota_credentials/
  root_ca_cert.pem
  ota_server_cert.pem
  ota_server_private.pem
  ota_server_public.pem
  manufacturing_token.txt
```

The OTA certificate is P-256, has `serverAuth`, contains the configured IP SAN and the role URI:

```text
urn:esp-pki:role:ota-server
```

When `--ssh-target` is supplied, the script creates `/share/ota_server/cert/` and copies only the files OTA actually requires. It deliberately does not copy `root_ca_private.pem`.

`manufacturing_token.txt` protects write access to the device-registration API. Treat it as a secret.

## 2. OTA manufacturing HTTPS service

OTA add-on version 0.1.16 exposes a manufacturing service on HTTPS port `8451` using the normal OTA server TLS certificate.

Public bootstrap endpoints:

```text
GET https://<ota-ip>:8451/api/manufacturing/root-ca.pem
GET https://<ota-ip>:8451/api/manufacturing/ota-server.pem
GET https://<ota-ip>:8451/api/manufacturing/ota-public.pem
GET https://<ota-ip>:8451/api/manufacturing/health
```

These contain only public material.

Device registration requires:

```text
POST https://<ota-ip>:8451/api/manufacturing/register-device
Authorization: Bearer <manufacturing_token>
```

The request contains the public `device_cert.pem`. OTA verifies that the certificate:

- is signed by `/share/ota_server/cert/root_ca_cert.pem`;
- is currently valid;
- has `CA:FALSE`;
- permits `digitalSignature`;
- has `clientAuth` EKU;
- uses a P-256 public key;
- has role `device`;
- contains a valid device IEEE identity.

Only after those checks is the certificate written to `/data/device_registry.db`. The device private key is never sent to OTA.

## 3. Per-device ESP certificate

The ESP project contains:

```text
tools/create_device_credentials.py
```

Run it locally for each physical ESP module. It needs access to the offline Root CA and to the OTA manufacturing HTTPS service.

Example:

```bash
python tools/create_device_credentials.py \
  --device-id 20:6e:f1:ff:fe:0d:45:94 \
  --group remotecontrol7-encoder \
  --device-model ESP32-C6-ENC \
  --product-role six-strip-cct-led-controller \
  --hardware-revision RevA \
  --chip-family ESP32-C6 \
  --flash-size 16MB \
  --ecosystem JaroslavZemanESP \
  --ca-dir D:/ESP-PKI/ca \
  --ota-url https://192.168.2.120:8451 \
  --manufacturing-token D:/ESP-PKI/ota_credentials/manufacturing_token.txt
```

The device certificate itself contains stable manufacturing identity, so this information does not need to be repeated in normal Zigbee HELLO messages:

```text
Organization            ecosystem
Organizational Unit     device group/family
serialNumber            Zigbee IEEE device id
SAN role                device
SAN device              device id
SAN group               group/family
SAN model               device model
SAN product-role        functional role
SAN hardware            hardware revision
SAN chip                chip family
SAN flash               flash size
EKU                      clientAuth
```

The script creates locally:

```text
device_credentials/
  device_private.pem      PRIVATE
  device_cert.pem         public
  root_ca_cert.pem        public
  ota_server_cert.pem     public, fetched from OTA
  ota_server_public.pem   public, fetched from OTA
```

Then it immediately registers `device_cert.pem` with OTA over the authenticated manufacturing API. OTA therefore already knows the device certificate, public key and hardware/product metadata before the ESP ever sends its first Zigbee HELLO.

The script never uploads `device_private.pem`.

## 4. ESP build and flash

The ESP project's CMake requires the generated `device_credentials/` workspace. Build fails if required files are missing.

CMake embeds into firmware:

```text
device_private.pem
device_cert.pem
root_ca_cert.pem
ota_server_cert.pem
```

The public Root CA + OTA certificate are also assembled into the HTTPS trust bundle used by the OTA client.

All generated files under `device_credentials/` are excluded from Git.

After the firmware has been successfully flashed to the intended physical module, remove the workstation copy of its private key:

```bash
python tools/cleanup_device_credentials.py
```

This deletes only `device_private.pem`. To remove the public build copies too:

```bash
python tools/cleanup_device_credentials.py --all
```

The public `device_cert.pem` does not need to remain on the workstation because OTA already stores it in `/data/device_registry.db`.

## 5. Why device metadata is in the certificate

Device ID, ecosystem, group, model, product role and hardware information are manufacturing facts. Putting them in the CA-signed device certificate means OTA receives those facts once through the trusted manufacturing path.

Consequently the later Zigbee HELLO can stay small. It needs to prove freshness and possession of the device private key, not resend the certificate or all static hardware metadata. OTA can resolve the certificate and public key from its registry by `device_id` and verify the HELLO signature against the already registered identity.

## Security rules

Never commit or copy these outside their intended secure location:

```text
root_ca_private.pem
ota_server_private.pem
manufacturing_token.txt
device_private.pem
```

The Root CA private key remains offline. Home Assistant receives only the public Root CA, OTA's own private key/certificate and the manufacturing API token. Each ESP receives only its own private key plus public certificates.

The Home Assistant host should keep a stable IP address, preferably by DHCP reservation, because the OTA TLS certificate contains that IP address as a SAN and ESP provisioning stores the OTA host address.
