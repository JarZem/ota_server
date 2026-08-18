# OTA Server

Home Assistant add-on providing HTTPS OTA firmware delivery, Zigbee2MQTT enrollment transport and a manufacturing PKI service for ESP devices.

## Certificate architecture

The ecosystem uses one offline P-256 Root CA. The Root CA private key is the only signing authority and must never be copied to Home Assistant, OTA server, ESP firmware or Git.

The established PKI URI namespace is:

```text
urn:jarzem:esp:pki:...
```

Existing OTA certificates using this namespace remain valid and are not regenerated merely because application code changes.

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

The OTA certificate uses the established role URI:

```text
urn:jarzem:esp:pki:role:ota-server
```

When `--ssh-target` is supplied, the script creates `/share/ota_server/cert/` and copies only the files OTA actually requires. It deliberately does not copy `root_ca_private.pem`.

## 2. OTA manufacturing HTTPS service

OTA add-on version 0.1.18 exposes a manufacturing service on HTTPS port `8451` using the normal OTA server TLS certificate.

Public endpoints:

```text
GET https://<ota-ip>:8451/api/manufacturing/root-ca.pem
GET https://<ota-ip>:8451/api/manufacturing/ota-server.pem
GET https://<ota-ip>:8451/api/manufacturing/ota-public.pem
GET https://<ota-ip>:8451/api/manufacturing/health
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

For every registration OTA verifies CA signature, validity, `CA:FALSE`, `digitalSignature`, `clientAuth`, P-256, role `device` and the device IEEE identity. Only after those checks is the public certificate written to `/data/device_registry.db`.

## 3. Per-device ESP certificate

The ESP project contains `tools/create_device_credentials.py`. It creates a local device private key, issues the matching certificate from the offline Root CA, registers only the public certificate with OTA and downloads the public OTA trust material.

The device certificate contains stable manufacturing identity: ecosystem, group/family, IEEE device id, model, product role, hardware revision, chip and flash size. These facts therefore do not need to be repeated in Zigbee HELLO.

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

## 4. ESP build and flash

The ESP project's CMake invokes `tools/create_device_credentials.py` automatically when no device credential workspace exists. It refuses to regenerate an identity when only part of an existing credential set is present.

CMake embeds into firmware:

```text
device_private.pem
device_cert.pem
root_ca_cert.pem
ota_server_cert.pem
```

After successful flashing run `python tools/cleanup_device_credentials.py`. This removes the local private key and build directories containing firmware images with the embedded private key.

## 5. Live manufacturing API test

Run:

```bash
python tests/test_manufacturing_live.py --ota-url https://192.168.2.120:8451 --ca-dir D:/ESP-PKI/ca --ecosystem JaroslavZemanESP
```

The test validates TLS through the real Root CA, verifies the OTA certificate including `urn:jarzem:esp:pki:role:ota-server`, checks the OTA public key endpoint, registers a valid CA-signed device certificate and verifies rejection of invalid certificates.

## Security rules

Never commit or copy these outside their intended secure location:

```text
root_ca_private.pem
ota_server_private.pem
device_private.pem
```

The Root CA private key remains offline. Home Assistant receives only the public Root CA and OTA's own private key/certificate. Each ESP receives only its own private key plus public certificates.
