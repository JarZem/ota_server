# ESP OTA Server

Home Assistant add-on providing HTTPS OTA firmware delivery for ESP devices.

## TLS certificates

The OTA server uses its own private certificate authority (CA). The server certificate is issued by this CA and ESP firmware trusts the public CA certificate.

The server expects:

```text
/share/ota_server/cert/ota-server.crt
/share/ota_server/cert/ota-server.key
```

Use `setup_certificates.py` to create the CA and OTA server certificate automatically.

### Requirements

```bash
pip install cryptography
```

### Create certificates

```bash
python setup_certificates.py
```

The script asks for the OTA ecosystem name, the fixed IP address of the Home Assistant machine running the OTA server, an organization name, and the output directory (default `./cert`).

It creates:

```text
cert/
  ca.crt
  ca.key
  ota-server.crt
  ota-server.key
```

`ca.crt` is the public CA certificate that ESP firmware must trust.

`ca.key` is the private CA key. Keep it secret and never copy it into ESP firmware or commit it to Git.

`ota-server.crt` and `ota-server.key` are used by the HTTPS OTA server. Copy them to:

```text
/share/ota_server/cert/
```

The server certificate contains the entered OTA server IP address as an IP Subject Alternative Name (SAN). No DNS or mDNS hostname is required.

## Stable Home Assistant IP

The Home Assistant machine running the OTA server should have a stable IP address. A DHCP reservation in the router is recommended; a static address configured directly in Home Assistant is not required.

If the OTA server IP changes, devices will try to reach the old address and the existing TLS certificate will not be valid for the new IP. Keep the address fixed or generate a new server certificate for the new address.

## Security

Never publish `ca.key` or `ota-server.key`. Generated certificate directories and private key files are excluded by `.gitignore`.
