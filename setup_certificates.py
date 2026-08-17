#!/usr/bin/env python3
"""Interactive generator of a private CA and TLS certificate for the ESP OTA server."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        value = input(f"{prompt}{suffix}: ").strip()
        if value:
            return value
        if default is not None:
            return default
        print("Value is required.")


def ask_ip() -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    while True:
        value = ask("OTA server IP address")
        try:
            return ipaddress.ip_address(value)
        except ValueError:
            print("Enter a valid IPv4 or IPv6 address.")


def write_private_key(path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    try:
        path.chmod(0o600)
    except OSError:
        pass


def write_certificate(path: Path, certificate: x509.Certificate) -> None:
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


def main() -> None:
    print("This script creates a private CA and the TLS certificate used by the ESP OTA server.")
    print("Enter your ecosystem name, the fixed IP address of the Home Assistant OTA server, and where the certificates should be created.\n")

    ecosystem = ask("OTA ecosystem name", "MyESP")
    ota_ip = ask_ip()
    organization = ask("Organization name", ecosystem)
    output_dir = Path(ask("Certificate output directory", "./cert")).expanduser().resolve()

    if output_dir.exists() and any(output_dir.iterdir()):
        answer = ask(f"Directory {output_dir} is not empty; overwrite certificate files", "no").lower()
        if answer not in {"y", "yes"}:
            print("Cancelled. Existing files were not changed.")
            return

    output_dir.mkdir(parents=True, exist_ok=True)

    ca_key_path = output_dir / "ca.key"
    ca_cert_path = output_dir / "ca.crt"
    server_key_path = output_dir / "ota-server.key"
    server_cert_path = output_dir / "ota-server.crt"

    for path in (ca_key_path, ca_cert_path, server_key_path, server_cert_path):
        if path.exists():
            path.unlink()

    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{ecosystem} OTA Root CA"),
        ]
    )

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    server_key = ec.generate_private_key(ec.SECP256R1())
    server_name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, str(ota_ip)),
        ]
    )

    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ota_ip)]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    write_private_key(ca_key_path, ca_key)
    write_certificate(ca_cert_path, ca_cert)
    write_private_key(server_key_path, server_key)
    write_certificate(server_cert_path, server_cert)

    print("\nCertificates created successfully:")
    print(f"  CA certificate:       {ca_cert_path}")
    print(f"  CA private key:       {ca_key_path}  KEEP SECRET")
    print(f"  OTA server certificate: {server_cert_path}")
    print(f"  OTA server private key: {server_key_path}  KEEP SECRET")
    print(f"\nServer certificate is valid for IP: {ota_ip}")
    print("Copy ota-server.crt and ota-server.key to /share/esp_ota/cert/ on Home Assistant.")
    print("The ESP firmware needs ca.crt (the public CA certificate), never ca.key.")
    print("Keep the OTA server IP fixed, preferably by a DHCP reservation in your router.")


if __name__ == "__main__":
    main()
