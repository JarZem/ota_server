#!/usr/bin/env python3
"""Create or reuse an offline Root CA, issue the OTA server certificate, and optionally deploy OTA public/private material to Home Assistant."""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import secrets
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT_CA_CERT_NAME = 'root_ca_cert.pem'
ROOT_CA_KEY_NAME = 'root_ca_private.pem'
OTA_CERT_NAME = 'ota_server_cert.pem'
OTA_KEY_NAME = 'ota_server_private.pem'
OTA_PUBLIC_NAME = 'ota_server_public.pem'
MANUFACTURING_TOKEN_NAME = 'manufacturing_token.txt'
REMOTE_CERT_DIR = '/share/ota_server/cert'
ROLE_URI = 'urn:esp-pki:role:ota-server'


def ask(prompt: str, default: str | None = None) -> str:
    suffix = f' [{default}]' if default is not None else ''
    value = input(f'{prompt}{suffix}: ').strip()
    return value or (default or '')


def write_private_key(path: Path, key: ec.EllipticCurvePrivateKey, password: bytes | None) -> None:
    encryption = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption))
    try:
        path.chmod(0o600)
    except OSError:
        pass


def create_root_ca(ca_dir: Path, ecosystem: str) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    print('No Root CA exists yet. This creates the offline Root CA; keep its private key away from Home Assistant and Git.')
    password1 = getpass.getpass('New Root CA private key password: ')
    password2 = getpass.getpass('Repeat Root CA private key password: ')
    if not password1 or password1 != password2:
        raise RuntimeError('Root CA password is empty or does not match')

    now = datetime.now(timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ecosystem),
        x509.NameAttribute(NameOID.COMMON_NAME, f'{ecosystem} ESP Root CA'),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )

    ca_dir.mkdir(parents=True, exist_ok=True)
    (ca_dir / ROOT_CA_CERT_NAME).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    write_private_key(ca_dir / ROOT_CA_KEY_NAME, key, password1.encode('utf-8'))
    print(f'Root CA created in {ca_dir}')
    return cert, key


def load_root_ca(ca_dir: Path, ecosystem: str, allow_create: bool) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    cert_path = ca_dir / ROOT_CA_CERT_NAME
    key_path = ca_dir / ROOT_CA_KEY_NAME
    if not cert_path.is_file() or not key_path.is_file():
        if not allow_create:
            raise FileNotFoundError(
                f'Missing {cert_path} or {key_path}. Use --init-ca only when creating a new ecosystem Root CA.'
            )
        return create_root_ca(ca_dir, ecosystem)

    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    password_text = getpass.getpass('Root CA private key password (empty only if key is unencrypted): ')
    password = password_text.encode('utf-8') if password_text else None
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=password)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise RuntimeError('Root CA private key is not EC')
    if cert.public_key().public_numbers() != key.public_key().public_numbers():
        raise RuntimeError('Root CA certificate/private key mismatch')
    return cert, key


def issue_ota_certificate(ca_cert: x509.Certificate, ca_key: ec.EllipticCurvePrivateKey,
                          ecosystem: str, ota_ip: ipaddress._BaseAddress,
                          output_dir: Path) -> None:
    now = datetime.now(timezone.utc)
    ota_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ecosystem),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'OTA Server'),
        x509.NameAttribute(NameOID.COMMON_NAME, f'{ecosystem} OTA Server'),
    ])
    ota_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(ota_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=True, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([
            x509.IPAddress(ota_ip),
            x509.UniformResourceIdentifier(ROLE_URI),
        ]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ota_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / OTA_CERT_NAME).write_bytes(ota_cert.public_bytes(serialization.Encoding.PEM))
    write_private_key(output_dir / OTA_KEY_NAME, ota_key, None)
    (output_dir / OTA_PUBLIC_NAME).write_bytes(ota_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    (output_dir / ROOT_CA_CERT_NAME).write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    token_path = output_dir / MANUFACTURING_TOKEN_NAME
    if not token_path.exists():
        token_path.write_text(secrets.token_urlsafe(48) + '\n', encoding='utf-8')
        try:
            token_path.chmod(0o600)
        except OSError:
            pass

    print(f'OTA certificate role: {ROLE_URI}')
    print(f'OTA certificate SHA256: {ota_cert.fingerprint(hashes.SHA256()).hex()}')


def deploy_to_home_assistant(output_dir: Path, ssh_target: str, ssh_key: str | None) -> None:
    ssh_args = ['ssh']
    scp_args = ['scp']
    if ssh_key:
        ssh_args += ['-i', ssh_key]
        scp_args += ['-i', ssh_key]
    subprocess.run(ssh_args + [ssh_target, f'mkdir -p {REMOTE_CERT_DIR} && chmod 700 {REMOTE_CERT_DIR}'], check=True)
    files = [ROOT_CA_CERT_NAME, OTA_CERT_NAME, OTA_KEY_NAME, OTA_PUBLIC_NAME, MANUFACTURING_TOKEN_NAME]
    subprocess.run(scp_args + [str(output_dir / name) for name in files] + [f'{ssh_target}:{REMOTE_CERT_DIR}/'], check=True)
    subprocess.run(ssh_args + [ssh_target,
        f'chmod 600 {REMOTE_CERT_DIR}/{OTA_KEY_NAME} {REMOTE_CERT_DIR}/{MANUFACTURING_TOKEN_NAME}; '
        f'chmod 644 {REMOTE_CERT_DIR}/{ROOT_CA_CERT_NAME} {REMOTE_CERT_DIR}/{OTA_CERT_NAME} {REMOTE_CERT_DIR}/{OTA_PUBLIC_NAME}'], check=True)
    print(f'OTA certificate material deployed to {ssh_target}:{REMOTE_CERT_DIR}/')


def main() -> None:
    parser = argparse.ArgumentParser(description='Prepare the ESP PKI Root CA/OTA certificate material and optionally deploy it to Home Assistant.')
    parser.add_argument('--ecosystem')
    parser.add_argument('--ota-ip')
    parser.add_argument('--ca-dir', type=Path)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--init-ca', action='store_true')
    parser.add_argument('--ssh-target', help='Example: root@192.168.2.120')
    parser.add_argument('--ssh-key', help='SSH private key path used for Home Assistant deployment')
    args = parser.parse_args()

    print('This script uses one offline Root CA, issues the OTA server certificate, exports OTA public material, and can copy only the required OTA files to Home Assistant.')
    ecosystem = args.ecosystem or ask('Ecosystem', 'JaroslavZemanESP')
    ota_ip = ipaddress.ip_address(args.ota_ip or ask('OTA/Home Assistant fixed IP', '192.168.2.120'))
    ca_dir = (args.ca_dir or Path(ask('Offline CA directory', './ca'))).expanduser().resolve()
    output_dir = (args.out or Path(ask('OTA certificate output directory', './ota_credentials'))).expanduser().resolve()

    ca_cert, ca_key = load_root_ca(ca_dir, ecosystem, args.init_ca)
    issue_ota_certificate(ca_cert, ca_key, ecosystem, ota_ip, output_dir)

    ssh_target = args.ssh_target or ask('Deploy to Home Assistant over SSH now (target, empty = no)', '')
    if ssh_target:
        ssh_key = args.ssh_key or ask('SSH private key path (empty = SSH default)', '') or None
        deploy_to_home_assistant(output_dir, ssh_target, ssh_key)

    print('\nCreated/required layout:')
    print(f'  OFFLINE ONLY: {ca_dir / ROOT_CA_KEY_NAME}')
    print(f'  Public CA:    {output_dir / ROOT_CA_CERT_NAME}')
    print(f'  OTA cert:     {output_dir / OTA_CERT_NAME}')
    print(f'  OTA key:      {output_dir / OTA_KEY_NAME}')
    print(f'  OTA public:   {output_dir / OTA_PUBLIC_NAME}')
    print(f'  API token:    {output_dir / MANUFACTURING_TOKEN_NAME}')
    print('The Root CA private key is never copied to Home Assistant or ESP firmware.')


if __name__ == '__main__':
    main()
