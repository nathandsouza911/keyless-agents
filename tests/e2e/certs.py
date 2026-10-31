"""A throwaway TLS trust root for the offline E2E demo.

The broker's transport is pinned to `https://graph.microsoft.com` (SD-031)
and its HTTP client trusts only certifi's bundle. To let the real transport
reach a *fake* Graph offline — without weakening that pin or changing any
production code — the E2E:

  1. generates a one-off CA here,
  2. issues a leaf certificate for `graph.microsoft.com` from it,
  3. serves the fake Graph with that leaf over TLS, network-aliased as
     `graph.microsoft.com` on the egress network, and
  4. bind-mounts the CA (as the whole `cacert.pem`) over the broker's certifi
     path, so the broker trusts exactly this one test CA and nothing else.

These certificates live only in a temporary directory for the test run and
are never committed. They prove nothing about Microsoft's real endpoints.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

GRAPH_HOST = "graph.microsoft.com"


@dataclass(frozen=True)
class E2ECerts:
    ca_pem: Path       # the only CA the broker trusts in the E2E (mounted over certifi)
    server_cert: Path  # leaf + CA chain for graph.microsoft.com
    server_key: Path


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def generate(into: Path) -> E2ECerts:
    into.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = _key()
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "clw-e2e-test-ca")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    server_key = _key()
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, GRAPH_HOST)]))
        .issuer_name(ca_name).public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(GRAPH_HOST)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    ca_pem = into / "ca.pem"
    server_cert = into / "graph.cert.pem"
    server_key_path = into / "graph.key.pem"
    ca_pem.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    # The leaf plus the CA, so the server presents a full chain.
    server_cert.write_bytes(leaf.public_bytes(serialization.Encoding.PEM)
                            + ca.public_bytes(serialization.Encoding.PEM))
    server_key_path.write_bytes(server_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    return E2ECerts(ca_pem=ca_pem, server_cert=server_cert, server_key=server_key_path)
