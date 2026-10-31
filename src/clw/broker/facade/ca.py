"""The deployment's facade CA (SD-041).

Inside script runs' network, the Graph host is the facade proxy. The
proxy proves that name with a certificate from a CA that exists only for
this deployment: its certificate is trusted inside the PowerShell task
image and nowhere else (not by the broker, not by the host). `create`
writes into an empty directory:

  public/ca.crt  the CA certificate: built into the PowerShell task image
  ca.key         the CA key: keep offline; only needed to issue a new leaf
  leaf.crt       the Graph host, signed by the CA: mounted into the proxy
  leaf.key       its key: mounted into the proxy only

The CA certificate is alone in public/ so that directory can be the task
image's build context: no key is ever sent to the Docker daemon (SD-044).
Keys are written owner-read-only where the platform supports it, and
nothing is overwritten.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from clw.broker.pagination import GRAPH_HOST  # the one place the Graph host is named

CA_DAYS = 3650
LEAF_DAYS = 397
FILES = ("public/ca.crt", "ca.key", "leaf.crt", "leaf.key")


@dataclass(frozen=True, slots=True)
class FacadeCA:
    ca_cert: Path
    leaf_cert: Path
    leaf_key: Path


def _write(path: Path, data: bytes, *, private: bool) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600 if private else 0o644)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def create(directory: Path, *, now: datetime | None = None) -> FacadeCA:
    directory = Path(directory)
    (directory / "public").mkdir(parents=True, exist_ok=True)
    if any((directory / name).exists() for name in FILES):
        raise FileExistsError("facade CA files already exist here; nothing was overwritten")
    now = now or datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Cloud Locksmith facade CA (this deployment only)")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=CA_DAYS))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                       data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                       crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.NameConstraints(permitted_subtrees=[x509.DNSName(GRAPH_HOST)], excluded_subtrees=None),
                         critical=True)
          .sign(ca_key, hashes.SHA256()))
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, GRAPH_HOST)]))
            .issuer_name(ca_name).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=LEAF_DAYS))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(GRAPH_HOST)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256()))

    def pem_key(key):
        return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption())

    _write(directory / "public" / "ca.crt", ca.public_bytes(serialization.Encoding.PEM), private=False)
    _write(directory / "ca.key", pem_key(ca_key), private=True)
    _write(directory / "leaf.crt", leaf.public_bytes(serialization.Encoding.PEM), private=False)
    _write(directory / "leaf.key", pem_key(leaf_key), private=True)
    return FacadeCA(ca_cert=directory / "public" / "ca.crt", leaf_cert=directory / "leaf.crt", leaf_key=directory / "leaf.key")
