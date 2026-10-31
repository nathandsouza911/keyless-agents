"""The quick start's one-time setup (v0.1; SD-051): python -m clw.demo.setup <demo dir>.

Idempotent. Writes into the shared demo directory:
  ca.pem, graph.cert.pem, graph.key.pem   a CA made here, and the fake Graph's
                                          certificate for graph.microsoft.com
  profile_key.pem                         the fictional apps' key (never a real one)
  session_secret                          the api's session-signing secret
then migrates the database and registers the fictional tenant and its one
person. Nothing here contacts anything outside the quick start.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import secrets
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from clw.demo import DEMO_TENANT_ID, DEMO_TENANT_NAME, DEMO_USER_OID, DEMO_USER_ROLE

GRAPH_HOST = "graph.microsoft.com"


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _pem_key(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def write_certs(into: Path) -> None:
    now = dt.datetime.now(dt.timezone.utc)
    ca_key, leaf_key = _key(), _key()
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Cloud Locksmith quick start CA (demo only)")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number())
          .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .sign(ca_key, hashes.SHA256()))
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, GRAPH_HOST)]))
            .issuer_name(ca_name).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(GRAPH_HOST)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256()))
    ca_pem = ca.public_bytes(serialization.Encoding.PEM)
    (into / "ca.pem").write_bytes(ca_pem)
    (into / "graph.cert.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM) + ca_pem)
    (into / "graph.key.pem").write_bytes(_pem_key(leaf_key))


async def _register() -> None:
    from sqlalchemy import text

    from clw.db.session import get_sessionmaker

    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        async with session.begin():
            await session.execute(text("INSERT INTO tenants (id, display_name, status) VALUES (:t, :n, 'active') "
                                       "ON CONFLICT (id) DO NOTHING"), {"t": DEMO_TENANT_ID, "n": DEMO_TENANT_NAME})
            await session.execute(text("INSERT INTO workbench_users (id, tenant_id, oid, role) "
                                       "VALUES (gen_random_uuid(), :t, :o, :r) ON CONFLICT DO NOTHING"),
                                  {"t": DEMO_TENANT_ID, "o": DEMO_USER_OID, "r": DEMO_USER_ROLE})


def main(argv: list[str]) -> int:
    demo_dir = Path(argv[0]) if argv else Path("/demo")
    demo_dir.mkdir(parents=True, exist_ok=True)
    if not (demo_dir / "ca.pem").exists():
        write_certs(demo_dir)
    if not (demo_dir / "profile_key.pem").exists():
        (demo_dir / "profile_key.pem").write_bytes(_pem_key(_key()))
    if not (demo_dir / "session_secret").exists():
        (demo_dir / "session_secret").write_text(secrets.token_urlsafe(48), encoding="ascii")
    for name in ("ca.pem", "graph.cert.pem", "graph.key.pem", "profile_key.pem", "session_secret"):
        (demo_dir / name).chmod(0o644)  # read by the other quick start containers' own users

    from alembic import command
    from alembic.config import Config

    config = Config(str(Path(__file__).resolve().parents[3] / "alembic.ini"))
    command.upgrade(config, "head")
    asyncio.run(_register())
    print("quick start setup: done")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main(sys.argv[1:]))
