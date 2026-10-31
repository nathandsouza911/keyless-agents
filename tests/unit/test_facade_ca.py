"""The deployment's facade CA (SD-041): a name-constrained CA for graph.microsoft.com only."""

from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from clw.broker.facade.ca import create


def test_the_leaf_is_for_graph_only_and_signed_by_a_name_constrained_ca(tmp_path):
    made = create(tmp_path)
    ca = x509.load_pem_x509_certificate(made.ca_cert.read_bytes())
    leaf = x509.load_pem_x509_certificate(made.leaf_cert.read_bytes())
    assert leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
        x509.DNSName) == ["graph.microsoft.com"]
    constraints = ca.extensions.get_extension_for_class(x509.NameConstraints)
    assert constraints.critical and [n.value for n in constraints.value.permitted_subtrees] == ["graph.microsoft.com"]
    ca.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm))
    assert not leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca


def test_nothing_is_overwritten(tmp_path):
    create(tmp_path)
    before = (tmp_path / "leaf.key").read_bytes()
    with pytest.raises(FileExistsError):
        create(tmp_path)
    assert (tmp_path / "leaf.key").read_bytes() == before


def test_the_public_directory_holds_the_ca_certificate_alone(tmp_path):
    # It is the task image's build context (SD-044): nothing in it may be a key.
    made = create(tmp_path)
    assert sorted(p.name for p in (tmp_path / "public").iterdir()) == ["ca.crt"]
    assert made.ca_cert == tmp_path / "public" / "ca.crt"
    assert b"PRIVATE KEY" not in made.ca_cert.read_bytes()
