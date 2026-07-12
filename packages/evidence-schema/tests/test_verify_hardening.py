"""Verifier hardening: curve/algorithm consistency and the raw path's defensive branches.

A bundle whose signature uses a weaker curve than its self-declared ``algorithm``
(ECDSA-P384-SHA384) must NOT verify, even though the signer really possessed that key:
accepting it would let a P-256 signature pass itself off as the stronger declared
scheme. Also covers the guards that reject malformed input by returning False rather
than raising.
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from evidence_schema import verify_bundle, verify_bundle_json
from evidence_schema.canonicalize import (
    CanonicalizationError,
    canonical_bytes,
    canonical_bytes_from_payload,
)
from evidence_schema.models import Signature
from evidence_schema.samples import worked_example_a_bundle
from evidence_schema.sign import public_key_to_spki_b64
from evidence_schema.types import utcnow
from evidence_schema.version import CANONICALIZATION_SCHEME, SIGNATURE_ALGORITHM


def _sign_with(bundle, key):
    """Attach a signature made with an arbitrary curve but the DECLARED hash (SHA-384),
    so the curve is the only mismatch, isolating the curve check."""
    payload = canonical_bytes(bundle)
    der = key.sign(payload, ec.ECDSA(hashes.SHA384()))
    sig = Signature(
        algorithm=SIGNATURE_ALGORITHM,  # declares P-384 regardless of the real curve
        canonicalization=CANONICALIZATION_SCHEME,
        public_key_spki_b64=public_key_to_spki_b64(key.public_key()),
        signature_b64=base64.b64encode(der).decode("ascii"),
        signed_at=utcnow(),
    )
    return bundle.model_copy(update={"signature": sig})


def test_p256_key_labelled_p384_does_not_verify():
    # A real, self-consistent P-256 signature that lies about its curve must fail both paths.
    p256 = ec.generate_private_key(ec.SECP256R1())
    forged = _sign_with(worked_example_a_bundle(), p256)
    assert verify_bundle(forged) is False
    assert verify_bundle_json(forged.model_dump_json()) is False


def test_p521_key_labelled_p384_does_not_verify():
    p521 = ec.generate_private_key(ec.SECP521R1())
    forged = _sign_with(worked_example_a_bundle(), p521)
    assert verify_bundle(forged) is False
    assert verify_bundle_json(forged.model_dump_json()) is False


def test_raw_verify_rejects_non_dict_json():
    assert verify_bundle_json("[]") is False
    assert verify_bundle_json("42") is False
    assert verify_bundle_json('"a string"') is False


def test_raw_verify_rejects_algorithm_mismatch():
    signed = worked_example_a_bundle()
    import json

    from evidence_schema import generate_keypair
    from evidence_schema.sign import sign_bundle

    data = json.loads(sign_bundle(signed, generate_keypair()).model_dump_json())
    data["signature"]["algorithm"] = "RSA-4096-SHA256"
    assert verify_bundle_json(json.dumps(data)) is False


def test_unsupported_key_algorithm_returns_false(monkeypatch):
    """Both verify paths promise 'returns False, never raises'. cryptography's
    load_der_public_key raises UnsupportedAlgorithm (not ValueError) for SPKI key
    types the OpenSSL backend cannot handle, so an attacker-supplied exotic key must
    surface as a clean False, not an exception. Simulated via a mocked loader
    because producing such DER portably across cryptography versions is unreliable."""
    from cryptography.exceptions import UnsupportedAlgorithm

    from evidence_schema import generate_keypair
    from evidence_schema.sign import sign_bundle

    signed = sign_bundle(worked_example_a_bundle(), generate_keypair())

    def _raise(_spki_b64: str):
        raise UnsupportedAlgorithm("key type not supported by this backend")

    monkeypatch.setattr("evidence_schema.sign.load_public_key_spki_b64", _raise)
    assert verify_bundle(signed) is False
    assert verify_bundle_json(signed.model_dump_json()) is False


def test_raw_canonicalize_rejects_out_of_domain_number():
    # The raw path must raise the typed error (not a bare Exception) on a value outside
    # the RFC 8785 domain, exactly like the model path.
    with pytest.raises(CanonicalizationError):
        canonical_bytes_from_payload({"x": 2**60})


def test_sign_bundle_rejects_non_p384_key():
    # A producer must not be able to emit a bundle that fails its own verifier: signing
    # with any curve other than P-384 raises before an artifact exists.
    from cryptography.hazmat.primitives.asymmetric import ec

    from evidence_schema import sign_bundle
    from evidence_schema.samples import worked_example_a_bundle

    for curve in (ec.SECP256R1(), ec.SECP521R1()):
        with pytest.raises(ValueError, match="P-384|secp384r1|SECP384R1"):
            sign_bundle(worked_example_a_bundle(), ec.generate_private_key(curve))


def test_load_public_key_rejects_non_p384():
    from cryptography.hazmat.primitives.asymmetric import ec

    from evidence_schema.sign import load_public_key_spki_b64, public_key_to_spki_b64

    p256_pub = ec.generate_private_key(ec.SECP256R1()).public_key()
    with pytest.raises(ValueError, match="P-384|secp384r1|SECP384R1"):
        load_public_key_spki_b64(public_key_to_spki_b64(p256_pub))
