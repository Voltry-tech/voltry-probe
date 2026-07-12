"""Sign/verify round-trip + tamper detection (ECDSA P-384 over canonical bytes)."""

from __future__ import annotations

import base64

import pytest

import evidence_schema as es
from evidence_schema.sign import public_key_to_spki_b64


def test_sign_then_verify_passes(sample_bundle, keypair):
    signed = es.sign_bundle(sample_bundle, keypair, signer="operator")
    assert signed.signature is not None
    assert signed.signature.algorithm == es.SIGNATURE_ALGORITHM
    assert signed.signature.canonicalization == es.CANONICALIZATION_SCHEME
    assert signed.signature.signer == "operator"
    assert es.verify_bundle(signed) is True


def test_signing_does_not_mutate_original(sample_bundle, keypair):
    es.sign_bundle(sample_bundle, keypair)
    assert sample_bundle.signature is None  # original untouched


def test_unsigned_bundle_does_not_verify(sample_bundle):
    assert es.verify_bundle(sample_bundle) is False


def _tamper(bundle, mutate):
    t = bundle.model_copy(deep=True)
    mutate(t)
    return t


TAMPERS = {
    "spare_rows": lambda b: setattr(b.measured.spare_rows, "remaining", 1),
    "ecc": lambda b: setattr(b.measured.ecc, "aggregate_uncorrectable", 99),
    "device_part": lambda b: setattr(b.identity, "device_part", "A100-SXM4"),
    "reflash": lambda b: setattr(b.identity, "reflash_detected", True),
    "tier": lambda b: setattr(b.provenance, "tier", es.Tier.GOLD),
    "exposure": lambda b: setattr(b.provenance, "exposure_assessed", True),
    "methodology": lambda b: setattr(b, "methodology_version_hash", "deadbeef"),
    "raw_reads": lambda b: b.measured.xid.append(es.XidEvent(xid=79, category="fell-off-bus")),
    "extensions": lambda b: b.measured.extensions.__setitem__("injected", "x"),
}


@pytest.mark.parametrize("name", list(TAMPERS))
def test_tamper_anywhere_breaks_verification(sample_bundle, keypair, name):
    signed = es.sign_bundle(sample_bundle, keypair)
    assert es.verify_bundle(signed) is True
    tampered = _tamper(signed, TAMPERS[name])
    assert es.verify_bundle(tampered) is False, f"tamper '{name}' was not detected"


def test_verify_with_correct_external_public_key(sample_bundle, keypair):
    signed = es.sign_bundle(sample_bundle, keypair)
    assert es.verify_bundle(signed, public_key=keypair.public_key()) is True


def test_verify_with_wrong_public_key_fails(sample_bundle, keypair):
    other = es.generate_keypair()
    signed = es.sign_bundle(sample_bundle, keypair)
    assert es.verify_bundle(signed, public_key=other.public_key()) is False


def test_corrupted_signature_bytes_fail(sample_bundle, keypair):
    signed = es.sign_bundle(sample_bundle, keypair)
    raw = bytearray(base64.b64decode(signed.signature.signature_b64))
    raw[-1] ^= 0xFF  # flip a byte
    signed.signature.signature_b64 = base64.b64encode(bytes(raw)).decode("ascii")
    assert es.verify_bundle(signed) is False


def test_malformed_signature_b64_fails(sample_bundle, keypair):
    signed = es.sign_bundle(sample_bundle, keypair)
    signed.signature.signature_b64 = "not!valid!base64!"
    assert es.verify_bundle(signed) is False


def test_malformed_public_key_fails(sample_bundle, keypair):
    signed = es.sign_bundle(sample_bundle, keypair)
    signed.signature.public_key_spki_b64 = base64.b64encode(b"not a key").decode("ascii")
    assert es.verify_bundle(signed) is False


def test_unsupported_algorithm_is_rejected(sample_bundle, keypair):
    signed = es.sign_bundle(sample_bundle, keypair)
    signed.signature.algorithm = "RSA-PKCS1-SHA256"
    assert es.verify_bundle(signed) is False


def test_unsupported_canonicalization_is_rejected(sample_bundle, keypair):
    signed = es.sign_bundle(sample_bundle, keypair)
    signed.signature.canonicalization = "BARE-JSON"
    assert es.verify_bundle(signed) is False


def test_public_key_spki_roundtrip(keypair):
    spki = public_key_to_spki_b64(keypair.public_key())
    loaded = es.load_public_key_spki_b64(spki)
    assert public_key_to_spki_b64(loaded) == spki


def test_load_non_ec_key_rejected():
    """A valid DER that is not an EC public key is rejected."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    rsa_pub = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    der = rsa_pub.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with pytest.raises(ValueError):
        es.load_public_key_spki_b64(base64.b64encode(der).decode("ascii"))
