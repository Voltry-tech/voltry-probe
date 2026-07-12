"""ECDSA P-384 sign/verify over the canonical bytes, and nothing else.

- **Algorithm:** ECDSA on curve secp384r1 (P-384) with SHA-384, via the vetted
  ``cryptography`` library. No homemade crypto. P-384 echoes the device-unique ECC-384
  identity (ADR 0001).
- **What is signed:** ``canonical_bytes(bundle)`` only: the RFC 8785 bytes of the
  bundle minus its signature. Never a bare ``json.dumps``.
- **Verification:** recomputes the canonical bytes and checks the signature; any tamper
  anywhere in the bundle changes those bytes and fails verification.

This module establishes **cryptographic integrity**: the bytes were signed by the
holder of the embedded (or caller-supplied) public key. Whether that public key belongs
to an *authorized* signer (operator/Voltry) is a registry/trust concern handled by the
platform, not here. No private key material ever lives in code, tests, or fixtures;
tests generate ephemeral keys.
"""

from __future__ import annotations

import base64
import binascii
import json

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .canonicalize import canonical_bytes, canonical_bytes_from_payload
from .models import EvidenceBundle, Signature
from .types import UtcDateTime, utcnow
from .version import CANONICALIZATION_SCHEME, SIGNATURE_ALGORITHM

_CURVE = ec.SECP384R1
_HASH = hashes.SHA384


def generate_keypair() -> ec.EllipticCurvePrivateKey:
    """Generate a fresh ECDSA P-384 private key (the public key is derivable from it)."""
    return ec.generate_private_key(_CURVE())


def public_key_to_spki_b64(public_key: ec.EllipticCurvePublicKey) -> str:
    """Encode a public key as base64 of its SubjectPublicKeyInfo DER."""
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(der).decode("ascii")


def load_public_key_spki_b64(spki_b64: str) -> ec.EllipticCurvePublicKey:
    """Load a public key from base64-encoded SubjectPublicKeyInfo DER.

    Raises ``ValueError`` if the material is malformed, is not an EC public key, or is
    not on P-384. The whole contract is P-384 (the signature algorithm field declares
    it), so a key on any other curve is rejected here rather than being loaded and
    silently used to verify a differently-curved signature that claims to be P-384.
    """
    der = base64.b64decode(spki_b64, validate=True)
    key = serialization.load_der_public_key(der)
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("public key is not an elliptic-curve key")
    if not isinstance(key.curve, _CURVE):
        raise ValueError(f"public key must be on {_CURVE.name}, got {key.curve.name}")
    return key


def sign_bundle(
    bundle: EvidenceBundle,
    private_key: ec.EllipticCurvePrivateKey,
    *,
    signer: str | None = None,
    key_id: str | None = None,
    signed_at: UtcDateTime | None = None,
) -> EvidenceBundle:
    """Return a copy of ``bundle`` with a valid :class:`Signature` attached.

    The original bundle is not mutated. Signing is over ``canonical_bytes`` only. Raises
    ``ValueError`` if ``private_key`` is not on P-384: the signature would declare
    ``ECDSA-P384`` while carrying a different-curve signature, and the verifier rejects
    that mismatch, so a non-P-384 key would only ever produce a bundle that fails its
    own verification. Refuse before emitting the artifact.
    """
    if not isinstance(private_key.curve, _CURVE):
        raise ValueError(
            f"signing key must be on {_CURVE.name}, got {private_key.curve.name}; "
            "the bundle signature algorithm is fixed to ECDSA P-384"
        )
    payload = canonical_bytes(bundle)
    der_signature = private_key.sign(payload, ec.ECDSA(_HASH()))
    signature = Signature(
        algorithm=SIGNATURE_ALGORITHM,
        canonicalization=CANONICALIZATION_SCHEME,
        public_key_spki_b64=public_key_to_spki_b64(private_key.public_key()),
        signature_b64=base64.b64encode(der_signature).decode("ascii"),
        signed_at=signed_at if signed_at is not None else utcnow(),
        signer=signer,
        key_id=key_id,
    )
    return bundle.model_copy(update={"signature": signature})


def verify_bundle(
    bundle: EvidenceBundle,
    *,
    public_key: ec.EllipticCurvePublicKey | None = None,
) -> bool:
    """Return True iff the bundle's signature verifies over its canonical bytes.

    Returns False (never raises) for the expected negative cases: no signature, an
    unsupported algorithm/canonicalization, malformed signature/key material, or a
    cryptographically invalid signature (i.e. any tamper). If ``public_key`` is given it
    is used instead of the key embedded in the signature.
    """
    signature = bundle.signature
    if signature is None:
        return False
    if (
        signature.algorithm != SIGNATURE_ALGORITHM
        or signature.canonicalization != CANONICALIZATION_SCHEME
    ):
        return False
    try:
        key = (
            public_key
            if public_key is not None
            else load_public_key_spki_b64(signature.public_key_spki_b64)
        )
        if not isinstance(key.curve, _CURVE):
            # Curve check: the algorithm field declares P-384; a key on any other curve
            # is a different (possibly weaker) signature masquerading as the declared
            # one. Reject even though the signer really held that key.
            return False
        der_signature = base64.b64decode(signature.signature_b64, validate=True)
        payload = canonical_bytes(bundle)
        key.verify(der_signature, payload, ec.ECDSA(_HASH()))
        return True
    except (InvalidSignature, ValueError, binascii.Error, UnsupportedAlgorithm):
        # UnsupportedAlgorithm: load_der_public_key raises it for key types the
        # OpenSSL backend does not support (seen with exotic/legacy SPKI algorithms);
        # that is malformed-input territory for this contract, so False, not a raise.
        return False


def verify_bundle_json(
    raw: str | bytes | dict,
    *,
    public_key: ec.EllipticCurvePublicKey | None = None,
) -> bool:
    """Verify a bundle from its RAW JSON, byte-faithful across schema versions.

    ``verify_bundle`` re-canonicalizes a parsed model, which materializes the CURRENT
    schema's defaults; a bundle signed under an older minor version would then produce
    different bytes and fail. This function canonicalizes the stored representation
    directly (minus ``signature``), reproducing exactly the bytes that were signed
    regardless of which schema version signed them. Use this path whenever the bundle
    arrives as JSON (files, object stores, APIs). Returns False, never raises, on any
    malformed input or invalid signature.
    """
    try:
        data = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
        if not isinstance(data, dict):
            return False
        signature = Signature.model_validate(data.get("signature"))
    except (ValueError, TypeError, RecursionError):
        # RecursionError: pathologically nested input; malformed, so False not raise.
        return False
    if (
        signature.algorithm != SIGNATURE_ALGORITHM
        or signature.canonicalization != CANONICALIZATION_SCHEME
    ):
        return False
    try:
        key = (
            public_key
            if public_key is not None
            else load_public_key_spki_b64(signature.public_key_spki_b64)
        )
        if not isinstance(key.curve, _CURVE):
            return False  # curve/algorithm mismatch, see verify_bundle
        der_signature = base64.b64decode(signature.signature_b64, validate=True)
        payload = canonical_bytes_from_payload(data)
        key.verify(der_signature, payload, ec.ECDSA(_HASH()))
        return True
    except (InvalidSignature, ValueError, binascii.Error, UnsupportedAlgorithm):
        # UnsupportedAlgorithm from key loading counts as malformed input; see
        # verify_bundle for the reasoning.
        return False


__all__ = [
    "generate_keypair",
    "public_key_to_spki_b64",
    "load_public_key_spki_b64",
    "sign_bundle",
    "verify_bundle",
    "verify_bundle_json",
]
