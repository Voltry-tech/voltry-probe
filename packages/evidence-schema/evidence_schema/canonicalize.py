"""The single canonical serializer, and the only path to signable bytes.

Canonicalization scheme: **RFC 8785 (JSON Canonicalization Scheme)** applied to the
bundle's JSON projection with the ``signature`` field excluded. RFC 8785 fixes object
key ordering (lexicographic on UTF-16 code units), number formatting (shortest
round-trip ECMAScript form), string escaping, and whitespace, so the same logical
bundle yields identical bytes across runs, processes, and languages.

Frozen rules (recorded in ``docs/adr/0002-evidence-schema-freeze.md``):

1. Serialize ``EvidenceBundle.model_dump(mode="json", exclude={"signature"})``, i.e.
   the full schema projection (defaults included, nulls included) minus the signature.
2. Feed that to ``rfc8785.dumps`` to obtain the canonical bytes.
3. Sign/verify operate on these bytes only. A bare ``json.dumps`` in the signing path
   would produce bytes that depend on Python's serializer settings, so it is forbidden.

The signature is excluded because a signature cannot cover itself; everything else in
the bundle is covered, so tampering with any other field changes the canonical bytes
and breaks verification.
"""

from __future__ import annotations

import rfc8785

from .models import EvidenceBundle


class CanonicalizationError(ValueError):
    """Raised when a bundle cannot be canonicalized (e.g. an out-of-domain number)."""


def canonical_payload(bundle: EvidenceBundle) -> dict:
    """The JSON projection that gets canonicalized: full schema minus the signature."""
    return bundle.model_dump(mode="json", exclude={"signature"})


def canonical_bytes(bundle: EvidenceBundle) -> bytes:
    """Return the canonical (RFC 8785) bytes of ``bundle``, the signable representation.

    Raises :class:`CanonicalizationError` if the bundle contains a value outside the
    RFC 8785 domain (notably an integer above 2**53 that slipped past the typed
    bounds; such data must be captured verbatim in ``raw_reads`` instead).
    """
    payload = canonical_payload(bundle)
    try:
        return rfc8785.dumps(payload)
    except Exception as exc:  # noqa: BLE001 - re-raised as a typed, explicit error.
        raise CanonicalizationError(
            f"bundle is not canonicalizable under RFC 8785: {exc}. "
            "Large/opaque values must be captured verbatim in raw_reads, not as JSON numbers."
        ) from exc


def canonical_json(bundle: EvidenceBundle) -> str:
    """The canonical bytes decoded as a UTF-8 string (for debugging/inspection only)."""
    return canonical_bytes(bundle).decode("utf-8")


def canonical_bytes_from_payload(payload: dict) -> bytes:
    """Canonical bytes of an already-serialized bundle payload (signature excluded).

    This is the cross-version verification path (version.py policy): a bundle's stored
    JSON is exactly the projection that was canonicalized at signing time under the
    schema version that signed it. Canonicalizing the RAW payload, rather than
    re-parsing through the CURRENT models (which would materialize new minor-version
    defaults), reproduces the signed bytes for any schema version, forever.
    """
    stripped = {k: v for k, v in payload.items() if k != "signature"}
    try:
        return rfc8785.dumps(stripped)
    except Exception as exc:  # noqa: BLE001 - re-raised as a typed, explicit error.
        raise CanonicalizationError(
            f"payload is not canonicalizable under RFC 8785: {exc}."
        ) from exc


__all__ = [
    "CanonicalizationError",
    "canonical_payload",
    "canonical_bytes",
    "canonical_bytes_from_payload",
    "canonical_json",
]
