"""Enumerations for the evidence bundle.

All are string enums so they canonicalize as stable JSON strings and read clearly
in the bundle. New members are an *additive* (minor) change; renaming or removing a
member is *breaking* (major). See :mod:`evidence_schema.version`.
"""

from __future__ import annotations

from enum import Enum

# (str, Enum) rather than StrEnum: the published packages support Python 3.10
# (ADR-0003) and StrEnum is 3.11+. Canonicalization reads .value via pydantic,
# so canonical bytes are unchanged; the golden-vector test proves it on 3.10.


class Tier(str, Enum):
    """Provenance/coverage tier. Maps to run mode: READ is roughly Bronze, a full
    functional pass Silver, continuous monitoring Gold."""

    BRONZE = "BRONZE"
    SILVER = "SILVER"
    GOLD = "GOLD"


class History(str, Enum):
    """Whether the unit's history was captured from first-seen or reconstructed."""

    BORN_ON = "BORN_ON"
    RECONSTRUCTED = "RECONSTRUCTED"


class IdentityScheme(str, Enum):
    """How the device identity is anchored."""

    #: Device-unique ECC-384 key fused at manufacture, verified via the NVIDIA chain.
    HARDWARE_ROOT = "HARDWARE_ROOT"
    #: Documented fallback for parts without a hardware root of trust; lower confidence.
    SECONDARY_FALLBACK = "SECONDARY_FALLBACK"


class RunMode(str, Enum):
    """The mode the agent ran in to produce the bundle."""

    READ = "READ"
    FUNCTIONAL = "FUNCTIONAL"
    MONITOR = "MONITOR"


class GateResult(str, Enum):
    """Outcome of a deterministic gate or functional pass/fail.

    ``NOT_ASSESSED`` is a first-class value: a gate that was not run is never
    silently treated as PASS, and consumers must render it as its own state
    rather than folding it into either outcome.
    """

    PASS = "PASS"  # noqa: S105 - enum member value, not a credential
    FAIL = "FAIL"
    NOT_ASSESSED = "NOT_ASSESSED"


class AttestationVerdict(str, Enum):
    """Result of the NVIDIA attestation chain verification.

    The verdict records what the chain evaluation actually returned; there is no
    default-to-verified path. ``UNVERIFIED`` means the chain could not be
    evaluated (e.g. PKI unreachable); ``FALLBACK`` means a secondary,
    lower-confidence scheme was used and is marked as such.
    """

    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    UNVERIFIED = "UNVERIFIED"
    FALLBACK = "FALLBACK"


__all__ = [
    "Tier",
    "History",
    "IdentityScheme",
    "RunMode",
    "GateResult",
    "AttestationVerdict",
]
