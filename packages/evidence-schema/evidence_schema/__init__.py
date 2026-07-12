"""Voltry evidence-schema: the signed evidence-bundle contract.

Public API: the typed models, the single canonical serializer, and ECDSA P-384
sign/verify. Everything that produces or consumes a bundle imports from here and never
re-implements the contract.
"""

from __future__ import annotations

from .canonicalize import CanonicalizationError, canonical_bytes, canonical_json, canonical_payload
from .enums import (
    AttestationVerdict,
    GateResult,
    History,
    IdentityScheme,
    RunMode,
    Tier,
)
from .jsonschema import generate_json_schema, json_schema_str
from .models import (
    SPARE_ROW_CAP,
    AgentInfo,
    Attestation,
    ClockPower,
    DeterministicGates,
    DutyBlock,
    EccCounters,
    EnvironmentBlock,
    EvidenceBundle,
    FunctionalBlock,
    IdentityBlock,
    MeasuredBlock,
    NvLinkStatus,
    PageRetirement,
    PcieStatus,
    ProvenanceBlock,
    RawPayload,
    RawReads,
    Sanitization,
    Signature,
    SpareRows,
    StabilitySignals,
    Thermals,
    XidEvent,
)
from .sign import (
    generate_keypair,
    load_public_key_spki_b64,
    public_key_to_spki_b64,
    sign_bundle,
    verify_bundle,
    verify_bundle_json,
)
from .version import CANONICALIZATION_SCHEME, SCHEMA_VERSION, SIGNATURE_ALGORITHM

__version__ = SCHEMA_VERSION

__all__ = [
    # version
    "SCHEMA_VERSION",
    "CANONICALIZATION_SCHEME",
    "SIGNATURE_ALGORITHM",
    "__version__",
    # enums
    "Tier",
    "History",
    "IdentityScheme",
    "RunMode",
    "GateResult",
    "AttestationVerdict",
    # models
    "SPARE_ROW_CAP",
    "EvidenceBundle",
    "AgentInfo",
    "DeterministicGates",
    "Attestation",
    "IdentityBlock",
    "EccCounters",
    "XidEvent",
    "PageRetirement",
    "SpareRows",
    "StabilitySignals",
    "Thermals",
    "ClockPower",
    "NvLinkStatus",
    "PcieStatus",
    "DutyBlock",
    "MeasuredBlock",
    "Sanitization",
    "FunctionalBlock",
    "RawPayload",
    "RawReads",
    "EnvironmentBlock",
    "ProvenanceBlock",
    "Signature",
    # canonicalize
    "canonical_bytes",
    "canonical_json",
    "canonical_payload",
    "CanonicalizationError",
    # sign
    "generate_keypair",
    "sign_bundle",
    "verify_bundle",
    "verify_bundle_json",
    "public_key_to_spki_b64",
    "load_public_key_spki_b64",
    # jsonschema
    "generate_json_schema",
    "json_schema_str",
]
