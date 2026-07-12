"""Models: every field typed + documented; strictness; neutrality (no price / no score)."""

from __future__ import annotations

import inspect
from datetime import datetime

import pytest
from pydantic import BaseModel, ValidationError

import evidence_schema as es
from evidence_schema import models as models_mod
from evidence_schema.types import SAFE_INTEGER_MAX

# Field names that would imply a price/value or a single collapsed score. Neither may
# exist anywhere in the schema, so every model's field NAMES are checked against this.
_FORBIDDEN_FIELD_TOKENS = (
    "price",
    "valuation",
    "appraisal",
    "resale",
    "market_value",
    "asset_value",
    "dollar",
    "worth",
    "msrp",
    "score",
    "grade",
)


def _all_model_classes() -> list[type[BaseModel]]:
    out = []
    for _name, obj in inspect.getmembers(models_mod):
        if (
            inspect.isclass(obj)
            and issubclass(obj, BaseModel)
            and obj.__module__ == models_mod.__name__
            and obj is not models_mod._Strict
        ):
            out.append(obj)
    return out


def test_sample_bundle_constructs(sample_bundle):
    assert sample_bundle.identity.device_part == "H100-SXM5"
    assert sample_bundle.measured.spare_rows.remaining == 509
    assert sample_bundle.measured.spare_rows.cap == 512
    assert sample_bundle.provenance.exposure_assessed is False
    assert sample_bundle.signature is None


def test_every_field_is_documented():
    """Each field on every model carries a non-empty description (flows into JSON Schema)."""
    missing = []
    for cls in _all_model_classes():
        for fname, field in cls.model_fields.items():
            if not (field.description and field.description.strip()):
                missing.append(f"{cls.__name__}.{fname}")
    assert not missing, f"fields missing a description: {missing}"


def test_no_price_or_score_field_anywhere():
    """No field name implies a price/value or a single collapsed score."""
    offenders = []
    for cls in _all_model_classes():
        for fname in cls.model_fields:
            low = fname.lower()
            for tok in _FORBIDDEN_FIELD_TOKENS:
                if tok in low:
                    offenders.append(f"{cls.__name__}.{fname} (matched '{tok}')")
    assert not offenders, f"forbidden field names present: {offenders}"


def test_unknown_field_is_rejected(sample_bundle):
    data = sample_bundle.model_dump(mode="json")
    data["surprise"] = 1
    with pytest.raises(ValidationError):
        es.EvidenceBundle.model_validate(data)


def test_naive_datetime_rejected(sample_bundle):
    """A naive created_at is rejected (determinism: timestamps must be UTC-aware)."""
    data = sample_bundle.model_dump(mode="json")
    data["created_at"] = datetime(2026, 6, 16, 12, 0, 0).isoformat()  # naive (no offset)
    with pytest.raises(ValidationError):
        es.EvidenceBundle.model_validate(data)


def test_count_safe_integer_bound_enforced():
    """A counter above the safe-integer domain is rejected at the boundary (pushed to raw_reads)."""
    with pytest.raises(ValidationError):
        es.SpareRows(remaining=SAFE_INTEGER_MAX + 5)


def test_authenticity_confidence_bounds():
    with pytest.raises(ValidationError):
        es.IdentityBlock(
            device_part="x",
            serial="x",
            ecc384_id="x",
            attestation=es.Attestation(
                scheme=es.IdentityScheme.HARDWARE_ROOT,
                verdict=es.AttestationVerdict.VERIFIED,
                root_reachability=True,
            ),
            reflash_detected=False,
            identity_scheme=es.IdentityScheme.HARDWARE_ROOT,
            authenticity_confidence=1.5,  # out of [0,1]
            gates=es.DeterministicGates(
                authenticity=es.GateResult.PASS, firmware_vbios=es.GateResult.PASS
            ),
        )


def test_attestation_freshness_defaults_honest():
    """Attestation data without challenge fields parses with challenge None and
    freshness NOT_ASSESSED. A report that was not challenge-bound is never treated
    as fresh (the GateResult honesty rule applies to freshness too)."""
    att = es.Attestation(
        scheme=es.IdentityScheme.HARDWARE_ROOT,
        verdict=es.AttestationVerdict.VERIFIED,
        root_reachability=True,
    )
    assert att.challenge is None
    assert att.freshness is es.GateResult.NOT_ASSESSED


def test_attestation_records_challenge_and_freshness():
    """An operator-issued challenge is recorded on the block so a third party can
    recompute the nonce comparison from the raw report."""
    challenge = "ab04" * 16
    att = es.Attestation(
        scheme=es.IdentityScheme.HARDWARE_ROOT,
        verdict=es.AttestationVerdict.VERIFIED,
        root_reachability=True,
        challenge=challenge,
        freshness=es.GateResult.PASS,
    )
    assert att.challenge == challenge
    assert att.freshness is es.GateResult.PASS


def test_attestation_assessed_freshness_requires_challenge():
    """freshness PASS/FAIL with no recorded challenge is internally inconsistent
    (nothing to recompute against) and is rejected loudly at the schema boundary."""
    for verdict_freshness in (es.GateResult.PASS, es.GateResult.FAIL):
        with pytest.raises(ValidationError):
            es.Attestation(
                scheme=es.IdentityScheme.HARDWARE_ROOT,
                verdict=es.AttestationVerdict.VERIFIED,
                root_reachability=True,
                freshness=verdict_freshness,
            )


def test_json_roundtrip_is_semantically_stable(sample_bundle):
    """Dumping to JSON and reloading yields an equal bundle (same canonical bytes)."""
    reloaded = es.EvidenceBundle.model_validate(sample_bundle.model_dump(mode="json"))
    assert es.canonical_bytes(reloaded) == es.canonical_bytes(sample_bundle)


def test_optional_blocks_default_absent(sample_bundle):
    assert sample_bundle.functional is None
    assert sample_bundle.environment is None
    assert sample_bundle.calibration_snapshot_id is None  # no modeled fields computed yet
