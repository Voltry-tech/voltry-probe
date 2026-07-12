"""Cross-version verification compatibility: the schema-evolution contract.

The one bug a trust product can never ship: a previously signed bundle failing to
verify after a schema upgrade. Additive (minor) schema changes materialize new
defaults when an OLD bundle is re-parsed by a NEW model, so re-canonicalizing the
model would change the bytes. The guarantee is therefore anchored on the RAW JSON:
``verify_bundle_json`` canonicalizes the bundle's stored representation directly,
byte-faithful to what was signed, regardless of the schema version doing the reading.

``tests/fixtures/bundle_v1_0_0_signed.json`` was generated and signed under schema
1.0.0 BEFORE the 1.1.0 DutyBlock addition and must verify forever.
``tests/fixtures/bundle_v1_1_0_signed.json`` was generated and signed under schema
1.1.0 BEFORE the 1.2.0 attestation challenge/freshness addition and must verify forever.
"""

from __future__ import annotations

import json
from pathlib import Path

from evidence_schema import (
    DutyBlock,
    EvidenceBundle,
    GateResult,
    generate_keypair,
    verify_bundle,
    verify_bundle_json,
)
from evidence_schema.samples import worked_example_a_bundle
from evidence_schema.sign import sign_bundle
from evidence_schema.version import SCHEMA_VERSION

FIXTURE = Path(__file__).parent / "fixtures" / "bundle_v1_0_0_signed.json"
FIXTURE_1_1 = Path(__file__).parent / "fixtures" / "bundle_v1_1_0_signed.json"


def test_schema_version_is_1_2_1():
    assert SCHEMA_VERSION == "1.2.2"


def test_v1_0_0_bundle_verifies_from_raw_json():
    # THE cross-version guarantee: bytes signed under 1.0.0 verify under 1.1.0+.
    raw = FIXTURE.read_text(encoding="utf-8")
    assert verify_bundle_json(raw) is True


def test_v1_0_0_bundle_still_parses_under_current_schema():
    bundle = EvidenceBundle.model_validate_json(FIXTURE.read_text(encoding="utf-8"))
    assert bundle.signature is not None
    assert bundle.measured.duty is None  # absent in 1.0.0 data reads back as None, not a default


def test_v1_1_0_bundle_verifies_from_raw_json():
    # Same guarantee for the 1.1.0 to 1.2.0 transition (challenge/freshness addition).
    raw = FIXTURE_1_1.read_text(encoding="utf-8")
    assert verify_bundle_json(raw) is True


def test_v1_1_0_bundle_parses_with_honest_freshness_defaults():
    # A pre-challenge bundle reads back with no challenge and freshness NOT_ASSESSED,
    # never retroactively marked fresh.
    bundle = EvidenceBundle.model_validate_json(FIXTURE_1_1.read_text(encoding="utf-8"))
    assert bundle.signature is not None
    assert bundle.identity.attestation.challenge is None
    assert bundle.identity.attestation.freshness is GateResult.NOT_ASSESSED


def test_raw_verify_detects_tamper():
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    data["measured"]["spare_rows"]["remaining"] = 512  # flatter the wear gauge
    assert verify_bundle_json(json.dumps(data)) is False


def test_raw_verify_rejects_unsigned():
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    data["signature"] = None
    assert verify_bundle_json(json.dumps(data)) is False


def test_fresh_current_bundle_verifies_both_paths():
    bundle = worked_example_a_bundle()
    signed = sign_bundle(bundle, generate_keypair())
    assert verify_bundle(signed) is True
    assert verify_bundle_json(signed.model_dump_json()) is True


def test_duty_block_roundtrips_and_signs():
    bundle = worked_example_a_bundle()
    bundle.measured.duty = DutyBlock(
        gpu_hours_total=8410.0,
        thermal_cycles_total=214,
        energy_kwh_total=5120.5,
        sustained_high_power_hours=1120.0,
        basis="registry_accumulated",
    )
    signed = sign_bundle(bundle, generate_keypair())
    assert verify_bundle(signed) is True
    assert verify_bundle_json(signed.model_dump_json()) is True
    reparsed = EvidenceBundle.model_validate_json(signed.model_dump_json())
    assert reparsed.measured.duty is not None
    assert reparsed.measured.duty.gpu_hours_total == 8410.0
    assert reparsed.measured.duty.basis == "registry_accumulated"


def test_duty_defaults_are_absent_never_fabricated():
    duty = DutyBlock()
    assert duty.gpu_hours_total is None
    assert duty.thermal_cycles_total is None
    assert duty.energy_kwh_total is None
    assert duty.basis is None


def test_duty_floats_bounded_to_safe_number_domain():
    """Review finding: an unbounded duty float at or above 2^53 can
    re-serialize as an int (RFC 8785 drops the '.0'), which reparses outside the
    safe-int domain and breaks raw-path verification. Values that large are also
    physically absurd, so the domain bound loses nothing."""
    import pydantic
    import pytest

    for field in ("gpu_hours_total", "energy_kwh_total", "sustained_high_power_hours"):
        with pytest.raises(pydantic.ValidationError):
            DutyBlock(**{field: float(2**53)})
        # The largest safe value is fine.
        DutyBlock(**{field: float(2**53 - 1)})
