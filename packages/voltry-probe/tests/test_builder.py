"""Build a Read-mode bundle from a capture: schema-valid, signed, tier=BRONZE, gates correct."""

from __future__ import annotations

import re

from evidence_schema import (
    EvidenceBundle,
    GateResult,
    History,
    IdentityScheme,
    Tier,
    verify_bundle,
)

from voltry_probe import build_read_bundle

_PRICE = re.compile(
    r"price|valuation|apprais|resale|\bworth\b|market[_ -]?value|asset[_ -]?value|\$\d", re.I
)


def _attested(capture, make_report, root_key, device_key, **kw):
    capture.attestation = make_report(root_key, device_key, **kw)
    return capture


def _build(capture, root_key, signer_key, agent, good_vbios):
    return build_read_bundle(
        capture,
        signer_key=signer_key,
        agent=agent,
        methodology_version_hash="read-v0",
        trusted_root_public_key=root_key.public_key(),
        expected_vbios_hash=good_vbios,
    )


def test_build_valid_read_bundle(
    capture, make_report, root_key, device_key, signer_key, agent, good_vbios, device_id
):
    bundle = _build(
        _attested(capture, make_report, root_key, device_key),
        root_key,
        signer_key,
        agent,
        good_vbios,
    )
    # Signed and verifiable.
    assert verify_bundle(bundle) is True
    # Read mode yields tier=BRONZE, history reconstructed, exposure Not Assessed.
    assert bundle.provenance.tier is Tier.BRONZE
    assert bundle.provenance.history is History.RECONSTRUCTED
    assert bundle.provenance.exposure_assessed is False
    # Gates reflect the real attestation outcome.
    assert bundle.identity.gates.authenticity is GateResult.PASS
    assert bundle.identity.gates.firmware_vbios is GateResult.PASS
    assert bundle.identity.reflash_detected is False
    assert bundle.identity.ecc384_id == device_id
    assert bundle.identity.identity_scheme is IdentityScheme.HARDWARE_ROOT
    # Measured facts carried through.
    assert bundle.measured.spare_rows.remaining == 509
    assert bundle.measured.nvlink is not None and bundle.measured.nvlink.active_links == 18
    # Raw reads: nvml + dcgm + redfish + attestation, all verbatim with integrity hashes.
    sources = {p.source for p in bundle.raw_reads.payloads}
    assert sources == {"nvml", "dcgm", "redfish", "attestation"}
    assert all(p.sha256 for p in bundle.raw_reads.payloads)
    # No modeled fields: the bundle carries no calibration snapshot.
    assert bundle.calibration_snapshot_id is None


def test_bundle_is_schema_valid_roundtrip(
    capture, make_report, root_key, device_key, signer_key, agent, good_vbios
):
    bundle = _build(
        _attested(capture, make_report, root_key, device_key),
        root_key,
        signer_key,
        agent,
        good_vbios,
    )
    reloaded = EvidenceBundle.model_validate(bundle.model_dump(mode="json"))
    assert verify_bundle(reloaded) is True


def test_no_price_anywhere_in_bundle(
    capture, make_report, root_key, device_key, signer_key, agent, good_vbios
):
    bundle = _build(
        _attested(capture, make_report, root_key, device_key),
        root_key,
        signer_key,
        agent,
        good_vbios,
    )
    assert not _PRICE.search(bundle.model_dump_json())


def test_tamper_breaks_signature(
    capture, make_report, root_key, device_key, signer_key, agent, good_vbios
):
    bundle = _build(
        _attested(capture, make_report, root_key, device_key),
        root_key,
        signer_key,
        agent,
        good_vbios,
    )
    tampered = bundle.model_copy(deep=True)
    tampered.measured.spare_rows.remaining = 1
    assert verify_bundle(tampered) is False


def test_challenge_bound_build_records_freshness(
    capture, make_report, root_key, device_key, signer_key, agent, good_vbios
):
    # The operator challenge is issued at scan time, echoed by the report, compared in
    # verify_attestation, and recorded in the bundle for third-party recomputation.
    challenge = "scan-challenge-2026-07-09"
    bundle = build_read_bundle(
        _attested(capture, make_report, root_key, device_key, nonce=challenge),
        signer_key=signer_key,
        agent=agent,
        methodology_version_hash="read-v0",
        trusted_root_public_key=root_key.public_key(),
        expected_vbios_hash=None,
        operator_challenge=challenge,
    )
    assert verify_bundle(bundle) is True
    assert bundle.identity.attestation.challenge == challenge
    assert bundle.identity.attestation.freshness is GateResult.PASS
    assert bundle.identity.authenticity_confidence == 0.99


def test_replayed_report_fails_gates_but_bundle_persists(
    capture, make_report, root_key, device_key, signer_key, agent
):
    # A genuine report bound to some OTHER nonce is a replay: disqualifying. The
    # failed attempt still produces a signed, persistable bundle (append-never-overwrite).
    bundle = build_read_bundle(
        _attested(capture, make_report, root_key, device_key, nonce="stale-from-june"),
        signer_key=signer_key,
        agent=agent,
        methodology_version_hash="read-v0",
        trusted_root_public_key=root_key.public_key(),
        operator_challenge="scan-challenge-2026-07-09",
    )
    assert verify_bundle(bundle) is True
    assert bundle.identity.gates.authenticity is GateResult.FAIL
    assert bundle.identity.attestation.freshness is GateResult.FAIL
    assert bundle.identity.authenticity_confidence == 0.0


def test_unchallenged_build_is_marked_not_assessed(
    capture, make_report, root_key, device_key, signer_key, agent, good_vbios
):
    # No challenge issued (pre-1.2.0 flow): verdict unchanged, freshness
    # NOT_ASSESSED, confidence stepped down rather than FAILED.
    bundle = _build(
        _attested(capture, make_report, root_key, device_key),
        root_key,
        signer_key,
        agent,
        good_vbios,
    )
    assert bundle.identity.attestation.challenge is None
    assert bundle.identity.attestation.freshness is GateResult.NOT_ASSESSED
    assert bundle.identity.gates.authenticity is GateResult.PASS
    assert bundle.identity.authenticity_confidence < 0.99


def test_no_attestation_is_unassessed_not_pass(capture, signer_key, agent):
    # capture.attestation stays None (no report).
    bundle = build_read_bundle(
        capture,
        signer_key=signer_key,
        agent=agent,
        methodology_version_hash="read-v0",
    )
    assert verify_bundle(bundle) is True
    assert bundle.identity.gates.authenticity is GateResult.NOT_ASSESSED  # never silently PASS
    assert bundle.identity.identity_scheme is IdentityScheme.SECONDARY_FALLBACK
    # Falls back to the GPU UUID as identity when no attested device id is present.
    assert bundle.identity.ecc384_id.startswith("GPU-")
    sources = {p.source for p in bundle.raw_reads.payloads}
    assert sources == {"nvml", "dcgm", "redfish"}  # no attestation payload


def test_duty_passthrough_monitor_mode(capture, signer_key, agent):
    """Monitor mode may carry accumulated duty; the builder never invents it."""
    from datetime import datetime, timezone

    from evidence_schema import DutyBlock

    from voltry_probe import build_monitor_bundle

    duty = DutyBlock(
        gpu_hours_total=3400.0,
        thermal_cycles_total=180,
        energy_kwh_total=1760.0,
        sustained_high_power_hours=1100.0,
        basis="monitor_continuous",
        since=datetime(2026, 1, 14, tzinfo=timezone.utc),
    )
    born = datetime(2026, 1, 14, tzinfo=timezone.utc)
    bundle = build_monitor_bundle(
        capture,
        born_on=born,
        signer_key=signer_key,
        agent=agent,
        methodology_version_hash="read-v0",
        duty=duty,
    )
    assert verify_bundle(bundle) is True
    assert bundle.measured.duty is not None
    assert bundle.measured.duty.gpu_hours_total == 3400.0
    assert bundle.measured.duty.basis == "monitor_continuous"


def test_duty_defaults_none_on_cold_start(capture, signer_key, agent):
    """A single Read-mode scan cannot measure lifetime duty, so it must stay None."""
    bundle = build_read_bundle(
        capture, signer_key=signer_key, agent=agent, methodology_version_hash="read-v0"
    )
    assert bundle.measured.duty is None


def test_failed_attestation_does_not_donate_identity(
    capture, make_report, root_key, device_key, signer_key, agent, good_vbios, device_id
):
    # A report whose signatures fail verification is attacker-controllable text; its
    # device_id must not become the permanent identity. The NVML-read UUID wins, and
    # the failing verdict is still recorded on the bundle.
    tampered = _attested(capture, make_report, root_key, device_key, tamper="root_sig")
    bundle = _build(tampered, root_key, signer_key, agent, good_vbios)
    assert bundle.identity.gates.authenticity is GateResult.FAIL
    assert bundle.identity.gpu_uuid is not None
    assert bundle.identity.ecc384_id == bundle.identity.gpu_uuid
    assert bundle.identity.ecc384_id != device_id
