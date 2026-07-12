"""Attestation verification runs real chain checks; no code path stubs a PASS.

Freshness (a replay gap found while answering an independent review of the
published 0.2.2 package): a genuine (nonce, vbios_hash,
signatures) tuple must not be replayable onto a later bundle. With an operator
challenge the verified nonce must echo it exactly; without one the verdict is
unchanged but confidence steps down (measured-at window as the weak fallback).
"""

from __future__ import annotations

import base64
from datetime import timedelta

import pytest
import rfc8785
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from evidence_schema import AttestationVerdict, GateResult, IdentityScheme, generate_keypair
from evidence_schema.types import utcnow

from voltry_probe.attestation import AttestationReport, verify_attestation

CHALLENGE = "nonce-2026-06-17"  # the make_report default nonce


def _report(make_report, root_key, device_key, **kw) -> AttestationReport:
    return AttestationReport.model_validate(make_report(root_key, device_key, **kw))


def test_valid_hardware_root_with_challenge_verifies_fully(
    make_report, root_key, device_key, good_vbios
):
    out = verify_attestation(
        _report(make_report, root_key, device_key),
        trusted_root_public_key=root_key.public_key(),
        expected_vbios_hash=good_vbios,
        operator_challenge=CHALLENGE,
    )
    assert out.attestation.verdict is AttestationVerdict.VERIFIED
    assert out.authenticity_gate is GateResult.PASS
    assert out.firmware_gate is GateResult.PASS
    assert out.reflash_detected is False
    assert out.authenticity_confidence == 0.99
    assert out.attestation.root_reachability is True
    assert out.attestation.freshness is GateResult.PASS
    assert out.attestation.challenge == CHALLENGE


def test_challenge_mismatch_fails_as_replay(make_report, root_key, device_key, good_vbios):
    # A genuinely-signed report whose nonce is not the challenge WE issued is a
    # replayed (stale) report, not proof of current state: disqualifying.
    out = verify_attestation(
        _report(make_report, root_key, device_key, nonce="stale-nonce-from-june"),
        trusted_root_public_key=root_key.public_key(),
        expected_vbios_hash=good_vbios,
        operator_challenge=CHALLENGE,
    )
    assert out.attestation.verdict is AttestationVerdict.FAILED
    assert out.authenticity_gate is GateResult.FAIL
    assert out.attestation.freshness is GateResult.FAIL
    assert out.authenticity_confidence == 0.0
    assert out.attestation.challenge == CHALLENGE
    assert "replay" in (out.attestation.detail or "").lower()


def test_no_challenge_verifies_at_marked_lower_confidence(
    make_report, root_key, device_key, good_vbios
):
    # Backward-compatible path: no challenge issued -> verdict unchanged, but the
    # outcome is marked (freshness NOT_ASSESSED) and confidence steps down.
    out = verify_attestation(
        _report(make_report, root_key, device_key),
        trusted_root_public_key=root_key.public_key(),
        expected_vbios_hash=good_vbios,
        measured_at=utcnow(),
    )
    assert out.attestation.verdict is AttestationVerdict.VERIFIED
    assert out.authenticity_gate is GateResult.PASS
    assert out.attestation.freshness is GateResult.NOT_ASSESSED
    assert out.attestation.challenge is None
    assert out.authenticity_confidence == 0.90
    assert "challenge" in (out.attestation.detail or "").lower()


def test_unknown_measured_at_never_scores_better_than_stale(
    make_report, root_key, device_key, good_vbios
):
    # No challenge AND no measured_at: age is unknown, which must not score better
    # than known-old, and measured_at stays None in the block (nothing invents one).
    out = verify_attestation(
        _report(make_report, root_key, device_key),
        trusted_root_public_key=root_key.public_key(),
        expected_vbios_hash=good_vbios,
    )
    assert out.attestation.verdict is AttestationVerdict.VERIFIED
    assert out.authenticity_confidence == 0.85
    assert out.attestation.measured_at is None


def test_short_challenge_rejected(make_report, root_key, device_key):
    # A guessable or empty challenge defeats the replay protection; it raises
    # ValueError instead of verifying at a silently lower confidence.
    for weak in ("", "test", "0123456789abcde"):  # 15 chars still too short
        with pytest.raises(ValueError, match="challenge"):
            verify_attestation(
                _report(make_report, root_key, device_key),
                trusted_root_public_key=root_key.public_key(),
                operator_challenge=weak,
            )


def test_no_challenge_outside_window_lowers_confidence_further(
    make_report, root_key, device_key, good_vbios
):
    out = verify_attestation(
        _report(make_report, root_key, device_key),
        trusted_root_public_key=root_key.public_key(),
        expected_vbios_hash=good_vbios,
        measured_at=utcnow() - timedelta(days=2),
    )
    assert out.attestation.verdict is AttestationVerdict.VERIFIED
    assert out.attestation.freshness is GateResult.NOT_ASSESSED
    assert out.authenticity_confidence == 0.85


def test_future_measured_at_scores_as_stale_not_fresh(
    make_report, root_key, device_key, good_vbios
):
    # A measured_at ahead of the verification clock is a clock-skew or tamper signal,
    # not freshness: it must land in the stale/unknown tier, never the fresher
    # unchallenged one (only 0 <= now - measured_at <= window counts as inside).
    out = verify_attestation(
        _report(make_report, root_key, device_key),
        trusted_root_public_key=root_key.public_key(),
        expected_vbios_hash=good_vbios,
        measured_at=utcnow() + timedelta(hours=12),
    )
    assert out.attestation.verdict is AttestationVerdict.VERIFIED
    assert out.attestation.freshness is GateResult.NOT_ASSESSED
    assert out.authenticity_confidence == 0.85


def test_freshness_window_is_configurable(make_report, root_key, device_key, good_vbios):
    two_hours_old = utcnow() - timedelta(hours=2)
    tight = verify_attestation(
        _report(make_report, root_key, device_key),
        trusted_root_public_key=root_key.public_key(),
        measured_at=two_hours_old,
        freshness_window=timedelta(hours=1),
    )
    loose = verify_attestation(
        _report(make_report, root_key, device_key),
        trusted_root_public_key=root_key.public_key(),
        measured_at=two_hours_old,
        freshness_window=timedelta(hours=3),
    )
    assert tight.authenticity_confidence == 0.85
    assert loose.authenticity_confidence == 0.90


def test_challenge_comparison_requires_valid_signature(make_report, root_key, device_key):
    # A matching nonce under a BAD measurement signature proves nothing: the
    # signature failure wins and freshness is never assessed from an unverified nonce.
    out = verify_attestation(
        _report(make_report, root_key, device_key, tamper="measurement_sig"),
        trusted_root_public_key=root_key.public_key(),
        operator_challenge=CHALLENGE,
    )
    assert out.attestation.verdict is AttestationVerdict.FAILED
    assert out.attestation.freshness is GateResult.NOT_ASSESSED
    assert "signature" in (out.attestation.detail or "").lower()


def test_reflash_detected_even_when_challenge_fresh(make_report, root_key, device_key, good_vbios):
    out = verify_attestation(
        _report(make_report, root_key, device_key, vbios_hash="deadbeef-reflashed"),
        trusted_root_public_key=root_key.public_key(),
        expected_vbios_hash=good_vbios,
        operator_challenge=CHALLENGE,
    )
    assert out.attestation.verdict is AttestationVerdict.VERIFIED
    assert out.attestation.freshness is GateResult.PASS
    assert out.reflash_detected is True
    assert out.firmware_gate is GateResult.FAIL


def test_no_trusted_root_is_unverified_never_pass(make_report, root_key, device_key):
    out = verify_attestation(
        _report(make_report, root_key, device_key),
        trusted_root_public_key=None,
        operator_challenge=CHALLENGE,
    )
    assert out.attestation.verdict is AttestationVerdict.UNVERIFIED
    assert out.authenticity_gate is GateResult.NOT_ASSESSED  # never silently PASS
    assert out.attestation.root_reachability is False
    # The issued challenge is still recorded; freshness stays NOT_ASSESSED.
    assert out.attestation.challenge == CHALLENGE
    assert out.attestation.freshness is GateResult.NOT_ASSESSED


def test_no_report_is_unverified():
    out = verify_attestation(None, trusted_root_public_key=None, operator_challenge=CHALLENGE)
    assert out.attestation.verdict is AttestationVerdict.UNVERIFIED
    assert out.authenticity_gate is GateResult.NOT_ASSESSED
    assert out.attestation.challenge == CHALLENGE
    assert out.attestation.freshness is GateResult.NOT_ASSESSED


def test_tampered_root_signature_fails(make_report, root_key, device_key):
    out = verify_attestation(
        _report(make_report, root_key, device_key, tamper="root_sig"),
        trusted_root_public_key=root_key.public_key(),
    )
    assert out.attestation.verdict is AttestationVerdict.FAILED
    assert out.authenticity_gate is GateResult.FAIL  # disqualifying


def test_wrong_root_key_fails(make_report, root_key, device_key):
    out = verify_attestation(
        _report(make_report, root_key, device_key),
        trusted_root_public_key=generate_keypair().public_key(),  # not the signing root
    )
    assert out.attestation.verdict is AttestationVerdict.FAILED
    assert out.authenticity_gate is GateResult.FAIL


def test_tampered_measurement_signature_fails(make_report, root_key, device_key):
    out = verify_attestation(
        _report(make_report, root_key, device_key, tamper="measurement_sig"),
        trusted_root_public_key=root_key.public_key(),
    )
    assert out.attestation.verdict is AttestationVerdict.FAILED
    assert out.authenticity_gate is GateResult.FAIL


def test_vbios_reflash_detected(make_report, root_key, device_key, good_vbios):
    # A validly-signed report that attests a DIFFERENT VBIOS than the known-good one.
    out = verify_attestation(
        _report(make_report, root_key, device_key, vbios_hash="deadbeef-reflashed"),
        trusted_root_public_key=root_key.public_key(),
        expected_vbios_hash=good_vbios,
    )
    assert out.attestation.verdict is AttestationVerdict.VERIFIED  # chain is genuine
    assert out.reflash_detected is True
    assert out.firmware_gate is GateResult.FAIL  # but firmware gate is disqualifying


def test_firmware_not_assessed_without_expected_vbios(make_report, root_key, device_key):
    out = verify_attestation(
        _report(make_report, root_key, device_key),
        trusted_root_public_key=root_key.public_key(),
        expected_vbios_hash=None,
    )
    assert out.firmware_gate is GateResult.NOT_ASSESSED
    assert out.reflash_detected is False


def test_secondary_fallback_marked_lower_confidence(make_report, root_key, device_key, good_vbios):
    out = verify_attestation(
        _report(make_report, root_key, device_key, scheme=IdentityScheme.SECONDARY_FALLBACK),
        trusted_root_public_key=root_key.public_key(),
        expected_vbios_hash=good_vbios,
        operator_challenge=CHALLENGE,
    )
    assert out.attestation.verdict is AttestationVerdict.FALLBACK
    assert out.authenticity_gate is GateResult.PASS  # genuine via secondary scheme
    assert out.authenticity_confidence == 0.60  # explicitly lower, marked
    assert out.identity_scheme is IdentityScheme.SECONDARY_FALLBACK


def test_secondary_fallback_unchallenged_tiers(make_report, root_key, device_key):
    # The freshness step-down composes with the scheme step-down, never replaces it.
    unchallenged = verify_attestation(
        _report(make_report, root_key, device_key, scheme=IdentityScheme.SECONDARY_FALLBACK),
        trusted_root_public_key=root_key.public_key(),
        measured_at=utcnow(),
    )
    stale = verify_attestation(
        _report(make_report, root_key, device_key, scheme=IdentityScheme.SECONDARY_FALLBACK),
        trusted_root_public_key=root_key.public_key(),
        measured_at=utcnow() - timedelta(days=2),
    )
    assert unchallenged.attestation.verdict is AttestationVerdict.FALLBACK
    assert unchallenged.authenticity_confidence == 0.55
    assert stale.authenticity_confidence == 0.50


def test_valid_root_sig_over_malformed_device_key_fails(root_key):
    # Root genuinely signs a binding whose device key is malformed: the chain is OK
    # but the device key cannot load, so the measurement is unverifiable and the
    # verdict is FAILED (not a silent pass).
    bad_key = "%%not-base64%%"
    root_stmt = rfc8785.dumps({"device_id": "dev", "device_public_key_b64": bad_key})
    root_sig = base64.b64encode(root_key.sign(root_stmt, ec.ECDSA(hashes.SHA384()))).decode("ascii")
    report = AttestationReport.model_validate(
        {
            "scheme": "HARDWARE_ROOT",
            "device_id": "dev",
            "device_public_key_b64": bad_key,
            "root_signature_b64": root_sig,
            "vbios_hash": "v",
            "nonce": "n",
            "measurement_signature_b64": base64.b64encode(b"sig").decode("ascii"),
        }
    )
    out = verify_attestation(report, trusted_root_public_key=root_key.public_key())
    assert out.attestation.verdict is AttestationVerdict.FAILED
    assert out.authenticity_gate is GateResult.FAIL


def _curve_report(root, dev, scheme, root_key, device_key):
    # Local report builder allowing an arbitrary-curve device key, for curve-enforcement tests.
    import base64

    import rfc8785
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from evidence_schema.sign import public_key_to_spki_b64

    from voltry_probe.attestation.model import AttestationReport

    dev_id, vbios, nonce = "aa" * 32, "bb" * 32, "challenge-1234567890abcd"

    def _s(k, payload):
        return base64.b64encode(k.sign(payload, ec.ECDSA(hashes.SHA384()))).decode()

    dev_pub = public_key_to_spki_b64(device_key.public_key())
    root_stmt = rfc8785.dumps({"device_id": dev_id, "device_public_key_b64": dev_pub})
    meas = rfc8785.dumps({"nonce": nonce, "vbios_hash": vbios})
    return AttestationReport.model_validate(
        {
            "scheme": scheme,
            "device_id": dev_id,
            "device_public_key_b64": dev_pub,
            "root_signature_b64": _s(root_key, root_stmt),
            "vbios_hash": vbios,
            "nonce": nonce,
            "measurement_signature_b64": _s(device_key, meas),
        }
    )


def test_p256_device_key_is_refused():
    # A report whose device key is not P-384 must not verify, even with valid signatures.
    from cryptography.hazmat.primitives.asymmetric import ec
    from evidence_schema import AttestationVerdict, GateResult, generate_keypair

    from voltry_probe.attestation.verify import verify_attestation

    root = generate_keypair()
    p256_dev = ec.generate_private_key(ec.SECP256R1())
    out = verify_attestation(
        _curve_report(root, p256_dev, "HARDWARE_ROOT", root, p256_dev),
        trusted_root_public_key=root.public_key(),
    )
    assert out.authenticity_gate is GateResult.FAIL
    assert out.attestation.verdict is AttestationVerdict.FAILED


def test_non_p384_trusted_root_is_not_evaluated():
    from cryptography.hazmat.primitives.asymmetric import ec
    from evidence_schema import AttestationVerdict, GateResult, generate_keypair

    from voltry_probe.attestation.verify import verify_attestation

    dev = generate_keypair()
    p256_root = ec.generate_private_key(ec.SECP256R1())
    out = verify_attestation(
        _curve_report(p256_root, dev, "HARDWARE_ROOT", p256_root, dev),
        trusted_root_public_key=p256_root.public_key(),
    )
    assert out.attestation.verdict is AttestationVerdict.UNVERIFIED
    assert out.authenticity_gate is GateResult.NOT_ASSESSED
