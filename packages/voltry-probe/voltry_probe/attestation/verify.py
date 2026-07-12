"""Verify an attestation report against a trusted root, using real ECDSA P-384 checks.

Every verdict below comes from an actual signature check; there is no stub path that
returns PASS without one. Outcome rules:
- no report: UNVERIFIED (authenticity NOT_ASSESSED)
- no trusted root provided: UNVERIFIED (chain not evaluable; authenticity NOT_ASSESSED)
- root signature invalid: FAILED (authenticity FAIL, disqualifying)
- measurement signature invalid: FAILED (authenticity FAIL, disqualifying)
- operator challenge issued and the verified nonce differs: FAILED (replay indication,
  authenticity FAIL, disqualifying)
- VBIOS hash != expected: reflash_detected=True, firmware FAIL (disqualifying)
- all checks pass, HARDWARE_ROOT scheme: VERIFIED (authenticity PASS, high confidence)
- all checks pass, fallback scheme: FALLBACK (authenticity PASS, lower confidence, marked)

Freshness: a valid signature over (nonce, vbios_hash) proves the device signed that
measurement at SOME point, not that it reflects the device now. Binding the nonce to
an operator-issued challenge is what makes the report non-replayable. Without a
challenge the verdict is unchanged for compatibility with pre-1.2.0 flows, but the
outcome is marked (``freshness`` NOT_ASSESSED) and confidence steps down, resting only
on the caller-supplied ``measured_at`` age against ``freshness_window``. That age is a
weak heuristic: the timestamp is capture metadata the device never signed.
"""

from __future__ import annotations

import base64
import binascii
from datetime import timedelta

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from evidence_schema import (
    Attestation,
    AttestationVerdict,
    GateResult,
    IdentityScheme,
)
from evidence_schema.sign import load_public_key_spki_b64
from evidence_schema.types import UtcDateTime, utcnow
from pydantic import BaseModel, ConfigDict

from .model import AttestationReport

_HASH = hashes.SHA384
# These confidence values are ordered policy tiers for ranking outcomes, not calibrated
# probabilities: nothing was measured to make 0.99 mean "99% genuine". The numbers only
# encode the ordering (hardware root above fallback; challenged above unchallenged above
# stale or unknown age), so third parties should compare them ordinally, never read them
# as odds or feed them into arithmetic.
_CONFIDENCE_VERIFIED = 0.99
_CONFIDENCE_FALLBACK = 0.60
_CONFIDENCE_UNVERIFIED = 0.0
_CONFIDENCE_FAILED = 0.0
# Without an operator challenge the report could be a replay, so confidence steps down;
# it steps down again when even the (unsigned) measured-at age cannot vouch for it.
_CONFIDENCE_VERIFIED_UNCHALLENGED = 0.90
_CONFIDENCE_VERIFIED_STALE = 0.85
_CONFIDENCE_FALLBACK_UNCHALLENGED = 0.55
_CONFIDENCE_FALLBACK_STALE = 0.50

#: Default fallback window for unchallenged reports. Deliberately generous: batch
#: capture pipelines can lag hours between capture and verification, and the window is
#: a weak heuristic either way (measured_at is unsigned metadata).
DEFAULT_FRESHNESS_WINDOW = timedelta(hours=24)

#: A guessable or empty challenge (e.g. "" or "test") lets a pre-recorded genuine
#: report verify as fresh, which is exactly the replay this flow exists to close. Short
#: challenges therefore raise ValueError instead of verifying at reduced confidence.
MIN_CHALLENGE_LENGTH = 16


class AttestationOutcome(BaseModel):
    """The verified result: the certificate's Attestation block + derived gate inputs."""

    model_config = ConfigDict(extra="forbid")

    attestation: Attestation
    reflash_detected: bool
    authenticity_confidence: float
    identity_scheme: IdentityScheme
    vbios_hash: str | None
    authenticity_gate: GateResult
    firmware_gate: GateResult


def _root_statement_bytes(report: AttestationReport) -> bytes:
    return rfc8785.dumps(
        {"device_id": report.device_id, "device_public_key_b64": report.device_public_key_b64}
    )


def _measurement_bytes(report: AttestationReport) -> bytes:
    return rfc8785.dumps({"nonce": report.nonce, "vbios_hash": report.vbios_hash})


def _ecdsa_ok(public_key: ec.EllipticCurvePublicKey, signature_b64: str, payload: bytes) -> bool:
    try:
        public_key.verify(
            base64.b64decode(signature_b64, validate=True), payload, ec.ECDSA(_HASH())
        )
        return True
    except (InvalidSignature, ValueError, binascii.Error):
        return False


def _unverified(
    scheme: IdentityScheme,
    detail: str,
    *,
    root_reachability: bool,
    measured_at: UtcDateTime | None,
    challenge: str | None,
) -> AttestationOutcome:
    return AttestationOutcome(
        attestation=Attestation(
            scheme=scheme,
            verdict=AttestationVerdict.UNVERIFIED,
            root_reachability=root_reachability,
            detail=detail,
            measured_at=measured_at,
            # The issued challenge is recorded even when the chain could not be
            # evaluated; freshness stays NOT_ASSESSED (nothing was verified).
            challenge=challenge,
        ),
        reflash_detected=False,
        authenticity_confidence=_CONFIDENCE_UNVERIFIED,
        identity_scheme=scheme,
        vbios_hash=None,
        authenticity_gate=GateResult.NOT_ASSESSED,
        firmware_gate=GateResult.NOT_ASSESSED,
    )


def verify_attestation(
    report: AttestationReport | None,
    *,
    trusted_root_public_key: ec.EllipticCurvePublicKey | None = None,
    expected_vbios_hash: str | None = None,
    measured_at: UtcDateTime | None = None,
    operator_challenge: str | None = None,
    verified_at: UtcDateTime | None = None,
    freshness_window: timedelta = DEFAULT_FRESHNESS_WINDOW,
) -> AttestationOutcome:
    """Verify ``report`` against ``trusted_root_public_key`` and return the real outcome.

    ``operator_challenge`` is the nonce the operator issued for THIS scan; when given,
    the report's (signature-verified) nonce must echo it exactly or the outcome is
    FAILED as a replay indication. It must be a fresh random nonce per scan (e.g.
    ``secrets.token_hex(32)``); anything shorter than ``MIN_CHALLENGE_LENGTH`` raises
    ``ValueError``. When absent, freshness falls back to comparing ``measured_at``
    against ``verified_at`` (default: now) within ``freshness_window``, at explicitly
    lower confidence; a ``measured_at`` that is unknown, or that lies in the future,
    scores as outside the window, never as fresh.
    """
    if operator_challenge is not None and len(operator_challenge) < MIN_CHALLENGE_LENGTH:
        raise ValueError(
            f"operator challenge must be at least {MIN_CHALLENGE_LENGTH} characters; "
            "issue a fresh random nonce per scan (e.g. secrets.token_hex(32))"
        )
    when = measured_at  # None stays None: an unknown age is recorded as unknown
    now = verified_at if verified_at is not None else utcnow()

    if report is None:
        return _unverified(
            IdentityScheme.SECONDARY_FALLBACK,
            "No attestation report available.",
            root_reachability=False,
            measured_at=when,
            challenge=operator_challenge,
        )
    if trusted_root_public_key is None:
        return _unverified(
            report.scheme,
            "Trusted root unreachable; attestation chain not evaluated.",
            root_reachability=False,
            measured_at=when,
            challenge=operator_challenge,
        )
    if not isinstance(trusted_root_public_key.curve, ec.SECP384R1):
        # A non-P-384 root can only make/verify non-P-384 signatures; accepting one would
        # let a weaker-curve chain pass as the declared P-384 attestation. The CLI already
        # rejects such a root; this guards the library entry point too. Not evaluable, so
        # UNVERIFIED (a caller misconfiguration, not a failed attestation).
        return _unverified(
            report.scheme,
            f"Trusted root is on {trusted_root_public_key.curve.name}, not P-384; "
            "attestation chain not evaluated.",
            root_reachability=False,
            measured_at=when,
            challenge=operator_challenge,
        )

    # 1) Chain: the root must have signed the device-key binding.
    root_ok = _ecdsa_ok(
        trusted_root_public_key, report.root_signature_b64, _root_statement_bytes(report)
    )
    # 2) Measurement: the device key must have signed (nonce, vbios_hash).
    measurement_ok = False
    if root_ok:
        try:
            device_key = load_public_key_spki_b64(report.device_public_key_b64)
            measurement_ok = _ecdsa_ok(
                device_key, report.measurement_signature_b64, _measurement_bytes(report)
            )
        except (ValueError, binascii.Error):
            measurement_ok = False

    if not (root_ok and measurement_ok):
        detail = "Root signature invalid." if not root_ok else "Measurement signature invalid."
        return AttestationOutcome(
            attestation=Attestation(
                scheme=report.scheme,
                verdict=AttestationVerdict.FAILED,
                root_reachability=True,
                detail=detail,
                measured_at=when,
                # Freshness is never assessed from an unverified nonce.
                challenge=operator_challenge,
            ),
            reflash_detected=False,
            authenticity_confidence=_CONFIDENCE_FAILED,
            identity_scheme=report.scheme,
            vbios_hash=report.vbios_hash,
            authenticity_gate=GateResult.FAIL,
            firmware_gate=GateResult.NOT_ASSESSED,
        )

    # 3) Freshness: the (now signature-verified) nonce must echo the challenge WE
    #    issued for this scan. A genuine signature over someone else's nonce is a
    #    replayed report, not proof of current state: disqualifying.
    if operator_challenge is not None and report.nonce != operator_challenge:
        return AttestationOutcome(
            attestation=Attestation(
                scheme=report.scheme,
                verdict=AttestationVerdict.FAILED,
                root_reachability=True,
                detail=(
                    "Measurement nonce does not match the operator challenge; "
                    "possible replay of a previously captured report."
                ),
                measured_at=when,
                challenge=operator_challenge,
                freshness=GateResult.FAIL,
            ),
            reflash_detected=False,
            authenticity_confidence=_CONFIDENCE_FAILED,
            identity_scheme=report.scheme,
            vbios_hash=report.vbios_hash,
            authenticity_gate=GateResult.FAIL,
            firmware_gate=GateResult.NOT_ASSESSED,
        )
    freshness = GateResult.PASS if operator_challenge is not None else GateResult.NOT_ASSESSED
    # An unknown measurement time never scores better than a known-old one, and a
    # measured_at ahead of the verification clock is a clock-skew or tamper signal,
    # not evidence of freshness. Only 0 <= now - measured_at <= window counts.
    within_window = (
        measured_at is not None and timedelta(0) <= (now - measured_at) <= freshness_window
    )

    # 4) Re-flash detection: compare attested VBIOS hash to the known-good expectation.
    reflash = expected_vbios_hash is not None and report.vbios_hash != expected_vbios_hash
    firmware_gate = (
        GateResult.FAIL
        if reflash
        else (GateResult.PASS if expected_vbios_hash is not None else GateResult.NOT_ASSESSED)
    )

    if report.scheme is IdentityScheme.HARDWARE_ROOT:
        verdict = AttestationVerdict.VERIFIED
        detail = "Device Identity chain verified; measurement signature valid."
        tiers = (
            _CONFIDENCE_VERIFIED,
            _CONFIDENCE_VERIFIED_UNCHALLENGED,
            _CONFIDENCE_VERIFIED_STALE,
        )
    else:
        verdict = AttestationVerdict.FALLBACK
        detail = "Secondary (no hardware root) scheme verified at lower confidence."
        tiers = (
            _CONFIDENCE_FALLBACK,
            _CONFIDENCE_FALLBACK_UNCHALLENGED,
            _CONFIDENCE_FALLBACK_STALE,
        )
    if freshness is GateResult.PASS:
        confidence = tiers[0]
        detail += " Operator challenge matched (fresh)."
    elif within_window:
        confidence = tiers[1]
        detail += " No operator challenge; freshness rests on the measured-at window only."
    else:
        confidence = tiers[2]
        detail += " No operator challenge; attestation age unknown or outside the freshness window."

    return AttestationOutcome(
        attestation=Attestation(
            scheme=report.scheme,
            verdict=verdict,
            root_reachability=True,
            detail=detail + (" VBIOS re-flash detected." if reflash else ""),
            measured_at=when,
            challenge=operator_challenge,
            freshness=freshness,
        ),
        reflash_detected=reflash,
        authenticity_confidence=confidence,
        identity_scheme=report.scheme,
        vbios_hash=report.vbios_hash,
        # A verified-genuine chain passes authenticity even on the marked fallback scheme;
        # a detected re-flash fails the firmware gate (disqualifying) but the part is still genuine.
        authenticity_gate=GateResult.PASS,
        firmware_gate=firmware_gate,
    )
