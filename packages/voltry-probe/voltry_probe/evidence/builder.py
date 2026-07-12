"""Assemble an :class:`EvidenceBundle` from a capture, then sign it."""

from __future__ import annotations

import hashlib
import json

from cryptography.hazmat.primitives.asymmetric import ec
from evidence_schema import (
    AgentInfo,
    DeterministicGates,
    DutyBlock,
    EvidenceBundle,
    FunctionalBlock,
    GateResult,
    History,
    IdentityBlock,
    MeasuredBlock,
    ProvenanceBlock,
    RawPayload,
    RawReads,
    Tier,
    sign_bundle,
)
from evidence_schema.types import UtcDateTime, utcnow

from ..attestation import AttestationReport, verify_attestation
from ..readers import map_dcgm, map_nvml, map_redfish
from ..sources.base import RawCapture


def _raw_payload(source: str, key: str, payload: object, captured_at: UtcDateTime) -> RawPayload:
    """Wrap a verbatim source payload as a RawPayload with an integrity hash."""
    content = json.dumps(payload, sort_keys=True, ensure_ascii=False)  # not the signing path
    return RawPayload(
        source=source,
        key=key,
        format="json",
        content=content,
        sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
        captured_at=captured_at,
    )


def build_read_bundle(
    capture: RawCapture,
    *,
    signer_key: ec.EllipticCurvePrivateKey,
    agent: AgentInfo,
    methodology_version_hash: str,
    trusted_root_public_key: ec.EllipticCurvePublicKey | None = None,
    expected_vbios_hash: str | None = None,
    operator_challenge: str | None = None,
    signer_label: str = "operator",
    created_at: UtcDateTime | None = None,
    functional: FunctionalBlock | None = None,
    tier: Tier = Tier.BRONZE,
    history: History = History.RECONSTRUCTED,
    born_on: UtcDateTime | None = None,
    duty: DutyBlock | None = None,
) -> EvidenceBundle:
    """Map a capture into a schema-valid, signed bundle.

    Read mode (the defaults) produces ``tier=BRONZE`` with reconstructed history.
    Functional mode passes a ``functional`` block (the functional gates derive from it)
    with ``tier=SILVER``; Monitor mode passes ``tier=GOLD``, ``history=BORN_ON`` and a
    ``born_on`` timestamp. The attestation chain is cryptographically checked in every
    mode; ``voltry_probe.attestation.verify`` documents the outcome rules.

    ``duty`` is the accumulated odometer supplied by the CALLER (registry deltas or a
    continuous-monitoring harness). The builder never derives it from the capture: a
    single point-in-time read cannot measure lifetime duty, so absent accumulation it
    stays None and renders Not Assessed.

    ``operator_challenge`` is the nonce issued for THIS scan; the attestation report's
    nonce must echo it or the attestation fails as a replay indication. It is recorded
    in the bundle's attestation block so third parties can recompute the comparison.
    Absent (pre-1.2.0 flow), the attestation verifies as before at lower, marked
    confidence.
    """
    when = created_at if created_at is not None else utcnow()

    nvml_out = map_nvml(capture.nvml)
    dcgm_out = map_dcgm(capture.dcgm)
    redfish_out = map_redfish(capture.redfish)

    report = AttestationReport.model_validate(capture.attestation) if capture.attestation else None
    att = verify_attestation(
        report,
        trusted_root_public_key=trusted_root_public_key,
        expected_vbios_hash=expected_vbios_hash,
        measured_at=capture.captured_at,
        operator_challenge=operator_challenge,
    )

    # The schema currently requires strings for these identity fields, so a device that
    # does not expose one gets the sentinel "UNKNOWN-IDENTITY"/"UNKNOWN" (wire-stable,
    # do not change the spelling). Consumers must treat the sentinels as absent values,
    # not as a real identity or serial.
    #
    # A report's device_id only becomes the permanent identity when the report's
    # signatures verified: a report that failed verification (tampered, replayed, or
    # signed under the wrong root) is attacker-controllable text and must not outrank
    # the NVML-read UUID. The failing verdict is recorded in the bundle either way.
    attested_id = report.device_id if report and att.authenticity_gate is GateResult.PASS else None
    ecc384_id = attested_id or nvml_out.gpu_uuid or "UNKNOWN-IDENTITY"

    identity = IdentityBlock(
        device_part=nvml_out.device_part or nvml_out.device_model or "UNKNOWN",
        device_model=nvml_out.device_model,
        serial=nvml_out.serial or "UNKNOWN",
        ecc384_id=ecc384_id,
        gpu_uuid=nvml_out.gpu_uuid,
        board_id=redfish_out.board_id,
        attestation=att.attestation,
        vbios_version=nvml_out.vbios_version,
        vbios_hash=att.vbios_hash,
        reflash_detected=att.reflash_detected,
        identity_scheme=att.identity_scheme,
        authenticity_confidence=att.authenticity_confidence,
        gates=DeterministicGates(
            authenticity=att.authenticity_gate,
            firmware_vbios=att.firmware_gate,
            # Functional gates derive from the functional block (functional mode); else
            # NOT_ASSESSED (Read/Monitor mode is non-disruptive).
            functional_burnin=functional.burnin_result if functional else GateResult.NOT_ASSESSED,
            sdc_functional=functional.sdc_functional if functional else GateResult.NOT_ASSESSED,
            data_sanitization=(
                functional.sanitization.result if functional else GateResult.NOT_ASSESSED
            ),
        ),
    )

    measured = MeasuredBlock(
        ecc=nvml_out.ecc,
        xid=nvml_out.xid,
        pages=nvml_out.pages,
        spare_rows=nvml_out.spare_rows,
        stability=nvml_out.stability,
        thermals=nvml_out.thermals,
        clock_power=nvml_out.clock_power,
        # DCGM values take precedence when present; NVML provides the same link health
        # directly on hosts without a DCGM telemetry path.
        nvlink=dcgm_out.nvlink or nvml_out.nvlink,
        pcie=dcgm_out.pcie or nvml_out.pcie,
        duty=duty,
        extensions=nvml_out.extensions,
    )

    # Enrich AgentInfo with library versions observed at capture time (never overwrite
    # values the caller set explicitly).
    observed = {
        "driver_version": nvml_out.driver_version,
        "nvml_version": nvml_out.nvml_version,
        "cuda_version": nvml_out.cuda_version,
    }
    updates = {k: v for k, v in observed.items() if v is not None and getattr(agent, k) is None}
    if updates:
        agent = agent.model_copy(update=updates)

    payloads = [_raw_payload("nvml", "readout", capture.nvml, capture.captured_at)]
    if capture.dcgm is not None:
        payloads.append(_raw_payload("dcgm", "telemetry", capture.dcgm, capture.captured_at))
    if capture.redfish is not None:
        payloads.append(_raw_payload("redfish", "system", capture.redfish, capture.captured_at))
    if capture.attestation is not None:
        payloads.append(
            _raw_payload("attestation", "report", capture.attestation, capture.captured_at)
        )

    bundle = EvidenceBundle(
        created_at=when,
        agent=agent,
        methodology_version_hash=methodology_version_hash,
        calibration_snapshot_id=None,  # No modeled fields are produced yet; stays None.
        identity=identity,
        measured=measured,
        functional=functional,
        raw_reads=RawReads(payloads=payloads),
        environment=None,  # No facility instrumentation, so exposure renders Not Assessed.
        provenance=ProvenanceBlock(
            tier=tier,
            history=history,
            # Born-on (Monitor) implies a continuous chain; reconstructed implies gaps.
            chain_gaps=history is not History.BORN_ON,
            exposure_assessed=False,
            born_on=born_on,
        ),
    )
    return sign_bundle(bundle, signer_key, signer=signer_label)


def build_monitor_bundle(
    capture: RawCapture,
    *,
    born_on: UtcDateTime,
    signer_key: ec.EllipticCurvePrivateKey,
    agent: AgentInfo,
    methodology_version_hash: str,
    trusted_root_public_key: ec.EllipticCurvePublicKey | None = None,
    expected_vbios_hash: str | None = None,
    operator_challenge: str | None = None,
    signer_label: str = "operator",
    created_at: UtcDateTime | None = None,
    functional: FunctionalBlock | None = None,
    duty: DutyBlock | None = None,
) -> EvidenceBundle:
    """A bundle from continuous read-only capture: ``tier=GOLD``, born-on history.

    Everything except ``born_on`` is forwarded to :func:`build_read_bundle` unchanged.
    The keywords are spelled out (rather than taking **kwargs) so callers keep type
    checking and completion on the full keyword surface.
    """
    return build_read_bundle(
        capture,
        signer_key=signer_key,
        agent=agent,
        methodology_version_hash=methodology_version_hash,
        trusted_root_public_key=trusted_root_public_key,
        expected_vbios_hash=expected_vbios_hash,
        operator_challenge=operator_challenge,
        signer_label=signer_label,
        created_at=created_at,
        functional=functional,
        tier=Tier.GOLD,
        history=History.BORN_ON,
        born_on=born_on,
        duty=duty,
    )
