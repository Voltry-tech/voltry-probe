"""Deterministic sample bundles for the demo and tests.

These are *simulated* reads (no PII, no real keys). ``worked_example_a_bundle`` is a
representative single-read scan: an H100-SXM5, Silver tier, history reconstructed,
exposure Not Assessed, 3 remapped pages, 509/512 spare rows, clean ECC/Xid. It is
built deterministically (fixed ids/timestamps) so canonical bytes are a stable golden
vector.

The sample attestation carries ``challenge=None`` and ``freshness=NOT_ASSESSED``. It
has to: freshness PASS is only honest when the recorded challenge nonce can be found
inside the raw attestation report, and this sample's ``report_b64`` is a placeholder
that contains no nonce. A real challenged scan earns PASS by having the operator issue
a nonce, passing it to the attestation flow so the device embeds it in the signed
report, then recording both the nonce (``challenge``) and the verbatim report
(``report_b64``) so any third party can recompute the comparison.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from .enums import (
    AttestationVerdict,
    GateResult,
    History,
    IdentityScheme,
    RunMode,
    Tier,
)
from .models import (
    AgentInfo,
    Attestation,
    ClockPower,
    DeterministicGates,
    EccCounters,
    EvidenceBundle,
    IdentityBlock,
    MeasuredBlock,
    PageRetirement,
    ProvenanceBlock,
    RawPayload,
    RawReads,
    SpareRows,
    StabilitySignals,
    Thermals,
)

_FIXED_TIME = datetime(2026, 6, 16, 12, 0, 0, tzinfo=timezone.utc)
_FIXED_ID = UUID("0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9")


def worked_example_a_bundle() -> EvidenceBundle:
    """The deterministic worked-example bundle (Silver, single read, exposure Not Assessed)."""
    return EvidenceBundle(
        bundle_id=_FIXED_ID,
        created_at=_FIXED_TIME,
        agent=AgentInfo(
            name="voltry-probe",
            version="0.1.0",
            build="demo",
            host_arch="x86_64",
            run_mode=RunMode.READ,
            nvml_version="12.560",
            driver_version="560.35.03",
        ),
        methodology_version_hash="a3f9c1d2e4b5a6978c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
        calibration_snapshot_id=None,  # No modeled fields are computed yet.
        identity=IdentityBlock(
            device_part="H100-SXM5",
            device_model="NVIDIA H100 80GB SXM5",
            serial="1320923000123",
            ecc384_id="04a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d",
            gpu_uuid="GPU-0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9",
            attestation=Attestation(
                scheme=IdentityScheme.HARDWARE_ROOT,
                verdict=AttestationVerdict.VERIFIED,
                report_b64="c2FtcGxlLWF0dGVzdGF0aW9uLXJlcG9ydA==",
                root_reachability=True,
                nras_used=True,
                detail="Device Identity over SPDM; VBIOS measurement matches.",
                measured_at=_FIXED_TIME,
                # No challenge was issued for this simulated scan, so freshness is
                # honestly NOT_ASSESSED (see the module docstring for what a real
                # challenged scan looks like).
                challenge=None,
                freshness=GateResult.NOT_ASSESSED,
            ),
            vbios_version="96.00.89.00.01",
            vbios_hash="9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            reflash_detected=False,
            identity_scheme=IdentityScheme.HARDWARE_ROOT,
            authenticity_confidence=0.99,
            gates=DeterministicGates(
                authenticity=GateResult.PASS,
                firmware_vbios=GateResult.PASS,
                functional_burnin=GateResult.NOT_ASSESSED,
                sdc_functional=GateResult.NOT_ASSESSED,
                data_sanitization=GateResult.NOT_ASSESSED,
            ),
        ),
        measured=MeasuredBlock(
            ecc=EccCounters(
                volatile_correctable=0,
                volatile_uncorrectable=0,
                aggregate_correctable=12,
                aggregate_uncorrectable=0,
            ),
            xid=[],
            extensions={"xid_events_source": "capture_payload"},
            pages=PageRetirement(retired=3, retired_sbe=3, retired_dbe=0, remapped=3),
            spare_rows=SpareRows(used=3, remaining=509, cap=512),
            stability=StabilitySignals(throttle_reasons=[]),
            thermals=Thermals(
                gpu_temp_c=41, memory_temp_c=49, hotspot_temp_c=55, throttle_temp_c=87
            ),
            clock_power=ClockPower(
                sm_clock_mhz=1980,
                mem_clock_mhz=2619,
                power_draw_w=312,
                power_limit_w=700,
                enforced_power_limit_w=700,
            ),
        ),
        functional=None,
        raw_reads=RawReads(
            payloads=[
                RawPayload(
                    source="nvml",
                    key="nvmlDeviceGetMemoryErrorCounter",
                    format="json",
                    content='{"aggregate_correctable": 12, "aggregate_uncorrectable": 0}',
                    sha256=None,
                    captured_at=_FIXED_TIME,
                ),
                RawPayload(
                    source="nvml",
                    key="nvmlDeviceGetRemappedRows",
                    format="json",
                    content='{"corrRows": 3, "uncRows": 0, "isPending": 0, "failureOccurred": 0}',
                    captured_at=_FIXED_TIME,
                ),
            ]
        ),
        environment=None,  # No facility instrumentation, so exposure stays Not Assessed.
        provenance=ProvenanceBlock(
            tier=Tier.SILVER,
            history=History.RECONSTRUCTED,
            chain_gaps=True,
            exposure_assessed=False,
            reconstructed_from="operator inventory records",
        ),
        signature=None,
    )


__all__ = ["worked_example_a_bundle"]
