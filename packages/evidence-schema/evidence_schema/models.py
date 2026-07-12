"""Pydantic v2 models for the signed evidence bundle.

Design rules the models enforce:

- **Capture wide.** History can only be recorded forward: whatever a unit's first
  scan fails to capture is gone for good, so ``MeasuredBlock`` and ``RawReads``
  carry everything a future modeled track could need even though nothing modeled
  is computed today. ``MeasuredBlock.extensions`` gives additive capture a landing
  zone that needs no schema change.
- **Measurement only.** The bundle holds measured facts and the verbatim replay
  substrate. There is no modeled estimate and no single "score" field anywhere;
  modeled values are recomputed later by the engine from ``raw_reads``, keyed by
  the ``methodology_version_hash`` and ``calibration_snapshot_id`` recorded here.
- **No price.** No value/price/valuation field exists anywhere, by construction
  (a test checks field names against a blocklist).
- **Determinism.** Counters are bounded to the safe-integer domain; large/opaque data
  lives verbatim in ``RawReads`` as strings. Datetimes are UTC. This keeps the canonical
  (RFC 8785) bytes byte-stable across runs, processes, and languages.

Field-by-field documentation lives in the ``Field(description=...)`` strings so it flows
into the generated JSON Schema for cross-language consumers.
"""

from __future__ import annotations

from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from .enums import (
    AttestationVerdict,
    GateResult,
    History,
    IdentityScheme,
    RunMode,
    Tier,
)
from .types import SAFE_INTEGER_MAX, Count, UtcDateTime
from .version import CANONICALIZATION_SCHEME, SCHEMA_VERSION, SIGNATURE_ALGORITHM

# Maximum spare rows on Hopper HBM: a fixed threshold that does not scale with
# capacity, so the remap margin toward that cap is the primary wear signal to read.
SPARE_ROW_CAP: int = 512


class _Strict(BaseModel):
    """Base for every bundle model: reject unknown fields so the contract stays explicit.

    Backward read-compatibility (older bundles, fewer fields) still holds because new
    fields are optional with defaults; ``extra='forbid'`` only rejects *unknown* keys,
    which is the forward-compat direction governed by the version policy.
    """

    model_config = ConfigDict(extra="forbid")


# --------------------------------------------------------------------------- agent


class AgentInfo(_Strict):
    """Identity of the probe build that produced the bundle (for replay + provenance)."""

    name: str = Field(description="Agent name, e.g. 'voltry-probe'.")
    version: str = Field(description="Agent semantic version.")
    build: str | None = Field(default=None, description="Build/commit identifier.")
    host_arch: str | None = Field(
        default=None, description="Host architecture, e.g. 'x86_64', 'aarch64'."
    )
    run_mode: RunMode = Field(description="Mode the agent ran in (READ/FUNCTIONAL/MONITOR).")
    nvml_version: str | None = Field(default=None, description="NVML library version observed.")
    dcgm_version: str | None = Field(
        default=None, description="DCGM library version observed, if used."
    )
    driver_version: str | None = Field(default=None, description="NVIDIA driver version observed.")
    cuda_version: str | None = Field(
        default=None, description="CUDA runtime/driver version observed."
    )


# ------------------------------------------------------------------------ identity


class DeterministicGates(_Strict):
    """Certificate block 1: deterministic pass/fail gates, no model.

    Authenticity and firmware failures are **disqualifying** (the unit cannot be
    certified genuine). A gate that was not run is ``NOT_ASSESSED``, never PASS.
    """

    authenticity: GateResult = Field(
        description="Device authenticity via attestation. FAIL is disqualifying."
    )
    firmware_vbios: GateResult = Field(
        description="Firmware/VBIOS integrity (no re-flash). FAIL is disqualifying."
    )
    functional_burnin: GateResult = Field(
        default=GateResult.NOT_ASSESSED, description="Functional burn-in pass (functional mode)."
    )
    sdc_functional: GateResult = Field(
        default=GateResult.NOT_ASSESSED,
        description="Silent-data-corruption functional test (functional mode).",
    )
    data_sanitization: GateResult = Field(
        default=GateResult.NOT_ASSESSED,
        description="Data sanitization per IEEE 2883-2022 (functional mode).",
    )


class Attestation(_Strict):
    """NVIDIA attestation result for this scan.

    The verdict is whatever the chain evaluation actually returned; the outcome
    semantics (UNVERIFIED, FALLBACK, and so on) live on
    :class:`~evidence_schema.enums.AttestationVerdict`.
    """

    scheme: IdentityScheme = Field(description="Identity anchoring scheme used.")
    verdict: AttestationVerdict = Field(
        description="Real verdict of the attestation chain evaluation."
    )
    report_b64: str | None = Field(
        default=None, description="Verbatim attestation report (opaque, base64). Replay substrate."
    )
    root_reachability: bool = Field(
        description=(
            "Whether the NVIDIA root/PKI was reachable; False means the verdict "
            "cannot be VERIFIED online."
        )
    )
    nras_used: bool = Field(
        default=False, description="Whether NRAS (remote attestation service) was used."
    )
    detail: str | None = Field(
        default=None, description="Human-readable note on the attestation outcome."
    )
    measured_at: UtcDateTime | None = Field(
        default=None, description="When attestation was performed (UTC)."
    )
    challenge: str | None = Field(
        default=None,
        description=(
            "Operator-issued challenge nonce for this scan, recorded so a third party "
            "can recompute the freshness comparison against the raw report's nonce. "
            "None means no challenge was issued (pre-1.2.0 flow)."
        ),
    )
    freshness: GateResult = Field(
        default=GateResult.NOT_ASSESSED,
        description=(
            "Challenge-nonce freshness of the report. PASS: the report's nonce matches "
            "the operator-issued challenge. FAIL: mismatch (replay indication, "
            "disqualifying). NOT_ASSESSED: no challenge was issued; freshness rests on "
            "the measured_at window only, at lower confidence."
        ),
    )

    @model_validator(mode="after")
    def _assessed_freshness_requires_challenge(self) -> Attestation:
        """An assessed freshness with no recorded challenge is internally inconsistent:
        there is nothing a third party could recompute the comparison against."""
        if self.freshness is not GateResult.NOT_ASSESSED and self.challenge is None:
            raise ValueError(
                "freshness PASS/FAIL requires a recorded challenge; "
                "without one freshness must stay NOT_ASSESSED"
            )
        return self


class IdentityBlock(_Strict):
    """The permanent identity of the unit and its authenticity evidence."""

    device_part: str = Field(description="Marketing/part identifier, e.g. 'H100-SXM5'.")
    device_model: str | None = Field(
        default=None, description="Detailed model/board name if available."
    )
    serial: str = Field(description="Board/device serial as reported (string; may be long).")
    ecc384_id: str = Field(
        description="Device-unique ECC-384 identity (hex/base64 string). The permanent key."
    )
    gpu_uuid: str | None = Field(default=None, description="NVML GPU UUID, if available.")
    board_id: str | None = Field(
        default=None, description="Board id / chassis-relative id, if available."
    )
    attestation: Attestation = Field(description="Attestation result for this identity.")
    vbios_version: str | None = Field(default=None, description="VBIOS version string.")
    vbios_hash: str | None = Field(
        default=None, description="VBIOS measurement hash (for re-flash detection)."
    )
    reflash_detected: bool = Field(description="True if VBIOS re-flash/tamper was detected.")
    identity_scheme: IdentityScheme = Field(
        description="Whether identity is hardware-rooted or a fallback."
    )
    authenticity_confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidence in authenticity [0,1]. Lower for SECONDARY_FALLBACK parts.",
    )
    gates: DeterministicGates = Field(description="Deterministic gates (certificate block 1).")


# ------------------------------------------------------------------------ measured


class EccCounters(_Strict):
    """ECC error counters captured wide (volatile + aggregate, SRAM + DRAM)."""

    volatile_correctable: Count = Field(default=0, description="Volatile correctable ECC errors.")
    volatile_uncorrectable: Count = Field(
        default=0, description="Volatile uncorrectable ECC errors."
    )
    aggregate_correctable: Count = Field(
        default=0, description="Lifetime aggregate correctable ECC errors."
    )
    aggregate_uncorrectable: Count = Field(
        default=0, description="Lifetime aggregate uncorrectable ECC errors."
    )
    sram_correctable: Count | None = Field(
        default=None, description="SRAM correctable errors, if separable."
    )
    sram_uncorrectable: Count | None = Field(
        default=None, description="SRAM uncorrectable errors, if separable."
    )
    dram_correctable: Count | None = Field(
        default=None, description="DRAM/HBM correctable errors, if separable."
    )
    dram_uncorrectable: Count | None = Field(
        default=None, description="DRAM/HBM uncorrectable errors, if separable."
    )


class XidEvent(_Strict):
    """A normalized Xid event (mapped to the one taxonomy before any pooling)."""

    xid: int = Field(ge=0, le=10_000, description="Xid code.")
    count: Count = Field(default=1, description="Occurrences of this Xid in the captured window.")
    category: str = Field(description="Normalized failure-taxonomy category for this Xid.")
    critical: bool = Field(default=False, description="Whether this Xid is in the critical set.")
    description: str | None = Field(default=None, description="Human-readable Xid description.")
    first_seen: UtcDateTime | None = Field(default=None, description="First observation (UTC).")
    last_seen: UtcDateTime | None = Field(
        default=None, description="Most recent observation (UTC)."
    )


class PageRetirement(_Strict):
    """Retired/remapped memory page accounting."""

    retired: Count = Field(default=0, description="Total retired pages.")
    retired_sbe: Count = Field(default=0, description="Pages retired due to single-bit errors.")
    retired_dbe: Count = Field(default=0, description="Pages retired due to double-bit errors.")
    pending_retirement: Count = Field(default=0, description="Pages pending retirement.")
    remapped: Count = Field(
        default=0, description="Remapped rows/pages reported by InfoROM, counted toward the cap."
    )


class SpareRows(_Strict):
    """HBM row-remap accounting from InfoROM: remaps counted toward the fixed cap (512 on
    Hopper). This is the reported remap margin, not a direct count of physical spare rows;
    read alongside pending and failure_occurred, which can matter before the cap is reached."""

    used: Count = Field(default=0, description="Spare rows consumed.")
    remaining: Count = Field(
        description="Reported remap margin toward the fixed cap (cap minus used)."
    )
    cap: int = Field(
        default=SPARE_ROW_CAP, ge=0, description="Fixed spare-row cap (512 on Hopper)."
    )
    correctable_remaps: Count | None = Field(
        default=None, description="Remaps from correctable errors, if separable."
    )
    uncorrectable_remaps: Count | None = Field(
        default=None, description="Remaps from uncorrectable errors, if separable."
    )
    pending: Count = Field(default=0, description="Pending remap operations.")
    failure_occurred: bool = Field(
        default=False, description="Whether a row-remap failure was reported."
    )


class StabilitySignals(_Strict):
    """Throttle/clock/power stability flags (facts, not a score)."""

    throttle_reasons: list[str] = Field(
        default_factory=list, description="Active throttle reasons (verbatim labels)."
    )
    thermal_throttle_active: bool = Field(default=False, description="Thermal throttling active.")
    power_throttle_active: bool = Field(default=False, description="Power-cap throttling active.")
    hw_slowdown_active: bool = Field(default=False, description="Hardware slowdown active.")
    sw_throttle_active: bool = Field(default=False, description="Software power-scaling active.")
    sync_boost_active: bool = Field(default=False, description="Sync-boost throttling active.")


class Thermals(_Strict):
    """Thermal snapshot (series captured in Monitor mode; wide for the thermal index)."""

    gpu_temp_c: int | None = Field(
        default=None, ge=-50, le=200, description="GPU core temperature (°C)."
    )
    memory_temp_c: int | None = Field(
        default=None, ge=-50, le=200, description="HBM/memory temperature (°C)."
    )
    hotspot_temp_c: int | None = Field(
        default=None, ge=-50, le=200, description="Hotspot temperature (°C)."
    )
    throttle_temp_c: int | None = Field(
        default=None, ge=-50, le=200, description="Throttle threshold (°C)."
    )
    max_operating_temp_c: int | None = Field(
        default=None, ge=-50, le=200, description="Max operating temp (°C)."
    )


class ClockPower(_Strict):
    """Clock and power snapshot (facts)."""

    sm_clock_mhz: int | None = Field(default=None, ge=0, le=100_000, description="SM clock (MHz).")
    mem_clock_mhz: int | None = Field(
        default=None, ge=0, le=100_000, description="Memory clock (MHz)."
    )
    graphics_clock_mhz: int | None = Field(
        default=None, ge=0, le=100_000, description="Graphics clock (MHz)."
    )
    power_draw_w: int | None = Field(
        default=None, ge=0, le=10_000, description="Instantaneous power draw (W)."
    )
    power_limit_w: int | None = Field(
        default=None, ge=0, le=10_000, description="Configured power limit (W)."
    )
    enforced_power_limit_w: int | None = Field(
        default=None, ge=0, le=10_000, description="Enforced power limit (W)."
    )
    default_power_limit_w: int | None = Field(
        default=None, ge=0, le=10_000, description="Default power limit (W)."
    )


class NvLinkStatus(_Strict):
    """NVLink presence/health captured wide (hardware sub-index input)."""

    active_links: Count | None = Field(default=None, description="Number of active NVLink links.")
    total_links: Count | None = Field(default=None, description="Total NVLink links on the board.")
    replay_errors: Count | None = Field(default=None, description="NVLink replay errors.")
    recovery_errors: Count | None = Field(default=None, description="NVLink recovery errors.")
    crc_errors: Count | None = Field(default=None, description="NVLink CRC errors.")


class PcieStatus(_Strict):
    """PCIe link status captured wide."""

    gen: int | None = Field(default=None, ge=0, le=10, description="Negotiated PCIe generation.")
    width: int | None = Field(default=None, ge=0, le=64, description="Negotiated PCIe lane width.")
    replay_counter: Count | None = Field(default=None, description="PCIe replay counter.")
    correctable_errors: Count | None = Field(default=None, description="PCIe correctable errors.")
    fatal_errors: Count | None = Field(default=None, description="PCIe fatal errors.")
    nonfatal_errors: Count | None = Field(default=None, description="PCIe non-fatal errors.")


class DutyBlock(_Strict):
    """Cumulative use, the odometer (added in schema 1.1.0).

    NVML exposes no lifetime-hours counter, so duty can only be ACCUMULATED
    (registry deltas across scans, or continuous monitoring), never read in one
    shot. Every field is optional: a quantity that has not been accumulated stays
    None (rendered as Not Assessed) rather than being estimated from a single
    point-in-time read. ``basis`` states how the values were accumulated so a
    reader can weigh them.
    """

    gpu_hours_total: float | None = Field(
        default=None,
        ge=0,
        le=SAFE_INTEGER_MAX - 1,
        description="Cumulative GPU-hours on the record.",
    )
    thermal_cycles_total: Count | None = Field(
        default=None, description="Cumulative thermal cycles on the record."
    )
    energy_kwh_total: float | None = Field(
        default=None,
        ge=0,
        le=SAFE_INTEGER_MAX - 1,
        description="Cumulative energy through the board, kWh.",
    )
    sustained_high_power_hours: float | None = Field(
        default=None,
        ge=0,
        le=SAFE_INTEGER_MAX - 1,
        description="Cumulative hours at sustained high power (>95% TDP).",
    )
    basis: str | None = Field(
        default=None,
        description="How duty was accumulated: 'registry_accumulated' (deltas across "
        "ledger scans) or 'monitor_continuous' (Gold monitoring). None = not accumulated.",
    )
    since: UtcDateTime | None = Field(
        default=None, description="Accumulation start (first scan or born-on)."
    )


class MeasuredBlock(_Strict):
    """Certificate block 2: measured condition (facts vs thresholds, no weights, no model).

    Wide and extensible. Everything a future modeled track could need is captured
    here even though nothing modeled is computed from it yet; first scans cannot be
    re-run, so under-capturing now would be an unrecoverable loss. ``extensions`` is
    the additive landing zone for underwriter fields that are not yet first-class
    (still typed JSON, no ``Any``).
    """

    ecc: EccCounters = Field(default_factory=EccCounters, description="ECC error counters.")
    xid: list[XidEvent] = Field(default_factory=list, description="Normalized Xid event history.")
    pages: PageRetirement = Field(
        default_factory=PageRetirement, description="Retired/remapped page accounting."
    )
    spare_rows: SpareRows = Field(
        description="HBM row-remap accounting (InfoROM): remap margin toward the fixed cap."
    )
    stability: StabilitySignals = Field(
        default_factory=StabilitySignals, description="Throttle/stability flags."
    )
    thermals: Thermals = Field(default_factory=Thermals, description="Thermal snapshot.")
    clock_power: ClockPower = Field(default_factory=ClockPower, description="Clock/power snapshot.")
    nvlink: NvLinkStatus | None = Field(default=None, description="NVLink status, if present.")
    pcie: PcieStatus | None = Field(default=None, description="PCIe link status, if available.")
    duty: DutyBlock | None = Field(
        default=None,
        description="Cumulative use (the odometer), registry-accumulated. None until "
        "accumulation exists; not derived from a single read (added in schema 1.1.0).",
    )
    extensions: dict[str, JsonValue] = Field(
        default_factory=dict,
        description="Additive, forward-compatible capture (underwriter fields). JSON values only; "
        "integers stay within the safe-integer domain (large/opaque data belongs in raw_reads).",
    )


# ---------------------------------------------------------------------- functional


class Sanitization(_Strict):
    """Data sanitization record (IEEE 2883-2022)."""

    standard: str = Field(default="IEEE-2883-2022", description="Sanitization standard applied.")
    method: str | None = Field(
        default=None, description="Sanitization method (clear/purge/destruct)."
    )
    result: GateResult = Field(default=GateResult.NOT_ASSESSED, description="Sanitization result.")
    verified: bool = Field(
        default=False, description="Whether sanitization was independently verified."
    )


class FunctionalBlock(_Strict):
    """Functional-mode results (drained unit). Present only when functional mode ran."""

    dcgm_runlevel: str | None = Field(
        default=None, description="DCGM diagnostic run level (r1-r4)."
    )
    dcgm_result: GateResult = Field(
        default=GateResult.NOT_ASSESSED, description="DCGM diagnostic result."
    )
    burnin_result: GateResult = Field(
        default=GateResult.NOT_ASSESSED, description="Burn-in result."
    )
    burnin_duration_s: Count | None = Field(default=None, description="Burn-in duration (seconds).")
    sdc_functional: GateResult = Field(
        default=GateResult.NOT_ASSESSED, description="SDC functional pass/fail."
    )
    sdc_detail: str | None = Field(default=None, description="SDC test detail.")
    sanitization: Sanitization = Field(
        default_factory=Sanitization, description="Data sanitization record."
    )


# ------------------------------------------------------------------------ raw reads


class RawPayload(_Strict):
    """A single verbatim source payload: the replay substrate.

    Stored as an **opaque string** (raw text or base64) so it is byte-exact and so any
    large numbers in raw telemetry are preserved without lossy JSON-number round-tripping.
    """

    source: str = Field(
        description="Source library, e.g. 'nvml', 'dcgm', 'redfish', 'attestation'."
    )
    key: str = Field(description="Logical name of this payload (e.g. the API/field it came from).")
    format: str = Field(
        default="json", description="Encoding of `content`: 'json' | 'text' | 'base64'."
    )
    content: str = Field(description="Verbatim payload content as returned by the source.")
    sha256: str | None = Field(
        default=None, description="Hex SHA-256 of `content` (producer-computed integrity tag)."
    )
    captured_at: UtcDateTime | None = Field(
        default=None, description="When this payload was captured (UTC)."
    )


class RawReads(_Strict):
    """All verbatim source payloads. Future model versions re-process this; never discard."""

    payloads: list[RawPayload] = Field(
        default_factory=list,
        description="Verbatim NVML/DCGM/Redfish/attestation payloads (the replay substrate).",
    )


# --------------------------------------------------------------------- environment


class EnvironmentBlock(_Strict):
    """Facility-layer context from a data-center connector. Absent means exposure
    renders as Not Assessed.

    Exposure is never inferred from board power (board-side draw says nothing about
    supply quality); it requires real facility instrumentation, which lands here
    when a connector is present.
    """

    facility_id: str | None = Field(
        default=None, description="Opaque facility identifier (no PII)."
    )
    connector: str | None = Field(default=None, description="Facility connector/source name.")
    power_quality_instrumented: bool = Field(
        default=False, description="Whether facility power-quality instrumentation is present."
    )
    notes: str | None = Field(default=None, description="Free-form facility notes (no PII).")


# ---------------------------------------------------------------------- provenance


class ProvenanceBlock(_Strict):
    """Certificate block 4: provenance and coverage. ``exposure_assessed`` defaults to
    False and is rendered prominently; it is only True with real facility
    instrumentation."""

    tier: Tier = Field(description="Provenance/coverage tier (BRONZE/SILVER/GOLD).")
    history: History = Field(description="BORN_ON (captured from first-seen) or RECONSTRUCTED.")
    chain_gaps: bool = Field(description="Whether there are gaps in the custody/telemetry chain.")
    custody_pointer: str | None = Field(
        default=None, description="Opaque pointer to custody records (no PII)."
    )
    exposure_assessed: bool = Field(
        default=False,
        description="True only with facility instrumentation. Never inferred from board power; "
        "rendered prominently.",
    )
    born_on: UtcDateTime | None = Field(
        default=None, description="First-seen timestamp (born-on), if known."
    )
    first_seen: UtcDateTime | None = Field(
        default=None, description="Earliest observation of this unit (UTC)."
    )
    reconstructed_from: str | None = Field(
        default=None, description="Provenance source when RECONSTRUCTED."
    )


# ----------------------------------------------------------------------- signature


class Signature(_Strict):
    """ECDSA P-384 signature over the canonical (RFC 8785) bytes of the bundle.

    Self-describing: it embeds the algorithm, canonicalization scheme, and the signer's
    public key (SPKI DER, base64) so any party can check *cryptographic integrity*.
    Binding the public key to an *authorized* signer (operator/Voltry) is a separate
    platform-registry concern, not a property of this object.
    """

    algorithm: str = Field(
        default=SIGNATURE_ALGORITHM, description="Signature algorithm identifier."
    )
    canonicalization: str = Field(
        default=CANONICALIZATION_SCHEME, description="Canonicalization scheme identifier."
    )
    public_key_spki_b64: str = Field(
        description="Signer public key, SubjectPublicKeyInfo DER, base64."
    )
    signature_b64: str = Field(description="DER-encoded ECDSA signature, base64.")
    signed_at: UtcDateTime = Field(description="When the bundle was signed (UTC).")
    signer: str | None = Field(
        default=None, description="Signer role/label, e.g. 'operator' or 'voltry'."
    )
    key_id: str | None = Field(
        default=None, description="Optional key identifier for rotation/lookup."
    )


# -------------------------------------------------------------------------- bundle


class EvidenceBundle(_Strict):
    """The signed evidence bundle: source of truth, replay artifact, and ledger leaf.

    The certificate is a *view* over this. It carries the measurement, the verbatim raw
    reads (replay substrate), and the provenance/methodology stamps, but no modeled
    estimate and no price.
    """

    schema_version: str = Field(
        default=SCHEMA_VERSION, description="Semver of the schema this bundle conforms to."
    )
    bundle_id: UUID = Field(default_factory=uuid4, description="Unique id for this bundle/attempt.")
    created_at: UtcDateTime = Field(description="When the bundle was assembled (UTC).")
    agent: AgentInfo = Field(description="The probe build that produced the bundle.")
    methodology_version_hash: str = Field(
        description="Hash of the methodology version this bundle was captured under, "
        "stamped so a third party can replay the exact method."
    )
    calibration_snapshot_id: str | None = Field(
        default=None,
        description="Calibration snapshot id for modeled fields. None while no "
        "modeled fields are computed.",
    )
    identity: IdentityBlock = Field(description="Permanent identity + authenticity evidence.")
    measured: MeasuredBlock = Field(description="Measured facts (certificate block 2), wide.")
    functional: FunctionalBlock | None = Field(
        default=None, description="Functional-mode results, if run."
    )
    raw_reads: RawReads = Field(description="Verbatim source payloads (the replay substrate).")
    environment: EnvironmentBlock | None = Field(
        default=None, description="Facility context from a data-center connector, if present."
    )
    provenance: ProvenanceBlock = Field(
        description="Provenance and coverage (certificate block 4)."
    )
    signature: Signature | None = Field(
        default=None, description="ECDSA P-384 signature over canonical bytes. None until signed."
    )


__all__ = [
    "SPARE_ROW_CAP",
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
    "EvidenceBundle",
]
