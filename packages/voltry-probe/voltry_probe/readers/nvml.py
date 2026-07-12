"""Maps a verbatim NVML payload into typed identity and measured blocks.

Pure function of its input dict, so it is read-only by construction. The expected
payload shape mirrors what the read-only ``nvmlDeviceGet*`` getters return (see
``sources/live.py``). Spare-rows remaining is derived from remapped rows against the
fixed 512 cap: the Hopper end-of-life gauge.

The one rule this module enforces (in ``_require``): a counter the certificate shows
as a measured fact must actually be present in the payload. A live capture always
writes those keys, so a missing key means the counter was never read, and mapping it
to a healthy default would turn "not read" into "0 errors" on the certificate.
"""

from __future__ import annotations

from evidence_schema import (
    ClockPower,
    EccCounters,
    NvLinkStatus,
    PageRetirement,
    PcieStatus,
    SpareRows,
    StabilitySignals,
    Thermals,
    XidEvent,
)
from evidence_schema.models import SPARE_ROW_CAP
from pydantic import BaseModel, ConfigDict

from ._util import _d
from .taxonomy import normalize_xid

_MISSING = object()

# Throttle-reason names the live source emits (the _THROTTLE_REASONS table in
# sources/live.py), keyed by a normalized form (lowercase, underscores stripped) so
# older fixtures spelled like "SW_Thermal_Slowdown" still map. Matching is by whole
# name, never substring: a reason we have not seen before sets no flags, so e.g. a
# future driver reason that merely contains "Power" cannot flip the power flag.
_THERMAL_REASONS = frozenset({"swthermalslowdown", "hwthermalslowdown"})
_POWER_REASONS = frozenset({"swpowercap", "hwpowerbrakeslowdown"})
# HwThermalSlowdown and HwPowerBrakeSlowdown are hardware-initiated, so they assert
# the hw-slowdown flag as well as their thermal/power flag.
_HW_SLOWDOWN_REASONS = frozenset({"hwslowdown", "hwthermalslowdown", "hwpowerbrakeslowdown"})


def _normalize_reason(reason: object) -> str:
    return str(reason).replace("_", "").lower()


def _require(nvml: dict, *keys: str) -> int:
    """Return an integer leaf that must be present in the payload.

    A real read always carries these leaves (see ``sources/live.py``), so absence
    means the counter was never read, not that it read zero. Raising here is what
    keeps an unread health counter from rendering as a clean measured 0; a payload
    that genuinely measured 0 passes through unchanged.
    """
    value = _d(nvml, *keys, default=_MISSING)
    if value is _MISSING:
        path = ".".join(keys)
        raise ValueError(
            f"NVML payload missing measured field {path!r}: refusing to certify unread "
            f"hardware state as a healthy default."
        )
    return int(value)


class NvmlReadout(BaseModel):
    """Typed result of mapping an NVML payload (identity fields + measured blocks)."""

    model_config = ConfigDict(extra="forbid")

    device_part: str | None
    device_model: str | None
    serial: str | None
    gpu_uuid: str | None
    vbios_version: str | None
    ecc: EccCounters
    xid: list[XidEvent]
    pages: PageRetirement
    spare_rows: SpareRows
    stability: StabilitySignals
    thermals: Thermals
    clock_power: ClockPower
    # NVML exposes PCIe/NVLink directly; DCGM-provided values take precedence in the
    # builder when both exist.
    nvlink: NvLinkStatus | None
    pcie: PcieStatus | None
    # Landing-zone facts (e.g. ecc_mode) and observed library versions.
    extensions: dict[str, bool | int | str]
    driver_version: str | None
    nvml_version: str | None
    cuda_version: str | None


def _map_ecc(nvml: dict) -> EccCounters:
    # Volatile + aggregate correctable/uncorrectable are the counters the certificate
    # renders as measured facts, hence _require. sram/dram breakdowns exist only on
    # some parts and stay optional (schema allows None).
    return EccCounters(
        volatile_correctable=_require(nvml, "ecc", "volatile", "correctable"),
        volatile_uncorrectable=_require(nvml, "ecc", "volatile", "uncorrectable"),
        aggregate_correctable=_require(nvml, "ecc", "aggregate", "correctable"),
        aggregate_uncorrectable=_require(nvml, "ecc", "aggregate", "uncorrectable"),
        sram_correctable=_d(nvml, "ecc", "sram", "correctable"),
        sram_uncorrectable=_d(nvml, "ecc", "sram", "uncorrectable"),
        dram_correctable=_d(nvml, "ecc", "dram", "correctable"),
        dram_uncorrectable=_d(nvml, "ecc", "dram", "uncorrectable"),
    )


def _map_xid(nvml: dict) -> list[XidEvent]:
    events: list[XidEvent] = []
    for entry in _d(nvml, "xid", default=[]) or []:
        if not isinstance(entry, dict):
            continue
        code = entry.get("xid")
        # An entry that lost its code (truncated log line, malformed fixture) is
        # skipped: defaulting it would invent an "Xid 0" event that never happened.
        # bool is excluded because it is an int subclass in Python.
        if not isinstance(code, int) or isinstance(code, bool):
            continue
        cls = normalize_xid(code)
        events.append(
            XidEvent(
                xid=code,
                count=int(entry.get("count", 1)),
                category=cls.category,
                critical=cls.critical,
                description=entry.get("description") or cls.description,
            )
        )
    return events


def _map_spare_rows(nvml: dict) -> SpareRows:
    # corrRows/uncRows drive "spare rows remaining", the wear gauge, so both go
    # through _require: an absent remap read must not render as 512/512 headroom.
    corr = _require(nvml, "remapped_rows", "corrRows")
    unc = _require(nvml, "remapped_rows", "uncRows")
    used = corr + unc
    rows = _d(nvml, "remapped_rows", default={}) or {}
    return SpareRows(
        used=used,
        remaining=max(SPARE_ROW_CAP - used, 0),
        cap=SPARE_ROW_CAP,
        correctable_remaps=corr,
        uncorrectable_remaps=unc,
        # isPending/failureOccurred carry schema defaults (0/False) and live capture
        # always writes both keys; a hand-built payload without them reads as the
        # defaults here rather than raising like the _require'd counters above.
        pending=int(rows.get("isPending", 0)),
        failure_occurred=bool(rows.get("failureOccurred", 0)),
    )


def map_nvml(nvml: dict) -> NvmlReadout:
    """Map a verbatim NVML payload into typed identity + measured blocks.

    Health-bearing counters (ECC volatile + aggregate, remapped rows, retired pages)
    go through ``_require`` and raise if the payload never carried them; everything
    optional by construction (sram/dram ECC, pending/failure flags, thermals, clocks)
    is best-effort and maps to None/absent when missing.
    """
    device = _d(nvml, "device", default={}) or {}
    throttle = _d(nvml, "throttle_reasons", default=[]) or []
    normalized_reasons = {_normalize_reason(r) for r in throttle}
    retired_sbe = _require(nvml, "pages", "retired_sbe")
    retired_dbe = _require(nvml, "pages", "retired_dbe")
    # The live source never writes a combined "retired" count (it reads the two
    # per-cause lists), but fixtures and older payloads may carry one. When the key
    # is present its value wins, including a measured 0; the sbe+dbe sum is only a
    # fallback for payloads that never had the combined key. "x or sum" would
    # silently replace a measured 0 with the sum.
    retired = _d(nvml, "pages", "retired", default=_MISSING)
    if retired is _MISSING or retired is None:
        retired = retired_sbe + retired_dbe
    corr_rows = _require(nvml, "remapped_rows", "corrRows")
    unc_rows = _require(nvml, "remapped_rows", "uncRows")

    # A near-twin NvLink/PCIe construction lives in readers/dcgm.py with extra
    # DCGM-only PCIe error fields; the two are intentionally not merged.
    nvlink_raw = _d(nvml, "nvlink")
    nvlink = (
        NvLinkStatus(
            active_links=_d(nvlink_raw, "active"),
            total_links=_d(nvlink_raw, "total"),
            replay_errors=_d(nvlink_raw, "replay_errors"),
            recovery_errors=_d(nvlink_raw, "recovery_errors"),
            crc_errors=_d(nvlink_raw, "crc_errors"),
        )
        if isinstance(nvlink_raw, dict)
        else None
    )
    pcie_raw = _d(nvml, "pcie")
    pcie = (
        PcieStatus(
            gen=_d(pcie_raw, "gen"),
            width=_d(pcie_raw, "width"),
            replay_counter=_d(pcie_raw, "replay_counter"),
        )
        if isinstance(pcie_raw, dict)
        else None
    )
    extensions: dict[str, bool | int | str] = {}
    if "xid" in nvml:
        # An Xid event source was actually read (fixture, log reader, DCGM watch).
        # Without this stamp the renderer must show "not read", never a clean zero.
        extensions["xid_events_source"] = "capture_payload"
    ecc_mode = _d(nvml, "ecc_mode")
    if isinstance(ecc_mode, dict):
        if "current" in ecc_mode:
            extensions["ecc_mode_enabled"] = bool(ecc_mode["current"])
        if "pending" in ecc_mode:
            extensions["ecc_mode_pending_enabled"] = bool(ecc_mode["pending"])
    if _d(nvml, "pages", "api") == "not_supported":
        # Row-remapping architecture: the page-retirement mechanism does not exist.
        extensions["page_retirement_api"] = "not_supported"

    return NvmlReadout(
        device_part=device.get("part"),
        device_model=device.get("name"),
        serial=device.get("serial"),
        gpu_uuid=device.get("uuid"),
        vbios_version=device.get("vbios_version"),
        ecc=_map_ecc(nvml),
        xid=_map_xid(nvml),
        pages=PageRetirement(
            retired=int(retired),
            retired_sbe=retired_sbe,
            retired_dbe=retired_dbe,
            # Schema default is 0 for this flag and live capture always writes the
            # key; a hand-built payload without it reads as 0 here (the flag is not
            # certificate-rendered).
            pending_retirement=_d(nvml, "pages", "pending", default=0),
            remapped=corr_rows + unc_rows,
        ),
        spare_rows=_map_spare_rows(nvml),
        stability=StabilitySignals(
            throttle_reasons=[str(r) for r in throttle],
            thermal_throttle_active=bool(normalized_reasons & _THERMAL_REASONS),
            power_throttle_active=bool(normalized_reasons & _POWER_REASONS),
            hw_slowdown_active=bool(normalized_reasons & _HW_SLOWDOWN_REASONS),
        ),
        thermals=Thermals(
            gpu_temp_c=_d(nvml, "thermals", "gpu"),
            memory_temp_c=_d(nvml, "thermals", "memory"),
            hotspot_temp_c=_d(nvml, "thermals", "hotspot"),
            throttle_temp_c=_d(nvml, "thermals", "throttle"),
        ),
        clock_power=ClockPower(
            sm_clock_mhz=_d(nvml, "clocks", "sm"),
            mem_clock_mhz=_d(nvml, "clocks", "mem"),
            graphics_clock_mhz=_d(nvml, "clocks", "graphics"),
            power_draw_w=_d(nvml, "power", "draw"),
            power_limit_w=_d(nvml, "power", "limit"),
            enforced_power_limit_w=_d(nvml, "power", "enforced"),
            default_power_limit_w=_d(nvml, "power", "default"),
        ),
        nvlink=nvlink,
        pcie=pcie,
        extensions=extensions,
        driver_version=_d(nvml, "system", "driver_version"),
        nvml_version=_d(nvml, "system", "nvml_version"),
        cuda_version=_d(nvml, "system", "cuda_version"),
    )
