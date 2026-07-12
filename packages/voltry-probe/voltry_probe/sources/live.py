"""Live hardware read source: NVML on real GPUs, read-only.

Requires the ``[hardware]`` extra (``nvidia-ml-py``) and a GPU. Every NVML call here
is a getter (``nvmlDeviceGet*`` / ``nvmlSystemGet*``); ``tests/test_read_only.py``
keeps it that way with a source scan plus a runtime spy.

Capture semantics, stated once for the whole file:

- Required health counters (ECC volatile + aggregate, remapped rows, retired pages)
  must read successfully or the scan fails. When the failure is
  ``NVMLError_NotSupported``, that is a device-class fact, not a fault: consumer
  cards have no ECC, workstation cards may ship ECC-disabled, pre-Ampere parts have
  no row remapping, and MIG mode hides both reads. Those cases raise
  :class:`UnsupportedGpuError` with a diagnosis naming the device. Any other
  ``NVMLError`` propagates unchanged so a flaky driver is never misreported as a
  device-class limitation.
- Optional telemetry (thermals, clocks, limits, throttle, PCIe, NVLink, ECC mode,
  library versions) is captured when the device/driver exposes it and left out of
  the payload when it does not. Downstream treats a missing key as "not read" and
  renders Not Assessed; writing a 0 instead would look like a clean measurement.
  The board serial is optional the same way (GeForce boards carry no inforom), and
  identity binds to the GPU UUID downstream.

The payload shape is locked by ``tests/test_live_source.py`` against a fake pynvml,
and validated on real hardware.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from .base import RawCapture, UnsupportedGpuError

# Throttle-reason bitmask constants mapped to stable names (which constants exist
# varies by driver/binding version). readers/nvml.py keys its stability flags off
# these exact names; keep the two in sync.
_THROTTLE_REASONS = (
    ("nvmlClocksThrottleReasonGpuIdle", "GpuIdle"),
    ("nvmlClocksThrottleReasonApplicationsClocksSetting", "ApplicationsClocksSetting"),
    ("nvmlClocksThrottleReasonSwPowerCap", "SwPowerCap"),
    ("nvmlClocksThrottleReasonHwSlowdown", "HwSlowdown"),
    ("nvmlClocksThrottleReasonSyncBoost", "SyncBoost"),
    ("nvmlClocksThrottleReasonSwThermalSlowdown", "SwThermalSlowdown"),
    ("nvmlClocksThrottleReasonHwThermalSlowdown", "HwThermalSlowdown"),
    ("nvmlClocksThrottleReasonHwPowerBrakeSlowdown", "HwPowerBrakeSlowdown"),
)


def _s(value: object) -> str:
    """NVML strings arrive as str or bytes depending on binding version."""
    return value.decode() if isinstance(value, bytes) else str(value)


def _mig_enabled(pynvml: Any, handle: Any) -> bool | None:
    """MIG mode state: True/False when read, None when unknown.

    Only a clean read (or a clean NotSupported, which means the part predates MIG) may
    assert a state; any other error is unknown, never a definitive "not MIG".
    """
    mig_fn = getattr(pynvml, "nvmlDeviceGetMigMode", None)
    if mig_fn is None:
        return None
    try:
        mig_current, _mig_pending = mig_fn(handle)
    except pynvml.NVMLError_NotSupported:
        return False
    except pynvml.NVMLError:
        return None
    return bool(mig_current)


def _architecture(pynvml: Any, handle: Any) -> int | None:
    """The device architecture constant, or None when it cannot be read."""
    arch_fn = getattr(pynvml, "nvmlDeviceGetArchitecture", None)
    if arch_fn is None:
        return None
    try:
        arch = int(arch_fn(handle))
    except pynvml.NVMLError:
        return None
    unknown = getattr(pynvml, "NVML_DEVICE_ARCH_UNKNOWN", None)
    if unknown is not None and arch == unknown:
        return None
    return arch


def _diagnose_no_ecc(pynvml: Any, handle: Any, name: str) -> str:
    """Why the ECC counters raised NotSupported: no ECC hardware, ECC off, MIG, or a quirk.

    Only a clean NotSupported from the ECC-mode read supports the no-ECC-hardware
    conclusion; a generic NVML error during this probe propagates so a flaky driver
    is not misdiagnosed as a consumer-class card.
    """
    try:
        current, _pending = pynvml.nvmlDeviceGetEccMode(handle)
    except pynvml.NVMLError_NotSupported:
        return (
            f"{name}: ECC error counters are not readable and the device exposes no ECC "
            "mode. This is a consumer-class GPU with no ECC memory, or a virtualized "
            "guest that hides board-level ECC; memory health cannot be read, so the "
            "scan refuses rather than certify unread state. voltry-probe certifies "
            "datacenter-class GPUs with ECC."
        )
    if not current:
        return (
            f"{name}: ECC is disabled on this device, so ECC error counters cannot be "
            "read. Enable ECC (administrator: nvidia-smi -e 1, then reboot) or scan a "
            "host that has ECC enabled."
        )
    if _mig_enabled(pynvml, handle):
        # On MIG-enabled GPUs the volatile ECC read fails on the plain device handle,
        # so this diagnosis fires before remapped rows is ever attempted.
        return (
            f"{name}: ECC counters are not readable while MIG mode is enabled, so memory "
            "health cannot be certified. Scan this GPU with MIG disabled (whole-GPU "
            "passthrough)."
        )
    return (
        f"{name}: ECC mode reports enabled but the ECC counters are unreadable on this "
        "driver/device combination; refusing to certify unread memory-health state."
    )


def _diagnose_no_remapping(pynvml: Any, handle: Any, name: str) -> str:
    """Why row remapping raised NotSupported: MIG hides it, or the part predates it.

    The pre-Ampere claim is only made when the architecture was actually read and is
    older than Ampere; otherwise the message states what is known without asserting an
    architecture fact that was never measured (virtualized guests hide these reads).
    """
    if _mig_enabled(pynvml, handle):
        return (
            f"{name}: row remapping is not readable while MIG mode is enabled, so "
            "memory health cannot be certified. Scan this GPU with MIG disabled "
            "(whole-GPU passthrough)."
        )
    arch = _architecture(pynvml, handle)
    ampere = getattr(pynvml, "NVML_DEVICE_ARCH_AMPERE", None)
    if arch is not None and ampere is not None and arch < ampere:
        return (
            f"{name}: this GPU does not support row remapping (pre-Ampere architecture). "
            "Spare-row headroom is part of the measured contract, so the scan refuses "
            "rather than fabricate it. voltry-probe certifies Ampere-or-newer datacenter "
            "GPUs today."
        )
    return (
        f"{name}: row remapping is not readable on this device/driver combination "
        "(a virtualized guest, an unreadable MIG state, or a driver limitation), so "
        "memory health cannot be certified; refusing to certify unread state."
    )


class LiveSource:
    """Reads NVML counters read-only from a real GPU. DCGM/Redfish/attestation captures
    are layered in by the probe's hardware integration."""

    def __init__(self, index: int = 0) -> None:
        self._index = index

    def capture(self) -> RawCapture:
        try:
            import pynvml
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise RuntimeError(
                "LiveSource requires the 'hardware' extra: pip install 'voltry-probe[hardware]'"
            ) from exc

        def _try(fn: Callable[..., Any], *args: object) -> Any:
            """Optional read: value on success, None when the device does not expose it."""
            try:
                return fn(*args)
            except pynvml.NVMLError:
                return None

        def _maybe(name: str, *args: object) -> Any:
            """Best-effort read: None when the BINDING lacks the getter (older
            nvidia-ml-py) or the device does not expose it."""
            fn = getattr(pynvml, name, None)
            return None if fn is None else _try(fn, *args)

        pynvml.nvmlInit()
        try:
            handle = pynvml.nvmlDeviceGetHandleByIndex(self._index)

            # Identity strings first (universally supported except serial), so a refusal
            # below can name the device it refused.
            name = _s(pynvml.nvmlDeviceGetName(handle))
            device: dict[str, Any] = {
                "name": name,
                "uuid": _s(pynvml.nvmlDeviceGetUUID(handle)),
                "vbios_version": _s(pynvml.nvmlDeviceGetVbiosVersion(handle)),
            }
            # Serial raises NotSupported on boards with no inforom (GeForce class).
            # Omitted: the builder records "UNKNOWN" and identity binds to the GPU UUID.
            with contextlib.suppress(pynvml.NVMLError_NotSupported):
                device["serial"] = _s(pynvml.nvmlDeviceGetSerial(handle))

            # Extra identity fields, captured when readable so a unit's first-scan record
            # is complete (confirmed live on L40S+V100).
            # The OEM board part number is the manufacturer SKU, distinct from the serial.
            board_part = _maybe("nvmlDeviceGetBoardPartNumber", handle)
            if board_part is not None:
                device["board_part_number"] = _s(board_part)
            brand = _maybe("nvmlDeviceGetBrand", handle)
            if brand is not None:
                device["brand"] = int(brand)
            arch = _maybe("nvmlDeviceGetArchitecture", handle)
            if arch is not None:
                device["architecture"] = int(arch)
            cc = _maybe("nvmlDeviceGetCudaComputeCapability", handle)
            if cc is not None:
                device["compute_capability"] = [int(cc[0]), int(cc[1])]
            board_id = _maybe("nvmlDeviceGetBoardId", handle)
            if board_id is not None:
                device["board_id"] = int(board_id)
            core_count = _maybe("nvmlDeviceGetNumGpuCores", handle)
            if core_count is not None:
                device["core_count"] = int(core_count)

            # ---- Required health counters (scan fails, with a diagnosis, if unreadable) ----
            try:
                ecc_corr = pynvml.nvmlDeviceGetTotalEccErrors(
                    handle, pynvml.NVML_MEMORY_ERROR_TYPE_CORRECTED, pynvml.NVML_VOLATILE_ECC
                )
                ecc_unc = pynvml.nvmlDeviceGetTotalEccErrors(
                    handle, pynvml.NVML_MEMORY_ERROR_TYPE_UNCORRECTED, pynvml.NVML_VOLATILE_ECC
                )
                ecc_agg_corr = pynvml.nvmlDeviceGetTotalEccErrors(
                    handle, pynvml.NVML_MEMORY_ERROR_TYPE_CORRECTED, pynvml.NVML_AGGREGATE_ECC
                )
                ecc_agg_unc = pynvml.nvmlDeviceGetTotalEccErrors(
                    handle, pynvml.NVML_MEMORY_ERROR_TYPE_UNCORRECTED, pynvml.NVML_AGGREGATE_ECC
                )
            except pynvml.NVMLError_NotSupported as exc:
                raise UnsupportedGpuError(_diagnose_no_ecc(pynvml, handle, name)) from exc

            try:
                corr_rows, unc_rows, is_pending, failure = pynvml.nvmlDeviceGetRemappedRows(handle)
            except pynvml.NVMLError_NotSupported as exc:
                raise UnsupportedGpuError(_diagnose_no_remapping(pynvml, handle, name)) from exc

            # Retired pages: pre-Ampere mechanism. On row-remapping architectures the
            # API raises NotSupported; there, zero retired pages is the true state of a
            # mechanism that does not exist, and the payload says so explicitly.
            try:
                retired_sbe = len(
                    pynvml.nvmlDeviceGetRetiredPages(
                        handle, pynvml.NVML_PAGE_RETIREMENT_CAUSE_MULTIPLE_SINGLE_BIT_ECC_ERRORS
                    )
                )
                retired_dbe = len(
                    pynvml.nvmlDeviceGetRetiredPages(
                        handle, pynvml.NVML_PAGE_RETIREMENT_CAUSE_DOUBLE_BIT_ECC_ERROR
                    )
                )
                pages_pending = pynvml.nvmlDeviceGetRetiredPagesPendingStatus(handle)
                pages: dict[str, Any] = {
                    "retired_sbe": retired_sbe,
                    "retired_dbe": retired_dbe,
                    "pending": pages_pending,
                }
            except pynvml.NVMLError_NotSupported:
                pages = {"retired_sbe": 0, "retired_dbe": 0, "pending": 0, "api": "not_supported"}

            nvml_payload: dict[str, Any] = {
                "device": device,
                "ecc": {
                    "volatile": {"correctable": ecc_corr, "uncorrectable": ecc_unc},
                    "aggregate": {"correctable": ecc_agg_corr, "uncorrectable": ecc_agg_unc},
                },
                "remapped_rows": {
                    "corrRows": corr_rows,
                    "uncRows": unc_rows,
                    "isPending": is_pending,
                    "failureOccurred": failure,
                },
                "pages": pages,
            }

            # ---- Optional telemetry (left out when the device does not expose it) ----
            power: dict[str, int] = {}
            draw_mw = _try(pynvml.nvmlDeviceGetPowerUsage, handle)
            if draw_mw is not None:
                power["draw"] = draw_mw // 1000
            for key, fn in (
                ("limit", pynvml.nvmlDeviceGetPowerManagementLimit),
                ("enforced", pynvml.nvmlDeviceGetEnforcedPowerLimit),
                ("default", pynvml.nvmlDeviceGetPowerManagementDefaultLimit),
            ):
                mw = _try(fn, handle)
                if mw is not None:
                    power[key] = mw // 1000
            constraints = _maybe("nvmlDeviceGetPowerManagementLimitConstraints", handle)
            if constraints is not None:
                # The board's allowed cap range: evidence of below-spec power capping.
                power["min_limit"] = int(constraints[0]) // 1000
                power["max_limit"] = int(constraints[1]) // 1000
            if power:
                nvml_payload["power"] = power

            thermals: dict[str, int] = {}
            gpu_temp = _try(pynvml.nvmlDeviceGetTemperature, handle, pynvml.NVML_TEMPERATURE_GPU)
            if gpu_temp is not None:
                thermals["gpu"] = gpu_temp
            slowdown = _try(
                pynvml.nvmlDeviceGetTemperatureThreshold,
                handle,
                pynvml.NVML_TEMPERATURE_THRESHOLD_SLOWDOWN,
            )
            if slowdown is not None:
                thermals["throttle"] = slowdown
            # HBM memory sensor, exposed only through the field-values API. The call
            # can succeed while the per-field status reports NotSupported (GDDR cards
            # have no memory sensor), so only a zero status records a reading. The
            # shape check below is deliberate and narrow: only NVMLError means "the
            # device cannot do this"; a malformed return from the binding (wrong
            # container, missing attributes) is a parser bug that should surface, not
            # be suppressed into a silently missing field.
            fv_fn = getattr(pynvml, "nvmlDeviceGetFieldValues", None)
            mem_temp_fid = getattr(pynvml, "NVML_FI_DEV_MEMORY_TEMP", None)
            if fv_fn is not None and mem_temp_fid is not None:
                try:
                    field_values = fv_fn(handle, [mem_temp_fid])
                except pynvml.NVMLError:
                    field_values = None
                if (
                    isinstance(field_values, (list, tuple))
                    and field_values
                    and getattr(field_values[0], "nvmlReturn", None) is not None
                ):
                    fv = field_values[0]
                    if int(fv.nvmlReturn) == 0:
                        thermals["memory"] = int(fv.value.uiVal)
            if thermals:
                nvml_payload["thermals"] = thermals

            clocks: dict[str, int] = {}
            max_clocks: dict[str, int] = {}
            default_app_clocks: dict[str, int] = {}
            for key, const in (
                ("sm", pynvml.NVML_CLOCK_SM),
                ("mem", pynvml.NVML_CLOCK_MEM),
                ("graphics", pynvml.NVML_CLOCK_GRAPHICS),
            ):
                mhz = _try(pynvml.nvmlDeviceGetClockInfo, handle, const)
                if mhz is not None:
                    clocks[key] = mhz
                # Rated ceiling + factory application clock: current-below-default with
                # load is capping evidence; at idle it is normal downclock. The reader
                # captures both numbers and asserts nothing.
                mhz = _maybe("nvmlDeviceGetMaxClockInfo", handle, const)
                if mhz is not None:
                    max_clocks[key] = mhz
                if key in ("sm", "mem"):
                    mhz = _maybe("nvmlDeviceGetDefaultApplicationsClock", handle, const)
                    if mhz is not None:
                        default_app_clocks[key] = mhz
            if clocks:
                nvml_payload["clocks"] = clocks
            if max_clocks:
                nvml_payload["clocks_max"] = max_clocks
            if default_app_clocks:
                nvml_payload["clocks_default_app"] = default_app_clocks

            mask = _try(pynvml.nvmlDeviceGetCurrentClocksThrottleReasons, handle)
            if mask is not None:
                reasons = [
                    name
                    for const_name, name in _THROTTLE_REASONS
                    if mask & getattr(pynvml, const_name, 0)
                ]
                nvml_payload["throttle_reasons"] = reasons

            pcie_gen = _try(pynvml.nvmlDeviceGetCurrPcieLinkGeneration, handle)
            if pcie_gen is not None:
                pcie: dict[str, int] = {"gen": pcie_gen}
                width = _try(pynvml.nvmlDeviceGetCurrPcieLinkWidth, handle)
                if width is not None:
                    pcie["width"] = width
                replay = _try(pynvml.nvmlDeviceGetPcieReplayCounter, handle)
                if replay is not None:
                    pcie["replay_counter"] = replay
                # Capability ceiling. Current-below-max at idle is normal power saving
                # (observed live: an idle L40S links at gen1 against a gen4 ceiling).
                max_gen = _maybe("nvmlDeviceGetMaxPcieLinkGeneration", handle)
                if max_gen is not None:
                    pcie["max_gen"] = max_gen
                nvml_payload["pcie"] = pcie

            nvlink = self._read_nvlink(pynvml, handle)
            if nvlink is not None:
                nvml_payload["nvlink"] = nvlink

            ecc_mode = _try(pynvml.nvmlDeviceGetEccMode, handle)
            if ecc_mode is not None:
                current, pending = ecc_mode
                nvml_payload["ecc_mode"] = {"current": bool(current), "pending": bool(pending)}

            # ---- Odometer counters + provenance extras ----
            # Captured now, rendered/modeled later: these land verbatim in every signed
            # bundle's raw reads so later model versions can re-read old bundles.
            # Whatever a unit's first scan misses is unrecoverable for that unit.
            # The accumulators reset with the driver, so a single read is never
            # lifetime duty; the payload records the "since_driver_load" basis
            # explicitly so nothing downstream mistakes it for one.
            mem_info = _maybe("nvmlDeviceGetMemoryInfo", handle)
            if mem_info is not None:
                # Total capacity only: a fraud check (claimed vs reported VRAM).
                # Free/used are workload state, not condition.
                nvml_payload["memory"] = {"total_bytes": int(mem_info.total)}

            energy_mj = _maybe("nvmlDeviceGetTotalEnergyConsumption", handle)
            if energy_mj is not None:
                nvml_payload["energy"] = {
                    "total_mj": int(energy_mj),
                    "basis": "since_driver_load",
                }

            violations: dict[str, Any] = {}
            for policy in ("power", "thermal", "reliability", "board_limit"):
                const = getattr(pynvml, f"NVML_PERF_POLICY_{policy.upper()}", None)
                if const is None:
                    continue
                vt = _maybe("nvmlDeviceGetViolationStatus", handle, const)
                if vt is not None:
                    violations[policy] = {
                        "violation_ns": int(vt.violationTime),
                        "reference_ns": int(vt.referenceTime),
                    }
            if violations:
                violations["basis"] = "since_driver_load"
                nvml_payload["violations"] = violations

            inforom: dict[str, Any] = {}
            image_version = _maybe("nvmlDeviceGetInforomImageVersion", handle)
            if image_version is not None:
                inforom["image_version"] = _s(image_version)
            for obj in ("oem", "ecc", "pwr"):
                const = getattr(pynvml, f"NVML_INFOROM_{obj.upper()}", None)
                if const is not None:
                    version = _maybe("nvmlDeviceGetInforomVersion", handle, const)
                    if version is not None:
                        inforom[f"{obj}_version"] = _s(version)
            checksum = _maybe("nvmlDeviceGetInforomConfigurationChecksum", handle)
            if checksum is not None:
                inforom["config_checksum"] = int(checksum)
            if inforom:
                nvml_payload["inforom"] = inforom

            gsp_version = _maybe("nvmlDeviceGetGspFirmwareVersion", handle)
            if gsp_version is not None:
                nvml_payload["gsp_firmware"] = {"version": _s(gsp_version)}

            perf_state = _maybe("nvmlDeviceGetPerformanceState", handle)
            if perf_state is not None:
                nvml_payload["performance_state"] = int(perf_state)

            # MIG state is sealed on every successful scan: MIG-off is a provenance fact
            # (on MIG-enabled cards the scan refuses earlier, at the ECC gate).
            mig = _maybe("nvmlDeviceGetMigMode", handle)
            if mig is not None:
                nvml_payload["mig"] = {"current": bool(mig[0]), "pending": bool(mig[1])}

            # Per-bank spare-row availability, when the binding exposes the histogram.
            hist = _maybe("nvmlDeviceGetRowRemapperHistogram", handle)
            if hist is not None:
                buckets: dict[str, int] = {}
                for bucket in ("max", "high", "partial", "low", "none"):
                    value = getattr(hist, bucket, None)
                    if value is not None:
                        buckets[bucket] = int(value)
                if buckets:
                    nvml_payload["remapper_histogram"] = buckets

            system: dict[str, str] = {}
            driver = _try(pynvml.nvmlSystemGetDriverVersion)
            if driver is not None:
                system["driver_version"] = _s(driver)
            nvml_ver = _try(pynvml.nvmlSystemGetNVMLVersion)
            if nvml_ver is not None:
                system["nvml_version"] = _s(nvml_ver)
            cuda = _try(pynvml.nvmlSystemGetCudaDriverVersion)
            if cuda is not None:
                system["cuda_version"] = f"{cuda // 1000}.{(cuda % 1000) // 10}"
            if system:
                nvml_payload["system"] = system

            return RawCapture(captured_at=datetime.now(timezone.utc), nvml=nvml_payload)
        finally:
            pynvml.nvmlShutdown()

    @staticmethod
    def _read_nvlink(pynvml: Any, handle: Any) -> dict[str, int] | None:
        """Aggregate NVLink state + error counters across links; None if unsupported.

        An error counter appears in the result only when it was actually measured:
        its NVML_NVLINK_ERROR_DL_* constant resolved AND at least one per-link read
        succeeded. Anything else is omitted and downstream renders Not Assessed.
        This covers a binding with no legacy counter API at all (found live on a
        rented A100 SXM4) and the partial drop in current nvidia-ml-py (12.575+),
        which removed NVML_NVLINK_ERROR_DL_CRC but kept REPLAY/RECOVERY: banking
        crc_errors: 0 there would claim a CRC check that never ran.
        """
        max_links = getattr(pynvml, "NVML_NVLINK_MAX_LINKS", 18)
        counter_fn = getattr(pynvml, "nvmlDeviceGetNvLinkErrorCounter", None)
        kinds: list[tuple[Any, str]] = []
        if counter_fn is not None:
            for const_name, bucket in (
                ("NVML_NVLINK_ERROR_DL_CRC", "crc"),
                ("NVML_NVLINK_ERROR_DL_REPLAY", "replay"),
                ("NVML_NVLINK_ERROR_DL_RECOVERY", "recovery"),
            ):
                const = getattr(pynvml, const_name, None)
                if const is not None:
                    kinds.append((const, bucket))
        active = 0
        probed = 0
        counts: dict[str, int] = {}
        for link in range(max_links):
            try:
                state = pynvml.nvmlDeviceGetNvLinkState(handle, link)
            except pynvml.NVMLError:
                # One unreadable link index does not end enumeration; a higher index may
                # still be live. Skip this link, keep probing the fixed range.
                continue
            probed += 1
            if not state:
                continue
            active += 1
            for kind, bucket in kinds:
                if counter_fn is None:  # pragma: no cover - kinds is empty without it
                    continue
                try:
                    count = counter_fn(handle, link, kind)
                except pynvml.NVMLError:
                    continue
                counts[bucket] = counts.get(bucket, 0) + count
        if probed == 0:
            return None
        result = {"active": active, "total": probed}
        for _, bucket in kinds:
            if bucket in counts:
                result[f"{bucket}_errors"] = counts[bucket]
        return result
