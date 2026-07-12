"""LiveSource against a fake pynvml: full Tier-1 capture, honest absence semantics.

These tests prove the live path's CONTRACT (which getters are called, how the payload
is shaped, and that unsupported optional reads are omitted rather than fabricated).
They cannot prove real-hardware behavior; that is validated on real hardware separately.
"""

from __future__ import annotations

import sys
import types
from datetime import datetime

import pytest
from pydantic import ValidationError

from voltry_probe.sources import RawCapture, UnsupportedGpuError
from voltry_probe.sources.live import LiveSource


class NVMLError(Exception):
    pass


class NVMLErrorNotSupported(NVMLError):
    pass


def _fake_pynvml(**overrides):
    """A module-like fake exposing the getters LiveSource uses. Healthy H100-ish."""
    m = types.ModuleType("pynvml")
    m.NVMLError = NVMLError
    m.NVMLError_NotSupported = NVMLErrorNotSupported

    # constants (values arbitrary; only identity matters)
    m.NVML_MEMORY_ERROR_TYPE_CORRECTED = 0
    m.NVML_MEMORY_ERROR_TYPE_UNCORRECTED = 1
    m.NVML_VOLATILE_ECC = 0
    m.NVML_AGGREGATE_ECC = 1
    m.NVML_PAGE_RETIREMENT_CAUSE_MULTIPLE_SINGLE_BIT_ECC_ERRORS = 0
    m.NVML_PAGE_RETIREMENT_CAUSE_DOUBLE_BIT_ECC_ERROR = 1
    m.NVML_TEMPERATURE_GPU = 0
    m.NVML_TEMPERATURE_THRESHOLD_SLOWDOWN = 0
    m.NVML_CLOCK_SM = 0
    m.NVML_CLOCK_MEM = 1
    m.NVML_CLOCK_GRAPHICS = 2
    m.NVML_NVLINK_ERROR_DL_CRC = 0
    m.NVML_NVLINK_ERROR_DL_REPLAY = 1
    m.NVML_NVLINK_ERROR_DL_RECOVERY = 2
    m.NVML_NVLINK_MAX_LINKS = 18
    # throttle-reason bitmask constants
    m.nvmlClocksThrottleReasonSwThermalSlowdown = 0x20
    m.nvmlClocksThrottleReasonHwSlowdown = 0x8
    m.nvmlClocksThrottleReasonSwPowerCap = 0x4
    m.nvmlClocksThrottleReasonHwPowerBrakeSlowdown = 0x80
    m.nvmlClocksThrottleReasonHwThermalSlowdown = 0x40
    m.nvmlClocksThrottleReasonSyncBoost = 0x10
    m.nvmlClocksThrottleReasonGpuIdle = 0x1
    m.nvmlClocksThrottleReasonApplicationsClocksSetting = 0x2

    m.shutdown_called = False

    def _noop(*_a, **_k):
        return None

    m.nvmlInit = _noop

    def _shutdown(*_a, **_k):
        m.shutdown_called = True

    m.nvmlShutdown = _shutdown
    m.nvmlDeviceGetHandleByIndex = lambda i: f"handle-{i}"
    m.nvmlDeviceGetName = lambda h: "NVIDIA H100 80GB HBM3"
    m.nvmlDeviceGetSerial = lambda h: "1320923000123"
    m.nvmlDeviceGetUUID = lambda h: "GPU-abc123"
    m.nvmlDeviceGetVbiosVersion = lambda h: "96.00.89.00.01"
    _ecc = {(0, 0): 0, (1, 0): 0, (0, 1): 12, (1, 1): 0}
    m.nvmlDeviceGetTotalEccErrors = lambda h, kind, scope: _ecc[(kind, scope)]
    m.nvmlDeviceGetRemappedRows = lambda h: (3, 0, 0, 0)
    m.nvmlDeviceGetRetiredPages = lambda h, cause: [1, 2, 3] if cause == 0 else []
    m.nvmlDeviceGetRetiredPagesPendingStatus = lambda h: 0
    m.nvmlDeviceGetPowerUsage = lambda h: 312_000  # mW
    m.nvmlDeviceGetTemperature = lambda h, sensor: 41
    m.nvmlDeviceGetTemperatureThreshold = lambda h, kind: 87
    m.nvmlDeviceGetClockInfo = lambda h, clock: {0: 1980, 1: 2619, 2: 1830}[clock]
    m.nvmlDeviceGetPowerManagementLimit = lambda h: 700_000
    m.nvmlDeviceGetEnforcedPowerLimit = lambda h: 700_000
    m.nvmlDeviceGetPowerManagementDefaultLimit = lambda h: 700_000
    m.nvmlDeviceGetCurrentClocksThrottleReasons = lambda h: 0x20 | 0x4  # sw thermal + power cap
    m.nvmlDeviceGetCurrPcieLinkGeneration = lambda h: 5
    m.nvmlDeviceGetCurrPcieLinkWidth = lambda h: 16
    m.nvmlDeviceGetPcieReplayCounter = lambda h: 2

    def _nvlink_state(h, link):
        if link < 4:
            return 1  # active
        raise NVMLErrorNotSupported()

    m.nvmlDeviceGetNvLinkState = _nvlink_state
    m.nvmlDeviceGetNvLinkErrorCounter = lambda h, link, kind: {0: 5, 1: 1, 2: 0}[kind]
    m.nvmlDeviceGetEccMode = lambda h: (1, 1)
    m.nvmlDeviceGetMigMode = lambda h: (0, 0)
    # optional identity/odometer getters (captured when present so a unit's
    # first-scan record is complete; all optional in the live reader)
    m.nvmlDeviceGetBoardPartNumber = lambda h: "900-2G520-0000-000"
    m.nvmlDeviceGetBrand = lambda h: 2
    m.nvmlDeviceGetCudaComputeCapability = lambda h: (9, 0)
    m.nvmlDeviceGetBoardId = lambda h: 12544
    m.nvmlDeviceGetMemoryInfo = lambda h: types.SimpleNamespace(
        total=85_899_345_920, free=85_899_345_920, used=0
    )
    m.nvmlDeviceGetTotalEnergyConsumption = lambda h: 304_675_237_548  # mJ since driver load
    m.NVML_PERF_POLICY_POWER = 0
    m.NVML_PERF_POLICY_THERMAL = 1
    m.NVML_PERF_POLICY_RELIABILITY = 2
    m.NVML_PERF_POLICY_BOARD_LIMIT = 3
    m.nvmlDeviceGetViolationStatus = lambda h, pol: types.SimpleNamespace(
        violationTime=12_000_000 * (pol + 1), referenceTime=1_783_215_936_000_000
    )
    m.NVML_INFOROM_OEM = 0
    m.NVML_INFOROM_ECC = 1
    m.NVML_INFOROM_PWR = 2
    m.nvmlDeviceGetInforomImageVersion = lambda h: "G520.0200.00.05"
    m.nvmlDeviceGetInforomVersion = lambda h, obj: {0: "2.1", 1: "6.16", 2: "1.0"}[obj]
    m.nvmlDeviceGetInforomConfigurationChecksum = lambda h: 0
    m.nvmlDeviceGetGspFirmwareVersion = lambda h: "570.211.01"
    m.nvmlDeviceGetPowerManagementLimitConstraints = lambda h: (100_000, 700_000)
    m.nvmlDeviceGetMaxClockInfo = lambda h, clock: {0: 1980, 1: 3201, 2: 2100}[clock]
    m.nvmlDeviceGetDefaultApplicationsClock = lambda h, clock: {0: 1830, 1: 3201, 2: 1980}[clock]
    m.nvmlDeviceGetMaxPcieLinkGeneration = lambda h: 5
    m.nvmlDeviceGetPerformanceState = lambda h: 0
    m.nvmlDeviceGetNumGpuCores = lambda h: 16896
    m.NVML_FI_DEV_MEMORY_TEMP = 82
    m.nvmlDeviceGetFieldValues = lambda h, fids: [
        types.SimpleNamespace(fieldId=fids[0], nvmlReturn=0, value=types.SimpleNamespace(uiVal=52))
    ]
    m.nvmlDeviceGetRowRemapperHistogram = lambda h: types.SimpleNamespace(
        **{"max": 0, "high": 0, "partial": 0, "low": 2, "none": 510}
    )
    m.NVML_DEVICE_ARCH_VOLTA = 5
    m.NVML_DEVICE_ARCH_TURING = 6
    m.NVML_DEVICE_ARCH_AMPERE = 7
    m.NVML_DEVICE_ARCH_HOPPER = 9
    m.NVML_DEVICE_ARCH_UNKNOWN = 0xFFFFFFFF
    m.nvmlDeviceGetArchitecture = lambda h: 9  # Hopper, matching the H100 defaults
    m.nvmlSystemGetDriverVersion = lambda: "550.54.15"
    m.nvmlSystemGetNVMLVersion = lambda: "12.550.54"
    m.nvmlSystemGetCudaDriverVersion = lambda: 12040

    for name, fn in overrides.items():
        setattr(m, name, fn)
    return m


@pytest.fixture()
def fake_nvml(monkeypatch):
    fake = _fake_pynvml()
    monkeypatch.setitem(sys.modules, "pynvml", fake)
    return fake


def _raise_nvml(*_a, **_k):
    raise NVMLError("not supported on this device")


def _raise_ns(*_a, **_k):
    raise NVMLErrorNotSupported("Not Supported")


def test_capture_reads_full_tier1_payload(fake_nvml):
    payload = LiveSource().capture().nvml
    assert payload["thermals"]["gpu"] == 41
    assert payload["thermals"]["throttle"] == 87
    assert payload["clocks"] == {"sm": 1980, "mem": 2619, "graphics": 1830}
    assert payload["power"] == {
        "draw": 312,
        "limit": 700,
        "enforced": 700,
        "default": 700,
        "min_limit": 100,
        "max_limit": 700,
    }
    assert "SwThermalSlowdown" in payload["throttle_reasons"]
    assert "SwPowerCap" in payload["throttle_reasons"]
    assert payload["pcie"] == {"gen": 5, "width": 16, "replay_counter": 2, "max_gen": 5}
    assert payload["nvlink"]["active"] == 4
    assert payload["nvlink"]["crc_errors"] == 20  # 5 per active link
    assert payload["nvlink"]["replay_errors"] == 4
    assert payload["system"]["driver_version"] == "550.54.15"
    assert payload["system"]["cuda_version"] == "12.4"
    assert payload["ecc_mode"] == {"current": True, "pending": True}
    # the required core is untouched
    assert payload["ecc"]["aggregate"]["correctable"] == 12
    assert payload["remapped_rows"]["corrRows"] == 3
    assert payload["pages"]["retired_sbe"] == 3


def test_unsupported_optionals_are_omitted_never_fabricated(monkeypatch):
    fake = _fake_pynvml(
        nvmlDeviceGetTemperature=_raise_nvml,
        nvmlDeviceGetTemperatureThreshold=_raise_nvml,
        nvmlDeviceGetFieldValues=_raise_nvml,
        nvmlDeviceGetClockInfo=_raise_nvml,
        nvmlDeviceGetCurrentClocksThrottleReasons=_raise_nvml,
        nvmlDeviceGetCurrPcieLinkGeneration=_raise_nvml,
        nvmlDeviceGetNvLinkState=_raise_nvml,
        nvmlDeviceGetEccMode=_raise_nvml,
        nvmlSystemGetDriverVersion=_raise_nvml,
    )
    monkeypatch.setitem(sys.modules, "pynvml", fake)
    payload = LiveSource().capture().nvml
    for absent in ("thermals", "clocks", "throttle_reasons", "pcie", "nvlink", "ecc_mode"):
        assert absent not in payload, f"{absent} must be omitted (Not Assessed), never defaulted"
    assert "driver_version" not in payload.get("system", {})
    # required reads still present
    assert "ecc" in payload and "remapped_rows" in payload and "pages" in payload


def test_required_read_failure_raises_and_shuts_down(monkeypatch):
    fake = _fake_pynvml(nvmlDeviceGetTotalEccErrors=_raise_nvml)
    monkeypatch.setitem(sys.modules, "pynvml", fake)
    with pytest.raises(NVMLError):
        LiveSource().capture()
    assert fake.shutdown_called is True


def test_wide_capture_provenance_and_odometer_counters(fake_nvml):
    # These fields are sealed into every signed bundle's raw reads from the moment
    # they are read, even before the certificate renders them (capture now, render
    # later). All confirmed supported on real silicon (L40S + V100 field run).
    payload = LiveSource().capture().nvml
    device = payload["device"]
    assert device["board_part_number"] == "900-2G520-0000-000"
    assert device["architecture"] == 9
    assert device["compute_capability"] == [9, 0]
    assert device["board_id"] == 12544
    assert payload["memory"] == {"total_bytes": 85_899_345_920}
    assert payload["energy"] == {"total_mj": 304_675_237_548, "basis": "since_driver_load"}
    viol = payload["violations"]
    assert viol["basis"] == "since_driver_load"
    assert viol["power"]["violation_ns"] == 12_000_000
    assert viol["thermal"]["violation_ns"] == 24_000_000
    inforom = payload["inforom"]
    assert inforom["image_version"] == "G520.0200.00.05"
    assert inforom["ecc_version"] == "6.16"
    assert inforom["config_checksum"] == 0
    assert payload["gsp_firmware"] == {"version": "570.211.01"}
    assert payload["power"]["min_limit"] == 100 and payload["power"]["max_limit"] == 700
    assert payload["clocks_max"]["sm"] == 1980
    assert payload["clocks_default_app"]["sm"] == 1830
    assert payload["pcie"]["max_gen"] == 5
    assert payload["performance_state"] == 0


def test_mig_state_is_sealed_on_every_successful_scan(fake_nvml):
    # MIG state used to exist only in refusal messages. A successful scan must seal
    # it too (MIG-off is itself a provenance fact).
    payload = LiveSource().capture().nvml
    assert payload["mig"] == {"current": False, "pending": False}


def test_core_count_hbm_temp_and_remapper_histogram_are_sealed(fake_nvml):
    payload = LiveSource().capture().nvml
    assert payload["device"]["core_count"] == 16896
    assert payload["thermals"]["memory"] == 52  # HBM sensor via the field-values API
    assert payload["remapper_histogram"] == {
        "max": 0,
        "high": 0,
        "partial": 0,
        "low": 2,
        "none": 510,
    }


def test_hbm_temp_unsupported_inside_field_value_is_omitted(monkeypatch):
    # The field-values call can SUCCEED while the value itself reports NotSupported
    # (GDDR cards have no memory sensor). Omit, never bank a zero.
    fake = _fake_pynvml(
        nvmlDeviceGetFieldValues=lambda h, fids: [
            types.SimpleNamespace(
                fieldId=fids[0], nvmlReturn=3, value=types.SimpleNamespace(uiVal=0)
            )
        ]
    )
    monkeypatch.setitem(sys.modules, "pynvml", fake)
    payload = LiveSource().capture().nvml
    assert "memory" not in payload["thermals"]


def test_hbm_temp_empty_field_values_list_is_omitted(monkeypatch):
    # A field-values call returning an empty list has measured nothing; the memory
    # key must be absent. The shape check handles this explicitly (the old broad
    # exception suppress would also have hidden real parser bugs).
    fake = _fake_pynvml(nvmlDeviceGetFieldValues=lambda h, fids: [])
    monkeypatch.setitem(sys.modules, "pynvml", fake)
    payload = LiveSource().capture().nvml
    assert "memory" not in payload["thermals"]


def test_captured_at_is_timezone_aware(fake_nvml):
    captured_at = LiveSource().capture().captured_at
    assert captured_at.tzinfo is not None
    assert captured_at.utcoffset() is not None


def test_raw_capture_rejects_naive_timestamp():
    # Freshness arithmetic downstream subtracts tz-aware timestamps; a naive value
    # must be rejected at the capture boundary, next to whoever produced it.
    with pytest.raises(ValidationError):
        RawCapture(captured_at=datetime(2026, 6, 17, 9, 0, 0), nvml={})


def test_wide_capture_fields_absent_in_old_bindings_are_omitted(monkeypatch):
    # A binding without the optional identity/odometer getters (older nvidia-ml-py)
    # must scan fine and omit them from the payload.
    fake = _fake_pynvml()
    for name in (
        "nvmlDeviceGetBoardPartNumber",
        "nvmlDeviceGetTotalEnergyConsumption",
        "nvmlDeviceGetViolationStatus",
        "nvmlDeviceGetInforomImageVersion",
        "nvmlDeviceGetInforomVersion",
        "nvmlDeviceGetInforomConfigurationChecksum",
        "nvmlDeviceGetGspFirmwareVersion",
        "nvmlDeviceGetPowerManagementLimitConstraints",
        "nvmlDeviceGetDefaultApplicationsClock",
        "nvmlDeviceGetMemoryInfo",
        "nvmlDeviceGetCudaComputeCapability",
        "nvmlDeviceGetNumGpuCores",
        "nvmlDeviceGetFieldValues",
        "nvmlDeviceGetRowRemapperHistogram",
        "nvmlDeviceGetMigMode",
    ):
        delattr(fake, name)
    monkeypatch.setitem(sys.modules, "pynvml", fake)
    payload = LiveSource().capture().nvml
    for absent in (
        "memory",
        "energy",
        "violations",
        "inforom",
        "gsp_firmware",
        "mig",
        "remapper_histogram",
    ):
        assert absent not in payload
    assert "board_part_number" not in payload["device"]
    assert "core_count" not in payload["device"]
    assert "min_limit" not in payload.get("power", {})


def test_wide_capture_lands_in_signed_raw_reads(fake_nvml, signer_key):
    # The odometer counters are inside the SIGNED record, not a sidecar, so they are
    # replayable and tamper-evident from day one.
    from evidence_schema import AgentInfo, RunMode

    from voltry_probe.evidence import build_read_bundle

    bundle = build_read_bundle(
        LiveSource().capture(),
        signer_key=signer_key,
        agent=AgentInfo(name="voltry-probe", version="0.2.1", run_mode=RunMode.READ),
        methodology_version_hash="read-v0",
    )
    nvml_raw = next(r for r in bundle.raw_reads.payloads if r.source == "nvml")
    for key in ('"energy"', '"violations"', '"board_part_number"', '"inforom"'):
        assert key in nvml_raw.content


def test_nvlink_counters_absent_in_modern_bindings_are_omitted(monkeypatch):
    # A binding with no legacy NVLink error-counter API at all (none of the
    # NVML_NVLINK_ERROR_DL_* constants, no nvmlDeviceGetNvLinkErrorCounter). Link state
    # must still capture; the counters are omitted, never fabricated. Found live on a
    # rented A100 SXM4 (2026-07-04 field run).
    fake = _fake_pynvml()
    del fake.NVML_NVLINK_ERROR_DL_CRC
    del fake.NVML_NVLINK_ERROR_DL_REPLAY
    del fake.NVML_NVLINK_ERROR_DL_RECOVERY
    del fake.nvmlDeviceGetNvLinkErrorCounter
    monkeypatch.setitem(sys.modules, "pynvml", fake)
    nvlink = LiveSource().capture().nvml["nvlink"]
    assert nvlink["active"] == 4 and nvlink["total"] == 4
    for absent in ("crc_errors", "replay_errors", "recovery_errors"):
        assert absent not in nvlink, f"{absent} must be omitted, never defaulted to zero"


def test_nvlink_partial_constant_set_omits_only_the_unmeasured_counter(monkeypatch):
    # Current nvidia-ml-py (12.575.51, 13.610.43) keeps nvmlDeviceGetNvLinkErrorCounter
    # and the REPLAY/RECOVERY constants but drops NVML_NVLINK_ERROR_DL_CRC. CRC was
    # never read there, so its key must be absent: a banked crc_errors: 0 would claim
    # a clean CRC check that never ran.
    fake = _fake_pynvml()
    del fake.NVML_NVLINK_ERROR_DL_CRC
    monkeypatch.setitem(sys.modules, "pynvml", fake)
    nvlink = LiveSource().capture().nvml["nvlink"]
    assert "crc_errors" not in nvlink, "crc_errors must be omitted, never defaulted to zero"
    assert nvlink["replay_errors"] == 4  # still measured: 1 per active link
    assert nvlink["recovery_errors"] == 0  # a genuinely-measured zero is a valid clean read
    assert nvlink["active"] == 4 and nvlink["total"] == 4


def test_nvlink_counter_unreadable_on_every_link_omits_counters(monkeypatch):
    # The constants can all resolve while the device refuses every per-link counter
    # read (virtualized guests, driver quirks). Nothing was measured, so no counter
    # key may be banked; link state alone is still an honest capture.
    fake = _fake_pynvml(nvmlDeviceGetNvLinkErrorCounter=_raise_nvml)
    monkeypatch.setitem(sys.modules, "pynvml", fake)
    nvlink = LiveSource().capture().nvml["nvlink"]
    assert nvlink["active"] == 4 and nvlink["total"] == 4
    for absent in ("crc_errors", "replay_errors", "recovery_errors"):
        assert absent not in nvlink, f"{absent} must be omitted, never defaulted to zero"


def test_nvlink_enumeration_skips_a_gap_index_never_undercounts(monkeypatch):
    # A single unreadable link index must not end enumeration: a higher index may be
    # live. Link 1 raises; links 0, 2, 3 are active -> 3 active, not 1.
    def _gappy_state(h, link):
        if link == 1:
            raise NVMLErrorNotSupported()
        if link < 4:
            return 1
        raise NVMLErrorNotSupported()

    fake = _fake_pynvml(nvmlDeviceGetNvLinkState=_gappy_state)
    monkeypatch.setitem(sys.modules, "pynvml", fake)
    nvlink = LiveSource().capture().nvml["nvlink"]
    assert nvlink["active"] == 3


def test_serial_not_supported_is_omitted_never_fabricated(monkeypatch):
    # GeForce boards carry no inforom serial. Identity falls back to the GPU UUID
    # downstream (the builder records serial "UNKNOWN"); the reader must omit, not fake.
    fake = _fake_pynvml(nvmlDeviceGetSerial=_raise_ns)
    monkeypatch.setitem(sys.modules, "pynvml", fake)
    device = LiveSource().capture().nvml["device"]
    assert "serial" not in device, "serial must be omitted when unsupported, never fabricated"
    assert device["uuid"] == "GPU-abc123"


def test_no_ecc_gpu_refuses_with_specific_reason(monkeypatch):
    # Consumer-class card: counters AND ecc mode both raise NotSupported (no ECC hardware).
    fake = _fake_pynvml(
        nvmlDeviceGetTotalEccErrors=_raise_ns,
        nvmlDeviceGetEccMode=_raise_ns,
        nvmlDeviceGetName=lambda h: "NVIDIA GeForce RTX 4090",
    )
    monkeypatch.setitem(sys.modules, "pynvml", fake)
    with pytest.raises(UnsupportedGpuError) as excinfo:
        LiveSource().capture()
    msg = str(excinfo.value)
    assert "NVIDIA GeForce RTX 4090" in msg
    assert "no ECC" in msg
    assert fake.shutdown_called is True


def test_ecc_disabled_gpu_refuses_and_names_the_fix(monkeypatch):
    # Workstation cards (RTX A6000 class) often ship ECC-capable but disabled.
    fake = _fake_pynvml(
        nvmlDeviceGetTotalEccErrors=_raise_ns,
        nvmlDeviceGetEccMode=lambda h: (0, 0),
    )
    monkeypatch.setitem(sys.modules, "pynvml", fake)
    with pytest.raises(UnsupportedGpuError, match="ECC is disabled"):
        LiveSource().capture()
    assert fake.shutdown_called is True


def test_ecc_unreadable_with_ecc_enabled_still_refuses(monkeypatch):
    # Mode says enabled but counters raise NotSupported: never certify unread state.
    fake = _fake_pynvml(nvmlDeviceGetTotalEccErrors=_raise_ns)
    monkeypatch.setitem(sys.modules, "pynvml", fake)
    with pytest.raises(UnsupportedGpuError, match="unreadable"):
        LiveSource().capture()


def test_mig_hides_ecc_counters_refuses_with_mig_reason(monkeypatch):
    # On MIG-enabled GPUs the volatile ECC read fails before remapped rows is ever
    # reached, so the ECC diagnosis must name MIG, not a vague driver quirk.
    fake = _fake_pynvml(
        nvmlDeviceGetTotalEccErrors=_raise_ns,
        nvmlDeviceGetMigMode=lambda h: (1, 1),
    )
    monkeypatch.setitem(sys.modules, "pynvml", fake)
    with pytest.raises(UnsupportedGpuError, match="MIG"):
        LiveSource().capture()


def test_pre_ampere_gpu_refuses_with_architecture_reason(monkeypatch):
    fake = _fake_pynvml(
        nvmlDeviceGetRemappedRows=_raise_ns,
        nvmlDeviceGetName=lambda h: "Tesla V100-SXM2-16GB",
        nvmlDeviceGetArchitecture=lambda h: 5,  # Volta
    )
    monkeypatch.setitem(sys.modules, "pynvml", fake)
    with pytest.raises(UnsupportedGpuError) as excinfo:
        LiveSource().capture()
    msg = str(excinfo.value)
    assert "Tesla V100-SXM2-16GB" in msg
    assert "row remapping" in msg
    assert "pre-Ampere" in msg
    assert fake.shutdown_called is True


def test_remapping_unreadable_on_modern_arch_never_claims_pre_ampere(monkeypatch):
    # Hopper part whose remapped-rows read is hidden (virtualized guest): the refusal
    # must not assert an architecture fact that contradicts the measured architecture.
    fake = _fake_pynvml(nvmlDeviceGetRemappedRows=_raise_ns)  # arch default: Hopper
    monkeypatch.setitem(sys.modules, "pynvml", fake)
    with pytest.raises(UnsupportedGpuError) as excinfo:
        LiveSource().capture()
    msg = str(excinfo.value)
    assert "pre-Ampere" not in msg
    assert "row remapping" in msg


def test_remapping_unreadable_with_unknown_arch_never_claims_pre_ampere(monkeypatch):
    # Architecture unreadable: state what is known, never assert what was not measured.
    fake = _fake_pynvml(
        nvmlDeviceGetRemappedRows=_raise_ns,
        nvmlDeviceGetArchitecture=_raise_nvml,
        nvmlDeviceGetMigMode=_raise_nvml,  # MIG state unknown too, not "definitely off"
    )
    monkeypatch.setitem(sys.modules, "pynvml", fake)
    with pytest.raises(UnsupportedGpuError) as excinfo:
        LiveSource().capture()
    msg = str(excinfo.value)
    assert "pre-Ampere" not in msg


def test_generic_ecc_mode_error_during_diagnosis_propagates(monkeypatch):
    # ECC counters NotSupported, then the ECC-mode probe hits a driver fault: the fault
    # must propagate, never be laundered into a "consumer-class GPU" claim.
    fake = _fake_pynvml(
        nvmlDeviceGetTotalEccErrors=_raise_ns,
        nvmlDeviceGetEccMode=_raise_nvml,
    )
    monkeypatch.setitem(sys.modules, "pynvml", fake)
    with pytest.raises(NVMLError):
        LiveSource().capture()
    assert fake.shutdown_called is True


def test_mig_enabled_gpu_refuses_with_mig_reason(monkeypatch):
    fake = _fake_pynvml(
        nvmlDeviceGetRemappedRows=_raise_ns,
        nvmlDeviceGetMigMode=lambda h: (1, 1),
    )
    monkeypatch.setitem(sys.modules, "pynvml", fake)
    with pytest.raises(UnsupportedGpuError, match="MIG"):
        LiveSource().capture()


def test_generic_nvml_error_on_remapped_rows_still_propagates(monkeypatch):
    # Only NotSupported gets the diagnostic treatment; a driver fault stays a driver fault.
    fake = _fake_pynvml(nvmlDeviceGetRemappedRows=_raise_nvml)
    monkeypatch.setitem(sys.modules, "pynvml", fake)
    with pytest.raises(NVMLError):
        LiveSource().capture()
    assert fake.shutdown_called is True


def test_retired_pages_not_supported_is_marked(monkeypatch):
    # Ampere+ replaces page retirement with row remapping; the API raises NotSupported.
    def _pages_ns(*_a, **_k):
        raise NVMLErrorNotSupported()

    fake = _fake_pynvml(nvmlDeviceGetRetiredPages=_pages_ns)
    monkeypatch.setitem(sys.modules, "pynvml", fake)
    payload = LiveSource().capture().nvml
    pages = payload["pages"]
    assert pages["retired_sbe"] == 0 and pages["retired_dbe"] == 0
    assert pages["api"] == "not_supported"


def test_bundle_roundtrip_from_live_capture(fake_nvml, signer_key):
    from evidence_schema import AgentInfo, RunMode, verify_bundle

    from voltry_probe.evidence import build_read_bundle

    capture = LiveSource().capture()
    bundle = build_read_bundle(
        capture,
        signer_key=signer_key,
        agent=AgentInfo(name="voltry-probe", version="0.2.0", run_mode=RunMode.READ),
        methodology_version_hash="read-v0",
    )
    assert verify_bundle(bundle) is True
    m = bundle.measured
    assert m.thermals.gpu_temp_c == 41
    assert m.clock_power.sm_clock_mhz == 1980
    assert m.clock_power.power_limit_w == 700
    assert m.stability.thermal_throttle_active is True
    assert m.pcie is not None and m.pcie.gen == 5
    assert m.nvlink is not None and m.nvlink.active_links == 4
    assert m.extensions["ecc_mode_enabled"] is True
    # agent info enriched from the live system block when unset
    assert bundle.agent.driver_version == "550.54.15"
    assert bundle.agent.cuda_version == "12.4"
    assert bundle.agent.nvml_version == "12.550.54"
