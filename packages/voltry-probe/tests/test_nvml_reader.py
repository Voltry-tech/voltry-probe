"""NVML mapper: fixture + inline payloads mapped to typed measured/identity blocks."""

from __future__ import annotations

import pytest

from voltry_probe.readers import map_nvml

# The health-bearing leaves a real NVML read always carries. The reader raises if any
# of them is absent, so inline test payloads start from a complete read.
_HEALTHY_MEASURED = {
    "ecc": {
        "volatile": {"correctable": 0, "uncorrectable": 0},
        "aggregate": {"correctable": 0, "uncorrectable": 0},
    },
    "remapped_rows": {"corrRows": 0, "uncRows": 0},
    "pages": {"retired_sbe": 0, "retired_dbe": 0},
}


def _payload(**overrides: object) -> dict:
    return {"device": {}, **_HEALTHY_MEASURED, **overrides}


def test_maps_identity_and_spare_rows(capture):
    out = map_nvml(capture.nvml)
    assert out.device_part == "H100-SXM5"
    assert out.serial == "1320923000123"
    assert out.vbios_version == "96.00.89.00.01"
    # Spare rows remaining is derived from remapped rows against the 512 cap.
    assert out.spare_rows.used == 3
    assert out.spare_rows.remaining == 509
    assert out.spare_rows.cap == 512
    assert out.ecc.aggregate_correctable == 12
    assert out.ecc.aggregate_uncorrectable == 0
    assert out.pages.retired == 3
    assert out.thermals.gpu_temp_c == 41
    assert out.clock_power.power_limit_w == 700


def test_xid_events_normalized_to_taxonomy():
    nvml = _payload(
        device={"part": "H100-SXM5", "serial": "x", "uuid": "GPU-x"},
        xid=[
            {"xid": 79, "count": 1},
            {"xid": 48, "count": 2},
            {"xid": 9999, "count": 1},  # unknown -> uncategorized, never dropped
        ],
    )
    out = map_nvml(nvml)
    by_xid = {e.xid: e for e in out.xid}
    assert by_xid[79].category == "off_bus" and by_xid[79].critical is True
    assert by_xid[48].category == "memory_dbe" and by_xid[48].critical is True
    assert by_xid[9999].category == "uncategorized" and by_xid[9999].critical is False
    assert by_xid[48].count == 2


def test_throttle_reasons_flagged():
    out = map_nvml(_payload(throttle_reasons=["SW_Thermal_Slowdown", "HW_Power_Brake_Slowdown"]))
    assert out.stability.thermal_throttle_active is True
    assert out.stability.throttle_reasons == ["SW_Thermal_Slowdown", "HW_Power_Brake_Slowdown"]


def test_live_source_reason_names_map_to_flags():
    # The exact names sources/live.py emits. The Hw* variants are hardware-initiated
    # and assert hw_slowdown_active alongside their thermal/power flag.
    out = map_nvml(_payload(throttle_reasons=["HwSlowdown", "SwPowerCap", "HwThermalSlowdown"]))
    assert out.stability.hw_slowdown_active is True
    assert out.stability.power_throttle_active is True
    assert out.stability.thermal_throttle_active is True

    out = map_nvml(_payload(throttle_reasons=["GpuIdle", "SyncBoost", "ApplicationsClocksSetting"]))
    assert out.stability.thermal_throttle_active is False
    assert out.stability.power_throttle_active is False
    assert out.stability.hw_slowdown_active is False


def test_unknown_throttle_reason_sets_no_flags():
    # Flag mapping is by whole reason name, not substring: an unrecognized name that
    # merely contains "power" must not flip the power flag. The raw name is still
    # preserved verbatim in throttle_reasons.
    out = map_nvml(_payload(throttle_reasons=["VendorPowerNap", "EmpowermentMode"]))
    assert out.stability.power_throttle_active is False
    assert out.stability.thermal_throttle_active is False
    assert out.stability.hw_slowdown_active is False
    assert out.stability.throttle_reasons == ["VendorPowerNap", "EmpowermentMode"]


def test_malformed_xid_entry_without_code_is_skipped():
    # An entry that lost its xid code (truncated log line, malformed fixture) must be
    # skipped, not defaulted: int(entry.get("xid", 0)) used to turn it into a
    # synthetic "Xid 0" event that never happened. Non-int codes (strings, bools) are
    # malformed the same way.
    nvml = _payload(
        xid=[
            {"count": 4, "description": "entry with no code"},
            {"xid": "79", "count": 1},
            {"xid": True, "count": 1},
            {"xid": 79, "count": 2},
        ]
    )
    out = map_nvml(nvml)
    assert [e.xid for e in out.xid] == [79]
    assert out.xid[0].count == 2


def test_retired_zero_with_nonzero_per_cause_counts_stays_zero():
    # A payload that carries a combined "retired" key wins even at 0: a measured zero
    # must not be silently replaced by the sbe+dbe sum ("value or sum" did exactly
    # that). The sum is only a fallback for payloads with no combined key at all.
    out = map_nvml(_payload(pages={"retired_sbe": 2, "retired_dbe": 1, "retired": 0}))
    assert out.pages.retired == 0
    assert out.pages.retired_sbe == 2 and out.pages.retired_dbe == 1


def test_retired_key_absent_falls_back_to_per_cause_sum():
    out = map_nvml(_payload(pages={"retired_sbe": 2, "retired_dbe": 1}))
    assert out.pages.retired == 3


def test_missing_ecc_block_refuses():
    # Absence of memory-health data must never certify as "0 errors": absent telemetry
    # is omitted, never recorded as zero.
    payload = _payload()
    del payload["ecc"]
    with pytest.raises(ValueError, match="ecc"):
        map_nvml(payload)


def test_empty_ecc_block_refuses():
    # An ecc block present but EMPTY is unread data too, not a measured zero.
    with pytest.raises(ValueError, match="ecc"):
        map_nvml(_payload(ecc={}))


def test_partial_ecc_missing_aggregate_refuses():
    # Volatile present but aggregate absent: the rendered "Uncorrectable ECC events"
    # (aggregate) must not silently default to 0.
    with pytest.raises(ValueError, match="ecc.aggregate"):
        map_nvml(_payload(ecc={"volatile": {"correctable": 0, "uncorrectable": 0}}))


def test_missing_remap_block_refuses():
    with pytest.raises(ValueError, match="remapped_rows"):
        map_nvml(_payload(remapped_rows=None))


def test_empty_remap_block_refuses():
    # An empty remapped_rows dict must never certify as "512/512 spare rows remaining".
    with pytest.raises(ValueError, match="remapped_rows"):
        map_nvml(_payload(remapped_rows={}))


def test_missing_pages_block_refuses():
    with pytest.raises(ValueError, match="pages"):
        map_nvml(_payload(pages={}))


def test_xid_source_stamped_when_payload_carries_events_key():
    # Presence of the xid key means an event source WAS read (fixture, log reader,
    # DCGM watch); its absence means no source, which the renderer must not show as 0.
    out = map_nvml(_payload(xid=[]))
    assert out.extensions.get("xid_events_source") == "capture_payload"
    payload = _payload()
    payload.pop("xid", None)
    out = map_nvml(payload)
    assert "xid_events_source" not in out.extensions


def test_present_zero_is_an_honest_zero():
    # A genuinely-measured zero across every required leaf is legitimately clean; the
    # refusals above are only for ABSENT data, never for a real read of zero.
    out = map_nvml(_payload())
    assert out.ecc.volatile_correctable == 0
    assert out.ecc.aggregate_uncorrectable == 0
    assert out.spare_rows.remaining == 512
    assert out.pages.retired == 0
    assert out.xid == []
