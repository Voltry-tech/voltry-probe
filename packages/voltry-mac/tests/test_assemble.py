"""Assembling the 23 surfaces from what a run collected (docs/VOLTRY_MAC_SPEC.md, the
surface registry, the value reasons, the ranges and the computed-values rule in Decision
8, the command records' reason mapping, and Decision 6's rounding).

The inputs are the 27 user commands' results, the panic count (R1), and what the broker
gives the two elevated surfaces. Each value is read through its parser, fitted to its
registry range and grammar, and turned into a value or the reason it is not one; the
computed values follow their inputs. Whole reports built this way must pass the
validator, which checks the same rules independently.
"""

from __future__ import annotations

import dataclasses
import json
import plistlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import pytest
import voltry_mac_test_reports as r

from voltry_mac import assemble, availability, model, parsers, registry, spawn
from voltry_mac import validate as v

Unavailable = availability.Unavailable
UNREAD = parsers.UNREAD
TESTS = Path(__file__).resolve().parent
M5 = TESTS / "fixtures" / "commands" / "m5-laptop"
LOG_HEX = (TESTS / "fixtures" / "smart" / "m5-laptop-2026-09-26.hex").read_text().strip()
COLLECTED_AT = datetime(2026, 9, 26, 12, 0, 0, tzinfo=UTC)
USER_IDS = [f"C{n}" for n in range(1, 10)] + [f"C{n}" for n in range(11, 29)]


def ran(command_id: str, stdout: str, code: int = 0) -> spawn.Result:
    return spawn.Result(command_id, spawn.Ending.EXITED, code, stdout, "", 20, False, True)


def ended(command_id: str, ending: spawn.Ending, *, missing: bool = False) -> spawn.Result:
    code = None if ending is spawn.Ending.NOT_STARTED else -15
    return spawn.Result(command_id, ending, code, "", "", 10, missing, True)


def smart_document(log: str = LOG_HEX) -> str:
    controller = {"location": "Internal", "media": ["disk0"], "status": "ok", "smart_hex": log}
    return json.dumps({"schema": "voltry-mac-smart/0", "controllers": [controller]})


def m5_results(**changes: spawn.Result) -> dict[str, spawn.Result]:
    results = {cid: ran(cid, (M5 / f"{cid}.out").read_text()) for cid in parsers.PARSERS}
    results["C28"] = ran("C28", smart_document())
    results.update(changes)
    return results


def decimals(*texts: str) -> list[Decimal]:
    return [Decimal(text) for text in texts]


# Sample E, part 3: the real five-sample capture (spec, the discovery log).
SAMPLE_E: dict[str, list[object]] = {
    "sample_elapsed_ns": [1006543000, 1011719875, 1008502124, 1011962250, 1011879791],
    "sample_thermal_pressure": ["Nominal"] * 5,
    "sample_cpu_power_mw": decimals("2675.49", "2513.54", "1641.05", "566.227", "665.099"),
    "sample_gpu_power_mw": decimals("50.6685", "50.4092", "60.4857", "55.338", "54.3543"),
    "sample_ane_power_mw": decimals("0", "0", "0", "0", "0"),
    "sample_combined_power_mw": decimals("2726.16", "2563.95", "1701.53", "621.565", "719.453"),
}
LEDGER: dict[str, object] = dict.fromkeys(
    (
        "correctable_event_rows",
        "correctable_reported_count",
        "uncorrectable_event_rows",
        "uncorrectable_reported_count",
    ),
    0,
)


def collected(**changes: object) -> assemble.Collected:
    base = assemble.Collected(
        results=m5_results(),
        panic=0,
        ledger=assemble.Elevated(values=LEDGER),
        power=assemble.Elevated(values=SAMPLE_E),
        collected_at=COLLECTED_AT,
    )
    return replace(base, **changes)


def built(inputs: assemble.Collected | None = None) -> dict[str, dict]:
    return {s["key"]: s for s in assemble.surfaces(inputs or collected())}


def values(surface: dict) -> dict[str, object]:
    """A surface's values as plain values, or Unavailable for those that are not."""
    return {
        name: (
            entry["value"] if entry["availability"] == "available" else Unavailable(entry["reason"])
        )
        for name, entry in surface["values"].items()
    }


M5_FIXTURE = r.load("m5-laptop")
ELEVATED_RECORDS = [c for c in M5_FIXTURE["commands"] if c["id"][0] in "XPS"]


def report(
    inputs: assemble.Collected,
    elevation: dict | None = None,
    elevated_records: list[dict] | None = None,
) -> dict:
    records = [
        {
            "id": cid,
            "runs": 1,
            "failed_runs": int(assemble.failed_run(cid, inputs.results[cid])),
            "duration_ms": 20,
        }
        for cid in USER_IDS
    ]
    return model.document(
        tool=M5_FIXTURE["tool"],
        collected_at=inputs.collected_at,
        time_zone="America/Los_Angeles",
        validated=True,
        elevation=elevation or M5_FIXTURE["elevation"],
        surfaces=assemble.surfaces(inputs),
        commands=records + (ELEVATED_RECORDS if elevated_records is None else elevated_records),
        paper="letter",
    )


# --- the M5, surface by surface -------------------------------------------------------------

M5_VALUES = {
    "os_version": {"product_name": "macOS", "product_version": "26.6.2", "build_version": "25G83"},
    "hardware_overview": {
        "machine_name": "MacBook Pro",
        "machine_model": "Mac17,2",
        "model_number": "MDE34LL/A",
        "chip_type": "Apple M5",
        "physical_memory_text": "24 GB",
        "serial_last4": "K7Q2",
        "activation_lock_enabled": True,
    },
    "firmware_and_boot": {"boot_rom_version": "18000.161.10", "os_loader_version": "18000.161.10"},
    "nvme_devices": {
        "entry_count": 1,
        "bsd_name": "disk0",
        "device_model": "APPLE SSD AP1024Z",
        "device_revision": "2973.120",
        "size_text": "1 TB",
        "size_bytes": 1000555581440,
        "smart_status": "Verified",
        "trim_support": True,
    },
    "gpu_configuration": {"core_count": 10, "metal_family": "Metal 4"},
    "memory_configuration": {
        "memory_type": "LPDDR5",
        "manufacturer": "Micron",
        "size_text": "24 GB",
    },
    "battery_health": {
        "condition": "Good",
        "maximum_capacity_percent": 99,
        "cycle_count": 58,
        "state_of_charge_percent": 100,
        "fully_charged": True,
        "is_charging": False,
        "charger_connected": False,
        "gauge_device_name": "bq40z651",
        "gauge_firmware_version": "0b00",
        "gauge_hardware_revision": "0100",
    },
    "battery_gauge": {
        "cycle_count": 58,
        "design_cycle_count": 1000,
        "design_capacity_mah": 6249,
        "full_charge_capacity_mah": 5910,
        "temperature_centi_c": 3029,
        "temperature_c": "30.29",
        "permanent_failure": False,
    },
    "thermal_warning_level": {"thermal_warning_recorded": False},
    "memory_pressure": {"free_percent": 63},
    "startup_disk": {
        "physical_store_count": 1,
        "physical_store": "disk0s2",
        "whole_disk": "disk0",
        "internal": True,
        "solid_state": True,
    },
    "sip_status": {"enabled": True},
    "gatekeeper_status": {"assessments_enabled": True},
    "filevault_status": {"enabled": True},
    "kernel_and_platform": {
        "hw_model": "Mac17,2",
        "hw_target": "J704AP",
        "memory_bytes": 25769803776,
        "cpu_count": 10,
        "cpu_brand": "Apple M5",
        "arm64": True,
        "perf_level_count": 2,
        "perf_level_names": ["Super", "Efficiency"],
        "perf_level_physical_cpus": [4, 6],
    },
    "virtualization_state": {"vmm_present": False},
    "boot_time": {
        "boot_epoch_seconds": 1787929257,
        "boot_time_utc": "2026-08-28T15:00:57Z",
        "days_since_boot": 28,
    },
    "smart_health_snapshot": {
        "critical_warning_byte": 0,
        "spare_below_threshold": False,
        "temperature_warning": False,
        "reliability_degraded": False,
        "read_only_mode": False,
        "volatile_backup_failed": False,
        "unknown_warning_bits": False,
        "composite_temperature_k": 330,
        "composite_temperature_c": 57,  # 56.85, half up
        "available_spare_percent": 100,
        "available_spare_threshold_percent": 99,
    },
    "smart_wear_attributes": {
        "percentage_used": 1,
        "data_units_read": "45102746",
        "data_units_written": "28928900",
        "bytes_read": "23092605952000",
        "bytes_written": "14811596800000",
        "power_cycles": "152",
        "power_on_hours": "454",
        "unsafe_shutdowns": "5",
        "media_errors": "0",
        "error_log_entries": "0",
    },
    "panic_report_count": {"count": 0},
    "memory_error_ledger": LEDGER,
    "power_and_thermal_samples": {
        "sample_count": 5,
        "sample_elapsed_ns": SAMPLE_E["sample_elapsed_ns"],
        "sample_thermal_pressure": ["Nominal"] * 5,
        "sample_cpu_power_mw": ["2675.49", "2513.54", "1641.05", "566.227", "665.099"],
        "sample_gpu_power_mw": ["50.6685", "50.4092", "60.4857", "55.338", "54.3543"],
        "sample_ane_power_mw": ["0.0"] * 5,
        "sample_combined_power_mw": ["2726.16", "2563.95", "1701.53", "621.565", "719.453"],
        "thermal_nominal_count": 5,
        "thermal_moderate_count": 0,
        "thermal_heavy_count": 0,
        "thermal_trapping_count": 0,
        "thermal_sleeping_count": 0,
        "cpu_power_mw_min": "566.227",
        "cpu_power_mw_max": "2675.49",
        "cpu_power_mw_mean": "1612.28",
        "gpu_power_mw_min": "50.4092",
        "gpu_power_mw_max": "60.4857",
        "gpu_power_mw_mean": "54.25",
        "ane_power_mw_min": "0.0",
        "ane_power_mw_max": "0.0",
        "ane_power_mw_mean": "0.0",
        "combined_power_mw_min": "621.565",
        "combined_power_mw_max": "2726.16",
        "combined_power_mw_mean": "1666.53",
    },
}


@pytest.mark.parametrize("key", list(M5_VALUES))
def test_the_m5_capture_builds_each_surface(key):
    surface = built()[key]
    assert surface["availability"] == "available"
    assert values(surface) == M5_VALUES[key]


def test_the_ecc_statement_is_the_fixed_unsupported_one():
    surface = built()["ecc_ras_telemetry"]
    assert (surface["availability"], surface["reason"]) == ("unavailable", "unsupported")


def test_the_surfaces_come_in_registry_order():
    assert [s["key"] for s in assemble.surfaces(collected())] == [
        spec.key for spec in registry.SURFACES
    ]


def test_the_m5_report_validates_and_is_complete():
    document = report(collected())
    v.validate(document)
    assert document["collection"] == {
        "status": "complete",
        "read": 22,
        "skipped": 0,
        "unavailable": 1,
        "not_applicable": 0,
        "unexpected_reasons": [],
    }
    assert not model.unexpected(document)


# --- the serial -------------------------------------------------------------------------------


def _c2(serial: object) -> spawn.Result:
    document = json.loads((M5 / "C2.out").read_text())
    document["SPHardwareDataType"][0]["serial_number"] = serial
    return ran("C2", json.dumps(document))


def test_the_serial_is_its_last_four_unless_shown():
    assert "serial_number" not in built()["hardware_overview"]["values"]
    shown = built(collected(show_serial=True))["hardware_overview"]
    assert values(shown)["serial_number"] == "C02XK1ZQK7Q2"
    assert values(shown)["serial_last4"] == "K7Q2"
    v.validate(report(collected(show_serial=True)))


@pytest.mark.parametrize("serial", [7, "", "K7Q", None])
def test_a_serial_that_cannot_give_four_characters_is_source_changed(serial):
    for shown in (False, True):
        inputs = collected(results=m5_results(C2=_c2(serial)), show_serial=shown)
        found = values(built(inputs)["hardware_overview"])
        assert found["serial_last4"] == Unavailable("source_changed")
        if shown:
            assert found["serial_number"] == Unavailable("source_changed")
        v.validate(report(inputs))


# --- failed commands --------------------------------------------------------------------------

ENDINGS = [
    (ended("X", spawn.Ending.DEADLINE), "timeout"),
    (ended("X", spawn.Ending.NOT_STARTED, missing=True), "source_absent"),
    (ended("X", spawn.Ending.NOT_STARTED), "tool_error"),
    (ended("X", spawn.Ending.OUTPUT_CAP), "source_changed"),
    (ended("X", spawn.Ending.SIGNALED), "tool_error"),
    (ran("X", "", 1), "tool_error"),
]
FEEDS = {
    "C1": ("os_version",),
    "C2": ("hardware_overview", "firmware_and_boot"),
    "C4": ("gpu_configuration",),
    "C5": ("memory_configuration",),
    "C6": ("battery_health",),
    "C7": ("battery_gauge",),
    "C8": ("thermal_warning_level",),
    "C9": ("memory_pressure",),
    "C12": ("sip_status",),
    "C13": ("gatekeeper_status",),
    "C14": ("filevault_status",),
    "C26": ("virtualization_state",),
    "C27": ("boot_time",),
}


@pytest.mark.parametrize("command_id", list(FEEDS))
@pytest.mark.parametrize(
    ("failure", "reason"),
    ENDINGS,
    ids=["deadline", "missing", "failed start", "output cap", "signal", "exit 1"],
)
def test_a_failed_command_gives_every_surface_it_feeds_its_reason(command_id, failure, reason):
    inputs = collected(results=m5_results(**{command_id: replace(failure, command_id=command_id)}))
    surfaces = built(inputs)
    for key in FEEDS[command_id]:
        assert (surfaces[key]["availability"], surfaces[key]["reason"]) == ("unavailable", reason)
    assert assemble.failed_run(command_id, inputs.results[command_id])
    v.validate(report(inputs))


@pytest.mark.parametrize("command_id", list(FEEDS))
def test_output_in_another_shape_is_source_changed_without_a_failed_run(command_id):
    inputs = collected(results=m5_results(**{command_id: ran(command_id, "\x00 unexpected\n")}))
    for key in FEEDS[command_id]:
        surface = built(inputs)[key]
        assert (surface["availability"], surface["reason"]) == ("unavailable", "source_changed")
    assert not assemble.failed_run(command_id, inputs.results[command_id])
    v.validate(report(inputs))


def test_gatekeeper_switched_off_is_read_as_off_with_no_failed_run():
    # Change record 11 (MAC 4.1's review, M2): spctl --status prints "assessments disabled"
    # and exits 1 with Gatekeeper off, which is its read of the setting, not a failure.
    inputs = collected(results=m5_results(C13=ran("C13", "assessments disabled\n", 1)))
    assert values(built(inputs)["gatekeeper_status"]) == {"assessments_enabled": False}
    assert not assemble.failed_run("C13", inputs.results["C13"])
    document = report(inputs)
    v.validate(document)
    assert document["collection"]["unexpected_reasons"] == []


def test_a_surface_whose_fields_are_all_unreadable_collapses_to_source_changed():
    inputs = collected(results=m5_results(C1=ran("C1", "ProductName:\n")))
    surface = built(inputs)["os_version"]
    assert (surface["availability"], surface["reason"]) == ("unavailable", "source_changed")


def test_a_field_with_a_control_or_bidirectional_character_is_source_changed():
    text = (M5 / "C1.out").read_text().replace("macOS", "mac\u202eOS")
    found = values(built(collected(results=m5_results(C1=ran("C1", text))))["os_version"])
    assert found["product_name"] == Unavailable("source_changed")
    assert found["product_version"] == "26.6.2"


def test_a_value_outside_its_range_is_source_changed():
    text = (M5 / "C9.out").read_text().replace("63%", "101%")
    inputs = collected(results=m5_results(C9=ran("C9", text)))
    surface = built(inputs)["memory_pressure"]
    assert (surface["availability"], surface["reason"]) == ("unavailable", "source_changed")
    v.validate(report(inputs))


# --- the batteries ----------------------------------------------------------------------------

NO_BATTERY_C6 = json.dumps({"SPPowerDataType": [{"_name": "sppower_ac_charger_information"}]})


def test_a_desktop_has_both_battery_surfaces_not_applicable():
    inputs = collected(results=m5_results(C6=ran("C6", NO_BATTERY_C6), C7=ran("C7", "")))
    surfaces = built(inputs)
    for key in ("battery_health", "battery_gauge"):
        assert (surfaces[key]["availability"], surfaces[key]["values"]) == ("not_applicable", {})
    document = report(inputs)
    v.validate(document)
    assert (document["collection"]["status"], document["collection"]["not_applicable"]) == (
        "complete",
        2,
    )


def test_two_battery_sources_that_disagree_leave_the_no_battery_one_source_changed():
    inputs = collected(results=m5_results(C6=ran("C6", NO_BATTERY_C6)))
    surfaces = built(inputs)
    assert surfaces["battery_health"]["reason"] == "source_changed"
    assert surfaces["battery_gauge"]["availability"] == "available"
    v.validate(report(inputs))


def test_one_battery_command_failed_beside_one_that_found_no_battery():
    # The domains table makes the pair not applicable only together, so the one that found
    # no battery cannot stand alone and reads as source_changed; an owner ruling on this
    # case is pending (the #342 review, minor 2).
    inputs = collected(results=m5_results(C6=ended("C6", spawn.Ending.DEADLINE), C7=ran("C7", "")))
    surfaces = built(inputs)
    assert surfaces["battery_health"]["reason"] == "timeout"
    assert surfaces["battery_gauge"]["reason"] == "source_changed"
    v.validate(report(inputs))


def test_the_battery_temperature_follows_its_reading():
    gauge = plistlib.loads((M5 / "C7.out").read_bytes())
    gauge[0]["Temperature"] = 12000  # above 100.00 degrees
    inputs = collected(results=m5_results(C7=ran("C7", plistlib.dumps(gauge).decode())))
    found = values(built(inputs)["battery_gauge"])
    assert found["temperature_centi_c"] == found["temperature_c"] == Unavailable("source_changed")
    gauge[0]["Temperature"] = -1234
    inputs = collected(results=m5_results(C7=ran("C7", plistlib.dumps(gauge).decode())))
    assert values(built(inputs)["battery_gauge"])["temperature_c"] == "-12.34"
    v.validate(report(inputs))


# --- the thermal warning ---------------------------------------------------------------------


def test_a_recorded_thermal_warning_carries_its_level():
    text = "2026-09-26 09:14:03 -0700 Thermal Warning Level = 70\n"
    inputs = collected(results=m5_results(C8=ran("C8", text)))
    assert values(built(inputs)["thermal_warning_level"]) == {
        "thermal_warning_recorded": True,
        "thermal_warning_level": 70,
    }
    v.validate(report(inputs))


# --- the kernel values ------------------------------------------------------------------------


def _kernel(inputs: assemble.Collected) -> dict[str, object] | Unavailable:
    surface = built(inputs)["kernel_and_platform"]
    if surface["availability"] == "unavailable":
        return Unavailable(surface["reason"])
    return values(surface)


def test_a_sysctl_that_timed_out_costs_only_its_own_value():
    inputs = collected(results=m5_results(C17=ended("C17", spawn.Ending.DEADLINE)))
    found = _kernel(inputs)
    assert found["memory_bytes"] == Unavailable("timeout")
    assert found["cpu_count"] == 10
    v.validate(report(inputs))


def test_a_missing_sysctl_is_source_absent_on_its_value():
    inputs = collected(results=m5_results(C18=ended("C18", spawn.Ending.NOT_STARTED, missing=True)))
    assert _kernel(inputs)["cpu_count"] == Unavailable("source_absent")
    v.validate(report(inputs))


def test_one_performance_level_uses_level_0_and_lets_c24_and_c25_fail():
    inputs = collected(
        results=m5_results(C21=ran("C21", "1\n"), C24=ran("C24", "", 1), C25=ran("C25", "", 1))
    )
    found = _kernel(inputs)
    assert (found["perf_level_count"], found["perf_level_names"]) == (1, ["Super"])
    assert found["perf_level_physical_cpus"] == [4]
    assert assemble.failed_run("C24", inputs.results["C24"])
    document = report(inputs)
    v.validate(document)
    assert document["collection"]["status"] == "complete"


def test_more_than_two_levels_make_all_three_keys_source_changed():
    inputs = collected(results=m5_results(C21=ran("C21", "3\n")))
    found = _kernel(inputs)
    for name in ("perf_level_count", "perf_level_names", "perf_level_physical_cpus"):
        assert found[name] == Unavailable("source_changed"), name
    v.validate(report(inputs))


def test_a_failed_c22_beside_an_available_count():
    inputs = collected(results=m5_results(C22=ran("C22", "", 1)))
    found = _kernel(inputs)
    assert found["perf_level_names"] == Unavailable("tool_error")
    assert found["perf_level_physical_cpus"] == [4, 6]
    v.validate(report(inputs))


def test_the_second_levels_own_failure_names_its_reason():
    inputs = collected(results=m5_results(C25=ended("C25", spawn.Ending.DEADLINE)))
    assert _kernel(inputs)["perf_level_physical_cpus"] == Unavailable("timeout")
    v.validate(report(inputs))


def test_an_unavailable_count_passes_its_reason_to_both_arrays():
    inputs = collected(results=m5_results(C21=ended("C21", spawn.Ending.DEADLINE)))
    found = _kernel(inputs)
    assert found["perf_level_count"] == found["perf_level_names"] == Unavailable("timeout")
    assert found["perf_level_physical_cpus"] == Unavailable("timeout")
    v.validate(report(inputs))


def test_every_sysctl_failing_collapses_to_the_first_values_reason():
    failures = {f"C{n}": ended(f"C{n}", spawn.Ending.DEADLINE) for n in range(15, 26)}
    failures["C15"] = ran("C15", "", 1)
    inputs = collected(results=m5_results(**failures))
    assert _kernel(inputs) == Unavailable("tool_error")
    v.validate(report(inputs))


# --- the boot time ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "epoch", [946684799, int(COLLECTED_AT.timestamp()) + 1], ids=["before 2000", "after now"]
)
def test_a_boot_epoch_outside_its_range_costs_the_dates_too(epoch):
    text = f"{{ sec = {epoch}, usec = 0 }} Sat Jan  1 00:00:00 2000\n"
    inputs = collected(results=m5_results(C27=ran("C27", text)))
    surface = built(inputs)["boot_time"]
    assert (surface["availability"], surface["reason"]) == ("unavailable", "source_changed")
    v.validate(report(inputs))


def test_a_boot_at_the_collection_instant_is_zero_days_ago():
    epoch = int(COLLECTED_AT.timestamp())
    text = f"{{ sec = {epoch}, usec = 0 }} Sat Sep 26 12:00:00 2026\n"
    inputs = collected(results=m5_results(C27=ran("C27", text)))
    assert values(built(inputs)["boot_time"])["days_since_boot"] == 0


# --- storage and SMART ------------------------------------------------------------------------


def test_the_smart_computed_values_follow_their_readings():
    raw = bytearray(bytes.fromhex(LOG_HEX))
    raw[1:3] = (401).to_bytes(2, "little")
    inputs = collected(results=m5_results(C28=ran("C28", smart_document(bytes(raw).hex()))))
    found = values(built(inputs)["smart_health_snapshot"])
    assert found["composite_temperature_k"] == Unavailable("source_changed")
    assert found["composite_temperature_c"] == Unavailable("source_changed")
    v.validate(report(inputs))


def test_a_failed_c11_closes_storage_and_validates():
    inputs = collected(results=m5_results(C11=ended("C11", spawn.Ending.DEADLINE)))
    surfaces = built(inputs)
    assert surfaces["startup_disk"]["reason"] == "timeout"
    assert surfaces["smart_health_snapshot"]["reason"] == "timeout"
    assert values(surfaces["nvme_devices"])["bsd_name"] == Unavailable("timeout")
    v.validate(report(inputs))


def test_a_failed_c28_is_a_failed_run_and_validates():
    inputs = collected(results=m5_results(C28=ended("C28", spawn.Ending.DEADLINE)))
    assert built(inputs)["smart_wear_attributes"]["reason"] == "timeout"
    assert assemble.failed_run("C28", inputs.results["C28"])
    v.validate(report(inputs))


def test_c28s_rows_8_to_12_are_not_failed_runs():
    other = json.dumps(
        {
            "schema": "voltry-mac-smart/0",
            "controllers": [
                {"location": "External", "media": ["disk4"], "status": "ok", "smart_hex": LOG_HEX}
            ],
        }
    )
    inputs = collected(results=m5_results(C28=ran("C28", other)))
    assert built(inputs)["smart_health_snapshot"]["reason"] == "source_absent"
    assert not assemble.failed_run("C28", inputs.results["C28"])
    v.validate(report(inputs))


# --- the panic count --------------------------------------------------------------------------


def test_the_panic_count_or_why_it_was_not_read():
    assert values(built(collected(panic=3))["panic_report_count"]) == {"count": 3}
    surface = built(collected(panic=Unavailable("no_admin")))["panic_report_count"]
    assert (surface["availability"], surface["reason"]) == ("unavailable", "no_admin")
    v.validate(report(collected(panic=Unavailable("no_admin"))))


def test_a_panic_count_no_report_can_hold_is_a_tool_error():
    surface = built(collected(panic=100001))["panic_report_count"]
    assert (surface["availability"], surface["reason"]) == ("unavailable", "tool_error")


# --- the elevated surfaces --------------------------------------------------------------------

DECLINED = assemble.Elevated(reason="declined", detail="not_attempted")


def test_a_declined_run_gives_both_elevated_surfaces_their_reason_and_detail():
    inputs = collected(ledger=DECLINED, power=DECLINED)
    surfaces = built(inputs)
    for key in ("memory_error_ledger", "power_and_thermal_samples"):
        surface = surfaces[key]
        assert (surface["reason"], surface["detail"]) == ("declined", "not_attempted")
    document = report(inputs, r.declined_record(), elevated_records=[])
    v.validate(document)
    assert document["collection"]["status"] == "partial"
    assert document["collection"]["skipped"] == 2
    assert not model.unexpected(document)


def test_an_unreadable_ledger_field_costs_only_that_value():
    ledger = {**LEDGER, "uncorrectable_reported_count": UNREAD}
    found = values(built(collected(ledger=assemble.Elevated(values=ledger)))["memory_error_ledger"])
    assert found["uncorrectable_reported_count"] == Unavailable("source_changed")
    assert found["correctable_event_rows"] == 0


def test_elevated_values_that_all_failed_are_the_brokers_to_classify():
    ledger = dict.fromkeys(LEDGER, UNREAD)
    with pytest.raises(ValueError):
        assemble.surfaces(collected(ledger=assemble.Elevated(values=ledger)))
    with pytest.raises(ValueError):
        assemble.Elevated(values=LEDGER, reason="declined", detail="not_attempted")
    with pytest.raises(ValueError):
        assemble.Elevated()


def _power(**series: list[object]) -> dict[str, object]:
    inputs = collected(power=assemble.Elevated(values={**SAMPLE_E, **series}))
    return values(built(inputs)["power_and_thermal_samples"])


def test_a_missing_gpu_sample_costs_the_series_and_its_statistics_only():
    gpu = [*SAMPLE_E["sample_gpu_power_mw"][:4], UNREAD]
    found = _power(sample_gpu_power_mw=gpu)
    for name in (
        "sample_gpu_power_mw",
        "gpu_power_mw_min",
        "gpu_power_mw_max",
        "gpu_power_mw_mean",
    ):
        assert found[name] == Unavailable("source_changed"), name
    assert found["cpu_power_mw_mean"] == "1612.28"
    inputs = collected(power=assemble.Elevated(values={**SAMPLE_E, "sample_gpu_power_mw": gpu}))
    document = report(inputs)
    v.validate(document)
    assert document["collection"]["status"] == "partial" and model.unexpected(document)


@pytest.mark.parametrize(
    "states",
    [["Nominal"] * 4 + [UNREAD], ["Nominal"] * 4 + ["Hot"]],
    ids=["a missing state", "a state outside the five"],
)
def test_a_thermal_series_that_did_not_read_costs_its_five_counts(states):
    found = _power(sample_thermal_pressure=states)
    assert found["sample_thermal_pressure"] == Unavailable("source_changed")
    for state in ("nominal", "moderate", "heavy", "trapping", "sleeping"):
        assert found[f"thermal_{state}_count"] == Unavailable("source_changed")


def test_the_thermal_counts_tally_the_states():
    found = _power(sample_thermal_pressure=["Heavy", "Nominal", "Heavy", "Nominal", "Heavy"])
    assert (found["thermal_heavy_count"], found["thermal_nominal_count"]) == (3, 2)
    assert found["thermal_moderate_count"] == 0


def test_a_sample_outside_its_range_costs_its_series():
    found = _power(sample_cpu_power_mw=decimals("1000000.01", "1", "1", "1", "1"))
    assert found["sample_cpu_power_mw"] == Unavailable("source_changed")
    assert found["cpu_power_mw_max"] == Unavailable("source_changed")
    found = _power(sample_elapsed_ns=[1_000_000_000] * 4 + [499_999_999])
    assert found["sample_elapsed_ns"] == Unavailable("source_changed")


def test_the_means_round_half_up_to_two_places_and_the_extremes_keep_their_digits():
    found = _power(sample_cpu_power_mw=decimals("1", "2", "2", "2", "1.025"))
    assert (found["cpu_power_mw_mean"], found["cpu_power_mw_min"]) == ("1.61", "1.0")
    found = _power(sample_cpu_power_mw=decimals("1.00", "1.0", "1", "1.000", "1.0"))
    assert found["cpu_power_mw_max"] == "1.0"


def test_a_power_series_needs_exactly_five_samples():
    with pytest.raises(ValueError):
        assemble.surfaces(
            collected(
                power=assemble.Elevated(
                    values={**SAMPLE_E, "sample_cpu_power_mw": SAMPLE_E["sample_cpu_power_mw"][:4]}
                )
            )
        )


# --- failed runs ------------------------------------------------------------------------------


def test_a_user_commands_failed_run_follows_how_it_ended():
    assert not assemble.failed_run("C1", ran("C1", "anything"))
    assert assemble.failed_run("C1", ran("C1", "", 1))
    assert assemble.failed_run("C9", ended("C9", spawn.Ending.DEADLINE))
    assert assemble.failed_run("C28", ran("C28", "{", 0)), "C28's row 6"
    assert not assemble.failed_run("C28", ran("C28", smart_document()))


def test_a_float_never_becomes_a_value():
    ledger = {**LEDGER, "correctable_event_rows": 0.5}
    with pytest.raises(ValueError):
        assemble.surfaces(collected(ledger=assemble.Elevated(values=ledger)))


# --- honesty (Test strategy part 3, "Honesty"), at the model --------------------------------


def test_every_value_carries_the_registrys_provenance():
    document = report(collected())
    for surface in document["surfaces"]:
        spec = registry.BY_KEY[surface["key"]]
        provenance = {value.name: value.provenance for value in spec.values}
        for name, entry in surface["values"].items():
            if entry["availability"] == "available":
                assert entry["provenance"] == provenance[name], (surface["key"], name)


def test_decision_6s_provenance_classes():
    def provenance(surface: str, name: str) -> str:
        return next(v.provenance for v in registry.BY_KEY[surface].values if v.name == name)

    # A count Voltry takes itself, a range or an average, a conversion emitted as its own
    # key: derived.
    derived = [
        ("nvme_devices", "entry_count"),
        ("startup_disk", "physical_store_count"),
        ("startup_disk", "whole_disk"),
        ("panic_report_count", "count"),
        ("power_and_thermal_samples", "sample_count"),
        ("power_and_thermal_samples", "thermal_heavy_count"),
        ("power_and_thermal_samples", "cpu_power_mw_mean"),
        ("power_and_thermal_samples", "gpu_power_mw_min"),
        ("smart_health_snapshot", "composite_temperature_c"),
        ("smart_wear_attributes", "bytes_written"),
        ("battery_gauge", "temperature_c"),
        ("boot_time", "boot_time_utc"),
        ("boot_time", "days_since_boot"),
    ]
    # A source-returned operational counter: measured.
    measured = [
        ("battery_health", "cycle_count"),
        ("battery_gauge", "cycle_count"),
        ("smart_wear_attributes", "power_on_hours"),
        ("smart_wear_attributes", "data_units_written"),
        ("smart_wear_attributes", "media_errors"),
        ("memory_error_ledger", "uncorrectable_reported_count"),
    ]
    # A configuration or design count: reported.
    reported = [
        ("battery_gauge", "design_cycle_count"),
        ("gpu_configuration", "core_count"),
        ("kernel_and_platform", "cpu_count"),
        ("kernel_and_platform", "perf_level_count"),
        ("kernel_and_platform", "perf_level_physical_cpus"),
    ]
    for label, keys in (("derived", derived), ("measured", measured), ("reported", reported)):
        for surface, name in keys:
            assert provenance(surface, name) == label, (surface, name)


@pytest.mark.parametrize(
    ("inputs", "code"),
    [
        (collected(), 0),
        (collected(ledger=DECLINED, power=DECLINED), 0),
        (
            collected(results=m5_results(C6=ran("C6", NO_BATTERY_C6), C7=ran("C7", ""))),
            0,
        ),
        (
            collected(
                power=assemble.Elevated(
                    values={
                        **SAMPLE_E,
                        "sample_gpu_power_mw": [*SAMPLE_E["sample_gpu_power_mw"][:4], UNREAD],
                    }
                )
            ),
            1,
        ),
    ],
    ids=["complete", "declined", "a desktop", "GPU power missing"],
)
def test_the_exit_code_of_each_honest_outcome(inputs, code):
    declined = inputs.ledger == DECLINED
    document = report(
        inputs,
        r.declined_record() if declined else None,
        elevated_records=[] if declined else None,
    )
    v.validate(document)
    assert model.exit_code(unexpected=model.unexpected(document)) == code


# --- the #345 review --------------------------------------------------------------------------

POWER_OUT_OF_RANGE: dict[str, list[object]] = {
    "sample_elapsed_ns": [1] * 5,
    "sample_thermal_pressure": ["Hot"] * 5,
    **{
        f"sample_{kind}_power_mw": decimals(*["2000000"] * 5)
        for kind in ("cpu", "gpu", "ane", "combined")
    },
}


@pytest.mark.parametrize(
    "series",
    [dict.fromkeys(SAMPLE_E, [UNREAD] * 5), POWER_OUT_OF_RANGE],
    ids=["every sample unread", "every sample out of range"],
)
def test_a_power_output_in_which_every_series_failed_is_the_brokers_unparsed(series):
    with pytest.raises(assemble.Unreadable, match="unparsed"):
        assemble.surfaces(collected(power=assemble.Elevated(values=series)))
    assert not assemble.readable("power_and_thermal_samples", series)


@pytest.mark.parametrize(
    "ledger",
    [dict.fromkeys(LEDGER, UNREAD), dict.fromkeys(LEDGER, 10**9 + 1)],
    ids=["every count unread", "every count out of range"],
)
def test_a_ledger_in_which_every_count_failed_is_the_brokers_unparsed(ledger):
    with pytest.raises(assemble.Unreadable, match="unparsed"):
        assemble.surfaces(collected(ledger=assemble.Elevated(values=ledger)))
    assert not assemble.readable("memory_error_ledger", ledger)


def test_values_with_one_readable_series_or_count_are_readable():
    assert assemble.readable("power_and_thermal_samples", SAMPLE_E)
    one_series = {**POWER_OUT_OF_RANGE, "sample_elapsed_ns": SAMPLE_E["sample_elapsed_ns"]}
    assert assemble.readable("power_and_thermal_samples", one_series)
    v.validate(report(collected(power=assemble.Elevated(values=one_series))))
    one_count = {**dict.fromkeys(LEDGER, UNREAD), "correctable_event_rows": 0}
    assert assemble.readable("memory_error_ledger", one_count)


@pytest.mark.parametrize(
    "value",
    [True, "3", Decimal("3"), 0.5, None, [1], {"a": 1}, Unavailable("timeout")],
    ids=["a bool", "digits", "a decimal", "a float", "None", "a list", "a dict", "an Unavailable"],
)
def test_a_ledger_count_of_another_type_is_refused(value):
    ledger = {**LEDGER, "correctable_event_rows": value}
    with pytest.raises(ValueError) as problem:
        assemble.surfaces(collected(ledger=assemble.Elevated(values=ledger)))
    assert not isinstance(problem.value, assemble.Unreadable), "a wrong type is no unparsed"


@pytest.mark.parametrize(
    ("name", "element"),
    [
        ("sample_thermal_pressure", 1),
        ("sample_thermal_pressure", Unavailable("timeout")),
        ("sample_cpu_power_mw", Decimal("NaN")),
        ("sample_cpu_power_mw", Decimal("Infinity")),
        ("sample_cpu_power_mw", 1),
        ("sample_cpu_power_mw", "1.0"),
        ("sample_cpu_power_mw", None),
        ("sample_elapsed_ns", Decimal("1000000000")),
        ("sample_elapsed_ns", True),
    ],
)
def test_a_power_sample_of_another_type_is_refused(name, element):
    series = [*SAMPLE_E[name][:4], element]
    with pytest.raises(ValueError) as problem:
        assemble.surfaces(collected(power=assemble.Elevated(values={**SAMPLE_E, name: series})))
    assert not isinstance(problem.value, assemble.Unreadable)


def test_a_series_is_a_list_not_text():
    power = {**SAMPLE_E, "sample_thermal_pressure": "Heavy"}
    with pytest.raises(ValueError):
        assemble.surfaces(collected(power=assemble.Elevated(values=power)))


def test_elevated_values_need_exactly_the_registrys_keys():
    short = {name: value for name, value in LEDGER.items() if name != "correctable_event_rows"}
    for ledger in (short, {**LEDGER, "note": 0}):
        with pytest.raises(ValueError):
            assemble.surfaces(collected(ledger=assemble.Elevated(values=ledger)))
    short_power = {name: value for name, value in SAMPLE_E.items() if name != "sample_ane_power_mw"}
    for power in (short_power, {**SAMPLE_E, "note": [0] * 5}):
        with pytest.raises(ValueError):
            assemble.surfaces(collected(power=assemble.Elevated(values=power)))


@pytest.mark.parametrize(
    ("value", "fits"),
    [
        ("", False),
        ("m" * 256, True),
        ("m" * 257, False),
        ("Mac" + chr(0x202E) + "Book", False),
        ("Mac" + chr(0x2028) + "Book", False),
        ("Mac" + chr(0x85) + "Book", False),
        ("Mac" + chr(0xD800) + "Book", False),
    ],
    ids=[
        "empty",
        "256 characters",
        "257 characters",
        "a bidirectional override",
        "a line separator",
        "a C1 control",
        "a lone surrogate",
    ],
)
def test_the_model_checks_every_string_itself(value, fits):
    # The parsers check these too; the model does not rely on them.
    assert assemble._fit("machine_name", value) == (
        value if fits else Unavailable("source_changed")
    )


def test_a_string_outside_its_grammar_is_source_changed():
    assert assemble._fit("whole_disk", "disk0") == "disk0"
    assert assemble._fit("whole_disk", "disk0s2") == Unavailable("source_changed")


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("vmm_present", 1),
        ("vmm_present", "true"),
        ("cpu_count", True),
        ("cpu_count", "10"),
        ("cpu_count", Decimal("10")),
        ("temperature_c", 30),
        ("temperature_c", "30.0"),
        ("temperature_c", Decimal("sNaN")),
        ("machine_name", 17),
        ("machine_name", b"MacBook Pro"),
    ],
)
def test_a_value_of_another_shape_than_the_registrys_is_refused(name, value):
    with pytest.raises(ValueError):
        assemble._fit(name, value)


def test_a_wrong_type_is_a_bug_for_readable_too_not_unparsed():
    with pytest.raises(ValueError) as problem:
        assemble.readable("memory_error_ledger", {**LEDGER, "correctable_event_rows": True})
    assert not isinstance(problem.value, assemble.Unreadable)


def test_a_name_the_registry_does_not_have_is_refused():
    with pytest.raises(ValueError):
        assemble._fit("x", "any text")


def test_both_levels_failing_give_the_first_levels_reason():
    inputs = collected(
        results=m5_results(C22=ended("C22", spawn.Ending.DEADLINE), C24=ran("C24", "", 1))
    )
    assert _kernel(inputs)["perf_level_names"] == Unavailable("timeout")
    v.validate(report(inputs))


def test_a_four_character_serial_is_its_own_last_four():
    inputs = collected(results=m5_results(C2=_c2("K7Q2")), show_serial=True)
    found = values(built(inputs)["hardware_overview"])
    assert (found["serial_last4"], found["serial_number"]) == ("K7Q2", "K7Q2")
    v.validate(report(inputs))


def test_a_boot_on_the_first_second_of_2000_is_in_range():
    text = "{ sec = 946684800, usec = 0 } Sat Jan  1 00:00:00 2000\n"
    found = values(built(collected(results=m5_results(C27=ran("C27", text))))["boot_time"])
    assert (found["boot_epoch_seconds"], found["boot_time_utc"]) == (
        946684800,
        "2000-01-01T00:00:00Z",
    )


@pytest.mark.parametrize(
    ("ago", "days"), [(3 * 86400, 3), (3 * 86400 - 1, 2), (86400, 1), (86399, 0)]
)
def test_the_day_count_is_whole_days(ago, days):
    epoch = int(COLLECTED_AT.timestamp()) - ago
    text = f"{{ sec = {epoch}, usec = 0 }} Wed Sep 23 12:00:00 2026\n"
    inputs = collected(results=m5_results(C27=ran("C27", text)))
    assert values(built(inputs)["boot_time"])["days_since_boot"] == days
    v.validate(report(inputs))


def test_a_clock_a_century_after_the_boot_costs_the_boot_time():
    text = "{ sec = 946684800, usec = 0 } Sat Jan  1 00:00:00 2000\n"
    at = datetime(2100, 1, 2, tzinfo=UTC)
    inputs = collected(results=m5_results(C27=ran("C27", text)), collected_at=at)
    surface = built(inputs)["boot_time"]
    assert (surface["availability"], surface["reason"]) == ("unavailable", "source_changed")
    v.validate(report(inputs))


def test_a_fractional_collection_instant_is_the_whole_second_before_it():
    at = COLLECTED_AT.replace(microsecond=600000)
    epoch = int(COLLECTED_AT.timestamp()) + 1
    text = f"{{ sec = {epoch}, usec = 0 }} Sat Sep 26 12:00:01 2026\n"
    inputs = collected(results=m5_results(C27=ran("C27", text)), collected_at=at)
    surface = built(inputs)["boot_time"]
    assert (surface["availability"], surface["reason"]) == ("unavailable", "source_changed")
    v.validate(report(inputs))


def test_the_top_of_a_power_samples_range_is_in_range():
    found = _power(sample_cpu_power_mw=decimals("1000000.00", "1", "1", "1", "1"))
    assert found["cpu_power_mw_max"] == "1000000.0"


def _gauge(temperature: int) -> spawn.Result:
    gauge = plistlib.loads((M5 / "C7.out").read_bytes())
    gauge[0]["Temperature"] = temperature
    return ran("C7", plistlib.dumps(gauge).decode())


def test_a_battery_at_exactly_100_c_is_in_range():
    found = values(built(collected(results=m5_results(C7=_gauge(10000))))["battery_gauge"])
    assert (found["temperature_centi_c"], found["temperature_c"]) == (10000, "100.0")
    found = values(built(collected(results=m5_results(C7=_gauge(10001))))["battery_gauge"])
    assert found["temperature_c"] == Unavailable("source_changed")


@pytest.mark.parametrize(("level", "fits"), [(100, True), (101, False)])
def test_a_thermal_warning_level_above_100_is_source_changed(level, fits):
    inputs = collected(results=m5_results(C8=ran("C8", f"Thermal Warning Level = {level}\n")))
    found = values(built(inputs)["thermal_warning_level"])
    assert found["thermal_warning_level"] == (level if fits else Unavailable("source_changed"))
    v.validate(report(inputs))


def test_a_naive_collection_instant_is_refused():
    with pytest.raises(ValueError):
        collected(collected_at=datetime(2026, 9, 26, 12, 0, 0))


def test_the_document_takes_its_one_instant_from_what_was_collected():
    inputs = collected()
    records = [
        {"id": cid, "runs": 1, "failed_runs": 0, "duration_ms": 20} for cid in USER_IDS
    ] + ELEVATED_RECORDS
    document = assemble.document(
        inputs,
        tool=M5_FIXTURE["tool"],
        time_zone="America/Los_Angeles",
        validated=True,
        elevation=M5_FIXTURE["elevation"],
        commands=records,
        paper="letter",
    )
    assert document == report(inputs)
    local = collected(
        collected_at=datetime(2026, 9, 26, 5, 0, 0, tzinfo=timezone(timedelta(hours=-7)))
    )
    kwargs = {
        "tool": M5_FIXTURE["tool"],
        "time_zone": "America/Los_Angeles",
        "validated": True,
        "elevation": M5_FIXTURE["elevation"],
        "commands": records,
        "paper": "letter",
    }
    assert assemble.document(local, **kwargs) == report(local), "the local offset is kept"


# --- the #345 review, round 2 ------------------------------------------------------------------

SERIES_NAMES = [
    "sample_elapsed_ns",
    "sample_thermal_pressure",
    "sample_cpu_power_mw",
    "sample_gpu_power_mw",
    "sample_ane_power_mw",
    "sample_combined_power_mw",
]


@pytest.mark.parametrize("kept", SERIES_NAMES)
def test_any_one_series_in_its_range_keeps_the_power_output_readable(kept):
    series = {**POWER_OUT_OF_RANGE, kept: SAMPLE_E[kept]}
    assert assemble.readable("power_and_thermal_samples", series)
    document = report(collected(power=assemble.Elevated(values=series)))
    assert r.surface(document, "power_and_thermal_samples")["availability"] == "available"
    v.validate(document)


@pytest.mark.parametrize("kept", list(LEDGER))
def test_any_one_count_in_its_range_keeps_the_ledger_readable(kept):
    ledger = {**dict.fromkeys(LEDGER, 10**9 + 1), kept: 0}
    assert assemble.readable("memory_error_ledger", ledger)
    v.validate(report(collected(ledger=assemble.Elevated(values=ledger))))


@pytest.mark.parametrize(
    "value",
    [Decimal("1E-13"), Decimal("1.2345678901234"), Decimal("1234567890123456")],
    ids=["13 fractional digits", "13 fractional digits, spelled out", "16 integer digits"],
)
def test_a_decimal_the_json_cannot_spell_is_refused_by_readable_too(value):
    # numbers.source_decimal never gives one; the model refuses it before recording parsed.
    series = {**SAMPLE_E, "sample_cpu_power_mw": [*SAMPLE_E["sample_cpu_power_mw"][:4], value]}
    with pytest.raises(ValueError) as problem:
        assemble.readable("power_and_thermal_samples", series)
    assert not isinstance(problem.value, assemble.Unreadable)


def test_a_decimal_with_trailing_zeros_past_twelve_places_is_the_same_value():
    series = {
        **SAMPLE_E,
        "sample_cpu_power_mw": [*SAMPLE_E["sample_cpu_power_mw"][:4], Decimal("1.00000000000000")],
    }
    assert assemble.readable("power_and_thermal_samples", series)


@pytest.mark.parametrize("value", ["abc", "-5", str(2**128), "01", ""])
def test_a_128_bit_counter_that_is_not_its_digit_string_is_refused(value):
    with pytest.raises(ValueError):
        assemble._fit("power_on_hours", value)


@pytest.mark.parametrize("value", ["abc", "-5", "01", ""])
def test_a_byte_total_that_is_not_its_digit_string_is_refused(value):
    with pytest.raises(ValueError):
        assemble._fit("bytes_read", value)
    assert assemble._fit("bytes_read", "512000") == "512000"


def test_a_registry_that_gives_one_name_two_shapes_is_refused(monkeypatch):
    first = registry.SURFACES[0]
    twin = dataclasses.replace(first.values[0], shape="bool")
    clash = dataclasses.replace(first, key="clash", values=(twin,))
    monkeypatch.setattr(registry, "SURFACES", (*registry.SURFACES, clash))
    with pytest.raises(ValueError):
        assemble._shapes()


def test_readable_takes_only_the_two_elevated_keys():
    for key in ("power", "memory", "nvme_devices"):
        with pytest.raises(ValueError):
            assemble.readable(key, SAMPLE_E)


def test_a_series_may_be_a_tuple():
    series = {**SAMPLE_E, "sample_cpu_power_mw": tuple(SAMPLE_E["sample_cpu_power_mw"])}
    assert assemble.readable("power_and_thermal_samples", series)


@pytest.mark.parametrize(
    "fields",
    [
        {"reason": "declined"},
        {"detail": "not_attempted"},
        {"values": LEDGER, "detail": "not_attempted"},
    ],
    ids=["a reason without its detail", "a detail without its reason", "values with a detail"],
)
def test_an_elevated_surface_has_its_values_or_both_a_reason_and_a_detail(fields):
    with pytest.raises(ValueError):
        assemble.Elevated(**fields)


@pytest.mark.parametrize("size", [0, 2**60 + 1], ids=["zero", "past 2^60"])
def test_an_nvme_size_outside_its_range_is_source_changed(size):
    document = json.loads((M5 / "C3.out").read_text())
    document["SPNVMeDataType"][0]["_items"][0]["size_in_bytes"] = size
    inputs = collected(results=m5_results(C3=ran("C3", json.dumps(document))))
    assert values(built(inputs)["nvme_devices"])["size_bytes"] == Unavailable("source_changed")
    v.validate(report(inputs))


def test_every_value_name_has_one_shape_across_the_surfaces():
    shapes: dict[str, set[str]] = {}
    for surface in registry.SURFACES:
        for value in surface.values:
            shapes.setdefault(value.name, set()).add(value.shape)
    assert all(len(found) == 1 for found in shapes.values())
    assert {"size_text", "cycle_count", "enabled"} <= {
        name
        for name in shapes
        if sum(name in [v.name for v in s.values] for s in registry.SURFACES) > 1
    }
