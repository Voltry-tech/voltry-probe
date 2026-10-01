"""The surface registry (docs/VOLTRY_MAC_SPEC.md, Decision 8, "Surface registry, normative").

The validator carries the registry verbatim: every surface's fixed attributes and value
keys, the availability domains, the value reasons, the ranges and the string grammars.
This file pins all of it from an independent transcription; tests/ci in the core
repository also parses the spec's own table and compares it with the module.
"""

from __future__ import annotations

import dataclasses

import pytest

from voltry_mac import registry as r

SURFACES = [
    (1, "os_version", "sw_vers (C1)", "user", "provenance"),
    (2, "hardware_overview", "system_profiler SPHardwareDataType (C2)", "user", "identity"),
    (3, "firmware_and_boot", "C2, the same run", "user", "provenance"),
    (4, "nvme_devices", "system_profiler SPNVMeDataType (C3)", "user", "instant"),
    (5, "gpu_configuration", "system_profiler SPDisplaysDataType (C4)", "user", "identity"),
    (6, "memory_configuration", "system_profiler SPMemoryDataType (C5)", "user", "identity"),
    (7, "battery_health", "system_profiler SPPowerDataType (C6)", "user", "instant"),
    (8, "battery_gauge", "ioreg -r -c AppleSmartBattery -a (C7)", "user", "counter"),
    (9, "thermal_warning_level", "pmset -g therm (C8)", "user", "instant"),
    (10, "memory_pressure", "memory_pressure -Q (C9)", "user", "instant"),
    (11, "startup_disk", "diskutil info -plist / (C11)", "user", "provenance"),
    (12, "sip_status", "csrutil status (C12)", "user", "provenance"),
    (13, "gatekeeper_status", "spctl --status (C13)", "user", "provenance"),
    (14, "filevault_status", "fdesetup status (C14)", "user", "provenance"),
    (15, "kernel_and_platform", "sysctl -n <OID> (C15 to C25)", "user", "identity"),
    (16, "virtualization_state", "sysctl -n kern.hv_vmm_present (C26)", "user", "instant"),
    (17, "boot_time", "sysctl -n kern.boottime (C27)", "user", "provenance"),
    (
        18,
        "smart_health_snapshot",
        "IOKit SMARTReadData through the SMART child (C28)",
        "user",
        "instant",
    ),
    (19, "smart_wear_attributes", "C28, the same read", "user", "counter"),
    (
        20,
        "panic_report_count",
        "count of .panic names under /Library/Logs/DiagnosticReports (R1)",
        "admin",
        "retained",
    ),
    (
        21,
        "memory_error_ledger",
        "sqlite3 on Apple's private store, as _mmaintenanced (S3)",
        "service",
        "retained",
    ),
    (22, "power_and_thermal_samples", "powermetrics (S4)", "root", "instant"),
    (
        23,
        "ecc_ras_telemetry",
        "none: the fixed statement that macOS has no public interface",
        "user",
        "coverage",
    ),
]

REP, MEA, DER = "reported", "measured", "derived"
POWER_SERIES = ["cpu", "gpu", "ane", "combined"]
VALUES: dict[str, list[tuple[str, str, str, bool]]] = {
    "os_version": [
        ("product_name", "str", REP, False),
        ("product_version", "str", REP, False),
        ("build_version", "str", REP, False),
    ],
    "hardware_overview": [
        ("machine_name", "str", REP, False),
        ("machine_model", "str", REP, False),
        ("model_number", "str", REP, False),
        ("chip_type", "str", REP, False),
        ("physical_memory_text", "str", REP, False),
        ("serial_last4", "str", REP, False),
        ("serial_number", "str", REP, True),
        ("activation_lock_enabled", "bool", REP, False),
    ],
    "firmware_and_boot": [
        ("boot_rom_version", "str", REP, False),
        ("os_loader_version", "str", REP, False),
    ],
    "nvme_devices": [
        ("entry_count", "int", DER, False),
        ("bsd_name", "str", REP, False),
        ("device_model", "str", REP, False),
        ("device_revision", "str", REP, False),
        ("size_text", "str", REP, False),
        ("size_bytes", "int", REP, False),
        ("smart_status", "str", REP, False),
        ("trim_support", "bool", REP, False),
    ],
    "gpu_configuration": [("core_count", "int", REP, False), ("metal_family", "str", REP, False)],
    "memory_configuration": [
        ("memory_type", "str", REP, False),
        ("manufacturer", "str", REP, False),
        ("size_text", "str", REP, False),
    ],
    "battery_health": [
        ("condition", "str", REP, False),
        ("maximum_capacity_percent", "int", REP, False),
        ("cycle_count", "int", MEA, False),
        ("state_of_charge_percent", "int", MEA, False),
        ("fully_charged", "bool", MEA, False),
        ("is_charging", "bool", MEA, False),
        ("charger_connected", "bool", MEA, False),
        ("gauge_device_name", "str", REP, False),
        ("gauge_firmware_version", "str", REP, False),
        ("gauge_hardware_revision", "str", REP, False),
    ],
    "battery_gauge": [
        ("cycle_count", "int", MEA, False),
        ("design_cycle_count", "int", REP, False),
        ("design_capacity_mah", "int", REP, False),
        ("full_charge_capacity_mah", "int", MEA, False),
        ("temperature_centi_c", "int", MEA, False),
        ("temperature_c", "dec", DER, False),
        ("permanent_failure", "bool", REP, False),
    ],
    "thermal_warning_level": [
        ("thermal_warning_recorded", "bool", REP, False),
        ("thermal_warning_level", "int", REP, True),
    ],
    "memory_pressure": [("free_percent", "int", MEA, False)],
    "startup_disk": [
        ("physical_store_count", "int", DER, False),
        ("physical_store", "str", REP, False),
        ("whole_disk", "str", DER, False),
        ("internal", "bool", REP, False),
        ("solid_state", "bool", REP, False),
    ],
    "sip_status": [("enabled", "bool", REP, False)],
    "gatekeeper_status": [("assessments_enabled", "bool", REP, False)],
    "filevault_status": [("enabled", "bool", REP, False)],
    "kernel_and_platform": [
        ("hw_model", "str", REP, False),
        ("hw_target", "str", REP, False),
        ("memory_bytes", "int", REP, False),
        ("cpu_count", "int", REP, False),
        ("cpu_brand", "str", REP, False),
        ("arm64", "bool", REP, False),
        ("perf_level_count", "int", REP, False),
        ("perf_level_names", "array of str", REP, False),
        ("perf_level_physical_cpus", "array of int", REP, False),
    ],
    "virtualization_state": [("vmm_present", "bool", MEA, False)],
    "boot_time": [
        ("boot_epoch_seconds", "int", MEA, False),
        ("boot_time_utc", "str", DER, False),
        ("days_since_boot", "int", DER, False),
    ],
    "smart_health_snapshot": [
        ("critical_warning_byte", "int", REP, False),
        ("spare_below_threshold", "bool", REP, False),
        ("temperature_warning", "bool", REP, False),
        ("reliability_degraded", "bool", REP, False),
        ("read_only_mode", "bool", REP, False),
        ("volatile_backup_failed", "bool", REP, False),
        ("unknown_warning_bits", "bool", REP, False),
        ("composite_temperature_k", "int", MEA, False),
        ("composite_temperature_c", "int", DER, False),
        ("available_spare_percent", "int", REP, False),
        ("available_spare_threshold_percent", "int", REP, False),
    ],
    "smart_wear_attributes": [
        ("percentage_used", "int", REP, False),
        ("data_units_read", "u128", MEA, False),
        ("data_units_written", "u128", MEA, False),
        ("bytes_read", "bytes128", DER, False),
        ("bytes_written", "bytes128", DER, False),
        ("power_cycles", "u128", MEA, False),
        ("power_on_hours", "u128", MEA, False),
        ("unsafe_shutdowns", "u128", MEA, False),
        ("media_errors", "u128", MEA, False),
        ("error_log_entries", "u128", MEA, False),
    ],
    "panic_report_count": [("count", "int", DER, False)],
    "memory_error_ledger": [
        ("correctable_event_rows", "int", MEA, False),
        ("correctable_reported_count", "int", MEA, False),
        ("uncorrectable_event_rows", "int", MEA, False),
        ("uncorrectable_reported_count", "int", MEA, False),
    ],
    "power_and_thermal_samples": [
        ("sample_count", "int", DER, False),
        ("sample_elapsed_ns", "array of int", MEA, False),
        ("sample_thermal_pressure", "array of str", REP, False),
        *[(f"sample_{kind}_power_mw", "array of dec", REP, False) for kind in POWER_SERIES],
        *[
            (f"thermal_{state}_count", "int", DER, False)
            for state in ("nominal", "moderate", "heavy", "trapping", "sleeping")
        ],
        *[
            (f"{kind}_power_mw_{stat}", "dec", DER, False)
            for kind in POWER_SERIES
            for stat in ("min", "max", "mean")
        ],
    ],
    "ecc_ras_telemetry": [],
}

USER_FOUR = {"tool_error", "timeout", "source_absent", "source_changed"}
ELEVATED = {
    "declined",
    "no_admin",
    "no_terminal",
    "unsupported",
    "tool_error",
    "not_granted",
    "timeout",
    "source_changed",
}


def test_the_registry_has_the_23_surfaces_in_order():
    assert [s.key for s in r.SURFACES] == [row[1] for row in SURFACES]
    assert [s.number for s in r.SURFACES] == list(range(1, 24))


@pytest.mark.parametrize("row", SURFACES, ids=[row[1] for row in SURFACES])
def test_each_surface_has_the_spec_attributes(row):
    number, key, interface, privilege, temporal = row
    surface = r.BY_KEY[key]
    assert (surface.number, surface.interface, surface.privilege, surface.temporal_class) == (
        number,
        interface,
        privilege,
        temporal,
    )
    assert len(surface.interface) <= 128


@pytest.mark.parametrize("key", list(VALUES), ids=list(VALUES))
def test_each_surface_has_the_spec_value_keys(key):
    got = [(v.name, v.shape, v.provenance, v.optional) for v in r.BY_KEY[key].values]
    assert got == VALUES[key]


def test_only_serial_number_and_thermal_warning_level_are_optional():
    optional = {(s.key, v.name) for s in r.SURFACES for v in s.values if v.optional}
    assert optional == {
        ("hardware_overview", "serial_number"),
        ("thermal_warning_level", "thermal_warning_level"),
    }


def test_the_registry_cannot_be_changed_at_run_time():
    surface = r.SURFACES[0]
    assert isinstance(r.SURFACES, tuple) and isinstance(surface.values, tuple)
    with pytest.raises(dataclasses.FrozenInstanceError):
        surface.key = "x"  # type: ignore[misc]
    with pytest.raises(TypeError):
        r.BY_KEY["x"] = surface  # type: ignore[index]


# --- availability domains and reasons --------------------------------------------------------


def test_the_reason_codes():
    assert r.REASONS == (
        "declined",
        "not_granted",
        "no_admin",
        "no_terminal",
        "unsupported",
        "source_absent",
        "source_changed",
        "timeout",
        "tool_error",
    )
    assert sorted(r.SKIPPED_REASONS) == ["declined", "no_admin", "no_terminal", "not_granted"]
    unexpected = ["source_absent", "source_changed", "timeout", "tool_error"]
    assert sorted(r.UNEXPECTED_REASONS) == unexpected


@pytest.mark.parametrize(
    ("keys", "reasons"),
    [
        (
            [
                "os_version",
                "hardware_overview",
                "firmware_and_boot",
                "gpu_configuration",
                "memory_configuration",
                "thermal_warning_level",
                "memory_pressure",
                "sip_status",
                "gatekeeper_status",
                "filevault_status",
                "kernel_and_platform",
                "virtualization_state",
                "boot_time",
                "nvme_devices",
                "battery_health",
                "battery_gauge",
                "startup_disk",
            ],
            USER_FOUR,
        ),
        (["smart_health_snapshot", "smart_wear_attributes"], USER_FOUR | {"unsupported"}),
        (["panic_report_count"], {"no_admin", "tool_error", "source_absent"}),
        (["memory_error_ledger", "power_and_thermal_samples"], ELEVATED),
        (["ecc_ras_telemetry"], {"unsupported"}),
    ],
)
def test_the_availability_domains(keys, reasons):
    for key in keys:
        assert r.BY_KEY[key].reasons == frozenset(reasons), key


def test_only_the_battery_surfaces_can_be_not_applicable():
    assert {s.key for s in r.SURFACES if s.not_applicable} == {"battery_health", "battery_gauge"}


def test_the_elevated_surface_details():
    assert r.DETAILS == (
        "not_attempted",
        "service_account_missing",
        "service_account_error",
        "sandbox_probe_failed",
        "listing_unavailable",
        "prepare_failed",
        "account_blocked",
        "policy_refusal",
        "auth_failed",
        "sudo_error",
        "spawn_failed",
        "payload_failed",
        "parse_failed",
        "runtime_deadline",
        "output_cap",
        "launch_deadline",
        "tracking_failed",
        "skipped_after_sudo_error",
        "skipped_after_unsafe_stop",
    )
    assert r.ELEVATED_SURFACES == ("memory_error_ledger", "power_and_thermal_samples")


# --- ranges and grammars ---------------------------------------------------------------------

RANGES = {
    "maximum_capacity_percent": (0, 100),
    "state_of_charge_percent": (0, 100),
    "free_percent": (0, 100),
    "available_spare_percent": (0, 100),
    "available_spare_threshold_percent": (0, 100),
    "percentage_used": (0, 255),
    "critical_warning_byte": (0, 255),
    "composite_temperature_k": (250, 400),
    "composite_temperature_c": (-24, 127),
    "temperature_centi_c": (-4000, 10000),
    "cycle_count": (0, 100000),
    "design_cycle_count": (1, 10000),
    "design_capacity_mah": (1, 100000),
    "full_charge_capacity_mah": (1, 100000),
    "entry_count": (1, 16),
    "physical_store_count": (1, 8),
    "size_bytes": (1, 2**60),
    "memory_bytes": (2**30, 2**48),
    "cpu_count": (1, 1024),
    "core_count": (1, 1024),
    "perf_level_physical_cpus": (1, 1024),
    "perf_level_count": (1, 2),
    "count": (0, 100000),
    "correctable_event_rows": (0, 10**9),
    "correctable_reported_count": (0, 10**9),
    "uncorrectable_event_rows": (0, 10**9),
    "uncorrectable_reported_count": (0, 10**9),
    "days_since_boot": (0, 36500),
    "sample_count": (5, 5),
    "sample_elapsed_ns": (500000000, 5000000000),
    "thermal_nominal_count": (0, 5),
    "thermal_moderate_count": (0, 5),
    "thermal_heavy_count": (0, 5),
    "thermal_trapping_count": (0, 5),
    "thermal_sleeping_count": (0, 5),
    "thermal_warning_level": (0, 100),
}


def test_every_int_key_has_the_spec_range():
    for name, bounds in RANGES.items():
        assert r.INT_RANGES[name] == bounds, name
    int_keys = {v.name for s in r.SURFACES for v in s.values if v.shape in ("int", "array of int")}
    assert int_keys - set(RANGES) == {"boot_epoch_seconds"}, "bounded by the collection instant"
    assert r.BOOT_EPOCH_MIN == 946684800


def test_decimal_ranges():
    from decimal import Decimal

    assert r.DEC_RANGES["temperature_c"] == (Decimal("-40.00"), Decimal("100.00"))
    power = {v.name for v in r.BY_KEY["power_and_thermal_samples"].values if "dec" in v.shape}
    for name in power:
        assert r.DEC_RANGES[name] == (Decimal("0.0"), Decimal("1000000.00")), name


def test_only_the_spec_keys_may_be_negative():
    negative_ints = {name for name, (low, _) in r.INT_RANGES.items() if low < 0}
    negative_decs = {name for name, (low, _) in r.DEC_RANGES.items() if low < 0}
    assert negative_ints == {"composite_temperature_c", "temperature_centi_c"}
    assert negative_decs == {"temperature_c"}


@pytest.mark.parametrize(
    ("name", "good", "bad"),
    [
        (
            "physical_store",
            ["disk0s2", "disk123s999"],
            ["disk0", "disk0s", "Disk0s2", "disk1234s1"],
        ),
        ("whole_disk", ["disk0", "disk999"], ["disk0s2", "disk", "disk1000", "/dev/disk0"]),
        ("bsd_name", ["disk0", "disk12"], ["disk0s1", "sda"]),
    ],
)
def test_the_storage_grammars(name, good, bad):
    for text in good:
        assert r.GRAMMARS[name].fullmatch(text), text
    for text in bad:
        assert not r.GRAMMARS[name].fullmatch(text), text


def test_the_thermal_states_and_array_lengths():
    assert r.THERMAL_STATES == ("Nominal", "Moderate", "Heavy", "Trapping", "Sleeping")
    assert r.SAMPLE_COUNT == 5
    assert r.MAX_STRING == 256 and r.MAX_INTERFACE == 128
