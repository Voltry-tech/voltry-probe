"""The surface registry: every surface's fixed attributes and value keys.

docs/VOLTRY_MAC_SPEC.md, Decision 8, "Surface registry, normative". The validator carries
the table verbatim: each surface's number, key, interface, privilege, temporal class and
value keys (name, shape, provenance, and whether it is optional), then the availability
domains, the value reasons, the ranges and the string grammars that follow the table.
The reason codes and their split into skipped and unexpected are Decision 6's; the details
of the two elevated surfaces are the outcome tables' in Decision 2. A test in the core
repository parses the spec's own table and compares it with this module.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal
from types import MappingProxyType
from typing import Final, Literal

Shape = Literal[
    "int", "dec", "u128", "bytes128", "str", "bool", "array of int", "array of str", "array of dec"
]
Provenance = Literal["measured", "reported", "derived"]
Privilege = Literal["user", "admin", "service", "root"]
TemporalClass = Literal["identity", "provenance", "coverage", "counter", "instant", "retained"]

MAX_STRING: Final = 256
MAX_INTERFACE: Final = 128
SAMPLE_COUNT: Final = 5
THERMAL_STATES: Final = ("Nominal", "Moderate", "Heavy", "Trapping", "Sleeping")

# Decision 6: the reason codes, in the spec's order, and how the collection status counts
# them. Skipped reasons keep exit 0; an unexpected one makes the exit 1.
REASONS: Final = (
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
SKIPPED_REASONS: Final = frozenset({"declined", "not_granted", "no_admin", "no_terminal"})
UNEXPECTED_REASONS: Final = frozenset({"source_absent", "source_changed", "timeout", "tool_error"})

# The details an unavailable elevated surface carries, in the spec's order.
DETAILS: Final = (
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
ELEVATED_SURFACES: Final = ("memory_error_ledger", "power_and_thermal_samples")


@dataclass(frozen=True)
class ValueKey:
    """One value key of a surface: its name, shape and provenance, and whether it is optional."""

    name: str
    shape: Shape
    provenance: Provenance
    optional: bool = False


@dataclass(frozen=True)
class Surface:
    """One registry row, with the reasons its availability domain allows."""

    number: int
    key: str
    interface: str
    privilege: Privilege
    temporal_class: TemporalClass
    values: tuple[ValueKey, ...]
    reasons: frozenset[str]
    not_applicable: bool = False


# Availability domains, normative.
_COMMAND: Final = frozenset({"tool_error", "timeout", "source_absent", "source_changed"})
_SMART: Final = _COMMAND | {"unsupported"}
_PANIC: Final = frozenset({"no_admin", "tool_error", "source_absent"})
# Every reason the outcome tables in Decision 2 give an elevated surface.
_ELEVATED: Final = frozenset(
    {
        "declined",
        "no_admin",
        "no_terminal",
        "unsupported",
        "tool_error",
        "not_granted",
        "timeout",
        "source_changed",
    }
)
_ECC: Final = frozenset({"unsupported"})

_POWER_KINDS: Final = ("cpu", "gpu", "ane", "combined")


def _surface(
    number: int,
    key: str,
    interface: str,
    privilege: Privilege,
    temporal_class: TemporalClass,
    reasons: frozenset[str],
    *values: ValueKey,
    not_applicable: bool = False,
) -> Surface:
    return Surface(
        number, key, interface, privilege, temporal_class, values, reasons, not_applicable
    )


SURFACES: Final[tuple[Surface, ...]] = (
    _surface(
        1,
        "os_version",
        "sw_vers (C1)",
        "user",
        "provenance",
        _COMMAND,
        ValueKey("product_name", "str", "reported"),
        ValueKey("product_version", "str", "reported"),
        ValueKey("build_version", "str", "reported"),
    ),
    _surface(
        2,
        "hardware_overview",
        "system_profiler SPHardwareDataType (C2)",
        "user",
        "identity",
        _COMMAND,
        ValueKey("machine_name", "str", "reported"),
        ValueKey("machine_model", "str", "reported"),
        ValueKey("model_number", "str", "reported"),
        ValueKey("chip_type", "str", "reported"),
        ValueKey("physical_memory_text", "str", "reported"),
        ValueKey("serial_last4", "str", "reported"),
        ValueKey("serial_number", "str", "reported", optional=True),  # only with --show-serial
        ValueKey("activation_lock_enabled", "bool", "reported"),
    ),
    _surface(
        3,
        "firmware_and_boot",
        "C2, the same run",
        "user",
        "provenance",
        _COMMAND,
        ValueKey("boot_rom_version", "str", "reported"),
        ValueKey("os_loader_version", "str", "reported"),
    ),
    _surface(
        4,
        "nvme_devices",
        "system_profiler SPNVMeDataType (C3)",
        "user",
        "instant",
        _COMMAND,
        ValueKey("entry_count", "int", "derived"),
        # The rest describe the one entry whose bsd_name is the startup disk.
        ValueKey("bsd_name", "str", "reported"),
        ValueKey("device_model", "str", "reported"),
        ValueKey("device_revision", "str", "reported"),
        ValueKey("size_text", "str", "reported"),
        ValueKey("size_bytes", "int", "reported"),
        ValueKey("smart_status", "str", "reported"),
        ValueKey("trim_support", "bool", "reported"),
    ),
    _surface(
        5,
        "gpu_configuration",
        "system_profiler SPDisplaysDataType (C4)",
        "user",
        "identity",
        _COMMAND,
        ValueKey("core_count", "int", "reported"),
        ValueKey("metal_family", "str", "reported"),
    ),
    _surface(
        6,
        "memory_configuration",
        "system_profiler SPMemoryDataType (C5)",
        "user",
        "identity",
        _COMMAND,
        ValueKey("memory_type", "str", "reported"),
        ValueKey("manufacturer", "str", "reported"),
        ValueKey("size_text", "str", "reported"),
    ),
    _surface(
        7,
        "battery_health",
        "system_profiler SPPowerDataType (C6)",
        "user",
        "instant",
        _COMMAND,
        ValueKey("condition", "str", "reported"),
        ValueKey("maximum_capacity_percent", "int", "reported"),
        ValueKey("cycle_count", "int", "measured"),
        ValueKey("state_of_charge_percent", "int", "measured"),
        ValueKey("fully_charged", "bool", "measured"),
        ValueKey("is_charging", "bool", "measured"),
        ValueKey("charger_connected", "bool", "measured"),
        ValueKey("gauge_device_name", "str", "reported"),
        ValueKey("gauge_firmware_version", "str", "reported"),
        ValueKey("gauge_hardware_revision", "str", "reported"),
        not_applicable=True,
    ),
    _surface(
        8,
        "battery_gauge",
        "ioreg -r -c AppleSmartBattery -a (C7)",
        "user",
        "counter",
        _COMMAND,
        ValueKey("cycle_count", "int", "measured"),
        ValueKey("design_cycle_count", "int", "reported"),
        ValueKey("design_capacity_mah", "int", "reported"),
        ValueKey("full_charge_capacity_mah", "int", "measured"),
        ValueKey("temperature_centi_c", "int", "measured"),
        ValueKey("temperature_c", "dec", "derived"),
        ValueKey("permanent_failure", "bool", "reported"),
        not_applicable=True,
    ),
    _surface(
        9,
        "thermal_warning_level",
        "pmset -g therm (C8)",
        "user",
        "instant",
        _COMMAND,
        ValueKey("thermal_warning_recorded", "bool", "reported"),
        ValueKey("thermal_warning_level", "int", "reported", optional=True),  # only when recorded
    ),
    _surface(
        10,
        "memory_pressure",
        "memory_pressure -Q (C9)",
        "user",
        "instant",
        _COMMAND,
        ValueKey("free_percent", "int", "measured"),
    ),
    _surface(
        11,
        "startup_disk",
        "diskutil info -plist / (C11)",
        "user",
        "provenance",
        _COMMAND,
        ValueKey("physical_store_count", "int", "derived"),
        ValueKey("physical_store", "str", "reported"),
        ValueKey("whole_disk", "str", "derived"),
        ValueKey("internal", "bool", "reported"),
        ValueKey("solid_state", "bool", "reported"),
    ),
    _surface(
        12,
        "sip_status",
        "csrutil status (C12)",
        "user",
        "provenance",
        _COMMAND,
        ValueKey("enabled", "bool", "reported"),
    ),
    _surface(
        13,
        "gatekeeper_status",
        "spctl --status (C13)",
        "user",
        "provenance",
        _COMMAND,
        ValueKey("assessments_enabled", "bool", "reported"),
    ),
    _surface(
        14,
        "filevault_status",
        "fdesetup status (C14)",
        "user",
        "provenance",
        _COMMAND,
        ValueKey("enabled", "bool", "reported"),
    ),
    _surface(
        15,
        "kernel_and_platform",
        "sysctl -n <OID> (C15 to C25)",
        "user",
        "identity",
        _COMMAND,
        ValueKey("hw_model", "str", "reported"),
        ValueKey("hw_target", "str", "reported"),
        ValueKey("memory_bytes", "int", "reported"),
        ValueKey("cpu_count", "int", "reported"),
        ValueKey("cpu_brand", "str", "reported"),
        ValueKey("arm64", "bool", "reported"),
        ValueKey("perf_level_count", "int", "reported"),
        ValueKey("perf_level_names", "array of str", "reported"),
        ValueKey("perf_level_physical_cpus", "array of int", "reported"),
    ),
    _surface(
        16,
        "virtualization_state",
        "sysctl -n kern.hv_vmm_present (C26)",
        "user",
        "instant",
        _COMMAND,
        ValueKey("vmm_present", "bool", "measured"),
    ),
    _surface(
        17,
        "boot_time",
        "sysctl -n kern.boottime (C27)",
        "user",
        "provenance",
        _COMMAND,
        ValueKey("boot_epoch_seconds", "int", "measured"),
        ValueKey("boot_time_utc", "str", "derived"),
        ValueKey("days_since_boot", "int", "derived"),
    ),
    _surface(
        18,
        "smart_health_snapshot",
        "IOKit SMARTReadData through the SMART child (C28)",
        "user",
        "instant",
        _SMART,
        ValueKey("critical_warning_byte", "int", "reported"),
        ValueKey("spare_below_threshold", "bool", "reported"),
        ValueKey("temperature_warning", "bool", "reported"),
        ValueKey("reliability_degraded", "bool", "reported"),
        ValueKey("read_only_mode", "bool", "reported"),
        ValueKey("volatile_backup_failed", "bool", "reported"),
        ValueKey("unknown_warning_bits", "bool", "reported"),
        ValueKey("composite_temperature_k", "int", "measured"),
        ValueKey("composite_temperature_c", "int", "derived"),
        ValueKey("available_spare_percent", "int", "reported"),
        ValueKey("available_spare_threshold_percent", "int", "reported"),
    ),
    _surface(
        19,
        "smart_wear_attributes",
        "C28, the same read",
        "user",
        "counter",
        _SMART,
        ValueKey("percentage_used", "int", "reported"),
        ValueKey("data_units_read", "u128", "measured"),
        ValueKey("data_units_written", "u128", "measured"),
        ValueKey("bytes_read", "bytes128", "derived"),
        ValueKey("bytes_written", "bytes128", "derived"),
        ValueKey("power_cycles", "u128", "measured"),
        ValueKey("power_on_hours", "u128", "measured"),
        ValueKey("unsafe_shutdowns", "u128", "measured"),
        ValueKey("media_errors", "u128", "measured"),
        ValueKey("error_log_entries", "u128", "measured"),
    ),
    _surface(
        20,
        "panic_report_count",
        "count of .panic names under /Library/Logs/DiagnosticReports (R1)",
        "admin",
        "retained",
        _PANIC,
        ValueKey("count", "int", "derived"),
    ),
    _surface(
        21,
        "memory_error_ledger",
        "sqlite3 on Apple's private store, as _mmaintenanced (S3)",
        "service",
        "retained",
        _ELEVATED,
        ValueKey("correctable_event_rows", "int", "measured"),
        ValueKey("correctable_reported_count", "int", "measured"),
        ValueKey("uncorrectable_event_rows", "int", "measured"),
        ValueKey("uncorrectable_reported_count", "int", "measured"),
    ),
    _surface(
        22,
        "power_and_thermal_samples",
        "powermetrics (S4)",
        "root",
        "instant",
        _ELEVATED,
        ValueKey("sample_count", "int", "derived"),
        ValueKey("sample_elapsed_ns", "array of int", "measured"),
        ValueKey("sample_thermal_pressure", "array of str", "reported"),
        *(ValueKey(f"sample_{kind}_power_mw", "array of dec", "reported") for kind in _POWER_KINDS),
        *(ValueKey(f"thermal_{state.lower()}_count", "int", "derived") for state in THERMAL_STATES),
        *(
            ValueKey(f"{kind}_power_mw_{stat}", "dec", "derived")
            for kind in _POWER_KINDS
            for stat in ("min", "max", "mean")
        ),
    ),
    _surface(
        23,
        "ecc_ras_telemetry",
        "none: the fixed statement that macOS has no public interface",
        "user",
        "coverage",
        _ECC,
    ),
)

BY_KEY: Final = MappingProxyType({surface.key: surface for surface in SURFACES})

# Ranges, normative, by value key; an array's bounds apply to each element. The start of
# boot_epoch_seconds is fixed and its end is the collection instant, so it is checked
# against the report, not here.
INT_RANGES: Final = MappingProxyType(
    {
        **dict.fromkeys(
            (
                "maximum_capacity_percent",
                "state_of_charge_percent",
                "free_percent",
                "available_spare_percent",
                "available_spare_threshold_percent",
            ),
            (0, 100),
        ),
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
        **dict.fromkeys(("cpu_count", "core_count", "perf_level_physical_cpus"), (1, 1024)),
        "perf_level_count": (1, 2),
        "count": (0, 100000),
        **dict.fromkeys(
            (
                "correctable_event_rows",
                "correctable_reported_count",
                "uncorrectable_event_rows",
                "uncorrectable_reported_count",
            ),
            (0, 10**9),
        ),
        "days_since_boot": (0, 36500),
        "sample_count": (SAMPLE_COUNT, SAMPLE_COUNT),
        "sample_elapsed_ns": (500_000_000, 5_000_000_000),
        **dict.fromkeys(
            (f"thermal_{state.lower()}_count" for state in THERMAL_STATES), (0, SAMPLE_COUNT)
        ),
        "thermal_warning_level": (0, 100),
    }
)
BOOT_EPOCH_MIN: Final = 946684800  # 2000-01-01T00:00:00Z

_POWER_RANGE: Final = (Decimal("0.0"), Decimal("1000000.00"))
DEC_RANGES: Final = MappingProxyType(
    {
        "temperature_c": (Decimal("-40.00"), Decimal("100.00")),
        **dict.fromkeys((f"sample_{kind}_power_mw" for kind in _POWER_KINDS), _POWER_RANGE),
        **dict.fromkeys(
            (f"{kind}_power_mw_{stat}" for kind in _POWER_KINDS for stat in ("min", "max", "mean")),
            _POWER_RANGE,
        ),
    }
)

# String grammars, for use with fullmatch: the forms diskutil and system_profiler print.
GRAMMARS: Final = MappingProxyType(
    {
        "physical_store": re.compile(r"disk[0-9]{1,3}s[0-9]{1,3}", re.ASCII),
        "whole_disk": re.compile(r"disk[0-9]{1,3}", re.ASCII),
        "bsd_name": re.compile(r"disk[0-9]{1,3}", re.ASCII),
    }
)
