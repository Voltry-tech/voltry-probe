"""What a report says, whatever prints it: the words for every unavailable item, the
names of surfaces and values, and numbers, dates and units as the report spells them.

docs/VOLTRY_MAC_SPEC.md, Decision 6 (the two labels, rounding and spelling), the outcome
tables and "How a no degrades" in Decision 2, and Failure modes. The terminal summary uses
it, and the PDF will, so every form of a report says the same thing. Pure: it reads the
report document and nothing else.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Context, Decimal, localcontext
from typing import Final

from voltry_mac import characters, registry

_MONTHS: Final = (
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
)


_FORMAT: Final = "macOS returned a format this version does not recognize"


NOT_REPORTED: Final = "not reported by macOS"


_ELEVATED: Final = frozenset({"memory_error_ledger", "power_and_thermal_samples"})


SMART: Final = ("smart_health_snapshot", "smart_wear_attributes")


STATES: Final = ("sleeping", "trapping", "heavy", "moderate", "nominal")


_STATE_KEYS: Final = ("nominal", "moderate", "heavy", "trapping", "sleeping")


WARNINGS: Final = (
    "spare capacity below its threshold",
    "temperature outside its threshold",
    "reliability degraded",
    "media placed in read-only mode",
    "volatile memory backup failed",
)


ROW_WARNINGS: Final = (
    "spare capacity below threshold",
    "temperature outside threshold",
    "reliability degraded",
    "read-only mode",
    "volatile memory backup failed",
)


# The unexpected reason codes (Decision 6), as the line after the collection names them.
_UNEXPECTED: Final = {
    "source_absent": "a file or device that is not present",
    "source_changed": _FORMAT[len("macOS returned ") :],
    "timeout": "a step that timed out",
    "tool_error": "a tool or step that failed",
}


# A value that would print as nothing: in the terminal once the characters it drops are
# gone, in the PDF when it holds only blank spaces.
EMPTY: Final = "(empty)"
# Exact enough for any value the schema allows: a byte total has at most 45 digits.
_EXACT: Final = Context(prec=120, rounding=ROUND_HALF_UP)


_PROGRAM: Final = {
    "os_version": "sw_vers",
    "hardware_overview": "system_profiler",
    "firmware_and_boot": "system_profiler",
    "nvme_devices": "system_profiler",
    "gpu_configuration": "system_profiler",
    "memory_configuration": "system_profiler",
    "battery_health": "system_profiler",
    "battery_gauge": "ioreg",
    "thermal_warning_level": "pmset",
    "memory_pressure": "memory_pressure",
    "startup_disk": "diskutil",
    "sip_status": "csrutil",
    "gatekeeper_status": "spctl",
    "filevault_status": "fdesetup",
    "kernel_and_platform": "sysctl",
    "virtualization_state": "sysctl",
    "boot_time": "sysctl",
}


_SURFACE_NAMES: Final = {
    "os_version": "macOS version",
    "hardware_overview": "Hardware overview",
    "firmware_and_boot": "Firmware version",
    "nvme_devices": "Startup disk drive entry",
    "gpu_configuration": "GPU",
    "memory_configuration": "Memory type",
    "battery_health": "Battery power report",
    "battery_gauge": "Battery gauge",
    "thermal_warning_level": "Thermal warning level",
    "memory_pressure": "Memory pressure",
    "startup_disk": "Startup disk",
    "sip_status": "System Integrity Protection",
    "gatekeeper_status": "Gatekeeper",
    "filevault_status": "FileVault",
    "kernel_and_platform": "Processor details",
    "virtualization_state": "Virtual machine check",
    "boot_time": "Last restart",
    "smart_health_snapshot": "SSD health log",
    "smart_wear_attributes": "SSD health log",
    "panic_report_count": "Panic reports",
    "memory_error_ledger": "Memory error records",
    "power_and_thermal_samples": "Power and thermal check",
    "ecc_ras_telemetry": "ECC error counters",
}


_SERIES: Final = {
    "Thermal pressure": ("sample_thermal_pressure", *(f"thermal_{s}_count" for s in _STATE_KEYS)),
    **{
        label: (
            f"sample_{kind}_power_mw",
            *(f"{kind}_power_mw_{end}" for end in ("min", "max", "mean")),
        )
        for kind, label in (
            ("cpu", "CPU power"),
            ("gpu", "GPU power"),
            ("ane", "Neural Engine"),
            ("combined", "Processor power"),
        )
    },
}


_VALUE_LABELS: Final[Mapping[str, Mapping[str, tuple[str, ...]]]] = {
    "os_version": {
        "macOS name": ("product_name",),
        "macOS version": ("product_version",),
        "macOS build": ("build_version",),
    },
    "hardware_overview": {
        "Model name": ("machine_name",),
        "Model identifier": ("machine_model",),
        "Model number": ("model_number",),
        "Chip (name)": ("chip_type",),
        "Memory size": ("physical_memory_text",),
        "Serial number (last 4)": ("serial_last4",),
        "Serial number (full)": ("serial_number",),
        "Activation Lock": ("activation_lock_enabled",),
    },
    "firmware_and_boot": {
        "Firmware version": ("boot_rom_version",),
        "OS loader version": ("os_loader_version",),
    },
    "nvme_devices": {
        "Drive entries": ("entry_count",),
        "Startup disk drive entry (name)": ("bsd_name",),
        "Startup disk drive entry (model)": ("device_model",),
        "Startup disk drive entry (firmware)": ("device_revision",),
        "Startup disk drive entry (rounded capacity)": ("size_text",),
        "Startup disk drive entry (capacity in bytes)": ("size_bytes",),
        "SMART status": ("smart_status",),
        "Startup disk drive entry (TRIM)": ("trim_support",),
    },
    "gpu_configuration": {"GPU cores": ("core_count",), "Metal support": ("metal_family",)},
    "memory_configuration": {
        "Memory type": ("memory_type",),
        "Memory manufacturer": ("manufacturer",),
        "Memory size (memory profile)": ("size_text",),
    },
    "battery_health": {
        "Battery condition": ("condition",),
        "Maximum capacity": ("maximum_capacity_percent",),
        "Charge cycles (power report)": ("cycle_count",),
        "Charge now (charge level)": ("state_of_charge_percent",),
        "Charge now (fully charged)": ("fully_charged",),
        "Power source (charging)": ("is_charging",),
        "Power source (charger)": ("charger_connected",),
        "Battery gauge revisions (chip)": ("gauge_device_name",),
        "Battery gauge revisions (firmware)": ("gauge_firmware_version",),
        "Battery gauge revisions (hardware)": ("gauge_hardware_revision",),
    },
    "battery_gauge": {
        "Charge cycles (battery gauge)": ("cycle_count",),
        "Design cycle count": ("design_cycle_count",),
        "Design capacity": ("design_capacity_mah",),
        "Full charge now": ("full_charge_capacity_mah",),
        "Battery temperature": ("temperature_centi_c", "temperature_c"),
        "Permanent failure flag": ("permanent_failure",),
    },
    "thermal_warning_level": {
        "Thermal warning level": ("thermal_warning_recorded", "thermal_warning_level")
    },
    "memory_pressure": {"Memory pressure": ("free_percent",)},
    "startup_disk": {
        "Physical stores": ("physical_store_count",),
        "Startup disk": ("physical_store", "whole_disk"),
        "Internal disk flag": ("internal",),
        "Solid-state flag": ("solid_state",),
    },
    "sip_status": {"System Integrity Protection": ("enabled",)},
    "gatekeeper_status": {"Gatekeeper": ("assessments_enabled",)},
    "filevault_status": {"FileVault": ("enabled",)},
    "kernel_and_platform": {
        "Model identifier (sysctl)": ("hw_model",),
        "Board ID": ("hw_target",),
        "Memory total": ("memory_bytes",),
        "CPU count": ("cpu_count",),
        "CPU brand": ("cpu_brand",),
        "Apple silicon flag": ("arm64",),
        "Core clusters (count)": ("perf_level_count",),
        "Core clusters (names)": ("perf_level_names",),
        "Core clusters (core counts)": ("perf_level_physical_cpus",),
    },
    "virtualization_state": {"Virtual machine check": ("vmm_present",)},
    "boot_time": {"Last restart": ("boot_epoch_seconds", "boot_time_utc", "days_since_boot")},
    "smart_health_snapshot": {
        "Critical warning": (
            "critical_warning_byte",
            "spare_below_threshold",
            "temperature_warning",
            "reliability_degraded",
            "read_only_mode",
            "volatile_backup_failed",
            "unknown_warning_bits",
        ),
        "SSD temperature": ("composite_temperature_k", "composite_temperature_c"),
        "Available spare": ("available_spare_percent",),
        "Available spare threshold": ("available_spare_threshold_percent",),
    },
    "smart_wear_attributes": {
        "Endurance used": ("percentage_used",),
        "Data read": ("data_units_read", "bytes_read"),
        "Data written": ("data_units_written", "bytes_written"),
        "Power cycles": ("power_cycles",),
        "Power-on hours": ("power_on_hours",),
        "Unsafe shutdowns": ("unsafe_shutdowns",),
        "Media errors": ("media_errors",),
        "Error log entries": ("error_log_entries",),
    },
    "panic_report_count": {"Panic reports": ("count",)},
    "memory_error_ledger": {
        "Memory error records (correctable)": ("correctable_event_rows",),
        "Memory error records (uncorrectable)": ("uncorrectable_event_rows",),
        "The log's own counts (correctable)": ("correctable_reported_count",),
        "The log's own counts (uncorrectable)": ("uncorrectable_reported_count",),
    },
    "power_and_thermal_samples": {
        "Samples": ("sample_count",),
        "Sample times": ("sample_elapsed_ns",),
        **_SERIES,
    },
}


_VALUE_NAMES: Final = {
    key: {name: label for label, names in labels.items() for name in names}
    for key, labels in _VALUE_LABELS.items()
}


# Letters and marks that print as nothing or as blank space: the Hangul fillers, the Braille
# blank, the default-ignorable marks their general category does not single out (the
# combining grapheme joiner, the Khmer inherent vowels, the Mongolian and other variation
# selectors), and the unassigned code points Unicode reserves as default-ignorable, which a
# terminal draws as nothing.
INVISIBLE: Final = frozenset(
    {0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x2065, 0x2800, 0x3164, 0xFFA0, 0xE0000}
    | set(range(0x180B, 0x1810))
    | set(range(0xFE00, 0xFE10))
    | set(range(0xFFF0, 0xFFF9))
    | set(range(0xE0002, 0xE0020))
    | set(range(0xE0080, 0xE0100))
    | set(range(0xE0100, 0xE01F0))
    | set(range(0xE01F0, 0xE1000))
)
# Marks that join the letter before them, and the conjoining Hangul vowels and finals that
# join the syllable before them: none takes a terminal column.
_JOINING: Final = frozenset({"Mn", "Me"})
_HANGUL_JOINING: Final = ((0x1160, 0x11FF), (0xD7B0, 0xD7FF))


def clean(text: str) -> str:
    """Text from system output, without control, format, separator or invisible
    characters, by the character table (characters.py), so every Python drops the same."""
    return "".join(
        c
        for c in text
        if characters.category(c) not in ("Cc", "Cf", "Zl", "Zp") and ord(c) not in INVISIBLE
    )


def plain(text: str) -> str:
    """Text as the terminal prints a value: clean, with no space at either end."""
    return clean(text).strip(characters.SPACES)


# The two spaces the PDF draws blank, the only characters it trims from a value's ends:
# every other character prints, as itself or as a counted "?" (Decision 4).
_BLANK: Final = " \u00a0"


def _cell(c: str) -> int:
    point = ord(c)
    if characters.category(c) in _JOINING or any(
        low <= point <= high for low, high in _HANGUL_JOINING
    ):
        return 0
    return 2 if characters.wide(c) else 1


def cells(text: str) -> int:
    """How many terminal columns text takes: wide characters two, and marks and conjoining
    Hangul that join the character before them none."""
    if text.isascii():
        return len(text)  # no ASCII character is wide or joins another
    return sum(_cell(c) for c in text)


@dataclass(frozen=True)
class Gap:
    """A surface, or a value inside an available one, that is unavailable."""

    key: str
    reason: str
    name: str | None = None
    detail: str | None = None


class Report:
    """A validated report document as one renderer reads it: the terminal's reading, or
    with ``pdf`` the PDF's. The terminal drops what clean() drops (the Architecture's
    renderers row: control characters from system output are stripped before printing);
    the PDF keeps every character for its encoder, which prints one outside WinAnsi as "?"
    and counts it in Appendix B (Decision 4), so none is lost unsaid."""

    def __init__(self, document: Mapping[str, object], *, pdf: bool = False) -> None:
        self.document = document
        self.pdf = pdf
        surfaces = document["surfaces"]
        assert isinstance(surfaces, list)  # noqa: S101 - a validated document
        self.surfaces: dict[str, Mapping[str, object]] = {s["key"]: s for s in surfaces}
        elevation = document["elevation"]
        assert isinstance(elevation, Mapping)  # noqa: S101 - a validated document
        self.elevation: Mapping[str, object] = elevation

    def state(self, key: str) -> str:
        return str(self.surfaces[key]["availability"])

    def entry(self, key: str, name: str) -> Mapping[str, object] | None:
        values = self.surfaces[key].get("values") or {}
        assert isinstance(values, Mapping)  # noqa: S101 - a validated document
        found = values.get(name)
        return found if isinstance(found, Mapping) else None

    def get(self, key: str, name: str) -> object | None:
        """The value, or None when the surface or the value is not available."""
        if self.state(key) != "available":
            return None
        found = self.entry(key, name)
        if found is None or found.get("availability") != "available":
            return None
        return found["value"]

    def text(self, key: str, name: str) -> str | None:
        """The text as this report's renderer prints it (shown); None when it was not
        read."""
        found = self.get(key, name)
        if not isinstance(found, str):
            return None
        return self.shown(found)

    def shown(self, text: str) -> str:
        """A text value as this report's renderer prints it: plain in the terminal, and in
        the PDF every character but the blank spaces at either end; EMPTY when nothing
        visible is left, so it never prints as nothing."""
        return (text.strip(_BLANK) if self.pdf else plain(text)) or EMPTY

    def plain(self, key: str, name: str) -> str | None:
        """The text as the terminal prints it (plain), whichever renderer reads the report;
        None when it was not read. What a choice between two sets of words compares, so
        the terminal and the PDF make the same choice."""
        found = self.get(key, name)
        return plain(found) if isinstance(found, str) else None

    def number(self, key: str, name: str) -> int | None:
        found = self.get(key, name)
        if isinstance(found, bool) or not isinstance(found, int | str):
            return None
        return int(found)

    def flag(self, key: str, name: str) -> bool | None:
        found = self.get(key, name)
        return found if isinstance(found, bool) else None

    def decimal(self, key: str, name: str) -> Decimal | None:
        found = self.get(key, name)
        return Decimal(found) if isinstance(found, str) else None

    def failed(self, command_id: str) -> bool:
        """Whether the command with this ID ran and failed, by its record."""
        records = self.document["commands"]
        assert isinstance(records, list)  # noqa: S101 - a validated document
        return any(r["id"] == command_id and r["failed_runs"] > 0 for r in records)

    def gap(self, key: str, name: str | None = None) -> Gap | None:
        """Why a surface, or one of its values, is unavailable; None when it is available."""
        surface = self.surfaces[key]
        if surface["availability"] == "unavailable":
            detail = surface.get("detail")
            return Gap(key, str(surface["reason"]), None, None if detail is None else str(detail))
        if surface["availability"] != "available" or name is None:
            return None
        found = self.entry(key, name)
        if found is not None and found.get("availability") == "unavailable":
            return Gap(key, str(found["reason"]), name)
        return None

    def gaps(self) -> list[Gap]:
        """Every gap in registry order: a surface once, or each value of an available one."""
        found = []
        for spec in registry.SURFACES:
            gap = self.gap(spec.key)
            if gap is not None:
                found.append(gap)
                continue
            if self.state(spec.key) == "available":
                for value in spec.values:
                    gap = self.gap(spec.key, value.name)
                    if gap is not None:
                        found.append(gap)
        return found


@dataclass(frozen=True)
class Words:
    """What a gap says: a lead ("Not read", "Could not read", "Unavailable", or none) and a
    phrase; a row prints both, a list the phrase alone."""

    lead: str
    phrase: str

    @property
    def row(self) -> str:
        return (
            f"{self.lead}: {self.phrase}"
            if self.lead
            else self.phrase[:1].upper() + self.phrase[1:]
        )


def _elevated_words(report: Report, gap: Gap) -> Words:
    detail, count = gap.detail, gap.key == "memory_error_ledger"
    consent, cause = report.elevation["consent"], report.elevation["skip_cause"]
    fixed = {
        "service_account_missing": "this macOS has no memory-maintenance account to read as",
        "service_account_error": "the memory-maintenance account could not be looked up",
        "sandbox_probe_failed": (
            "this Mac cannot run the administrator reads safely (no working sandbox)"
        ),
        "listing_unavailable": (
            "this Mac cannot run the administrator reads safely (process listing unavailable)"
        ),
        "prepare_failed": "administrator access could not be prepared (sudo -k failed)",
        "account_blocked": (
            "macOS reported a problem with this account, such as a lock or an expired password"
        ),
        "auth_failed": "administrator access was not granted",
        "sudo_error": "sudo reported an error",
        "spawn_failed": "sudo could not be started for this step",
        "launch_deadline": "the step did not start in time",
        "tracking_failed": "the step was stopped because its processes could not be tracked",
        "skipped_after_sudo_error": (
            "skipped after sudo reported an error at the memory-error step"
        ),
        "skipped_after_unsafe_stop": (
            "skipped after the memory-error step had to be stopped or its stop could not be "
            "confirmed"
        ),
    }
    if detail in fixed:
        return Words("Not read", fixed[detail])
    if detail in ("parse_failed", "output_cap"):
        return Words("Could not read", _FORMAT)
    if detail == "runtime_deadline":
        return Words("Not read", f"timed out after {10 if count else 20} seconds")
    if detail == "payload_failed":
        return Words(
            "Not read",
            (
                "macOS did not provide the memory error records"
                if count
                else "powermetrics returned an error"
            ),
        )
    if detail == "policy_refusal":
        if report.elevation["authenticate"] == "refused":
            return Words("Not read", "sudo does not allow this account to run these steps")
        return Words("Not read", "sudo did not allow this step")
    # not_attempted: the question, --no-root, or a skip cause.
    if consent == "no":
        return Words("Not read", "needs administrator access (you chose not to allow it)")
    return Words(
        "Not read",
        {
            "no_root_flag": "skipped with --no-root",
            "not_admin": "this account is not an administrator on this Mac",
            "no_terminal": "no terminal to ask for a password",
        }.get(str(cause), "needs administrator access"),
    )


def _read_words(key: str, reason: str) -> Words:
    """A user read that failed, by the mapping Failure modes gives."""
    if reason == "source_changed":
        return Words("Could not read", _FORMAT)
    if reason == "timeout":
        return Words("Not read", f"timed out after {15 if key in SMART else 10} seconds")
    program = _PROGRAM.get(key, "the tool")
    if reason == "source_absent":
        return Words("Not read", f"{program} is not on this Mac")
    return Words("Not read", f"{program} returned an error")


_MULTI_STORE: Final = "the startup volume spans more than one physical store"
_NO_LOG: Final = "the startup disk could not be matched to one health log"


def _trunk_words(report: Report, key: str) -> Words | None:
    """The storage dependency table: while the startup volume's trunk (its store and whole
    disk) is unread, the drive entry's fields and the health log take its reason, and say
    so rather than repeat a timeout or an error that was the trunk's."""
    trunk = report.gap("startup_disk", "whole_disk")
    if trunk is None:
        return None
    if trunk.reason == "unsupported":
        return Words("Not read", _NO_LOG if key in SMART else _MULTI_STORE)
    return Words("Not read", "the startup disk could not be identified")


def words(report: Report, gap: Gap) -> Words:
    key, reason = gap.key, gap.reason
    if key == "ecc_ras_telemetry":
        return Words("Unavailable", "macOS has no public interface")
    if key in _ELEVATED and gap.name is None:
        return _elevated_words(report, gap)
    if key in SMART or (key == "nvme_devices" and gap.name is not None):
        trunk = _trunk_words(report, key)
        if trunk is not None:
            return trunk
    if gap.name is not None:
        if key in SMART:
            # Only a decoded bound makes a SMART value unread (smart.py).
            return Words("", "the drive reported a reading outside its range")
        if reason == "unsupported":
            return Words("Not read", _MULTI_STORE)
        if key == "kernel_and_platform" or (key == "startup_disk" and reason != "source_changed"):
            return _read_words(key, reason)
        if key == "startup_disk":
            return Words("Could not read", _FORMAT)
        return Words("", NOT_REPORTED)
    if key in SMART:
        return Words(
            "Not read",
            {
                "source_absent": _NO_LOG,
                # C28 rows 9 and 10 (another medium on the controller, or no SMART
                # interface) both give unsupported; these words are true of both.
                "unsupported": "this startup disk has no health log this version can read",
                "timeout": "timed out after 15 seconds",
            }.get(reason, "the startup disk's health log could not be read"),
        )
    if key == "nvme_devices" and reason in ("source_absent", "source_changed"):
        if report.failed("C3") or report.gap("startup_disk", "whole_disk") is not None:
            # C3 itself failed, or its output did not parse where no match was tried.
            return _read_words(key, reason)
        return Words("Not read", "the startup disk could not be matched to one drive entry")
    if key == "panic_report_count":
        return Words(
            "Not read",
            {
                "no_admin": "readable by administrator accounts only",
                "source_absent": "the crash report folder was not found",
            }.get(reason, "the crash report folder could not be read"),
        )
    return _read_words(key, reason)


def missing(part: str, report: Report, key: str, *names: str, plural: bool = False) -> str:
    """One part of a row that shows the others: "the size is not reported by macOS", or
    "the chip's name was not read (system_profiler returned an error)"; ``plural`` for a
    part that names two things ("the version and build were not read")."""
    gaps = [report.gap(key, name) for name in names or (None,)]
    first = next((gap for gap in gaps if gap is not None), None)
    said = Words("", NOT_REPORTED) if first is None else words(report, first)
    was, is_ = ("were", "are") if plural else ("was", "is")
    return f"{part} {was} not read ({said.phrase})" if said.lead else f"{part} {is_} {NOT_REPORTED}"


def listed(report: Report, gap: Gap) -> str:
    """A gap as the Not read line lists it."""
    if gap.key == "ecc_ras_telemetry":
        return "ECC error counters: no public interface on Macs."
    return f"{gap_name(gap)}: {words(report, gap).phrase}."


def gap_name(gap: Gap) -> str:
    if gap.name is None:
        return _SURFACE_NAMES[gap.key]
    return value_name(gap.key, gap.name)


def value_name(key: str, name: str) -> str:
    """A value's name as the Not read line gives it: its row, and its part in parentheses."""
    return _VALUE_NAMES[key][name]


def row_gap(report: Report, key: str, *names: str) -> str:
    """What a row says when one of its inputs is unavailable: the first one's words."""
    for name in names or (None,):
        gap = report.gap(key, name)
        if gap is not None:
            return words(report, gap).row
    return Words("", NOT_REPORTED).row


KINDS: Final = ("correctable", "uncorrectable")


def joined(names: Sequence[str]) -> str:
    """Names as a list in prose: "a", "a and b", "a, b and c"."""
    return names[0] if len(names) == 1 else f"{', '.join(names[:-1])} and {names[-1]}"


def thousands(value: int | str) -> str:
    return f"{int(value):,}"


def round_half_up(value: Decimal, places: int) -> Decimal:
    with localcontext(_EXACT):
        return value.quantize(Decimal(1).scaleb(-places), rounding=ROUND_HALF_UP)


def decimal(value: Decimal, places: int) -> str:
    """A decimal rounded half up to its places, thousands grouped, and zero never signed."""
    rounded = round_half_up(value, places)
    return f"{abs(rounded) if rounded.is_zero() else rounded:,}"


def watt_places(values: Sequence[Decimal]) -> int:
    """The decimals Decision 6 gives milliwatts shown as watts on one row: two when a
    non-zero value is below 0.1 W or one decimal would collapse the range (the first two
    values, the lowest and the highest), else one."""
    with localcontext(_EXACT):
        watts = [value / 1000 for value in values]
    small = any(0 < w < Decimal("0.1") for w in watts)
    low, high = watts[0], (watts[1] if len(watts) > 1 else watts[0])
    collapsed = low != high and round_half_up(low, 1) == round_half_up(high, 1)
    return 2 if small or collapsed else 1


def watts(values: Sequence[Decimal], places: int | None = None) -> list[str]:
    """Milliwatts as watts, by Decision 6, at the row's precision (watt_places), or at
    places when another row decides it; an exact zero is 0.0."""
    shown = watt_places(values) if places is None else places
    with localcontext(_EXACT):
        watts = [value / 1000 for value in values]
    return ["0.0" if w == 0 else decimal(w, shown) for w in watts]


@dataclass(frozen=True)
class Local:
    """collected_at_local (2026-09-23T14:05:31-07:00): the date, the time, the offset."""

    year: int
    month: int
    day: int
    hour: int
    minute: int
    offset: int  # minutes east of UTC

    @classmethod
    def parse(cls, text: str) -> Local:
        sign = -1 if text[19] == "-" else 1
        return cls(
            int(text[0:4]),
            int(text[5:7]),
            int(text[8:10]),
            int(text[11:13]),
            int(text[14:16]),
            sign * (int(text[20:22]) * 60 + int(text[23:25])),
        )


def date(year: int, month: int, day: int) -> str:
    return f"{day} {_MONTHS[month - 1]} {year}"


def offset(minutes: int) -> str:
    if minutes == 0:
        return "UTC"
    sign = "-" if minutes < 0 else "+"
    hours, rest = divmod(abs(minutes), 60)
    return f"UTC{sign}{hours}" + (f":{rest:02d}" if rest else "")


def civil(days: int) -> tuple[int, int, int]:
    """The proleptic Gregorian date of a day count since 1970-01-01."""
    days += 719468
    era = days // 146097
    day_of_era = days - era * 146097
    year_of_era = (
        day_of_era - day_of_era // 1460 + day_of_era // 36524 - day_of_era // 146096
    ) // 365
    day_of_year = day_of_era - (365 * year_of_era + year_of_era // 4 - year_of_era // 100)
    shifted = (5 * day_of_year + 2) // 153
    day = day_of_year - (153 * shifted + 2) // 5 + 1
    month = shifted + 3 if shifted < 10 else shifted - 9
    return year_of_era + era * 400 + (1 if month <= 2 else 0), month, day


def total(digits: str) -> str:
    """Bytes in decimal SI units: TB below 1 PB, PB from it, one decimal, half up, exact
    for the largest total the schema allows (45 digits)."""
    total = Decimal(digits)
    with localcontext(_EXACT):
        if total >= 10**15:
            return f"{decimal(total.scaleb(-15), 1)} PB"
        return f"{decimal(total.scaleb(-12), 1)} TB"


def warnings(byte: int, known: Sequence[str]) -> str:
    """The critical-warning bits that are set: bits 0 to 4 by name, then bits 5 to 7,
    which NVMe reserves, as unknown, joined as the spec's "and an unknown warning bit"."""
    said = [text for bit, text in enumerate(known) if byte >> bit & 1]
    unknown = [bit for bit in range(5, 8) if byte >> bit & 1]
    if unknown:
        said.append("an unknown warning bit" if len(unknown) == 1 else "unknown warning bits")
    return joined(said)


def unexpected(report: Report) -> str | None:
    """The collection's unexpected reasons, in the JSON's order; None when there are none."""
    counts = report.document["collection"]
    assert isinstance(counts, Mapping)  # noqa: S101 - a validated document
    reasons = counts["unexpected_reasons"]
    assert isinstance(reasons, list)  # noqa: S101 - a validated document
    if not reasons:
        return None
    said = [_UNEXPECTED[str(reason)] for reason in reasons]
    joined = said[0] if len(said) == 1 else f"{', '.join(said[:-1])} and {said[-1]}"
    return f"Unexpected: {joined}."


def plural(count: int, one: str, many: str) -> str:
    return f"{thousands(count)} {one if count == 1 else many}"


def guarantee(cleanup: str) -> str:
    """What the listing after a payload lets Voltry say, and no more: Decision 2's
    guarantee, stated exactly and conditionally. Appendix B prints it beside each payload's
    cleanup (the GPT audit, pass 3, G3-04), so it speaks for that step's recorded processes
    alone; and a survivor is named only where it was, in the terminal output, since the
    saved report keeps no process's identity (pass 4, G4-01)."""
    if cleanup == "verified":
        return (
            "Every process the listings recorded for this step, the payload included if it "
            "started, has ended. A process that starts and ends between two listings is never "
            "recorded."
        )
    if cleanup == "survivor":
        return (
            "A process recorded for this step may still be running. Voltry named it in its "
            "terminal output when this report was made; nothing else is claimed."
        )
    if cleanup == "listing_failed":
        return (
            "The listing after this step failed, so Voltry could not check that the processes "
            "recorded for it ended, and claims nothing about them."
        )
    raise ValueError(f"{cleanup!r} is not a cleanup a payload can have")
