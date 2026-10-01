"""render's validator, second pass: the report's own relations.

docs/VOLTRY_MAC_SPEC.md, Decision 8: the registry invariants, the computed-values rule,
the storage dependency table and the SMART child's outcome table, each user command
against the surfaces it feeds, the collection block restating Decision 6's status rule,
and the save gate. ``check`` runs after every shape has passed, so it reads the document
without checking types again; it raises ``canonical.Invalid`` naming the field path.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Final

from voltry_mac import numbers, registry
from voltry_mac.canonical import Invalid, child_path

SAVE_GATE: Final = 8
COUNTS: Final = ("read", "skipped", "unavailable", "not_applicable")

# Value reasons, normative: source_changed for any value; the four command reasons for a
# kernel value (its own sysctl call); unsupported for the store and the whole disk; and
# for the NVMe entry's keys, whatever the whole disk or its surface carried.
COMMAND_REASONS: Final = frozenset({"tool_error", "timeout", "source_absent", "source_changed"})
NVME_ENTRY: Final = (
    "bsd_name",
    "device_model",
    "device_revision",
    "size_text",
    "size_bytes",
    "smart_status",
    "trim_support",
)
_WARNING_FLAGS: Final = (
    "spare_below_threshold",
    "temperature_warning",
    "reliability_degraded",
    "read_only_mode",
    "volatile_backup_failed",
)
_POWER_KINDS: Final = ("cpu", "gpu", "ane", "combined")
# C28's row 12: a decoded bound can reject only these raw fields, and what is derived from
# them; every other value of an available SMART surface is read.
_SMART_BOUNDED: Final = frozenset(
    {
        "composite_temperature_k",
        "composite_temperature_c",
        "available_spare_percent",
        "available_spare_threshold_percent",
    }
)

# The computed-values rule: each computed key and its inputs, in the spec's order.
_INPUTS: Final[tuple[tuple[str, str, tuple[tuple[str, str], ...]], ...]] = (
    ("smart_wear_attributes", "bytes_read", (("smart_wear_attributes", "data_units_read"),)),
    ("smart_wear_attributes", "bytes_written", (("smart_wear_attributes", "data_units_written"),)),
    (
        "smart_health_snapshot",
        "composite_temperature_c",
        (("smart_health_snapshot", "composite_temperature_k"),),
    ),
    ("battery_gauge", "temperature_c", (("battery_gauge", "temperature_centi_c"),)),
    ("boot_time", "boot_time_utc", (("boot_time", "boot_epoch_seconds"),)),
    ("boot_time", "days_since_boot", (("boot_time", "boot_epoch_seconds"),)),
    *(
        ("smart_health_snapshot", flag, (("smart_health_snapshot", "critical_warning_byte"),))
        for flag in (*_WARNING_FLAGS, "unknown_warning_bits")
    ),
    *(
        (
            "power_and_thermal_samples",
            f"{kind}_power_mw_{stat}",
            (("power_and_thermal_samples", f"sample_{kind}_power_mw"),),
        )
        for kind in _POWER_KINDS
        for stat in ("min", "max", "mean")
    ),
    *(
        (
            "power_and_thermal_samples",
            f"thermal_{state.lower()}_count",
            (("power_and_thermal_samples", "sample_thermal_pressure"),),
        )
        for state in registry.THERMAL_STATES
    ),
    ("startup_disk", "whole_disk", (("startup_disk", "physical_store"),)),
)

# The user commands and the surfaces each feeds; the sysctl OIDs and C28 have their own
# rules below.
_FEEDS: Final = {
    "C1": ("os_version",),
    "C2": ("hardware_overview", "firmware_and_boot"),
    "C3": ("nvme_devices",),
    "C4": ("gpu_configuration",),
    "C5": ("memory_configuration",),
    "C6": ("battery_health",),
    "C7": ("battery_gauge",),
    "C8": ("thermal_warning_level",),
    "C9": ("memory_pressure",),
    "C11": ("startup_disk",),
    "C12": ("sip_status",),
    "C13": ("gatekeeper_status",),
    "C14": ("filevault_status",),
    "C26": ("virtualization_state",),
    "C27": ("boot_time",),
}
_KERNEL_OIDS: Final = {
    "hw_model": "C15",
    "hw_target": "C16",
    "memory_bytes": "C17",
    "cpu_count": "C18",
    "cpu_brand": "C19",
    "arm64": "C20",
    "perf_level_count": "C21",
}
_PERF_OIDS: Final = {"perf_level_names": ("C22", "C24"), "perf_level_physical_cpus": ("C23", "C25")}

_ABSENT: Final = object()


@dataclass(frozen=True)
class _Status:
    available: bool
    reason: str | None


class Report:
    """The shape-checked document, with lookups by surface key and command ID."""

    def __init__(self, document: Mapping[str, object], instant: int) -> None:
        self.document = document
        self.instant = instant
        surfaces = document["surfaces"]
        commands = document["commands"]
        assert isinstance(surfaces, list) and isinstance(commands, list)  # noqa: S101
        self.surfaces: list[dict] = surfaces
        self.by_key = {surface["key"]: surface for surface in surfaces}
        self.index = {surface["key"]: i for i, surface in enumerate(surfaces)}
        self.commands = {record["id"]: record for record in commands}
        self.command_index = {record["id"]: i for i, record in enumerate(commands)}

    def path(self, key: str, name: str | None = None, field: str | None = None) -> str:
        path = f"surfaces[{self.index[key]}]"
        if name is not None:
            path = child_path(f"{path}.values", name)
        return f"{path}.{field}" if field is not None else path

    def command_path(self, command_id: str, field: str) -> str:
        return f"commands[{self.command_index[command_id]}].{field}"

    def availability(self, key: str) -> str:
        return self.by_key[key]["availability"]

    def status(self, key: str, name: str) -> _Status:
        """A required value's availability; inside an unavailable surface, that surface's reason.

        Callers ask only for required keys of surfaces that cannot be not applicable, and the
        shape pass has put every required key in every available surface.
        """
        surface = self.by_key[key]
        if surface["availability"] != "available":
            return _Status(False, surface.get("reason"))
        entry = surface["values"][name]
        return _Status(entry["availability"] == "available", entry.get("reason"))

    def value(self, key: str, name: str) -> object:
        """The value, or _ABSENT when it is not available."""
        surface = self.by_key[key]
        entry = surface["values"].get(name) if surface["availability"] == "available" else None
        if entry is None or entry["availability"] != "available":
            return _ABSENT
        return entry["value"]

    def failed(self, command_id: str) -> bool:
        record = self.commands.get(command_id)
        return record is not None and record["failed_runs"] > 0


def check(report: Report) -> None:
    """Raise ``Invalid`` at the first relation of the report that does not hold."""
    _surfaces_hold_values(report)
    _batteries(report)
    _optional_keys(report)
    _smart(report)
    _conversions(report)
    _power(report)
    _computed(report)
    _storage(report)
    _kernel(report)
    _user_commands(report)
    _collection(report)
    _save_gate(report)


def _surfaces_hold_values(report: Report) -> None:
    for surface in report.surfaces:
        if surface["availability"] != "available":
            continue
        if not any(entry["availability"] == "available" for entry in surface["values"].values()):
            raise Invalid(
                "an available surface needs at least one available value",
                report.path(surface["key"], field="availability"),
            )


def _batteries(report: Report) -> None:
    health = report.availability("battery_health") == "not_applicable"
    gauge = report.availability("battery_gauge") == "not_applicable"
    if health != gauge:
        raise Invalid(
            "the two battery surfaces are not applicable together or not at all",
            report.path("battery_gauge", field="availability"),
        )


def _optional_keys(report: Report) -> None:
    if report.availability("thermal_warning_level") == "available":
        recorded = report.value("thermal_warning_level", "thermal_warning_recorded") is True
        present = "thermal_warning_level" in report.by_key["thermal_warning_level"]["values"]
        if recorded != present:
            raise Invalid(
                "present exactly when a thermal warning is recorded",
                report.path("thermal_warning_level", "thermal_warning_level"),
            )
    serial = report.value("hardware_overview", "serial_number")
    last4 = report.value("hardware_overview", "serial_last4")
    if serial is not _ABSENT and last4 is not _ABSENT:
        assert isinstance(serial, str) and isinstance(last4, str)  # noqa: S101
        if not serial.endswith(last4):
            raise Invalid(
                "the full serial must end with serial_last4",
                report.path("hardware_overview", "serial_number", "value"),
            )


def _smart(report: Report) -> None:
    health = report.by_key["smart_health_snapshot"]
    wear = report.by_key["smart_wear_attributes"]
    if health["availability"] != wear["availability"]:
        raise Invalid(
            "the two SMART surfaces come from one log and share one availability",
            report.path("smart_wear_attributes", field="availability"),
        )
    if health["availability"] == "unavailable" and health["reason"] != wear["reason"]:
        raise Invalid(
            "the two SMART surfaces come from one log and share one reason",
            report.path("smart_wear_attributes", field="reason"),
        )
    if health["availability"] == "available":
        for key in ("smart_health_snapshot", "smart_wear_attributes"):
            values = report.by_key[key]["values"]
            for spec in registry.BY_KEY[key].values:
                entry = values[spec.name]
                if entry["availability"] == "unavailable" and spec.name not in _SMART_BOUNDED:
                    raise Invalid(
                        "only the temperature and spare fields can fail their bounds on an "
                        "available SMART surface",
                        report.path(key, spec.name),
                    )
    byte = report.value("smart_health_snapshot", "critical_warning_byte")
    if byte is _ABSENT:
        return
    assert isinstance(byte, int)  # noqa: S101
    expected = {flag: bool(byte >> bit & 1) for bit, flag in enumerate(_WARNING_FLAGS)}
    expected["unknown_warning_bits"] = bool(byte & 0xE0)
    for flag, bit_set in expected.items():
        value = report.value("smart_health_snapshot", flag)
        if value is not _ABSENT and value is not bit_set:
            raise Invalid(
                "disagrees with critical_warning_byte",
                report.path("smart_health_snapshot", flag, "value"),
            )


def _conversions(report: Report) -> None:
    pairs = (
        (
            "smart_health_snapshot",
            "composite_temperature_k",
            "composite_temperature_c",
            numbers.kelvin_to_celsius,
        ),
        (
            "battery_gauge",
            "temperature_centi_c",
            "temperature_c",
            lambda centi: numbers.canonical(numbers.centi_to_degrees(centi)),
        ),
        (
            "smart_wear_attributes",
            "data_units_read",
            "bytes_read",
            lambda units: str(numbers.data_units_to_bytes(int(units))),
        ),
        (
            "smart_wear_attributes",
            "data_units_written",
            "bytes_written",
            lambda units: str(numbers.data_units_to_bytes(int(units))),
        ),
    )
    for key, source, derived, convert in pairs:
        raw = report.value(key, source)
        value = report.value(key, derived)
        if raw is not _ABSENT and value is not _ABSENT and convert(raw) != value:
            raise Invalid(f"disagrees with {source}", report.path(key, derived, "value"))
    epoch = report.value("boot_time", "boot_epoch_seconds")
    if epoch is _ABSENT:
        return
    assert isinstance(epoch, int)  # noqa: S101
    rendered = datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    utc = report.value("boot_time", "boot_time_utc")
    if utc is not _ABSENT and utc != rendered:
        raise Invalid(
            "disagrees with boot_epoch_seconds", report.path("boot_time", "boot_time_utc", "value")
        )
    days = report.value("boot_time", "days_since_boot")
    if days is not _ABSENT and days != (report.instant - epoch) // 86400:
        raise Invalid(
            "disagrees with the boot and the collection instant",
            report.path("boot_time", "days_since_boot", "value"),
        )


_SAMPLE_SERIES: Final = (
    "sample_elapsed_ns",
    "sample_thermal_pressure",
    *(f"sample_{kind}_power_mw" for kind in _POWER_KINDS),
)


def _power(report: Report) -> None:
    key = "power_and_thermal_samples"
    if report.availability(key) == "available" and not report.status(key, "sample_count").available:
        raise Invalid("always 5 while the surface is available", report.path(key, "sample_count"))
    # A power output in which every value fails is the ending unparsed (Decision 2), so an
    # available surface keeps at least one sample series.
    if report.availability(key) == "available" and not any(
        report.status(key, name).available for name in _SAMPLE_SERIES
    ):
        raise Invalid(
            "an available power surface keeps at least one of its samples",
            report.path(key, "sample_elapsed_ns"),
        )
    states = report.value(key, "sample_thermal_pressure")
    if states is not _ABSENT:
        assert isinstance(states, list)  # noqa: S101
        for state in registry.THERMAL_STATES:
            name = f"thermal_{state.lower()}_count"
            count = report.value(key, name)
            if count is not _ABSENT and count != states.count(state):
                raise Invalid("disagrees with the samples", report.path(key, name, "value"))
    for kind in _POWER_KINDS:
        series = report.value(key, f"sample_{kind}_power_mw")
        if series is _ABSENT:
            continue
        assert isinstance(series, list)  # noqa: S101
        exact = [Decimal(text) for text in series]
        expected = {
            "min": numbers.canonical(min(exact)),
            "max": numbers.canonical(max(exact)),
            "mean": numbers.canonical(numbers.mean(exact)),
        }
        for stat, text in expected.items():
            name = f"{kind}_power_mw_{stat}"
            value = report.value(key, name)
            if value is not _ABSENT and value != text:
                raise Invalid("disagrees with its series", report.path(key, name, "value"))
    count = report.value("kernel_and_platform", "perf_level_count")
    for name in _PERF_OIDS:
        array = report.value("kernel_and_platform", name)
        if count is not _ABSENT and array is not _ABSENT and len(array) != count:  # type: ignore[arg-type]
            raise Invalid(
                "must have perf_level_count elements",
                report.path("kernel_and_platform", name, "value"),
            )


def _computed(report: Report) -> None:
    """A computed value is available exactly when its inputs are, with the first failing reason."""
    for key, name, inputs in _INPUTS:
        if report.availability(key) != "available":
            continue
        entry = report.by_key[key]["values"][name]
        failing = [
            status
            for status in (report.status(*source) for source in inputs)
            if not status.available
        ]
        _derived(report, key, name, entry, failing[0] if failing else None)


def _derived(report: Report, key: str, name: str, entry: dict, failing: _Status | None) -> None:
    available = entry["availability"] == "available"
    if failing is None and not available:
        raise Invalid("a computed value is available when its inputs are", report.path(key, name))
    if failing is not None:
        if available:
            raise Invalid(
                "a computed value is unavailable when an input is", report.path(key, name)
            )
        if entry["reason"] != failing.reason:
            raise Invalid(
                "must carry the reason of its first unavailable input",
                report.path(key, name, "reason"),
            )


def _storage(report: Report) -> None:
    """The storage dependency table: C11's store, its whole disk, C3's entry and C28."""
    if report.availability("startup_disk") == "available":
        count = report.status("startup_disk", "physical_store_count")
        store = report.by_key["startup_disk"]["values"]["physical_store"]
        store_count = report.value("startup_disk", "physical_store_count")
        if not count.available:
            _derived(report, "startup_disk", "physical_store", store, count)
        elif store_count != 1:
            _derived(report, "startup_disk", "physical_store", store, _Status(False, "unsupported"))
        elif store["availability"] == "unavailable" and store["reason"] != "source_changed":
            raise Invalid(
                "with one physical store, a store that did not read is source_changed",
                report.path("startup_disk", "physical_store", "reason"),
            )
        whole = report.value("startup_disk", "whole_disk")
        physical = report.value("startup_disk", "physical_store")
        if whole is not _ABSENT and physical is not _ABSENT:
            assert isinstance(physical, str)  # noqa: S101
            if whole != physical.rsplit("s", 1)[0]:
                raise Invalid(
                    "must be physical_store without its final s and digits",
                    report.path("startup_disk", "whole_disk", "value"),
                )
    whole_disk = report.status("startup_disk", "whole_disk")
    _nvme(report, whole_disk)
    _smart_chain(report, whole_disk)


def _nvme(report: Report, whole_disk: _Status) -> None:
    surface = report.by_key["nvme_devices"]
    if surface["availability"] == "unavailable":
        if not report.failed("C3") and surface["reason"] not in (
            ("source_absent", "source_changed") if whole_disk.available else ("source_changed",)
        ):
            raise Invalid(
                "not a reason the storage chain gives while C3 ran",
                report.path("nvme_devices", field="reason"),
            )
        return
    for name in NVME_ENTRY:
        entry = surface["values"][name]
        if whole_disk.available:
            if entry["availability"] == "unavailable" and entry["reason"] != "source_changed":
                raise Invalid(
                    "with the whole disk known, an entry field that did not read is source_changed",
                    report.path("nvme_devices", name, "reason"),
                )
        else:
            _derived(report, "nvme_devices", name, entry, whole_disk)
    bsd_name = report.value("nvme_devices", "bsd_name")
    whole = report.value("startup_disk", "whole_disk")
    if bsd_name is not _ABSENT and whole is not _ABSENT and bsd_name != whole:
        raise Invalid(
            "must be the startup disk's whole-disk name",
            report.path("nvme_devices", "bsd_name", "value"),
        )


def _smart_chain(report: Report, whole_disk: _Status) -> None:
    surface = report.by_key["smart_health_snapshot"]
    if not whole_disk.available:
        if surface["availability"] != "unavailable":
            raise Invalid(
                "the SMART surfaces are unavailable while the whole disk is",
                report.path("smart_health_snapshot", field="availability"),
            )
        if surface["reason"] != whole_disk.reason:
            raise Invalid(
                "must carry the whole disk's reason",
                report.path("smart_health_snapshot", field="reason"),
            )
        return
    # C28's outcome table, the part a report shows.
    reason = surface.get("reason") if surface["availability"] == "unavailable" else None
    failed = report.failed("C28")
    if reason in (None, "source_absent", "unsupported") and failed:
        raise Invalid(
            "C28's table needs no failed run here", report.command_path("C28", "failed_runs")
        )
    if reason in ("timeout", "source_changed") and not failed:
        raise Invalid(
            "C28's table needs a failed run here", report.command_path("C28", "failed_runs")
        )


def _kernel(report: Report) -> None:
    surface = report.by_key["kernel_and_platform"]
    if surface["availability"] == "unavailable":
        if surface["reason"] != "source_changed" and not report.failed("C15"):
            raise Invalid(
                "its first value's command did not fail",
                report.path("kernel_and_platform", field="reason"),
            )
        return
    values = surface["values"]
    for name, command_id in _KERNEL_OIDS.items():
        _own_command(report, name, values[name], report.failed(command_id))
    count = report.status("kernel_and_platform", "perf_level_count")
    levels = report.value("kernel_and_platform", "perf_level_count")
    for name, oids in _PERF_OIDS.items():
        entry = values[name]
        if not count.available:
            _derived(report, "kernel_and_platform", name, entry, count)
            continue
        assert isinstance(levels, int)  # noqa: S101
        _own_command(report, name, entry, any(report.failed(oid) for oid in oids[:levels]))


def _own_command(report: Report, name: str, entry: dict, failed: bool) -> None:
    available = entry["availability"] == "available"
    if failed and available:
        raise Invalid(
            "its sysctl call failed, so this value is unavailable",
            report.path("kernel_and_platform", name),
        )
    if not failed and not available and entry["reason"] != "source_changed":
        raise Invalid(
            "its sysctl call did not fail", report.path("kernel_and_platform", name, "reason")
        )


def _user_commands(report: Report) -> None:
    for command_id, keys in _FEEDS.items():
        failed = report.failed(command_id)
        reasons: set[str] = set()
        for key in keys:
            surface = report.by_key[key]
            if failed:
                if surface["availability"] != "unavailable":
                    raise Invalid(
                        f"{command_id} failed, so this surface is unavailable",
                        report.path(key, field="availability"),
                    )
                reasons.add(surface["reason"])
                if len(reasons) > 1:
                    raise Invalid(
                        f"{command_id} failed once, so every surface it feeds carries the same "
                        "reason",
                        report.path(key, field="reason"),
                    )
            elif surface["availability"] == "unavailable" and surface["reason"] not in (
                "source_changed",
                *(("source_absent",) if key == "nvme_devices" else ()),
            ):
                raise Invalid(f"{command_id} did not fail", report.path(key, field="reason"))


def _collection(report: Report) -> None:
    counts = dict.fromkeys(COUNTS, 0)
    codes: set[str] = set()
    missing_value = False
    only_unsupported = True
    for surface in report.surfaces:
        availability = surface["availability"]
        if availability == "available":
            counts["read"] += 1
            for entry in surface["values"].values():
                if entry["availability"] == "unavailable":
                    missing_value = True
                    codes.add(entry["reason"])
        elif availability == "not_applicable":
            counts["not_applicable"] += 1
        else:
            reason = surface["reason"]
            codes.add(reason)
            counts["skipped" if reason in registry.SKIPPED_REASONS else "unavailable"] += 1
            only_unsupported = only_unsupported and reason == "unsupported"
    collection = report.document["collection"]
    assert isinstance(collection, dict)  # noqa: S101
    for name in COUNTS:
        if collection[name] != counts[name]:
            raise Invalid("does not match the surfaces", f"collection.{name}")
    complete = counts["skipped"] == 0 and only_unsupported and not missing_value
    if collection["status"] != ("complete" if complete else "partial"):
        raise Invalid("does not follow from the surfaces", "collection.status")
    if collection["unexpected_reasons"] != sorted(codes & registry.UNEXPECTED_REASONS):
        raise Invalid(
            "must be the unexpected reasons present on the surfaces and values",
            "collection.unexpected_reasons",
        )


def _save_gate(report: Report) -> None:
    read = sum(surface["availability"] == "available" for surface in report.surfaces)
    identity = "available" in (
        report.availability("hardware_overview"),
        report.availability("kernel_and_platform"),
    )
    if read < SAVE_GATE or not identity:
        raise Invalid(
            "below the save gate: at least 8 surfaces must be available, including "
            "hardware_overview or kernel_and_platform",
            "surfaces",
        )
