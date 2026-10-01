"""A report's detail sections as data, before any layout: This Mac, Security settings,
System records, Storage health and wear, Battery, Memory, and the Power and thermal check.

docs/VOLTRY_MAC_SPEC.md, Decision 6 (the section order, the two labels), "How a no
degrades", Failure modes, the field inventory and transcripts 1, 2 and 7. A section is a
title, the source line beside it and rows of label, text and label chip, each row saying
whether its value is unavailable; terminal.py lays them out at 80 columns, and
report_pdf.py on the PDF's pages, with the rows the field inventory prints in the PDF alone
(``full``). Pure.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from voltry_mac import phrases, sections


@dataclass(frozen=True)
class Row:
    """One row: its label, its text and its provenance chip. An unavailable row names why
    in its text and carries no chip; in a section whose header names the provenance, an
    available row carries none either, so ``unavailable`` tells the two apart."""

    label: str
    text: str
    chip: str | None = None
    notes: tuple[str, ...] = ()
    unavailable: bool = False


@dataclass(frozen=True)
class Source:
    """A source line inside a section, above the rows it names."""

    text: str


@dataclass(frozen=True)
class Section:
    """A detail section: its title, the source line beside it, its rows and the source
    lines between them; or, instead of rows, one line of text, with its availability
    (unavailable, not_applicable). The Power and thermal check adds a subtitle and a note
    under its rows."""

    title: str
    source: str | None
    items: tuple[Row | Source, ...]
    text: str | None = None
    subtitle: str | None = None
    note: str | None = None
    availability: str = "available"


def _gap(label: str, report: phrases.Report, key: str, *names: str) -> Row:
    """An unavailable row: the words for the first of its inputs that is unavailable."""
    return Row(label, phrases.row_gap(report, key, *names), unavailable=True)


def this_mac(report: phrases.Report) -> Section:
    rows = [
        _model(report),
        _chip(report),
        _memory(report),
        _startup_disk(report),
        _serial(report),
        _macos(report),
    ]
    return Section("This Mac", "as macOS reports it", tuple(rows))


def _model(report: phrases.Report) -> Row:
    parts = [
        report.text("hardware_overview", "machine_name"),
        report.text("hardware_overview", "machine_model"),
    ]
    number = report.text("hardware_overview", "model_number")
    said = [part for part in parts if part]
    if number:
        said.append(f"model number {number}")
    if not said:
        return _gap("Model", report, "hardware_overview", "machine_name")
    return Row("Model", ", ".join(said))


def _cores(report: phrases.Report) -> tuple[str | None, str | None]:
    """The core clusters, by macOS's own names: "4 Super and 6 Efficiency cores"; with one
    half unread, the half that was read and the words for the other."""
    key = "kernel_and_platform"
    names = report.get(key, "perf_level_names")
    cpus = report.get(key, "perf_level_physical_cpus")
    named = [report.shown(str(name)) for name in names] if isinstance(names, list) else []
    counted = [phrases.thousands(count) for count in cpus] if isinstance(cpus, list) else []
    if named and counted:
        if len(named) != len(counted):  # not in a validated report
            return None, None
        clusters = [f"{count} {name}" for count, name in zip(counted, named, strict=True)]
        return f"{phrases.joined(clusters)} cores", None
    if named:
        missing = phrases.missing(
            "each cluster's core count", report, key, "perf_level_physical_cpus"
        )
        return f"{phrases.joined(named)} cores", missing
    if counted:
        missing = phrases.missing("each cluster's name", report, key, "perf_level_names")
        return f"clusters of {phrases.joined(counted)} cores", missing
    return None, None


def _chip(report: phrases.Report) -> Row:
    # The hardware overview's chip and the core clusters; sysctl's CPU brand and core
    # total are Appendix A's (the field inventory).
    chip = report.text("hardware_overview", "chip_type")
    cores, unread = _cores(report)
    gpu = report.number("gpu_configuration", "core_count")
    gpu_text = None if gpu is None else f"{phrases.thousands(gpu)}-core GPU"
    if chip is None:
        rest = ", ".join(part for part in (cores, gpu_text) if part)
        if not rest:
            return _gap("Chip", report, "hardware_overview", "chip_type")
        name = phrases.missing("the chip's name", report, "hardware_overview", "chip_type")
        said = f"{name}; {rest}"
    else:
        said = f"{chip}: {cores}" if cores else chip
        said = f"{said}, {gpu_text}" if gpu_text else said
    # Half of the clusters unread: the half read prints, and the other half's words last.
    return Row("Chip", f"{said}; {unread}" if unread else said)


def _memory(report: phrases.Report) -> Row:
    size = report.text("hardware_overview", "physical_memory_text")
    profile = report.text("memory_configuration", "size_text")
    kind = report.text("memory_configuration", "memory_type")
    maker = report.text("memory_configuration", "manufacturer")
    shown = size or profile
    made = " (manufacturer empty)" if maker == phrases.EMPTY else f" ({maker})" if maker else ""
    if shown is None:
        if not kind and not maker:
            return _gap("Memory", report, "hardware_overview", "physical_memory_text")
        name = phrases.missing("the size", report, "hardware_overview", "physical_memory_text")
        return Row("Memory", f"{name}; {kind}{made}" if kind else f"{name}; manufacturer {maker}")
    said = " ".join(part for part in (shown, kind) if part) + made
    # The two sizes compared as the terminal prints them, in the PDF too: a format character
    # or a space at the end that only the PDF prints is no disagreement.
    agree = report.plain("memory_configuration", "size_text") == report.plain(
        "hardware_overview", "physical_memory_text"
    )
    if size is None:
        # The authoritative size is unread: the other source prints, and says so.
        said += "; size from the memory profile"
    elif profile and not agree:
        said += f"; the memory profile says {profile}"
    return Row("Memory", said)


def _where(report: phrases.Report) -> str | None:
    internal = report.flag("startup_disk", "internal")
    solid = report.flag("startup_disk", "solid_state")
    if internal is None or solid is None:
        return None
    kind = "SSD" if solid else "disk"
    return f"the internal {kind}" if internal else f"an external {kind}"


def _startup_disk(report: phrases.Report) -> Row:
    """The NVMe entry's own model, size and name, and where the disk is. The field
    inventory prints the entry's own name, so without the entry the row says whether the
    disk is internal (Failure modes) and that its name was not read: the whole disk's
    name, derived from the startup volume's store, is Appendix A's, never this section's,
    whose values are all as macOS reports them (the GPT audit, pass 1, G1-03)."""
    model = report.text("nvme_devices", "device_model")
    size = report.text("nvme_devices", "size_text")
    if size is None:
        # The entry's own capacity text omitted, its byte count read: the bytes print.
        size_bytes = report.number("nvme_devices", "size_bytes")
        size = None if size_bytes is None else phrases.plural(size_bytes, "byte", "bytes")
    name = report.text("nvme_devices", "bsd_name")
    where = _where(report)
    if not (model or size or name):
        # The first unread link names why: the startup volume's store, then the entry.
        trunk = ("physical_store", "whole_disk")
        unread = (
            ("startup_disk", *trunk)
            if any(report.gap("startup_disk", each) is not None for each in trunk)
            else ("nvme_devices", "bsd_name")
        )
        if where is None:
            return _gap("Startup disk", report, *unread)
        # Failure modes: This Mac still says whether the disk is internal.
        said = phrases.missing("its name", report, *unread)
        return Row("Startup disk", f"{where}; {said}")
    head = ", ".join(part for part in (model, size, where) if part)
    if head:
        return Row("Startup disk", f"{head} ({name})" if name else head)
    return Row("Startup disk", str(name))


def _serial(report: phrases.Report) -> Row:
    full = report.text("hardware_overview", "serial_number")
    if full:
        return Row("Serial number", full)
    last = report.text("hardware_overview", "serial_last4")
    if last is None:
        return _gap("Serial number", report, "hardware_overview", "serial_last4")
    if report.entry("hardware_overview", "serial_number") is not None:
        # Asked for with --show-serial, and not given.
        said = phrases.missing("the full serial", report, "hardware_overview", "serial_number")
        return Row("Serial number", f"ending in {last} ({said})")
    return Row("Serial number", f"ending in {last} (add --show-serial to print it)")


def _macos(report: phrases.Report) -> Row:
    version = report.text("os_version", "product_version")
    build = report.text("os_version", "build_version")
    firmware = report.text("firmware_and_boot", "boot_rom_version")
    if version is None and build:
        # The build still prints, and the version says it was not read.
        name = phrases.missing("the version", report, "os_version", "product_version")
        said = f"{name}; build {build}"
    elif version is None and firmware:
        # Neither read: the words for both, then the firmware apart from them.
        names = ("product_version", "build_version")
        both = phrases.missing("the version and build", report, "os_version", *names, plural=True)
        return Row("macOS", f"{both}; firmware {firmware}")
    elif version is None:
        return _gap("macOS", report, "os_version", "product_version")
    else:
        said = f"{version} ({build})" if build else version
    return Row("macOS", f"{said}, firmware {firmware}" if firmware else said)


def security(report: phrases.Report) -> Section:
    rows = []
    for key, name, _, full in sections.SECURITY:
        state = report.flag(key, name)
        rows.append(
            _gap(full, report, key, name) if state is None else Row(full, "On" if state else "Off")
        )
    return Section("Security settings", "as macOS reports it", tuple(rows))


def system_records(report: phrases.Report, *, full: bool = False) -> Section:
    """The section; ``full`` adds the formula the last restart comes from, as the PDF prints
    derived values."""
    epoch = report.number("boot_time", "boot_epoch_seconds")
    days = report.number("boot_time", "days_since_boot")
    if epoch is None or days is None:
        restart = _gap("Last restart", report, "boot_time", "boot_epoch_seconds", "days_since_boot")
    else:
        offset = phrases.Local.parse(str(report.document["collected_at_local"])).offset
        year, month, day = phrases.civil((epoch + offset * 60) // 86400)
        ago = {0: "less than a day ago", 1: "1 day ago"}.get(
            days, f"{phrases.thousands(days)} days ago"
        )
        said = f"{phrases.date(year, month, day)}, {ago}"
        if full:
            said += " (macOS's boot time, and the whole days from it to the collection)"
        restart = Row("Last restart", said, "derived")
    count = report.number("panic_report_count", "count")
    panics = (
        _gap("Panic reports", report, "panic_report_count", "count")
        if count is None
        else Row("Panic reports", f"{phrases.thousands(count)} kept on this Mac", "derived")
    )
    return Section("System records", "from the boot clock and the crash reports", (restart, panics))


def storage(report: phrases.Report, *, full: bool = False) -> Section:
    """The section; ``full`` adds what the field inventory prints in the PDF alone: the
    critical warning when none is set, data read, power cycles, and the Kelvin reading
    beside the temperature it gives."""
    status = report.text("nvme_devices", "smart_status")
    items: list[Row | Source] = [
        (
            Row("SMART status", status, "reported")
            if status
            else _gap("SMART status", report, "nvme_devices", "smart_status")
        ),
        Source("from the disk's own controller (IOKit)"),
    ]
    gap = report.gap("smart_health_snapshot")
    if gap is not None:
        items.append(Row("Health log", phrases.words(report, gap).row, unavailable=True))
        return Section("Storage health and wear", "from macOS's disk profile", tuple(items))
    byte = report.number("smart_health_snapshot", "critical_warning_byte")
    if full and not byte:
        shown = None if byte is None else "none"
        warning = "critical_warning_byte"
        items.append(
            _value_row(report, "Critical warning", phrases.SMART[0], warning, shown, "reported")
        )
    if byte:
        said = phrases.warnings(byte, phrases.ROW_WARNINGS)
        bits = [bit for bit in range(8) if byte >> bit & 1]
        where = (
            f"bit {bits[0]}" if len(bits) == 1 else f"bits {phrases.joined([str(b) for b in bits])}"
        )
        items.append(Row("Critical warning", f"{said} ({where})", "reported"))
    health, wear = phrases.SMART
    used = report.number(wear, "percentage_used")
    spare = report.number(health, "available_spare_percent")
    threshold = report.number(health, "available_spare_threshold_percent")
    celsius = report.number(health, "composite_temperature_c")
    kelvin = report.number(health, "composite_temperature_k")
    temperature = None if celsius is None else f"{celsius} °C"
    if full and temperature is not None and kelvin is not None:
        temperature += f" ({phrases.thousands(kelvin)} K minus 273.15, to the nearest degree)"
    items += [
        _value_row(
            report,
            "Endurance used",
            wear,
            "percentage_used",
            None if used is None else f"{used}%",
            "reported",
        ),
        _value_row(
            report,
            "Available spare",
            health,
            ("available_spare_percent", "available_spare_threshold_percent"),
            (
                None
                if spare is None and threshold is None
                else f"{_part(spare, '{}%', _OUT_OF_RANGE)} "
                f"(threshold {_part(threshold, '{}%', _OUT_OF_RANGE)})"
            ),
            "reported",
        ),
        *(
            _data_row(report, label, direction)
            for label, direction in (("Data read", "read"), ("Data written", "written"))
            if full or direction == "written"
        ),
    ]
    for label, name in (
        ("Power-on hours", "power_on_hours"),
        *((("Power cycles", "power_cycles"),) if full else ()),
        ("Unsafe shutdowns", "unsafe_shutdowns"),
        ("Media errors", "media_errors"),
        ("Error log entries", "error_log_entries"),
    ):
        count = report.number(wear, name)
        shown = None if count is None else phrases.thousands(count)
        items.append(_value_row(report, label, wear, name, shown, "measured"))
    items.append(
        _value_row(
            report,
            "Temperature now",
            health,
            "composite_temperature_c",
            temperature,
            "derived",
        )
    )
    return Section("Storage health and wear", "from macOS's disk profile", tuple(items))


def _data_row(report: phrases.Report, label: str, direction: str) -> Row:
    """Data read or written: the bytes, with the count of 512,000-byte units they come from."""
    wear = phrases.SMART[1]
    units = report.number(wear, f"data_units_{direction}")
    counted = report.get(wear, f"bytes_{direction}")
    shown = (
        None
        if units is None or not isinstance(counted, str)
        else f"{phrases.total(counted)} ({phrases.plural(units, 'unit', 'units')} of 512,000 B)"
    )
    names = (f"data_units_{direction}", f"bytes_{direction}")
    return _value_row(report, label, wear, names, shown, "derived")


# A row with two values shows the one it has, and names the other's gap in a word or two.
_OUT_OF_RANGE: Final = "out of range"


def _part(value: object | None, form: str, missing: str) -> str:
    return missing if value is None else form.format(value)


def _either(flag: bool | None, true: str, false: str, missing: str) -> str:
    return missing if flag is None else true if flag else false


def battery(report: phrases.Report, *, full: bool = False) -> Section:
    """The section; ``full`` adds what the field inventory prints in the PDF alone: the
    permanent-failure flag when it is not set, and the gauge's hundredths of a degree
    beside the temperature they give."""
    if report.state("battery_health") == "not_applicable":
        return Section(
            "Battery",
            None,
            (),
            text="Not applicable: this Mac has no battery.",
            availability=sections.NOT_APPLICABLE,
        )
    items: list[Row | Source] = []
    gap = report.gap("battery_health")
    if gap is not None:
        items.append(Row("Power report", phrases.words(report, gap).row, unavailable=True))
    else:
        items += _power_report_rows(report)
    items.append(Source("from the battery's own gauge"))
    gap = report.gap("battery_gauge")
    if gap is not None:
        items.append(Row("Battery gauge", phrases.words(report, gap).row, unavailable=True))
        # Decision 8: the authoritative count unread, the other source's prints, named.
        other = report.number("battery_health", "cycle_count")
        if other is not None:
            said = f"{phrases.thousands(other)} (macOS's power report)"
            items.append(Row("Charge cycles", said, "measured"))
    else:
        items += _gauge_rows(report, full)
    return Section("Battery", "from macOS's power report", tuple(items))


def _value_row(
    report: phrases.Report,
    label: str,
    key: str,
    names: str | Sequence[str],
    shown: str | None,
    chip: str,
) -> Row:
    """A row with its chip, or, when a value it needs is unavailable, that value's words."""
    if shown is not None:
        return Row(label, shown, chip)
    return _gap(label, report, key, *([names] if isinstance(names, str) else names))


def _power_report_rows(report: phrases.Report) -> list[Row]:
    key = "battery_health"
    condition = report.text(key, "condition")
    capacity = report.number(key, "maximum_capacity_percent")
    charge = report.number(key, "state_of_charge_percent")
    full = report.flag(key, "fully_charged")
    connected = report.flag(key, "charger_connected")
    charging = report.flag(key, "is_charging")
    charge_text = None
    if charge is not None and full is not None:
        charge_text = f"{charge}%, fully charged" if full else f"{charge}%"
    elif charge is not None or full is not None:
        # One of the two read: it shows, and the other says it was not reported.
        charge_text = "; ".join(
            [
                _part(charge, "{}%", f"the charge level is {phrases.NOT_REPORTED}"),
                _either(
                    full,
                    "fully charged",
                    "not fully charged",
                    f"whether it is fully charged is {phrases.NOT_REPORTED}",
                ),
            ]
        )
    source = None
    if connected is not None and charging is not None:
        if connected:
            source = (
                "charger connected, charging" if charging else "charger connected, not charging"
            )
        else:
            source = "charging" if charging else "on battery power"
    elif connected is not None or charging is not None:
        source = "; ".join(
            [
                _either(
                    connected,
                    "charger connected",
                    "charger not connected",
                    f"whether a charger is connected is {phrases.NOT_REPORTED}",
                ),
                _either(
                    charging,
                    "charging",
                    "not charging",
                    f"whether it is charging is {phrases.NOT_REPORTED}",
                ),
            ]
        )
    return [
        _value_row(report, "Condition", key, "condition", condition, "reported"),
        _value_row(
            report,
            "Maximum capacity",
            key,
            "maximum_capacity_percent",
            None if capacity is None else f"{capacity}%",
            "reported",
        ),
        _value_row(
            report,
            "Charge now",
            key,
            ("state_of_charge_percent", "fully_charged"),
            charge_text,
            "measured",
        ),
        _value_row(
            report, "Power source", key, ("charger_connected", "is_charging"), source, "measured"
        ),
    ]


def _gauge_rows(report: phrases.Report, full: bool) -> list[Row]:
    key = "battery_gauge"
    cycles = report.number(key, "cycle_count")
    other = report.number("battery_health", "cycle_count")
    if cycles is None:
        # Under the gauge's source line, the power report's count names its own source.
        cycle_text = None if other is None else f"{phrases.thousands(other)} (macOS's power report)"
    elif other is not None and other != cycles:
        cycle_text = (
            f"{phrases.thousands(cycles)} (macOS's power report: {phrases.thousands(other)})"
        )
    else:
        cycle_text = phrases.thousands(cycles)
    design_cycles = report.number(key, "design_cycle_count")
    charged = report.number(key, "full_charge_capacity_mah")
    design = report.number(key, "design_capacity_mah")
    celsius = report.decimal(key, "temperature_c")
    hundredths = report.number(key, "temperature_centi_c")
    temperature = None if celsius is None else f"{phrases.decimal(celsius, 1)} °C"
    if full and temperature is not None and hundredths is not None:
        temperature += f" ({phrases.thousands(hundredths)} hundredths of a degree)"
    rows = [
        _value_row(report, "Charge cycles", key, "cycle_count", cycle_text, "measured"),
        _value_row(
            report,
            "Design cycle count",
            key,
            "design_cycle_count",
            None if design_cycles is None else phrases.thousands(design_cycles),
            "reported",
        ),
        _value_row(
            report,
            "Full charge now",
            key,
            "full_charge_capacity_mah",
            None if charged is None else f"{phrases.thousands(charged)} mAh",
            "measured",
        ),
        _value_row(
            report,
            "Design capacity",
            key,
            "design_capacity_mah",
            None if design is None else f"{phrases.thousands(design)} mAh",
            "reported",
        ),
        _value_row(
            report,
            "Temperature",
            key,
            "temperature_c",
            temperature,
            "derived",
        ),
    ]
    failure = report.flag(key, "permanent_failure")
    if failure or full:
        shown = None if failure is None else "flag set" if failure else "none set"
        rows.append(
            _value_row(report, "Permanent failure", key, "permanent_failure", shown, "reported")
        )
    return rows


def memory(report: phrases.Report) -> Section:
    free = report.number("memory_pressure", "free_percent")
    rows = [
        _value_row(
            report,
            "Memory pressure now",
            "memory_pressure",
            "free_percent",
            None if free is None else f"{free}% free",
            "measured",
        )
    ]
    key = "memory_error_ledger"
    gap = report.gap(key)
    if gap is not None:
        rows.append(Row("Memory error records", phrases.words(report, gap).row, unavailable=True))
    else:
        rows.append(_ledger_row(report))
    rows.append(_gap("ECC error counters", report, "ecc_ras_telemetry"))
    return Section("Memory", None, tuple(rows))


def _ledger_row(report: phrases.Report) -> Row:
    """Each count the log gave, the log's own count beside it when that differs, the log's
    own count in place of a record count macOS left unread, and a count it did not give as
    not reported, never as zero (Decision 6)."""
    key = "memory_error_ledger"
    rows = {kind: report.number(key, f"{kind}_event_rows") for kind in phrases.KINDS}
    own = {kind: report.number(key, f"{kind}_reported_count") for kind in phrases.KINDS}
    printed: list[int] = []
    # Whether a count the row prints is the log's own, a sum over its records, not records.
    stood = False
    if all(rows[kind] is None for kind in phrases.KINDS):
        counts = [(kind, own[kind]) for kind in phrases.KINDS if own[kind] is not None]
        # An available surface has a value read, so a log with no record count has its own.
        assert counts  # noqa: S101 - a validated document
        listed = phrases.joined(
            [f"{phrases.thousands(count or 0)} {kind}" for kind, count in counts]
        )
        unread = [kind for kind in phrases.KINDS if own[kind] is None]
        what = f"its records, and the {unread[0]} count," if unread else "its records"
        said = f"the log counts {listed}; {what} were {phrases.NOT_REPORTED}"
        printed, stood = [count or 0 for _, count in counts], True
    else:
        parts = []
        for kind in phrases.KINDS:
            count, stand_in = rows[kind], own[kind]
            if count is None:
                if stand_in is None:
                    parts.append(f"{kind} {phrases.NOT_REPORTED}")
                else:
                    parts.append(
                        f"{kind} records {phrases.NOT_REPORTED} (the log counts "
                        f"{phrases.thousands(stand_in)})"
                    )
                    printed.append(stand_in)
                    stood = True
                continue
            part = f"{phrases.thousands(count)} {kind}"
            if stand_in is None:
                part += " (the log's own count not reported)"
            elif stand_in != count:
                part += f" (the log counts {phrases.thousands(stand_in)})"
            parts.append(part)
            printed.append(count)
        said = ", ".join(parts)
    note = "From Apple's private memory error log: undocumented, retention unknown."
    if any(printed):
        note += (
            " These are what the log holds now; counts are not a rate."
            if stood
            else " These are records present now; counts are not a rate."
        )
    if 0 in printed:
        note += " Zero means none are recorded there now, not none ever."
    return Row("Memory error records", said, "measured", (note,))


def power(report: phrases.Report) -> Section:
    key = "power_and_thermal_samples"
    gap = report.gap(key)
    if gap is not None:
        return Section(
            "Power and thermal check",
            None,
            (),
            text=phrases.words(report, gap).row + ".",
            availability="unavailable",
        )
    total = report.number(key, "sample_count") or 5
    states = sections.states(report)
    rows = [
        (
            Row("Thermal pressure", states, "derived")
            if states is not None
            else _gap("Thermal pressure", report, key, "thermal_nominal_count")
        )
    ]
    for label, kind, combined in (
        ("Processor power", "combined", True),
        ("CPU power", "cpu", False),
        ("GPU power", "gpu", False),
        ("Neural Engine", "ane", False),
    ):
        low = report.decimal(key, f"{kind}_power_mw_min")
        high = report.decimal(key, f"{kind}_power_mw_max")
        mean = report.decimal(key, f"{kind}_power_mw_mean")
        if low is None or high is None or mean is None:
            rows.append(_gap(label, report, key, f"{kind}_power_mw_min"))
            continue
        if low == high:
            (shown,) = phrases.watts([low])
            rows.append(Row(label, f"{shown} W in every sample", "derived"))
            continue
        low_w, high_w, mean_w = phrases.watts([low, high, mean])
        extra = " combined" if combined else ""
        rows.append(Row(label, f"{low_w} to {high_w} W{extra}, average {mean_w} W", "derived"))
    return Section(
        "Power and thermal check",
        None,
        tuple(rows),
        subtitle=f"({total} seconds, no load applied)",
        note=f"{power_labels(total)} Not wall power. Not comparable between Macs.",
    )


def power_labels(total: int) -> str:
    """Which of the check's values macOS estimates and which are computed from them."""
    return (
        "Each sample is a macOS estimate (reported); the ranges, averages and counts are "
        f"computed from the {total} samples (derived)."
    )


def warning_level(report: phrases.Report) -> Row:
    """macOS's own thermal warning level, which the PDF prints on page 4 whether or not the
    power check ran (the field inventory)."""
    said = sections.warning_level(report)
    if said is None:
        return _gap(
            "Thermal warning level", report, "thermal_warning_level", "thermal_warning_recorded"
        )
    return Row("Thermal warning level", said, "reported")
