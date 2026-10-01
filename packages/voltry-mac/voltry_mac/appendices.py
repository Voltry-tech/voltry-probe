"""The PDF's appendices as data: everything the report tried to read (Appendix A) and how
it was made (Appendix B).

docs/VOLTRY_MAC_SPEC.md, "Page by page" (pages 5 and on), the field inventory (the values
it assigns to Appendix A, and its metadata table) and Decision 4's render rules (each
command's fixed template from the producing version's manifest, or the IDs alone with a
note). The words for every gap are phrases.py's, as the terminal's are. report_pdf.py lays
the appendices out. Pure: it reads the report document and nothing else.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from voltry_mac import phrases, registry, versions

# Each surface's own name, distinct where the Not read line groups two under one.
NAMES: Final = {
    "os_version": "macOS version",
    "hardware_overview": "Hardware overview",
    "firmware_and_boot": "Firmware",
    "nvme_devices": "Startup disk drive entry",
    "gpu_configuration": "GPU",
    "memory_configuration": "Memory profile",
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
    "smart_health_snapshot": "SSD health log: health",
    "smart_wear_attributes": "SSD health log: wear",
    "panic_report_count": "Panic reports",
    "memory_error_ledger": "Memory error records",
    "power_and_thermal_samples": "Power and thermal check",
    "ecc_ras_telemetry": "ECC error counters",
}

# As whom each privilege reads, after the registry's own interface text.
_AS: Final = {
    "user": "as you",
    "admin": "as you, from a folder only administrator accounts can read",
    "service": "through sudo, sandboxed",
    "root": "as root, through sudo, sandboxed",
}

NOT_APPLICABLE: Final = "not applicable"
UNAVAILABLE: Final = "unavailable"
_NO_BATTERY: Final = "Not applicable: this Mac has no battery."


@dataclass(frozen=True)
class Tried:
    """One surface in Appendix A's table."""

    key: str
    name: str
    result: str
    how: str
    why: str


def tried(report: phrases.Report) -> list[Tried]:
    """Every surface in registry order: its result with its reason code, how it is read and
    as whom, and why it, or any value inside it, was not read, with each value's code."""
    rows = []
    for spec in registry.SURFACES:
        how = f"{spec.interface}, {_AS[spec.privilege]}" if spec.values else spec.interface
        state = report.state(spec.key)
        gap = report.gap(spec.key)
        if state == "not_applicable":
            result, why = NOT_APPLICABLE, "This Mac has no battery."
        elif gap is not None:
            result, why = f"{UNAVAILABLE}: {gap.reason}", phrases.words(report, gap).row
        else:
            said: dict[str, str] = {}
            for value in spec.values:
                found = report.gap(spec.key, value.name)
                if found is not None:
                    name = f"{phrases.gap_name(found)} ({found.reason})"
                    said.setdefault(name, phrases.words(report, found).phrase)
            result, why = "available", " ".join(f"{name}: {text}." for name, text in said.items())
        rows.append(Tried(spec.key, NAMES[spec.key], result, how, why))
    return rows


@dataclass(frozen=True)
class Value:
    """One value the field inventory prints in Appendix A: its text, and its provenance
    chip when read or its availability chip when not."""

    key: str
    name: str
    label: str
    text: str
    chip: str | None
    availability: str | None


# (label, surface, value, unit after the number)
_VALUES: Final = (
    ("Metal support", "gpu_configuration", "metal_family", ""),
    ("OS loader version", "firmware_and_boot", "os_loader_version", ""),
    ("Model identifier (sysctl)", "kernel_and_platform", "hw_model", ""),
    ("Board ID", "kernel_and_platform", "hw_target", ""),
    ("CPU brand", "kernel_and_platform", "cpu_brand", ""),
    ("Apple silicon", "kernel_and_platform", "arm64", ""),
    ("CPU count", "kernel_and_platform", "cpu_count", ""),
    ("Memory total", "kernel_and_platform", "memory_bytes", " bytes"),
    ("Drive firmware revision", "nvme_devices", "device_revision", ""),
    ("TRIM support", "nvme_devices", "trim_support", ""),
    ("Drive capacity", "nvme_devices", "size_bytes", " bytes"),
    ("Drive entries", "nvme_devices", "entry_count", ""),
    ("Physical stores", "startup_disk", "physical_store_count", ""),
    ("Physical store", "startup_disk", "physical_store", ""),
    ("Battery gauge chip", "battery_health", "gauge_device_name", ""),
    ("Battery gauge firmware", "battery_health", "gauge_firmware_version", ""),
    ("Battery gauge hardware", "battery_health", "gauge_hardware_revision", ""),
    ("Memory size (memory profile)", "memory_configuration", "size_text", ""),
    ("Charge cycles (power report)", "battery_health", "cycle_count", ""),
    ("Virtual machine", "virtualization_state", "vmm_present", ""),
)
_PROVENANCE: Final = {
    (spec.key, value.name): value.provenance for spec in registry.SURFACES for value in spec.values
}


def _text(report: phrases.Report, key: str, name: str, unit: str) -> str | None:
    found = report.get(key, name)
    if isinstance(found, bool):
        return "yes" if found else "no"
    if isinstance(found, int):
        return f"{phrases.thousands(found)}{unit}"
    return report.text(key, name)


def values(report: phrases.Report) -> list[Value]:
    """The values the field inventory assigns to Appendix A, in its order."""
    found = []
    for label, key, name, unit in _VALUES:
        text = _text(report, key, name, unit)
        if report.state(key) == "not_applicable":
            found.append(Value(key, name, label, _NO_BATTERY, None, NOT_APPLICABLE))
        elif text is None:
            said = phrases.row_gap(report, key, name)
            found.append(Value(key, name, label, said, None, UNAVAILABLE))
        else:
            found.append(Value(key, name, label, text, _PROVENANCE[(key, name)], None))
    return found


# The cleanups a payload that ran can have, each with its guarantee (Decision 2).
GUARANTEED: Final = ("verified", "survivor", "listing_failed")


@dataclass(frozen=True)
class Line:
    """One line of Appendix B; mono for codes, IDs and links, printed as they are, and wide
    for a link or an ID set across the page, whole on one line when it fits and broken only
    after a slash when it does not."""

    label: str
    text: str
    mono: bool = False
    wide: bool = False


SOURCE: Final = (
    "https://github.com/Voltry-tech/voltry-probe/tree/voltry-mac-v{version}/packages/voltry-mac"
)
PYPI: Final = "https://pypi.org/project/voltry-mac/{version}/"
# Decision 2: the one thing the run changes, which the README and Appendix B both say.
SUDO: Final = (
    "One thing: voltry-mac clears the sudo authorization remembered for your account (per "
    "terminal by default, for every terminal under a global timestamp policy) before and "
    "after the administrator reads, and warns you if the final clear fails. The Prepare and "
    "Final clear lines above record this run's."
)
# A run that never prepared sudo, because the administrator reads were declined or skipped,
# changed nothing (the review of #352, round 2).
UNCHANGED: Final = (
    "Nothing: the administrator reads did not run, so voltry-mac left the sudo authorization "
    "as it was. The Prepare and Final clear lines above record this run's."
)


def _macos(report: phrases.Report) -> str:
    version = report.text("os_version", "product_version")
    if version is None:
        return phrases.row_gap(report, "os_version", "product_version")
    name = report.text("os_version", "product_name") or "macOS"
    build = report.text("os_version", "build_version")
    return f"{name} {version} ({build})" if build else f"{name} {version}"


def _replaced(count: int) -> str:
    if count == 0:
        return "none"
    if count == 1:
        return "1 character outside the PDF's character set was printed as ?"
    return (
        f"{phrases.thousands(count)} characters outside the PDF's character set were printed as ?"
    )


def _elevation(record: Mapping[str, object]) -> list[Line]:
    """The full elevation record, each field as its code."""
    checks = record["checks"]
    assert isinstance(checks, Mapping)  # noqa: S101 - a validated document
    lines = [("Consent", f"{record['consent']}")]
    if record["skip_cause"] is not None:
        lines[0] = ("Consent", f"{record['consent']}, skip cause {record['skip_cause']}")
    lines += [
        ("Mode", str(record["mode"])),
        ("Service account", str(checks["service_account"])),
        ("Sandbox probe", str(checks["sandbox_probe"])),
        ("Process listing", str(checks["listing"])),
        ("Prepare (sudo -k)", str(record["prepare"])),
        ("Authenticate (sudo -v)", str(record["authenticate"])),
    ]
    guarantees: dict[int, Line] = {}
    for label, name in (("Memory-error step", "count"), ("Power and thermal step", "power")):
        step = record[name]
        assert isinstance(step, Mapping)  # noqa: S101 - a validated document
        lines.append((label, f"{step['ending']}, cleanup {step['cleanup']}"))
        if step["cleanup"] in GUARANTEED:
            # Decision 2's guarantee, stated exactly and conditionally, beside the cleanup
            # it qualifies (the GPT audit, pass 3, G3-04).
            guarantees[len(lines) - 1] = Line("What it covers", phrases.guarantee(step["cleanup"]))
    cleared = str(record["cleared"])
    if record["clear_error"] is not None:
        cleared += f", {record['clear_error']}"
    lines.append(("Final clear (sudo -k)", cleared))
    out: list[Line] = []
    for index, (label, text) in enumerate(lines):
        out.append(Line(label, text, mono=True))
        if index in guarantees:
            out.append(guarantees[index])
    return out


def drawing(made_by: str, drawn_by: str | None) -> str:
    """The package version drawing the PDF: drawn_by, or made_by, the version that made the
    report, when drawn_by is None. It must be a version a report could hold, so the note and
    /Producer never name an empty, blank or padded one."""
    if drawn_by is None:
        return made_by
    if not versions.is_version(drawn_by):
        raise ValueError(
            f"the drawing version must be a PEP 440 version of at most 32 characters, "
            f"not {drawn_by!r}"
        )
    return drawn_by


def made(
    report: phrases.Report, *, renderer: str, replaced: int, drawn_by: str | None = None
) -> list[Line]:
    """Appendix B's lines: the versions that made the report, and a note naming both the
    versions that made it and the ones that drew this PDF when either differs (Decision 4,
    and Failure modes' render row); the macOS build, the collection time, the validated
    flag, the elevation record and what the run changes, the characters replaced, the full
    report ID, and the public source and the PyPI page of the producing version. drawn_by
    is the package version drawing the PDF, None for the version that made the report, so
    the same report, version and renderer give the same PDF. An unknown time zone leaves the
    offset alone (Decision 8)."""
    document = report.document
    tool = document["tool"]
    platform = document["platform"]
    assert isinstance(tool, Mapping) and isinstance(platform, Mapping)  # noqa: S101
    made_by = (
        f"voltry-mac {tool['version']}, renderer {tool['renderer_version']}, "
        f"Python {tool['python']}, {tool['architecture']}"
    )
    if tool["rosetta"]:
        made_by += ", under Rosetta"
    lines = [Line("Made by", made_by)]
    drawn = drawing(str(tool["version"]), drawn_by)
    if drawn != tool["version"] or renderer != tool["renderer_version"]:
        lines.append(
            Line(
                "Note",
                f"This PDF was drawn by voltry-mac {drawn}, renderer {renderer}; the report "
                f"was made by voltry-mac {tool['version']}, renderer {tool['renderer_version']}, "
                "so this file may differ from the original PDF.",
            )
        )
    local = str(document["collected_at_local"])
    if document["time_zone"] != "unknown":
        local += f" ({document['time_zone']})"
    return [
        *lines,
        Line("macOS", _macos(report)),
        Line("Collected, UTC", str(document["collected_at_utc"])),
        Line("Collected, local time", local),
        Line("Validated configuration", "yes" if platform["validated"] else "no"),
        *_elevation(report.elevation),
        Line("What it changes", UNCHANGED if report.elevation["prepare"] == "not_run" else SUDO),
        Line("Characters replaced", _replaced(replaced)),
        Line("Report ID", str(document["report_id"]), mono=True, wide=True),
        Line("Source", SOURCE.format(version=tool["version"]), mono=True, wide=True),
        Line("PyPI", PYPI.format(version=tool["version"]), mono=True, wide=True),
    ]


@dataclass(frozen=True)
class Ran:
    """One command record: its ID, runs, failed runs, total time and fixed template."""

    id: str
    runs: str
    failed: str
    time: str
    template: str


def commands(report: phrases.Report, templates: Mapping[str, str] | None) -> list[Ran]:
    """Each command that ran, with its template from the producing version's manifest;
    every ID has none when the manifest is unknown, and an ID the manifest lacks says so."""
    records = report.document["commands"]
    tool = report.document["tool"]
    assert isinstance(records, list) and isinstance(tool, Mapping)  # noqa: S101
    missing = f"(not in the manifest of voltry-mac {tool['version']})"
    known = templates or {}
    return [
        Ran(
            str(record["id"]),
            phrases.thousands(record["runs"]),
            phrases.thousands(record["failed_runs"]),
            f"{phrases.thousands(record['duration_ms'])} ms",
            known.get(str(record["id"]), "" if templates is None else missing),
        )
        for record in records
    ]


def unknown_templates(version: str) -> str:
    """The note Appendix B prints when the producing version's manifest is unknown."""
    return (
        f"This renderer does not know the command templates of voltry-mac {version}, so the "
        "commands are listed by ID alone."
    )
