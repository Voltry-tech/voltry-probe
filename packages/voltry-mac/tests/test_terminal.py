"""The terminal summary (docs/VOLTRY_MAC_SPEC.md, "CLI transcripts", Decision 6, Decision 7,
"How a no degrades", Failure modes and the field inventory's Terminal column).

The summary is a pure function of the report document: the same findings as the PDF,
concise, at 80 columns. Transcript 1 is generated from the m5-laptop fixture exactly, apart
from the made-up report ID and one space in a header; transcripts 2 and 7 follow the same
rules (tests/ci/test_voltry_mac_transcripts.py compares them with the spec). The layout,
measured from transcript 1: prose at most 69 columns; At a glance topics at column 2 and
text at 12, wrapped at 50 with the label chip at column 63, or at 56 without one; detail
rows with the label chip at column 64 and the source lines ending at column 72.
"""

from __future__ import annotations

import copy
import itertools
import re
import unicodedata
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
import voltry_mac_test_reports as r

from voltry_mac import canonical, terminal, validate

GOLDEN = Path(__file__).resolve().parent / "golden" / "terminal"
CHIPS = ("measured", "reported", "derived")
CONSENT_NO = r.declined_record("no")


# The few documents the validator refuses that a test still renders, to show the summary
# stays safe on one anyway (defense in depth).
_REFUSED: list[dict] = []


def refused(document: dict) -> dict:
    """A document the validator refuses, which summary() will render: each test that uses
    one says what the validator refuses."""
    with pytest.raises(canonical.Invalid):
        validate.validate(document)
    _REFUSED.append(document)
    return document


def summary(document: dict) -> str:
    # Every other document these tests render is one the validator accepts: the summary is
    # drawn only from a validated report, so a test on a document it refuses shows nothing
    # a Mac owner could see.
    if not any(document is each for each in _REFUSED):
        validate.validate(document)
    return terminal.summary(document)


def lines(document: dict) -> list[str]:
    text = summary(document)
    assert text.endswith("\n") and not text.endswith("\n\n")
    return text[:-1].split("\n")


def section(document: dict, title: str) -> list[str]:
    """The lines of one section, from its header to the blank line after it."""
    found = lines(document)
    start = next(i for i, line in enumerate(found) if line.startswith(title))
    end = next((i for i in range(start, len(found)) if found[i] == ""), len(found))
    return found[start:end]


def _row(document: dict, title: str, label: str) -> tuple[list[str], int]:
    found = section(document, title)
    start = next(i for i, line in enumerate(found) if line.startswith(f"  {label}  "))
    return found[start:], len(found[start]) - len(found[start][2 + len(label) :].lstrip())


def row(document: dict, title: str, label: str) -> str:
    """One detail row: its value with the continuation lines at the value's column joined,
    spaces collapsed, then its chip, if any."""
    found, column = _row(document, title, label)
    first = found[0][column:]
    chip = re.search(r" +(measured|reported|derived)$", first)
    parts = [first[: chip.start()] if chip else first]
    for line in found[1:]:
        # A continuation starts at the value's column; a source line sits further right.
        if not line.startswith(" " * column) or line[column : column + 1] in ("", " "):
            break
        parts.append(line.strip())
    text = " ".join(" ".join(parts).split())
    return f"{text} {chip[1]}" if chip else text


def notes(document: dict, title: str, label: str) -> str:
    """The note lines under a row, indented four, joined."""
    found, column = _row(document, title, label)
    rest = [line for line in found[1:] if not line.startswith(" " * column)]
    taken = []
    for line in rest:
        if not line.startswith("    "):
            break
        taken.append(line.strip())
    return " ".join(taken)


def glance(document: dict) -> list[str]:
    """At a glance as entries: the topic, the text with its continuations joined, then the
    chip, if any."""
    entries: list[list[str]] = []
    for line in section(document, "AT A GLANCE")[1:]:
        chip = re.search(r" +(measured|reported|derived)$", line)
        text = line[: chip.start()] if chip else line
        if line[2:12].strip():
            entries.append([text[2:], chip[1] if chip else ""])
        else:
            entries[-1][0] += " " + text.strip()
    return [" ".join(f"{text} {chip}".split()) for text, chip in entries]


def title(document: dict) -> str:
    """The title block below its two fixed lines, joined."""
    found = lines(document)
    return " ".join(found[2 : found.index("")])


def load(name: str) -> dict:
    return r.load(name)


def m5() -> dict:
    return r.load("m5-laptop")


def history(name: str, key: str) -> dict:
    record, count, power = r.LEGAL[key]
    return r.history(name, record, count, power)


def declined() -> dict:
    return r.history(
        "m5-laptop", CONSENT_NO, ("declined", "not_attempted"), ("declined", "not_attempted")
    )


def edited(name: str, *edits) -> dict:
    document = r.load(name)
    for edit in edits:
        edit(document)
    return r.finish(document)


def width(line: str) -> int:
    """Terminal columns: wide characters two, and marks that join the letter before them
    and conjoining Hangul vowels and finals none."""

    def cell(c: str) -> int:
        point = ord(c)
        if unicodedata.category(c) in ("Mn", "Me") or any(
            low <= point <= high for low, high in ((0x1160, 0x11FF), (0xD7B0, 0xD7FF))
        ):
            return 0
        return 2 if unicodedata.east_asian_width(c) in "WF" else 1

    return sum(cell(c) for c in line)


# --- goldens ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "document"),
    [
        ("m5-laptop", m5),
        ("concerning-desktop", lambda: load("concerning-desktop")),
        ("m5-laptop-declined", declined),
    ],
)
def test_the_summary_matches_its_golden(name, document):
    assert summary(document()) == (GOLDEN / f"{name}.txt").read_text()


# --- layout, over every legal elevation history and many edits ---------------------------------


def _documents() -> list[tuple[str, dict]]:
    found = [("m5-laptop", m5()), ("concerning-desktop", load("concerning-desktop"))]
    for key in r.LEGAL:
        for name in r.NAMES:
            found.append((f"{name}: {key}", history(name, key)))
    return found


DOCUMENTS = _documents()


@pytest.mark.parametrize(("label", "document"), DOCUMENTS, ids=[d[0] for d in DOCUMENTS])
def test_every_line_fits_80_columns_with_no_trailing_space(label, document):
    for line in lines(document):
        assert width(line) <= 80, line
        assert line == line.rstrip(), line


@pytest.mark.parametrize(("label", "document"), DOCUMENTS, ids=[d[0] for d in DOCUMENTS])
def test_label_chips_sit_in_their_column(label, document):
    in_glance = False
    for line in lines(document):
        if line.isupper() or line == "":
            in_glance = line == "AT A GLANCE"
            continue
        chip = re.search(r" (measured|reported|derived)$", line)
        if chip is None:
            continue
        column = 63 if in_glance else 64
        assert chip.start() + 1 == column, line
        assert line[: column - 1].rstrip() and line[column - 1] == " ", line


@pytest.mark.parametrize(("label", "document"), DOCUMENTS, ids=[d[0] for d in DOCUMENTS])
def test_the_sections_come_in_the_spec_order(label, document):
    names = [
        found[1]
        for line in lines(document)
        if (found := re.match(r"^([A-Z][A-Z ]*[A-Z])(?=\s{2,}| \(|$)", line))
    ]
    assert names == [
        "MAC HARDWARE OBSERVATION REPORT",
        "AT A GLANCE",
        "WHAT THIS REPORT CANNOT TELL YOU",
        "THIS MAC",
        "SECURITY SETTINGS",
        "SYSTEM RECORDS",
        "STORAGE HEALTH AND WEAR",
        "BATTERY",
        "MEMORY",
        "POWER AND THERMAL CHECK",
    ]


def test_prose_wraps_at_69_columns():
    document = declined()
    for line in section(document, "WHAT THIS REPORT CANNOT TELL YOU"):
        assert len(line) <= 69
    for line in lines(document)[:7]:
        assert len(line) <= 69 or line.startswith("MacBook Pro")


# --- the field inventory's Terminal column ------------------------------------------------------

# Every inventory row marked Terminal Yes, and the metadata the terminal prints (Test strategy,
# "Complete fixtures"), as the m5-laptop summary shows it.
TERMINAL_YES = {
    "model name, identifier and model number": ["MacBook Pro, Mac17,2, model number MDE34LL/A"],
    "chip, core clusters and GPU cores": ["Apple M5: 4 Super and 6 Efficiency cores, 10-core GPU"],
    "memory size, type and manufacturer": ["Memory            24 GB LPDDR5 (Micron)"],
    "serial number, last four": ["ending in K7Q2 (add --show-serial to print it)"],
    "firmware version": ["firmware 18000.161.10"],
    "Activation Lock": ["Activation Lock              On"],
    "macOS version and build": ["macOS             26.6.2 (25G83)"],
    "last restart": ["Last restart      28 Aug 2026, 26 days ago"],
    "panic reports kept": ["Panic reports     0 kept on this Mac"],
    "SIP, Gatekeeper and FileVault": [
        "System Integrity Protection  On",
        "Gatekeeper                   On",
        "FileVault                    On",
    ],
    "memory free": ["Memory pressure now   38% free"],
    "startup disk, internal and solid-state": ["the internal SSD (disk0)"],
    "disk model, capacity, SMART status and BSD name": [
        "APPLE SSD AP1024Z, 1 TB,",
        "SMART status        Verified",
    ],
    "disk temperature": ["Temperature now     35 °C"],
    "available spare and threshold": ["Available spare     100% (threshold 99%)"],
    "endurance used": ["Endurance used      1%"],
    "data written, as bytes with the unit count": [
        "Data written        13.3 TB (26,019,396 units of 512,000 B)"
    ],
    "power-on hours": ["Power-on hours      427"],
    "unsafe shutdowns, media errors and error-log entries": [
        "Unsafe shutdowns    5",
        "Media errors        0",
        "Error log entries   0",
    ],
    "battery condition and maximum capacity": [
        "Condition           Good",
        "Maximum capacity    99%",
    ],
    "cycle count": ["Charge cycles       57"],
    "design cycle count and design capacity": [
        "Design cycle count  1,000",
        "Design capacity     6,249 mAh",
    ],
    "full charge capacity": ["Full charge now     5,954 mAh"],
    "battery temperature": ["Temperature         30.4 °C"],
    "charge, fully charged, charger and charging": [
        "Charge now          100%, fully charged",
        "Power source        charger connected, not charging",
    ],
    "memory error records": ["Memory error records  0 correctable, 0 uncorrectable"],
    "ECC counters": ["ECC error counters    Unavailable: macOS has no public interface"],
    "thermal pressure counts": ["Thermal pressure    Nominal in 5 of 5 samples"],
    "ranges and averages, four lines": [
        "Processor power     0.6 to 2.7 W combined, average 1.7 W",
        "CPU power           0.6 to 2.7 W, average 1.6 W",
        "GPU power           0.05 to 0.06 W, average 0.05 W",
        "Neural Engine       0.0 W in every sample",
    ],
    "local time with offset": ["23 Sep 2026, 14:05 (UTC-7)"],
    "validated flag": ["Validated configuration: yes."],
    "elevation record": ["Administrator reads: asked, granted, cleared."],
    "collection status": ["Collection: complete. 22 read, 0 skipped, 1 unavailable"],
    "report ID, first 12 digits": ["ID 5331136e3e93"],
}


@pytest.mark.parametrize(("field", "shown"), list(TERMINAL_YES.items()), ids=list(TERMINAL_YES))
def test_every_terminal_field_appears(field, shown):
    text = summary(m5())
    for piece in shown:
        assert piece in text, (field, piece)


def test_the_only_if_fields_appear_only_when_set():
    quiet = summary(m5())
    for absent in ("virtual machine", "Critical warning", "Permanent failure", "thermal warning"):
        assert absent not in quiet
    assert "Critical warning    spare capacity below threshold (bit 0)" in summary(
        load("concerning-desktop")
    )
    assert "macOS thermal warning level now: none recorded." in summary(declined())


def test_storage_and_battery_rows_sit_under_their_source_lines():
    storage = section(m5(), "STORAGE HEALTH AND WEAR")
    assert storage[0].endswith("from macOS's disk profile")
    assert storage[1].startswith("  SMART status")
    assert storage[2].strip() == "from the disk's own controller (IOKit)"
    assert [line.split("  ")[1] for line in storage[3:]] == [
        "Endurance used",
        "Available spare",
        "Data written",
        "Power-on hours",
        "Unsafe shutdowns",
        "Media errors",
        "Error log entries",
        "Temperature now",
    ]
    battery = section(m5(), "BATTERY")
    assert battery[0].endswith("from macOS's power report")
    assert [line.split("  ")[1] for line in battery[1:5]] == [
        "Condition",
        "Maximum capacity",
        "Charge now",
        "Power source",
    ]
    assert battery[5].strip() == "from the battery's own gauge"
    assert [line.split("  ")[1] for line in battery[6:]] == [
        "Charge cycles",
        "Design cycle count",
        "Full charge now",
        "Design capacity",
        "Temperature",
    ]


def test_every_range_and_average_line_has_both_parts():
    for label in ("Processor power", "CPU power", "GPU power"):
        text = row(load("concerning-desktop"), "POWER AND THERMAL CHECK", label)
        assert text == "Not reported by macOS" or (" to " in text and ", average " in text)


# --- the title block ---------------------------------------------------------------------------


def test_the_identity_line_names_the_mac_the_local_time_and_the_id():
    found = lines(m5())
    assert found[:3] == [
        "MAC HARDWARE OBSERVATION REPORT",
        "Point-in-time observations, not a diagnosis, grade or certificate.",
        "MacBook Pro (Mac17,2), Apple M5. 23 Sep 2026, 14:05 (UTC-7). ID 5331136e3e93",
    ]


def test_an_identity_line_past_80_columns_moves_the_id_to_its_own_line():
    found = lines(load("concerning-desktop"))
    assert found[2:4] == [
        "Mac Studio (Mac14,14), Apple M2 Ultra. 23 Sep 2026, 16:40 (UTC-7).",
        "ID 3e1cf9398636",
    ]


def _local(text: str):
    """Collected at another instant: the local time, the UTC time and the last restart move
    together."""

    def edit(document: dict) -> None:
        instant = datetime.fromisoformat(text)
        before = datetime.fromisoformat(document["collected_at_utc"].replace("Z", "+00:00"))
        boot = r.values(document, "boot_time")
        epoch = int(instant.timestamp()) - (
            int(before.timestamp()) - boot["boot_epoch_seconds"]["value"]
        )
        document["collected_at_local"] = text
        document["collected_at_utc"] = instant.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        boot["boot_epoch_seconds"]["value"] = epoch
        boot["boot_time_utc"]["value"] = datetime.fromtimestamp(epoch, UTC).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

    return edit


@pytest.mark.parametrize(
    ("local", "shown"),
    [
        ("2026-09-23T21:05:31+00:00", "23 Sep 2026, 21:05 (UTC)"),
        ("2026-09-24T02:35:31+05:30", "24 Sep 2026, 02:35 (UTC+5:30)"),
        ("2026-09-23T11:35:31-09:30", "23 Sep 2026, 11:35 (UTC-9:30)"),
        ("2026-09-24T11:05:31+14:00", "24 Sep 2026, 11:05 (UTC+14)"),
        ("2026-09-23T14:05:31-07:00", "23 Sep 2026, 14:05 (UTC-7)"),
    ],
)
def test_the_local_time_and_offset_come_from_the_json(local, shown):
    document = edited("m5-laptop", _local(local))
    assert f". {shown}. ID " in title(document)


def test_a_day_below_ten_has_no_leading_zero():
    document = edited("m5-laptop", _local("2026-09-03T04:05:31-07:00"))
    assert "Apple M5. 3 Sep 2026, 04:05 (UTC-7)." in title(document)


# The command each user-read surface comes from (the spec's command inventory). A failed
# command leaves every surface it feeds unavailable with one reason; output in another shape
# fails no run (Decision 8).
FED_BY = {
    "os_version": "C1",
    "hardware_overview": "C2",
    "firmware_and_boot": "C2",
    "nvme_devices": "C3",
    "gpu_configuration": "C4",
    "memory_configuration": "C5",
    "battery_health": "C6",
    "battery_gauge": "C7",
    "thermal_warning_level": "C8",
    "memory_pressure": "C9",
    "startup_disk": "C11",
    "sip_status": "C12",
    "gatekeeper_status": "C13",
    "filevault_status": "C14",
    "virtualization_state": "C26",
    "boot_time": "C27",
}


def _unavailable(key: str, reason: str, detail: str | None = None):
    """A surface unavailable as a run leaves it: a reason other than output in another
    shape fails the surface's command, and every surface that command feeds; the sysctl
    surface fails its first OID."""

    def edit(document: dict) -> None:
        command = FED_BY.get(key)
        shapes = ("source_changed", *(("source_absent",) if key == "nvme_devices" else ()))
        keys = [key]
        if command is not None and reason not in shapes:
            r.fail(document, command)
            keys = [each for each, feeder in FED_BY.items() if feeder == command]
        if key == "kernel_and_platform" and reason != "source_changed":
            r.fail(document, "C15")  # the surface takes its first value's reason
        for each in keys:
            r.unavailable(document, each, reason, detail)

    return edit


# Each sysctl value's own call (the spec's command inventory).
SYSCTL = {
    "hw_model": "C15",
    "hw_target": "C16",
    "memory_bytes": "C17",
    "cpu_count": "C18",
    "cpu_brand": "C19",
    "arm64": "C20",
    "perf_level_count": "C21",
}


def _sysctl_failed(name: str, reason: str):
    """One sysctl call failed: its value takes the reason and the call records a failed run."""

    def edit(document: dict) -> None:
        r.value_unavailable(document, "kernel_and_platform", name, reason)
        r.fail(document, SYSCTL[name])

    return edit


def _value_unavailable(key: str, name: str, reason: str = "source_changed"):
    return lambda document: r.value_unavailable(document, key, name, reason)


def _set(key: str, name: str, value: object):
    return lambda document: r.set_value(document, key, name, value)


def test_without_the_hardware_overview_the_identity_names_no_model_or_chip():
    # sysctl's model and CPU brand are Appendix A's, not the terminal's (field inventory).
    document = edited("m5-laptop", _unavailable("hardware_overview", "tool_error"))
    assert title(document).startswith("Mac. 23 Sep 2026")


@pytest.mark.parametrize(
    ("edits", "start"),
    [
        ([_value_unavailable("hardware_overview", "machine_name")], "Mac (Mac17,2), Apple M5."),
        ([_value_unavailable("hardware_overview", "machine_model")], "MacBook Pro, Apple M5."),
        ([_value_unavailable("hardware_overview", "chip_type")], "MacBook Pro (Mac17,2)."),
    ],
    ids=["no name", "no model", "no chip"],
)
def test_the_identity_line_leaves_out_what_was_not_read(edits, start):
    assert title(edited("m5-laptop", *edits)).startswith(start)


@pytest.mark.parametrize(
    ("edits", "line"),
    [
        (
            [],
            "Collection: complete. 22 read, 0 skipped, 1 unavailable "
            "(no public interface on Macs).",
        ),
        (
            [_unavailable("memory_pressure", "source_changed")],
            "Collection: partial. 21 read, 0 skipped, 2 unavailable.",
        ),
    ],
)
def test_the_collection_line(edits, line):
    assert line in title(edited("m5-laptop", *edits))


@pytest.mark.parametrize(
    ("key", "parenthetical"),
    [
        ("declined at the question", "(administrator reads declined)"),
        ("--no-root", "(administrator reads skipped with --no-root)"),
        ("not an administrator", "(this account is not an administrator)"),
        ("no terminal", "(no terminal to ask for a password)"),
        ("authentication denied at S2", "(administrator access not granted)"),
    ],
)
def test_the_collection_line_says_why_items_were_skipped(key, parenthetical):
    text = title(history("m5-laptop", key))
    assert f"Collection: partial. 20 read, 2 skipped {parenthetical}, 1 unavailable." in text


def test_the_count_phrases_never_break():
    found = lines(load("concerning-desktop"))
    assert found[4:6] == [
        "Collection: partial. 19 read, 0 skipped, 2 unavailable,",
        "2 not applicable.",
    ]


ELEVATION_LINES = {
    "declined at the question": "asked; you chose not to allow them.",
    "--no-root": "not asked; skipped with --no-root.",
    "not an administrator": "not asked; this account is not an administrator on this Mac.",
    "no terminal": "not asked; no terminal to ask for a password.",
    "no service account": "asked, granted, cleared.",
    "the sandbox probe failed": (
        "asked; not run: this Mac cannot run them safely (no working sandbox)."
    ),
    "the listing failed": (
        "asked; not run: this Mac cannot run them safely (process listing unavailable)."
    ),
    "sudo -k failed": "asked; not prepared (sudo -k failed), cleared.",
    "an account-state message at S2": "asked, macOS reported a problem with this account, cleared.",
    "a policy refusal at S2": "asked, refused by sudo's policy for this account, cleared.",
    "authentication denied at S2": "asked, not granted, cleared.",
    "an unexplained sudo error at S2": "asked, sudo reported an error, cleared.",
}


@pytest.mark.parametrize(("key", "line"), list(ELEVATION_LINES.items()), ids=list(ELEVATION_LINES))
def test_the_elevation_line(key, line):
    assert f"Administrator reads: {line}" in title(history("m5-laptop", key))


def test_the_elevation_line_names_yes_by_flag_a_failed_clear_and_an_unverified_stop():
    flag = r.history("m5-laptop", r.record(consent="flag"), None, None)
    assert "Administrator reads: allowed with --yes, granted, cleared." in title(flag)
    failed = r.history(
        "m5-laptop", r.record(cleared="failed", clear_error="nonzero_exit"), None, None
    )
    assert "Administrator reads: asked, granted, not cleared: run sudo -k." in title(failed)
    survivor = r.history(
        "m5-laptop",
        r.record(count=("parsed", "survivor"), power=r.NOT_RUN),
        None,
        r.UNSAFE_STOP,
    )
    text = title(survivor)
    assert "Administrator reads: asked, granted, cleared; a stop could not be verified." in text


def test_the_validated_line():
    assert "Validated configuration: yes." in title(m5())
    assert title(load("concerning-desktop")).endswith(
        "Validated configuration: no. This configuration has not been validated by Voltry "
        "yet; more items than usual may be unavailable."
    )


# --- At a glance -------------------------------------------------------------------------------


def test_at_a_glance_on_the_m5():
    assert glance(m5()) == [
        "Storage SSD reports 1% of its rated endurance used. reported",
        "Battery macOS reports condition Good, capacity 99%. reported",
        "Memory 0 records in macOS's private memory error log. That does not prove the memory "
        "never had errors. measured",
        "Thermal Nominal in 5 of 5 samples. derived",
        "Security SIP, Gatekeeper, FileVault and Activation Lock on. reported",
        "Not read ECC error counters: no public interface on Macs.",
    ]


def test_a_virtual_machine_opens_at_a_glance():
    document = edited("m5-laptop", _set("virtualization_state", "vmm_present", True))
    assert glance(document)[0] == (
        "Machine This is a virtual machine. Hardware readings describe the virtual machine, not "
        "a physical Mac. measured"
    )


@pytest.mark.parametrize(
    ("byte", "text"),
    [
        (1, "spare capacity below its threshold"),
        (2, "temperature outside its threshold"),
        (4, "reliability degraded"),
        (8, "media placed in read-only mode"),
        (16, "volatile memory backup failed"),
        (32, "an unknown warning bit"),
        (96, "unknown warning bits"),
        (5, "spare capacity below its threshold and reliability degraded"),
        (33, "spare capacity below its threshold and an unknown warning bit"),
        (
            7,
            "spare capacity below its threshold, temperature outside its threshold and "
            "reliability degraded",
        ),
    ],
)
def test_a_critical_warning_leads_the_storage_lines(byte, text):
    flags = {
        "spare_below_threshold": bool(byte & 1),
        "temperature_warning": bool(byte & 2),
        "reliability_degraded": bool(byte & 4),
        "read_only_mode": bool(byte & 8),
        "volatile_backup_failed": bool(byte & 16),
        "unknown_warning_bits": bool(byte & 224),
    }
    edits = [_set("smart_health_snapshot", "critical_warning_byte", byte)]
    edits += [_set("smart_health_snapshot", name, value) for name, value in flags.items()]
    entry = glance(edited("m5-laptop", *edits))[0]
    assert entry.startswith(f"Storage SSD reports a critical warning: {text}.")
    assert re.search(r" reported\b", entry)


def test_media_errors_add_a_storage_line():
    document = edited("m5-laptop", _set("smart_wear_attributes", "media_errors", "1"))
    assert glance(document)[:2] == [
        "Storage SSD reports 1% of its rated endurance used. reported",
        "Storage 1 media error on the controller's counter. measured",
    ]


def test_unread_storage_says_why():
    document = edited("m5-laptop", *_smart_failed("timeout"))
    assert glance(document)[0] == "Storage SSD health log not read: timed out after 15 seconds."


@pytest.mark.parametrize(
    ("edits", "entry"),
    [
        (
            [_value_unavailable("battery_health", "maximum_capacity_percent")],
            "Battery macOS reports condition Good. reported",
        ),
        (
            [_value_unavailable("battery_health", "condition")],
            "Battery macOS reports capacity 99%. reported",
        ),
        (
            [_unavailable("battery_health", "tool_error")],
            "Battery Power report not read: system_profiler returned an error.",
        ),
    ],
)
def test_the_battery_line(edits, entry):
    assert glance(edited("m5-laptop", *edits))[1] == entry


def test_a_permanent_failure_flag_adds_a_battery_line():
    document = edited("m5-laptop", _set("battery_gauge", "permanent_failure", True))
    # It leads the battery lines (round 3, Nit 4).
    assert glance(document)[1] == "Battery The battery reports a permanent failure. reported"
    assert row(document, "BATTERY", "Permanent failure") == "flag set reported"


def test_a_desktop_says_not_applicable_after_security():
    entries = glance(load("concerning-desktop"))
    security = next(i for i, e in enumerate(entries) if e.startswith("Security"))
    assert entries[security + 1] == "Battery Not applicable: this Mac has no battery."


def _ledger(correctable: int, uncorrectable: int, reported: tuple[int, int] | None = None):
    reported = reported or (correctable, uncorrectable)
    return [
        _set("memory_error_ledger", "correctable_event_rows", correctable),
        _set("memory_error_ledger", "uncorrectable_event_rows", uncorrectable),
        _set("memory_error_ledger", "correctable_reported_count", reported[0]),
        _set("memory_error_ledger", "uncorrectable_reported_count", reported[1]),
    ]


def test_records_in_the_ledger_say_they_exist_and_nothing_more():
    entries = glance(edited("m5-laptop", *_ledger(1, 0)))
    assert entries[2] == (
        "Memory 1 correctable and 0 uncorrectable records in macOS's private memory error log. "
        "Records exist; how far back the log reaches is unknown. measured"
    )


def test_a_reported_count_that_differs_prints_in_parentheses():
    document = edited("m5-laptop", *_ledger(14, 2, (15, 2)))
    assert row(document, "MEMORY", "Memory error records") == (
        "14 correctable (the log counts 15), 2 uncorrectable measured"
    )
    assert notes(document, "MEMORY", "Memory error records") == (
        "From Apple's private memory error log: undocumented, retention unknown. These are "
        "records present now; counts are not a rate."
    )


def test_zero_records_have_their_own_note():
    assert notes(m5(), "MEMORY", "Memory error records") == (
        "From Apple's private memory error log: undocumented, retention unknown. Zero means "
        "none are recorded there now, not none ever."
    )
    assert notes(declined(), "MEMORY", "Memory error records") == ""


@pytest.mark.parametrize(
    ("counts", "text"),
    [
        ({"nominal": 5}, "Nominal in 5 of 5 samples."),
        ({"heavy": 3, "nominal": 2}, "Heavy in 3 of 5 samples, Nominal in 2."),
        ({"nominal": 4, "moderate": 1}, "Moderate in 1 of 5 samples, Nominal in 4."),
        (
            {"sleeping": 1, "trapping": 1, "heavy": 1, "moderate": 1, "nominal": 1},
            "Sleeping in 1 of 5 samples, Trapping in 1, Heavy in 1, Moderate in 1, Nominal in 1.",
        ),
    ],
)
def test_thermal_states_print_worst_first(counts, text):
    states = ("nominal", "moderate", "heavy", "trapping", "sleeping")
    series = [s.capitalize() for s in states for _ in range(counts.get(s, 0))]
    edits = [_set("power_and_thermal_samples", "sample_thermal_pressure", series)]
    edits += [
        _set("power_and_thermal_samples", f"thermal_{s}_count", counts.get(s, 0)) for s in states
    ]
    entries = glance(edited("m5-laptop", *edits))
    assert entries[3].startswith(f"Thermal {text}")


@pytest.mark.parametrize(
    ("edits", "entry"),
    [
        ([], "Thermal macOS thermal warning level now: none recorded. reported"),
        (
            [
                _set("thermal_warning_level", "thermal_warning_recorded", True),
                lambda d: r.values(d, "thermal_warning_level").update(
                    thermal_warning_level={
                        "availability": "available",
                        "value": 70,
                        "provenance": "reported",
                    }
                ),
            ],
            "Thermal macOS thermal warning level now: 70. reported",
        ),
        (
            [_unavailable("thermal_warning_level", "tool_error")],
            "Thermal Thermal pressure not read: needs administrator access (you chose not to "
            "allow it).",
        ),
    ],
)
def test_without_the_power_sample_thermal_falls_back_to_the_warning_level(edits, entry):
    document = declined()
    for edit in edits:
        edit(document)
    document = r.finish(document)
    assert glance(document)[3] == entry


@pytest.mark.parametrize(
    ("edits", "entry"),
    [
        (
            [_set("sip_status", "enabled", False)],
            "Security System Integrity Protection is off. reported",
        ),
        (
            [_set("sip_status", "enabled", False), _set("filevault_status", "enabled", False)],
            "Security System Integrity Protection and FileVault are off. reported",
        ),
        (
            [_set("hardware_overview", "activation_lock_enabled", False)],
            "Security Activation Lock is off. reported",
        ),
        (
            [_unavailable("gatekeeper_status", "timeout")],
            "Security SIP, FileVault and Activation Lock on; Gatekeeper not read: timed out after "
            "10 seconds. reported",
        ),
        (
            [_set("sip_status", "enabled", False), _unavailable("gatekeeper_status", "timeout")],
            "Security System Integrity Protection is off; Gatekeeper not read: timed out after 10 "
            "seconds. reported",
        ),
        (
            [
                _unavailable("sip_status", "timeout"),
                _unavailable("gatekeeper_status", "timeout"),
                _unavailable("filevault_status", "timeout"),
                _value_unavailable("hardware_overview", "activation_lock_enabled"),
            ],
            "Security System Integrity Protection, Gatekeeper and FileVault not read: timed out "
            "after 10 seconds; Activation Lock not reported by macOS.",
        ),
        (
            [
                _unavailable("sip_status", "timeout"),
                _unavailable("gatekeeper_status", "tool_error"),
            ],
            "Security FileVault and Activation Lock on; System Integrity Protection not read: "
            "timed out after 10 seconds; Gatekeeper not read: spctl returned an error. reported",
        ),
    ],
)
def test_the_security_line(edits, entry):
    assert glance(edited("m5-laptop", *edits))[4] == entry


def test_not_read_lists_every_gap_the_topics_do_not_cover_in_registry_order():
    document = edited(
        "m5-laptop",
        _unavailable("os_version", "timeout"),
        _sysctl_failed("hw_target", "tool_error"),
        _value_unavailable("power_and_thermal_samples", "sample_gpu_power_mw"),
        _value_unavailable("power_and_thermal_samples", "gpu_power_mw_min"),
        _value_unavailable("power_and_thermal_samples", "gpu_power_mw_max"),
        _value_unavailable("power_and_thermal_samples", "gpu_power_mw_mean"),
    )
    assert glance(document)[-1] == (
        "Not read macOS version: timed out after 10 seconds. Board ID: sysctl returned an "
        "error. GPU power: not reported by macOS. ECC error counters: no public interface "
        "on Macs."
    )


def test_the_declined_run_lists_the_power_sample_as_not_read():
    assert glance(declined())[-1] == (
        "Not read Power and thermal check: needs administrator access (you chose not to allow "
        "it). ECC error counters: no public interface on Macs."
    )


# --- item reasons ------------------------------------------------------------------------------

ELEVATED = {
    "declined at the question": (
        "Not read: needs administrator access (you chose not to allow it)",
        "Not read: needs administrator access (you chose not to allow it).",
    ),
    "--no-root": ("Not read: skipped with --no-root", "Not read: skipped with --no-root."),
    "not an administrator": (
        "Not read: this account is not an administrator on this Mac",
        "Not read: this account is not an administrator on this Mac.",
    ),
    "no terminal": (
        "Not read: no terminal to ask for a password",
        "Not read: no terminal to ask for a password.",
    ),
    "no service account": (
        "Not read: this macOS has no memory-maintenance account to read as",
        None,
    ),
    "the account lookup failed": (
        "Not read: the memory-maintenance account could not be looked up",
        None,
    ),
    "the sandbox probe failed": (
        "Not read: this Mac cannot run the administrator reads safely (no working sandbox)",
        "Not read: this Mac cannot run the administrator reads safely (no working sandbox).",
    ),
    "the listing failed": (
        "Not read: this Mac cannot run the administrator reads safely (process listing "
        "unavailable)",
        "Not read: this Mac cannot run the administrator reads safely (process listing "
        "unavailable).",
    ),
    "sudo -k failed": (
        "Not read: administrator access could not be prepared (sudo -k failed)",
        "Not read: administrator access could not be prepared (sudo -k failed).",
    ),
    "an account-state message at S2": (
        "Not read: macOS reported a problem with this account, such as a lock or an expired "
        "password",
        "Not read: macOS reported a problem with this account, such as a lock or an expired "
        "password.",
    ),
    "a policy refusal at S2": (
        "Not read: sudo does not allow this account to run these steps",
        "Not read: sudo does not allow this account to run these steps.",
    ),
    "authentication denied at S2": (
        "Not read: administrator access was not granted",
        "Not read: administrator access was not granted.",
    ),
    "an unexplained sudo error at S2": (
        "Not read: sudo reported an error",
        "Not read: sudo reported an error.",
    ),
}


@pytest.mark.parametrize(("key", "texts"), list(ELEVATED.items()), ids=list(ELEVATED))
def test_each_elevated_stop_before_the_payloads_has_its_words(key, texts):
    document = history("m5-laptop", key)
    ledger, power = texts
    assert row(document, "MEMORY", "Memory error records") == ledger
    if power is None:
        assert section(document, "POWER AND THERMAL CHECK")[0].endswith("no load applied)")
    else:
        assert section(document, "POWER AND THERMAL CHECK") == [
            "POWER AND THERMAL CHECK",
            *[f"  {line}" for line in _wrap(power, 67)],
        ]


def _wrap(text: str, size: int) -> list[str]:
    out: list[str] = []
    for word in text.split():
        if out and len(out[-1]) + 1 + len(word) <= size:
            out[-1] += " " + word
        else:
            out.append(word)
    return out


def _payload_history(ending: str, detail_reason: tuple[str, str], which: str = "count"):
    if which == "count":
        skipped = (
            r.UNSAFE_STOP
            if ending in ("runtime_deadline", "output_cap", "launch_deadline", "tracking_failed")
            else None
        )
        power = r.NOT_RUN if skipped else ("parsed", "verified")
        if ending in ("auth_failed", "account_blocked"):
            skipped, power = ("not_granted", ending), r.NOT_RUN
        if ending == "sudo_error":
            skipped, power = ("tool_error", "skipped_after_sudo_error"), r.NOT_RUN
        return r.history(
            "m5-laptop", r.record(count=(ending, "verified"), power=power), detail_reason, skipped
        )
    return r.history("m5-laptop", r.record(power=(ending, "verified")), None, detail_reason)


PAYLOADS = [
    (
        "count",
        "spawn_failed",
        ("tool_error", "spawn_failed"),
        "Not read: sudo could not be started for this step",
    ),
    (
        "count",
        "payload_error",
        ("tool_error", "payload_failed"),
        "Not read: macOS did not provide the memory error records",
    ),
    (
        "power",
        "payload_error",
        ("tool_error", "payload_failed"),
        "Not read: powermetrics returned an error",
    ),
    (
        "count",
        "unparsed",
        ("source_changed", "parse_failed"),
        "Could not read: macOS returned a format this version does not recognize",
    ),
    (
        "count",
        "policy_refusal",
        ("not_granted", "policy_refusal"),
        "Not read: sudo did not allow this step",
    ),
    (
        "count",
        "runtime_deadline",
        ("timeout", "runtime_deadline"),
        "Not read: timed out after 10 seconds",
    ),
    (
        "power",
        "runtime_deadline",
        ("timeout", "runtime_deadline"),
        "Not read: timed out after 20 seconds",
    ),
    (
        "count",
        "output_cap",
        ("source_changed", "output_cap"),
        "Could not read: macOS returned a format this version does not recognize",
    ),
    (
        "count",
        "launch_deadline",
        ("tool_error", "launch_deadline"),
        "Not read: the step did not start in time",
    ),
    (
        "count",
        "tracking_failed",
        ("tool_error", "tracking_failed"),
        "Not read: the step was stopped because its processes could not be tracked",
    ),
    (
        "count",
        "auth_failed",
        ("not_granted", "auth_failed"),
        "Not read: administrator access was not granted",
    ),
    (
        "count",
        "account_blocked",
        ("not_granted", "account_blocked"),
        "Not read: macOS reported a problem with this account, such as a lock or an expired "
        "password",
    ),
    ("count", "sudo_error", ("tool_error", "sudo_error"), "Not read: sudo reported an error"),
]


@pytest.mark.parametrize(("which", "ending", "reason", "text"), PAYLOADS)
def test_each_payload_ending_has_its_words(which, ending, reason, text):
    document = _payload_history(ending, reason, which)
    if which == "count":
        assert row(document, "MEMORY", "Memory error records") == text
    else:
        assert " ".join(" ".join(section(document, "POWER AND THERMAL CHECK")[1:]).split()) == (
            text + "."
        )


@pytest.mark.parametrize(
    ("ending", "text"),
    [
        (
            "runtime_deadline",
            "Not read: skipped after the memory-error step had to be stopped or its stop "
            "could not be confirmed.",
        ),
        ("sudo_error", "Not read: skipped after sudo reported an error at the memory-error step."),
        ("auth_failed", "Not read: administrator access was not granted."),
    ],
)
def test_a_power_sample_skipped_after_the_count_says_why(ending, text):
    reasons = {p[1]: p[2] for p in PAYLOADS if p[0] == "count"}
    document = _payload_history(ending, reasons[ending])
    assert " ".join(" ".join(section(document, "POWER AND THERMAL CHECK")[1:]).split()) == text


USER_READS = [
    ("os_version", "tool_error", "macOS", "Not read: sw_vers returned an error"),
    ("os_version", "timeout", "macOS", "Not read: timed out after 10 seconds"),
    (
        "os_version",
        "source_changed",
        "macOS",
        "Could not read: macOS returned a format this version does not recognize",
    ),
    ("os_version", "source_absent", "macOS", "Not read: sw_vers is not on this Mac"),
    (
        "memory_pressure",
        "tool_error",
        "Memory pressure now",
        "Not read: memory_pressure returned an error",
    ),
    (
        "panic_report_count",
        "no_admin",
        "Panic reports",
        "Not read: readable by administrator accounts only",
    ),
    (
        "panic_report_count",
        "tool_error",
        "Panic reports",
        "Not read: the crash report folder could not be read",
    ),
    (
        "panic_report_count",
        "source_absent",
        "Panic reports",
        "Not read: the crash report folder was not found",
    ),
    ("boot_time", "tool_error", "Last restart", "Not read: sysctl returned an error"),
]
SECTION_OF = {
    "macOS": "THIS MAC",
    "Memory pressure now": "MEMORY",
    "Panic reports": "SYSTEM RECORDS",
    "Last restart": "SYSTEM RECORDS",
}


@pytest.mark.parametrize(("key", "reason", "label", "text"), USER_READS)
def test_each_user_read_failure_has_its_words(key, reason, label, text):
    document = edited("m5-laptop", _unavailable(key, reason))
    if label == "macOS":
        # Neither the version nor the build read: their words, and the firmware apart from
        # them (round 3, Minor 1).
        text = f"the version and build were not read ({text.split(': ', 1)[1]}); firmware "
        text += "18000.161.10"
    assert row(document, SECTION_OF[label], label) == text


@pytest.mark.parametrize(
    ("reason", "text"),
    [
        ("source_absent", "Not read: the startup disk could not be matched to one health log"),
        ("unsupported", "Not read: this startup disk has no health log this version can read"),
        ("tool_error", "Not read: the startup disk's health log could not be read"),
        ("timeout", "Not read: timed out after 15 seconds"),
        ("source_changed", "Not read: the startup disk's health log could not be read"),
    ],
)
def test_an_unread_health_log_is_one_row(reason, text):
    document = edited("m5-laptop", *_smart_failed(reason))
    found = section(document, "STORAGE HEALTH AND WEAR")
    assert found[2].strip() == "from the disk's own controller (IOKit)"
    assert found[3].startswith("  Health log          ")
    assert row(document, "STORAGE HEALTH AND WEAR", "Health log") == text
    assert all(line.startswith(" " * 22) for line in found[4:])


@pytest.mark.parametrize(
    ("reason", "text"),
    [
        ("source_absent", "the startup disk could not be matched to one drive entry"),
        ("source_changed", "the startup disk could not be matched to one drive entry"),
        ("tool_error", "system_profiler returned an error"),
    ],
)
def test_an_unread_drive_entry(reason, text):
    document = edited("m5-laptop", _unavailable("nvme_devices", reason))
    assert row(document, "STORAGE HEALTH AND WEAR", "SMART status") == f"Not read: {text}"
    # The field inventory prints the drive entry's own name. The whole disk's, derived
    # from the startup volume's store, never prints in a section headed "as macOS reports
    # it" (the GPT audit, pass 1, G1-03).
    assert row(document, "THIS MAC", "Startup disk") == (
        f"the internal SSD; its name was not read ({text})"
    )


def test_an_unread_drive_entry_and_location_leave_the_row_unread():
    document = edited(
        "m5-laptop",
        _unavailable("nvme_devices", "timeout"),
        _value_unavailable("startup_disk", "internal"),
    )
    assert row(document, "THIS MAC", "Startup disk") == "Not read: timed out after 10 seconds"
    assert "disk0" not in "\n".join(_row(document, "THIS MAC", "Startup disk")[0])


def test_a_value_macos_omitted_is_not_reported():
    document = edited("m5-laptop", _value_unavailable("battery_health", "maximum_capacity_percent"))
    assert row(document, "BATTERY", "Maximum capacity") == "Not reported by macOS"


def test_a_multi_store_startup_volume():
    document = edited(
        "m5-laptop",
        _set("startup_disk", "physical_store_count", 2),
        _value_unavailable("startup_disk", "physical_store", "unsupported"),
        _value_unavailable("startup_disk", "whole_disk", "unsupported"),
        *[
            _value_unavailable("nvme_devices", name, "unsupported")
            for name in (
                "bsd_name",
                "device_model",
                "device_revision",
                "size_text",
                "size_bytes",
                "smart_status",
                "trim_support",
            )
        ],
        _unavailable("smart_health_snapshot", "unsupported"),
        _unavailable("smart_wear_attributes", "unsupported"),
    )
    assert row(document, "THIS MAC", "Startup disk") == (
        "the internal SSD; its name was not read (the startup volume spans more than one "
        "physical store)"
    )
    # The trunk's own words, for the branches that take its reason.
    assert row(document, "STORAGE HEALTH AND WEAR", "SMART status") == (
        "Not read: the startup volume spans more than one physical store"
    )
    assert row(document, "STORAGE HEALTH AND WEAR", "Health log") == (
        "Not read: the startup disk could not be matched to one health log"
    )


def _trunk_failed(reason: str, *, store: bool = False):
    """The startup volume's trunk failed: every entry field and the SMART log take its
    reason, by the storage dependency table."""
    names = ("bsd_name", "device_model", "device_revision", "size_text", "size_bytes")
    names += ("smart_status", "trim_support")
    edits = [_value_unavailable("nvme_devices", name, reason) for name in names]
    edits += [
        _unavailable("smart_health_snapshot", reason),
        _unavailable("smart_wear_attributes", reason),
    ]
    if store:
        edits += [
            _value_unavailable("startup_disk", "physical_store", reason),
            _value_unavailable("startup_disk", "whole_disk", reason),
        ]
    else:
        edits.append(_unavailable("startup_disk", reason))
    return edits


def _smart_failed(reason: str) -> list:
    """The SMART child's own failure: both surfaces read one log, and C28's outcome table
    records a failed run for a timeout or output in another shape."""
    edits = [
        _unavailable(each, reason) for each in ("smart_health_snapshot", "smart_wear_attributes")
    ]
    if reason in ("timeout", "source_changed"):
        edits.append(lambda document: r.fail(document, "C28"))
    return edits


def _registry_values():
    from voltry_mac import registry

    document = m5()
    for spec in registry.SURFACES:
        if r.surface(document, spec.key)["availability"] != "available":
            continue
        for value in spec.values:
            if value.name in r.values(document, spec.key):
                yield spec.key, value.name


def _legal(*candidates: list) -> dict | None:
    """m5-laptop with the first of these edit lists the validator accepts, or None."""
    for edits in candidates:
        document = edited("m5-laptop", *edits)
        try:
            validate.validate(document)
        except canonical.Invalid:
            continue
        return document
    return None


def _computed_from(key: str, name: str) -> list[str]:
    """The values computed from one value, by Decision 8's computed-values rule."""
    from voltry_mac import validate_relations

    return [each for _, each, inputs in validate_relations._INPUTS if (key, name) in inputs]


# Values whose gap other values follow by the spec's own rules: the performance levels'
# arrays follow their count, and the storage chain follows the startup volume's store.
_FOLLOWERS = {
    ("kernel_and_platform", "perf_level_count"): lambda: [
        _value_unavailable("kernel_and_platform", name)
        for name in ("perf_level_names", "perf_level_physical_cpus")
    ],
    ("startup_disk", "physical_store"): lambda: _trunk_failed("source_changed", store=True),
    ("startup_disk", "physical_store_count"): lambda: _trunk_failed("source_changed", store=True),
}


def _gap_edits(key: str, name: str) -> list:
    """The edits that leave one value unread, and the values that follow it."""
    names = [name, *_computed_from(key, name)]
    follow = _FOLLOWERS.get((key, name), list)
    return [*[_value_unavailable(key, each) for each in names], *follow()]


def _value_gap(key: str, name: str) -> dict | None:
    """m5-laptop with one value macOS did not report, and the values that follow it; None
    where a report cannot hold that gap alone (see VALUES_NEVER_UNREAD_ALONE)."""
    return _legal(_gap_edits(key, name))


# The values a report never leaves unread on their own: a surface's only value (the
# surface's own gap stands for it), a value computed from another (its input's gap stands
# for it), and the SMART fields an available log always decodes.
VALUES_NEVER_UNREAD_ALONE = {
    # A surface's only value, with any computed from it: the surface's own gap stands for it.
    "boot_time.boot_epoch_seconds",
    "filevault_status.enabled",
    "gatekeeper_status.assessments_enabled",
    "memory_pressure.free_percent",
    "panic_report_count.count",
    "sip_status.enabled",
    "thermal_warning_level.thermal_warning_recorded",
    "virtualization_state.vmm_present",
    # Computed from another value: that input's gap stands for it.
    "battery_gauge.temperature_c",
    "boot_time.boot_time_utc",
    "boot_time.days_since_boot",
    *(
        f"power_and_thermal_samples.{kind}_power_mw_{stat}"
        for kind in ("cpu", "gpu", "ane", "combined")
        for stat in ("min", "max", "mean")
    ),
    *(
        f"power_and_thermal_samples.thermal_{state}_count"
        for state in ("nominal", "moderate", "heavy", "trapping", "sleeping")
    ),
    "smart_health_snapshot.composite_temperature_c",
    *(
        f"smart_health_snapshot.{flag}"
        for flag in (
            "spare_below_threshold",
            "temperature_warning",
            "reliability_degraded",
            "read_only_mode",
            "volatile_backup_failed",
            "unknown_warning_bits",
        )
    ),
    "smart_wear_attributes.bytes_read",
    "smart_wear_attributes.bytes_written",
    "startup_disk.whole_disk",
    # Always 5 while the samples are available.
    "power_and_thermal_samples.sample_count",
    # Fields an available SMART log always decodes: only its temperature and spare fields
    # can fall outside their bounds.
    "smart_health_snapshot.critical_warning_byte",
    *(
        f"smart_wear_attributes.{name}"
        for name in (
            "percentage_used",
            "data_units_read",
            "data_units_written",
            "power_cycles",
            "power_on_hours",
            "unsafe_shutdowns",
            "media_errors",
            "error_log_entries",
        )
    ),
}


VALUE_GAPS = [
    (key, name, document)
    for key, name in _registry_values()
    if (document := _value_gap(key, name)) is not None
]


def test_the_values_never_unread_alone_are_the_pinned_ones():
    left_out = {f"{key}.{name}" for key, name in _registry_values()} - {
        f"{key}.{name}" for key, name, _ in VALUE_GAPS
    }
    assert left_out == VALUES_NEVER_UNREAD_ALONE


@pytest.mark.parametrize(
    ("key", "name", "document"), VALUE_GAPS, ids=[f"{k}.{n}" for k, n, _ in VALUE_GAPS]
)
def test_any_value_macos_did_not_report_is_named_and_fits(key, name, document):
    text = summary(document)
    assert all(width(line) <= 80 for line in text.split("\n"))
    added = set(text.split("\n")) - set(summary(m5()).split("\n"))
    said = " ".join(" ".join(added).split())
    markers = ("ot reported by macOS", "Not read", "not recognize", "could not be matched")
    assert any(marker in said for marker in markers), said


def test_a_matched_drive_entry_with_fields_macos_omitted():
    # With the whole disk known, an entry's field can be unavailable only because the
    # profile omitted it: the entry matched.
    document = edited("m5-laptop", _value_unavailable("nvme_devices", "smart_status"))
    assert row(document, "STORAGE HEALTH AND WEAR", "SMART status") == "Not reported by macOS"
    assert row(document, "THIS MAC", "Startup disk") == (
        "APPLE SSD AP1024Z, 1 TB, the internal SSD (disk0)"
    )
    assert "SMART status: not reported by macOS." in glance(document)[-1]


def test_a_startup_disk_that_could_not_be_identified():
    # diskutil timed out: the log and the entry inherit its timeout, and say the disk
    # could not be identified, not that the SMART child timed out.
    document = edited("m5-laptop", *_trunk_failed("timeout"))
    assert row(document, "THIS MAC", "Startup disk") == "Not read: timed out after 10 seconds"
    for label in ("SMART status", "Health log"):
        assert row(document, "STORAGE HEALTH AND WEAR", label) == (
            "Not read: the startup disk could not be identified"
        )
    assert glance(document)[0] == (
        "Storage SSD health log not read: the startup disk could not be identified."
    )


def test_a_garbled_physical_store_names_no_disk():
    document = edited("m5-laptop", *_trunk_failed("source_changed", store=True))
    assert row(document, "THIS MAC", "Startup disk") == (
        "the internal SSD; its name was not read (macOS returned a format this version does "
        "not recognize)"
    )
    assert row(document, "STORAGE HEALTH AND WEAR", "Health log") == (
        "Not read: the startup disk could not be identified"
    )


def test_a_garbled_physical_store():
    document = edited(
        "m5-laptop",
        _value_unavailable("startup_disk", "physical_store"),
        _value_unavailable("startup_disk", "whole_disk"),
        *[
            _value_unavailable("nvme_devices", name)
            for name in ("bsd_name", "device_model", "device_revision", "size_text")
        ],
        *[
            _value_unavailable("nvme_devices", name)
            for name in ("size_bytes", "smart_status", "trim_support")
        ],
        _unavailable("smart_health_snapshot", "source_changed"),
        _unavailable("smart_wear_attributes", "source_changed"),
    )
    assert row(document, "THIS MAC", "Startup disk") == (
        "the internal SSD; its name was not read (macOS returned a format this version does "
        "not recognize)"
    )


@pytest.mark.parametrize(
    ("edits", "entry", "index"),
    [
        # An available SSD health log always decodes its endurance, and an available memory
        # error log always has a count read: neither topic has a value macOS did not report.
        (
            [
                _value_unavailable("battery_health", "condition"),
                _value_unavailable("battery_health", "maximum_capacity_percent"),
            ],
            "Battery Battery condition and capacity not reported by macOS.",
            1,
        ),
        (
            [
                _value_unavailable("power_and_thermal_samples", name)
                for name in (
                    "sample_thermal_pressure",
                    "thermal_nominal_count",
                    "thermal_moderate_count",
                    "thermal_heavy_count",
                    "thermal_trapping_count",
                    "thermal_sleeping_count",
                )
            ],
            "Thermal Thermal pressure not reported by macOS.",
            3,
        ),
        (
            [
                _value_unavailable("power_and_thermal_samples", name)
                for name in (
                    "sample_thermal_pressure",
                    "thermal_nominal_count",
                    "thermal_moderate_count",
                    "thermal_heavy_count",
                    "thermal_trapping_count",
                    "thermal_sleeping_count",
                )
            ]
            + [_unavailable("thermal_warning_level", "timeout")],
            "Thermal Thermal pressure not reported by macOS.",
            3,
        ),
    ],
    ids=["battery", "thermal series", "thermal unread"],
)
def test_a_topic_whose_value_macos_did_not_report_says_so(edits, entry, index):
    entries = glance(edited("m5-laptop", *edits))
    assert entries[index] == entry
    assert entries[-1].startswith("Not read ")


def test_a_thermal_series_macos_left_out_is_said_once():
    names = ("sample_thermal_pressure", "thermal_nominal_count", "thermal_moderate_count")
    names += ("thermal_heavy_count", "thermal_trapping_count", "thermal_sleeping_count")
    document = edited(
        "m5-laptop", *[_value_unavailable("power_and_thermal_samples", n) for n in names]
    )
    assert glance(document)[3] == "Thermal Thermal pressure not reported by macOS."
    assert "Thermal pressure" not in glance(document)[-1]
    assert row(document, "POWER AND THERMAL CHECK", "Thermal pressure") == ("Not reported by macOS")


def test_with_nothing_unread_there_is_no_not_read_line():
    # No valid report gets here, since the ECC statement is always unavailable; the line
    # is left out rather than printed empty.
    def ecc_read(document: dict) -> None:
        entry = r.surface(document, "ecc_ras_telemetry")
        entry.update(availability="available", values={})
        entry.pop("reason")

    entries = glance(refused(edited("m5-laptop", ecc_read)))
    assert not any(entry.startswith("Not read") for entry in entries)


def test_a_value_of_the_wrong_type_is_not_reported_rather_than_a_crash():
    # The validator refuses a boolean here; the summary still does not fail on one.
    document = refused(
        edited("m5-laptop", _set("battery_health", "maximum_capacity_percent", True))
    )
    assert row(document, "BATTERY", "Maximum capacity") == "Not reported by macOS"


# --- the detail sections -----------------------------------------------------------------------


def test_the_chip_row_without_perf_levels_or_gpu():
    document = edited(
        "m5-laptop",
        *[
            _value_unavailable("kernel_and_platform", name)
            for name in ("perf_level_count", "perf_level_names", "perf_level_physical_cpus")
        ],
        _unavailable("gpu_configuration", "timeout"),
    )
    # sysctl's core total is Appendix A's (field inventory), so the row names only the chip.
    assert row(document, "THIS MAC", "Chip") == "Apple M5"


def test_the_chip_row_without_any_core_count():
    document = edited(
        "m5-laptop",
        *[
            _value_unavailable("kernel_and_platform", name)
            for name in ("perf_level_count", "perf_level_names", "perf_level_physical_cpus")
        ],
        _sysctl_failed("cpu_count", "tool_error"),
    )
    assert row(document, "THIS MAC", "Chip") == "Apple M5, 10-core GPU"


def test_one_perf_level():
    document = edited(
        "m5-laptop",
        _set("kernel_and_platform", "perf_level_count", 1),
        _set("kernel_and_platform", "perf_level_names", ["Performance"]),
        _set("kernel_and_platform", "perf_level_physical_cpus", [8]),
        _set("kernel_and_platform", "cpu_count", 8),
    )
    assert row(document, "THIS MAC", "Chip") == "Apple M5: 8 Performance cores, 10-core GPU"


@pytest.mark.parametrize(
    ("edits", "text"),
    [
        (
            [_set("memory_configuration", "size_text", "16 GB")],
            "24 GB LPDDR5 (Micron); the memory profile says 16 GB",
        ),
        (
            [_value_unavailable("hardware_overview", "physical_memory_text")],
            "24 GB LPDDR5 (Micron); size from the memory profile",
        ),
        ([_unavailable("memory_configuration", "timeout")], "24 GB"),
        ([_value_unavailable("memory_configuration", "manufacturer")], "24 GB LPDDR5"),
    ],
)
def test_the_memory_row(edits, text):
    assert row(edited("m5-laptop", *edits), "THIS MAC", "Memory") == text


@pytest.mark.parametrize(
    ("internal", "solid_state", "text"),
    [
        (True, True, "the internal SSD"),
        (True, False, "the internal disk"),
        (False, True, "an external SSD"),
        (False, False, "an external disk"),
    ],
)
def test_the_startup_disk_row(internal, solid_state, text):
    document = edited(
        "m5-laptop",
        _set("startup_disk", "internal", internal),
        _set("startup_disk", "solid_state", solid_state),
    )
    assert row(document, "THIS MAC", "Startup disk") == f"APPLE SSD AP1024Z, 1 TB, {text} (disk0)"


def test_the_memory_row_with_neither_size():
    document = edited(
        "m5-laptop",
        _value_unavailable("hardware_overview", "physical_memory_text"),
        _value_unavailable("memory_configuration", "size_text"),
    )
    assert row(document, "THIS MAC", "Memory") == (
        "the size is not reported by macOS; LPDDR5 (Micron)"
    )


def test_the_startup_disk_row_without_where_it_is():
    document = edited("m5-laptop", _value_unavailable("startup_disk", "internal"))
    assert row(document, "THIS MAC", "Startup disk") == "APPLE SSD AP1024Z, 1 TB (disk0)"


def test_show_serial_prints_the_full_serial():
    def full(document: dict) -> None:
        r.values(document, "hardware_overview")["serial_number"] = {
            "availability": "available",
            "value": "SYNTHK7Q2",
            "provenance": "reported",
        }

    assert row(edited("m5-laptop", full), "THIS MAC", "Serial number") == "SYNTHK7Q2"


def test_the_macos_row_without_the_firmware():
    document = edited("m5-laptop", _unavailable("firmware_and_boot", "timeout"))
    assert row(document, "THIS MAC", "macOS") == "26.6.2 (25G83)"


@pytest.mark.parametrize(
    ("days", "text"), [(26, "26 days ago"), (1, "1 day ago"), (0, "less than a day ago")]
)
def test_the_last_restart_row(days, text):
    collected = int(datetime(2026, 9, 23, 21, 5, 31, tzinfo=UTC).timestamp())  # the fixture's
    epoch = collected - days * 86400 - 60
    utc = datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    document = edited(
        "m5-laptop",
        _set("boot_time", "boot_epoch_seconds", epoch),
        _set("boot_time", "boot_time_utc", utc),
        _set("boot_time", "days_since_boot", days),
    )
    local = datetime.fromtimestamp(epoch - 7 * 3600, UTC)
    date = f"{local.day} {local.strftime('%b %Y')}"
    assert row(document, "SYSTEM RECORDS", "Last restart") == f"{date}, {text} derived"


@pytest.mark.parametrize(
    ("units", "text"),
    [
        ("26019396", "13.3 TB (26,019,396 units of 512,000 B)"),
        ("1953125", "1.0 TB (1,953,125 units of 512,000 B)"),
        ("1953124", "1.0 TB (1,953,124 units of 512,000 B)"),
        ("1", "0.0 TB (1 unit of 512,000 B)"),
        ("0", "0.0 TB (0 units of 512,000 B)"),
        ("1953125000", "1.0 PB (1,953,125,000 units of 512,000 B)"),
        ("1953124999", "1,000.0 TB (1,953,124,999 units of 512,000 B)"),
    ],
)
def test_data_written_in_tb_or_pb(units, text):
    document = edited(
        "m5-laptop",
        _set("smart_wear_attributes", "data_units_written", units),
        _set("smart_wear_attributes", "bytes_written", str(int(units) * 512000)),
    )
    assert row(document, "STORAGE HEALTH AND WEAR", "Data written") == f"{text} derived"


@pytest.mark.parametrize(
    ("connected", "charging", "full", "charge", "source"),
    [
        (True, False, True, "100%, fully charged", "charger connected, not charging"),
        (True, True, False, "80%", "charger connected, charging"),
        (False, False, False, "80%", "on battery power"),
    ],
)
def test_charge_and_power_source(connected, charging, full, charge, source):
    document = edited(
        "m5-laptop",
        _set("battery_health", "charger_connected", connected),
        _set("battery_health", "is_charging", charging),
        _set("battery_health", "fully_charged", full),
        _set("battery_health", "state_of_charge_percent", 100 if full else 80),
    )
    assert row(document, "BATTERY", "Charge now") == f"{charge} measured"
    assert row(document, "BATTERY", "Power source") == f"{source} measured"


@pytest.mark.parametrize(
    ("name", "label"),
    [
        ("state_of_charge_percent", "Charge now"),
        ("fully_charged", "Charge now"),
        ("charger_connected", "Power source"),
        ("is_charging", "Power source"),
    ],
)
def test_a_charge_row_missing_both_of_its_values(name, label):
    others = {"Charge now": ("state_of_charge_percent", "fully_charged")}
    others["Power source"] = ("charger_connected", "is_charging")
    document = edited(
        "m5-laptop", *[_value_unavailable("battery_health", n) for n in others[label]]
    )
    assert row(document, "BATTERY", label) == "Not reported by macOS"


@pytest.mark.parametrize(
    ("name", "label", "text"),
    [
        (
            "state_of_charge_percent",
            "Charge now",
            "the charge level is not reported by macOS; fully charged measured",
        ),
        (
            "fully_charged",
            "Charge now",
            "100%; whether it is fully charged is not reported by macOS measured",
        ),
        (
            "charger_connected",
            "Power source",
            "whether a charger is connected is not reported by macOS; not charging measured",
        ),
        (
            "is_charging",
            "Power source",
            "charger connected; whether it is charging is not reported by macOS measured",
        ),
    ],
)
def test_a_charge_row_missing_one_value_still_shows_the_other(name, label, text):
    document = edited("m5-laptop", _value_unavailable("battery_health", name))
    assert row(document, "BATTERY", label) == text


def test_cycle_counts_fall_back_and_print_both_when_they_differ():
    differ = edited("m5-laptop", _set("battery_health", "cycle_count", 58))
    assert row(differ, "BATTERY", "Charge cycles") == "57 (macOS's power report: 58) measured"
    fallback = edited("m5-laptop", _value_unavailable("battery_gauge", "cycle_count"))
    # The other source prints, and names itself under the gauge's source line.
    assert row(fallback, "BATTERY", "Charge cycles") == "57 (macOS's power report) measured"
    assert "Charge cycles (battery gauge): not reported by macOS." in glance(fallback)[-1]


def test_an_unread_battery_collapses_to_one_row_per_source():
    document = edited(
        "m5-laptop",
        _unavailable("battery_health", "tool_error"),
        _unavailable("battery_gauge", "timeout"),
    )
    assert section(document, "BATTERY") == [
        "BATTERY                                        from macOS's power report",
        "  Power report        Not read: system_profiler returned an error",
        "                                            from the battery's own gauge",
        "  Battery gauge       Not read: timed out after 10 seconds",
    ]


def _series(kind: str, values: list[str]):
    decimals = [Decimal(v) for v in values]
    mean = sum(decimals) / 5
    mean = mean.quantize(Decimal("0.01"), rounding="ROUND_HALF_UP")
    from voltry_mac import numbers

    return [
        _set("power_and_thermal_samples", f"sample_{kind}_power_mw", values),
        _set("power_and_thermal_samples", f"{kind}_power_mw_min", numbers.canonical(min(decimals))),
        _set("power_and_thermal_samples", f"{kind}_power_mw_max", numbers.canonical(max(decimals))),
        _set("power_and_thermal_samples", f"{kind}_power_mw_mean", numbers.canonical(mean)),
    ]


@pytest.mark.parametrize(
    ("values", "text"),
    [
        (["566.227", "2675.49", "1641.05", "600.0", "700.0"], "0.6 to 2.7 W, average 1.2 W"),
        (["50.4092", "60.4857", "55.0", "52.0", "53.0"], "0.05 to 0.06 W, average 0.05 W"),
        (["1210.0", "1240.0", "1220.0", "1230.0", "1225.0"], "1.21 to 1.24 W, average 1.23 W"),
        (["0.0", "0.0", "0.0", "0.0", "0.0"], "0.0 W in every sample"),
        (["1500.0", "1500.0", "1500.0", "1500.0", "1500.0"], "1.5 W in every sample"),
        (["0.0", "0.0", "0.0", "0.0", "150.0"], "0.0 to 0.15 W, average 0.03 W"),
        (["0.0", "0.0", "0.0", "0.0", "50.0"], "0.0 to 0.05 W, average 0.01 W"),
        (["1050.0", "1149.0", "1100.0", "1100.0", "1100.0"], "1.05 to 1.15 W, average 1.10 W"),
        (["1250.0", "2350.0", "1800.0", "1800.0", "1800.0"], "1.3 to 2.4 W, average 1.8 W"),
    ],
    ids=[
        "one decimal",
        "below 0.1 W",
        "a collapsed range",
        "all zero",
        "all equal",
        "a small mean",
        "a zero and a small maximum",
        "collapsed by rounding",
        "half up",
    ],
)
def test_watts_follow_decision_6(values, text):
    document = edited("m5-laptop", *_series("cpu", values))
    assert row(document, "POWER AND THERMAL CHECK", "CPU power") == f"{text} derived"


def test_the_combined_row_says_combined():
    assert row(m5(), "POWER AND THERMAL CHECK", "Processor power") == (
        "0.6 to 2.7 W combined, average 1.7 W derived"
    )


# --- the limits section ------------------------------------------------------------------------


def test_the_limits_open_with_the_ssd_when_it_warns():
    failing = edited("m5-laptop", _set("nvme_devices", "smart_status", "Failing"))
    found = section(failing, "WHAT THIS REPORT CANNOT TELL YOU")
    assert found[1] == "  - Why the SSD reports a warning, or whether it will fail. It shows"
    assert section(m5(), "WHAT THIS REPORT CANNOT TELL YOU")[1].startswith(
        "  - Whether the memory has ever had errors."
    )


# --- words and characters ----------------------------------------------------------------------

# Constructions the report never uses (Decision 6's copy policy): a verdict, a grade or score,
# a certificate, a price or resale figure, or a prediction of remaining life. The fixed lines
# that say what the report does not do are the only place these words appear. "Safe to
# delete" is no verdict, and "its rated endurance" no rating (the copy pass's review, round
# 2, m3).
PROHIBITED = [
    r"\b(un)?healthy\b",
    r"\bhealthi(er|est)\b",
    r"\bgrad(e|es|ed|ing)\b",
    r"\bpric(e|es|ed|ing)\b",
    r"\boverpriced\b",
    r"\bvalue\b",
    r"\bvalu(ed|ing|ation|able)\b",
    r"\bvalues? (it|this Mac|the Mac) at\b",
    r"\bworthless\b",
    r"\bin good (condition|health|shape)\b",
    r"\b(great|excellent|perfect|good|fine|mint|pristine) (condition|health|shape)\b",
    r"\blike[- ]new\b",
    r"\bpass(ed|es|ing)?\b",
    r"\bgrade [A-F]\b",
    r"\bscor(e|es|ed|ing)\b",
    r"\brated ([0-9]|[A-F]\b)",
    r"\brating (of|[0-9]|[A-F]\b)",
    r"\bcertif",
    r"\bworth\b",
    r"\bresale\b",
    r"\$\s?\d",
    r"\bremaining life\b",
    r"\blifespan\b",
    r"\byears? of life\b",
    r"\blife left\b",
    r"\b(will|should) last\b",
    r"\bsafe to (buy|use)\b",
    r"\b(is|are|looks|seems) safe\b(?! to delete)",
    r"\breliable\b",
    r"\bverdict\b",
    r"\bnothing wrong\b",
    r"\bno problems?\b",
    r"\bno (errors?|issues?|faults?)\b",
    # And the third round's (the copy pass's review, round 3, m3): the Acceptance line's "no
    # errors or any clean claim" in its other forms, fail as Voltry's judgment, a price with
    # no dollar sign, a prediction, a verdict and a grade. Two let through words the tool
    # rightly prints, and only those: "uv cache clean", the uninstall the README gives as the
    # spec does, and "or whether it will fail", from the SSD's line in the limits, which is
    # fixed copy saying what the report cannot tell.
    r"\bno (\w+ ){0,2}(errors|issues|faults|problems)\b",
    r"\b(0|zero) (\w+ )?errors\b",
    r"\b(error|fault)[- ]free\b",
    r"\bfree of (errors?|faults?)\b",
    r"(?<!uv cache )\bclean(er|est)?\b",
    r"\bbill of health\b",
    r"\bhealth (is|looks|seems) (good|fine|excellent|great)\b",
    r"\b(condition|health): (good|fine|excellent|great|perfect)\b",
    r"\bflawless\b",
    r"\btrustworthy\b",
    r"\bnothing to worry\b",
    r"\bred flags?\b",
    r"\blooks (good|fine|great)\b",
    r"\bfail(s|ed)? (our|the|this|its) (check|test)\b",
    r"\bresult: fail\b",
    r"\b[0-9]+ ?(/|out of) ?(5|10|100)\b",
    r"\bstars?\b",
    r"\btier\b",
    r"\b[A-F][+-] rating\b",
    r"\b(dollars?|usd|eur|euros?|gbp|pounds?)\b",
    r"[€£¥]\s?\d",  # a euro, pound or yen sign
    r"\btrade[- ]in\b",
    r"\bsells? for\b",
    r"\binvaluable\b",
    r"(?<!or whether it )\b(will|is likely to|is about to) (fail|die)\b",
    r"\b(can|may|could|might) last\b",
    r"\bdiagnos(e|es|ed|ing|is)\b",
    r"\b(years?|months?) left\b",
    r"\blife expectancy\b",
    r"\bend of (its )?life\b",
]
FIXED_LIMITS = (
    "Point-in-time observations, not a diagnosis, grade or certificate.",
    "here shows how it was used, or how long it will last.",
    "- Value or price. Voltry does not assess either.",
)
# The copy rules read a summary whole: its chips out and its lines joined, so a construction
# wrapped across two lines, or split by a chip, is seen as the reader sees it (the pass-3
# pre-audit, P3-output-02: "counts 0 correctable" [chip] "errors" passed line by line).
_CHIP_AT_END = re.compile(r" +(measured|reported|derived)$", re.MULTILINE)


def prohibited(text: str) -> list[tuple[str, str]]:
    """Each prohibited construction the summary holds, read whole, with the words around it;
    the fixed lines that say what the report does not do are left out."""
    said = " ".join(_CHIP_AT_END.sub("", text).split())
    for fixed in FIXED_LIMITS:
        said = said.replace(fixed, " ")
    found = []
    for pattern in PROHIBITED:
        for match in re.finditer(pattern, said, re.IGNORECASE):
            found.append((pattern, said[max(0, match.start() - 60) : match.end() + 40]))
    return found


@pytest.mark.parametrize(("label", "document"), DOCUMENTS, ids=[d[0] for d in DOCUMENTS])
def test_no_prohibited_construction(label, document):
    assert prohibited(summary(document)) == []


@pytest.mark.parametrize(("label", "document"), DOCUMENTS, ids=[d[0] for d in DOCUMENTS])
def test_no_em_or_en_dash(label, document):
    text = summary(document)
    assert chr(0x2013) not in text and chr(0x2014) not in text


@pytest.mark.parametrize(
    "character",
    [chr(c) for c in (0x07, 0x1B, 0x7F, 0x85, 0x200B, 0x200E, 0x202E, 0x2028, 0x2066, 0xFEFF)],
)
def test_control_characters_from_system_output_are_stripped(character):
    document = edited(
        "m5-laptop", _set("hardware_overview", "model_number", f"MDE{character}34LL/A")
    )
    # The validator refuses a control, separator or bidirectional control character in a
    # value and lets the other format characters through; the summary strips them all.
    if character not in "\u200b\u200e\ufeff":
        document = refused(document)
    text = summary(document)
    assert character not in text
    assert "model number MDE34LL/A" in text


def test_a_long_value_wraps_inside_its_column():
    long = "Apple M5 " + "Max " * 30
    document = edited("m5-laptop", _set("hardware_overview", "chip_type", long.strip()))
    found = section(document, "THIS MAC")
    chip = [line for line in found if line.startswith("  Chip") or line.startswith(" " * 20)]
    assert len(chip) > 2 and all(len(line) <= 80 for line in chip)
    assert all(line.startswith(" " * 20) for line in chip[1:])


def test_a_word_longer_than_its_column_is_split():
    document = edited("m5-laptop", _set("hardware_overview", "model_number", "X" * 200))
    assert all(len(line) <= 80 for line in lines(document))
    assert "".join(section(document, "THIS MAC")).count("X") == 200


def test_wide_characters_count_twice():
    document = edited("m5-laptop", _set("memory_configuration", "manufacturer", chr(0x4E09) * 40))
    assert all(width(line) <= 80 for line in lines(document))


def test_the_summary_does_not_change_the_document():
    document = load("concerning-desktop")
    before = copy.deepcopy(document)
    summary(document)
    assert document == before


@pytest.mark.parametrize("module", ["phrases", "sections", "details", "terminal", "characters"])
def test_the_renderer_reads_no_clock_file_process_or_network(module):
    # "Renderers | Pure | ... | Read the clock or the network" (the Architecture's table).
    # Not unicodedata either: a character is what the character table says (the first
    # audit's G1-08).
    import ast

    tree = ast.parse((Path(terminal.__file__).parent / f"{module}.py").read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    assert imported <= {
        "__future__",
        "bisect",
        "collections.abc",
        "dataclasses",
        "decimal",
        "typing",
        "voltry_mac",
    }
    called = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not called & {"open", "print", "input", "exec", "eval", "__import__"}


# --- the review of #349 ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "shown", "glanced"),
    [
        (
            "uncorrectable_event_rows",
            "14 correctable, uncorrectable records not reported by macOS (the log counts 2) "
            "measured",
            "Memory 14 correctable records in macOS's private memory error log; the "
            "uncorrectable records were not reported by macOS, and the log's own uncorrectable "
            "count is 2. Records exist; how far back the log reaches is unknown. measured",
        ),
        (
            "correctable_event_rows",
            "correctable records not reported by macOS (the log counts 14), 2 uncorrectable "
            "measured",
            "Memory 2 uncorrectable records in macOS's private memory error log; the "
            "correctable records were not reported by macOS, and the log's own correctable "
            "count is 14. Records exist; how far back the log reaches is unknown. measured",
        ),
    ],
)
def test_a_missing_memory_error_count_is_never_a_zero(name, shown, glanced):
    # Decision 6: a value the source omitted prints as not reported by macOS, never as 0.
    document = edited("concerning-desktop", _value_unavailable("memory_error_ledger", name))
    assert row(document, "MEMORY", "Memory error records") == shown
    assert glanced in glance(document)
    assert "Zero means" not in notes(document, "MEMORY", "Memory error records")


def test_no_report_has_all_four_ledger_values_unread():
    # An available surface has a value read, so the summary has no words for a memory error
    # log with none (the review of #349, round 4).
    document = edited(
        "m5-laptop",
        *[
            _value_unavailable("memory_error_ledger", f"{kind}_{column}")
            for kind in ("correctable", "uncorrectable")
            for column in ("event_rows", "reported_count")
        ],
    )
    with pytest.raises(canonical.Invalid, match="needs at least one available value"):
        validate.validate(document)


def test_a_missing_count_of_the_logs_own_is_named_apart():
    document = edited(
        "m5-laptop", _value_unavailable("memory_error_ledger", "correctable_reported_count")
    )
    assert row(document, "MEMORY", "Memory error records") == (
        "0 correctable (the log's own count not reported), 0 uncorrectable measured"
    )
    assert "The log's own counts (correctable): not reported by macOS." in glance(document)[-1]


def _units(units: int):
    return [
        _set("smart_wear_attributes", "data_units_written", str(units)),
        _set("smart_wear_attributes", "bytes_written", str(units * 512000)),
    ]


def _oracle_total(total: int) -> str:
    """Bytes as Decision 6 spells them, in integers: TB below 1 PB, PB from it, half up."""
    unit = 10**15 if total >= 10**15 else 10**12
    tenths, rest = divmod(total * 10, unit)
    tenths += rest * 2 >= unit
    whole, fraction = divmod(tenths, 10)
    return f"{whole:,}.{fraction} {'PB' if unit == 10**15 else 'TB'}"


@pytest.mark.parametrize(
    "units", [2**128 - 1, 19531250000000000000097656249, 1953124999999999999999999999999]
)
def test_the_largest_counters_print_exactly(units):
    # A 128-bit counter can be all ones; its byte total has 45 digits, past the default
    # 28-digit decimal context, which crashed or rounded twice.
    document = edited("m5-laptop", *_units(units))
    # A number wider than the column breaks after a comma; row() joins with a space.
    shown = row(document, "STORAGE HEALTH AND WEAR", "Data written").replace(", ", ",")
    assert shown == f"{_oracle_total(units * 512000)} ({units:,} units of 512,000 B) derived"


def test_a_long_number_breaks_only_after_a_group():
    document = edited("m5-laptop", *_units(2**128 - 1))
    lines = section(document, "STORAGE HEALTH AND WEAR")
    start = next(i for i, line in enumerate(lines) if line.startswith("  Data written"))
    value = [lines[start][22:63].rstrip()]
    value += [line.strip() for line in lines[start + 1 :] if line.startswith(" " * 22)]
    for line in value[:-1]:
        assert line.endswith((",", "B)")) or not line[-1].isdigit(), value


PAYLOAD_STOPS = {
    "count: authentication failed": "asked, granted, then not granted at the memory-error "
    "step, cleared.",
    "count: account blocked": "asked, granted, then macOS reported a problem with this account "
    "at the memory-error step, cleared.",
    "count: refused by policy": "asked, granted, then refused by sudo's policy at the "
    "memory-error step, cleared.",
    "count: an unexplained sudo error": "asked, granted, then sudo reported an error at the "
    "memory-error step, cleared.",
    "power: authentication failed": "asked, granted, then not granted at the power and thermal "
    "step, cleared.",
    "power: account blocked": "asked, granted, then macOS reported a problem with this account "
    "at the power and thermal step, cleared.",
    "power: refused by policy": "asked, granted, then refused by sudo's policy at the power and "
    "thermal step, cleared.",
    "power: an unexplained sudo error": "asked, granted, then sudo reported an error at the "
    "power and thermal step, cleared.",
    "count: authentication failed, then a survivor": "asked, granted, then not granted at the "
    "memory-error step, cleared; a stop could not be verified.",
    "count: parsed, then the listing failed": "asked, granted, cleared; a stop could not be "
    "verified.",
    "-n forms, authentication denied": "allowed with --yes, not granted, cleared.",
}


@pytest.mark.parametrize(("key", "line"), list(PAYLOAD_STOPS.items()), ids=list(PAYLOAD_STOPS))
def test_the_elevation_line_names_a_step_sudo_did_not_grant(key, line):
    assert f"Administrator reads: {line}" in title(history("m5-laptop", key))


def test_two_reasons_to_skip_are_joined():
    document = edited("m5-laptop", _unavailable("panic_report_count", "no_admin"))
    record, count, power = r.LEGAL["declined at the question"]
    r.elevate(document, record, count=count, power=power)
    document = r.finish(document)
    assert (
        "3 skipped (administrator reads declined; the crash report folder is readable by "
        "administrator accounts only)" in title(document)
    )


def test_a_level_recorded_but_not_read_is_never_none_recorded():
    document = declined()
    r.set_value(document, "thermal_warning_level", "thermal_warning_recorded", True)
    r.values(document, "thermal_warning_level")["thermal_warning_level"] = {
        "availability": "unavailable",
        "reason": "source_changed",
    }
    document = r.finish(document)
    entries = glance(document)
    assert entries[3] == (
        "Thermal macOS thermal warning level now: recorded, the level itself not reported by "
        "macOS. reported"
    )
    assert "Thermal warning level:" not in entries[-1], "said once"


@pytest.mark.parametrize(
    ("celsius", "centi", "shown"),
    [("-0.04", -4, "0.0"), ("-0.05", -5, "-0.1"), ("30.45", 3045, "30.5")],
)
def test_a_battery_temperature_rounds_half_up_and_never_to_minus_zero(celsius, centi, shown):
    document = edited(
        "m5-laptop",
        _set("battery_gauge", "temperature_c", celsius),
        _set("battery_gauge", "temperature_centi_c", centi),
    )
    assert row(document, "BATTERY", "Temperature") == f"{shown} °C derived"


@pytest.mark.parametrize(
    ("spare", "threshold", "shown"),
    [
        (None, 99, "out of range (threshold 99%) reported"),
        (100, None, "100% (threshold out of range) reported"),
    ],
)
def test_the_spare_row_shows_the_value_it_has(spare, threshold, shown):
    edits = []
    for name, value in (
        ("available_spare_percent", spare),
        ("available_spare_threshold_percent", threshold),
    ):
        if value is None:
            edits.append(_value_unavailable("smart_health_snapshot", name))
    document = edited("m5-laptop", *edits)
    assert row(document, "STORAGE HEALTH AND WEAR", "Available spare") == shown


def test_a_smart_value_outside_its_range_says_so():
    document = edited(
        "m5-laptop",
        _value_unavailable("smart_health_snapshot", "available_spare_threshold_percent"),
    )
    assert (
        "Available spare threshold: the drive reported a reading outside its range."
        in glance(document)[-1]
    )


CHIP_WORD_DOCUMENTS = [
    ("concerning, macOS version unreadable", ("concerning-desktop", "os_version", "tool_error")),
    ("m5, macOS version unreadable", ("m5-laptop", "os_version", "tool_error")),
]


@pytest.mark.parametrize(
    ("label", "case"), CHIP_WORD_DOCUMENTS, ids=[c[0] for c in CHIP_WORD_DOCUMENTS]
)
def test_the_reports_own_words_never_end_a_line_like_a_chip(label, case):
    name, key, reason = case
    document = edited(name, _unavailable(key, reason))
    in_glance = False
    for line in lines(document):
        if line == "" or not line.startswith(" "):
            in_glance = line == "AT A GLANCE"
            continue
        found = re.search(r" (measured|reported|derived)$", line)
        if found:
            assert found.start() + 1 == (63 if in_glance else 64), line
            assert _word_before_chip(line) not in ("not", "Not"), line


def test_the_thermal_fallback_never_ends_a_line_like_a_chip():
    document = history("m5-laptop", "count: an unexplained sudo error")
    for line in lines(document):
        found = re.search(r" (measured|reported|derived)$", line)
        if found:
            assert found.start() + 1 in (63, 64), line


@pytest.mark.parametrize(
    ("month", "name"),
    list(enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep"], start=1)),
)
def test_every_month_is_named(month, name):
    collected = int(datetime(2026, 9, 23, 21, 5, 31, tzinfo=UTC).timestamp())
    epoch = int(datetime(2026, month, 1, 12, 0, 0, tzinfo=UTC).timestamp())
    days = (collected - epoch) // 86400
    utc = datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    document = edited(
        "m5-laptop",
        _set("boot_time", "boot_epoch_seconds", epoch),
        _set("boot_time", "boot_time_utc", utc),
        _set("boot_time", "days_since_boot", days),
    )
    assert row(document, "SYSTEM RECORDS", "Last restart").startswith(f"1 {name} 2026, ")


@pytest.mark.parametrize(
    ("local", "shown"),
    [
        ("2026-10-31T23:59:00-07:00", "31 Oct 2026, 23:59"),
        ("2026-11-30T08:00:00-07:00", "30 Nov 2026, 08:00"),
        ("2026-12-31T23:30:00+14:00", "31 Dec 2026, 23:30"),
        ("2028-02-29T12:00:00+00:00", "29 Feb 2028, 12:00"),
    ],
)
def test_months_ten_to_twelve_and_a_leap_day(local, shown):
    assert f". {shown} (" in title(edited("m5-laptop", _local(local)))


@pytest.mark.parametrize(
    ("values", "text"),
    [
        (["100.0", "200.0", "150.0", "150.0", "150.0"], "0.1 to 0.2 W, average 0.2 W"),
        (["0.0", "0.0", "200.0", "200.0", "200.0"], "0.0 to 0.2 W, average 0.1 W"),
        (["0.0", "0.0", "100.0", "0.0", "0.0"], "0.0 to 0.10 W, average 0.02 W"),
        (["1210.0", "1290.0", "1230.0", "1250.0", "1245.0"], "1.2 to 1.3 W, average 1.2 W"),
    ],
    ids=[
        "exactly 0.1 W",
        "an exact zero keeps one decimal",
        "a mean below 0.1 W takes two",
        "the range decides, not the mean",
    ],
)
def test_watts_at_their_boundaries(values, text):
    document = edited("m5-laptop", *_series("cpu", values))
    assert row(document, "POWER AND THERMAL CHECK", "CPU power") == f"{text} derived"


@pytest.mark.parametrize(
    ("byte", "text"),
    [
        (2, "temperature outside threshold (bit 1)"),
        (4, "reliability degraded (bit 2)"),
        (8, "read-only mode (bit 3)"),
        (16, "volatile memory backup failed (bit 4)"),
        (32, "an unknown warning bit (bit 5)"),
        (192, "unknown warning bits (bits 6 and 7)"),
        (3, "spare capacity below threshold and temperature outside threshold (bits 0 and 1)"),
        (33, "spare capacity below threshold and an unknown warning bit (bits 0 and 5)"),
        (225, "spare capacity below threshold and unknown warning bits (bits 0, 5, 6 and 7)"),
    ],
)
def test_the_critical_warning_row_names_each_bit(byte, text):
    flags = {
        "spare_below_threshold": bool(byte & 1),
        "temperature_warning": bool(byte & 2),
        "reliability_degraded": bool(byte & 4),
        "read_only_mode": bool(byte & 8),
        "volatile_backup_failed": bool(byte & 16),
        "unknown_warning_bits": bool(byte & 224),
    }
    edits = [_set("smart_health_snapshot", "critical_warning_byte", byte)]
    edits += [_set("smart_health_snapshot", name, value) for name, value in flags.items()]
    shown = row(edited("m5-laptop", *edits), "STORAGE HEALTH AND WEAR", "Critical warning")
    assert shown == f"{text} reported"


def test_a_word_wider_than_its_column_splits_into_whole_pieces():
    document = edited("m5-laptop", _set("hardware_overview", "model_number", "X" * 130))
    found = section(document, "THIS MAC")
    start = next(i for i, line in enumerate(found) if line.startswith("  Model"))
    assert found[start][20:] == "MacBook Pro, Mac17,2, model number"
    assert [line[20:] for line in found[start + 1 : start + 4]] == ["X" * 60, "X" * 60, "X" * 10]


def test_combining_marks_take_no_column_and_wide_characters_two():
    # 26 base letters with a combining acute each, then wide characters: the Memory row's
    # value column holds exactly 60 columns.
    maker = "e" + chr(0x0301)
    document = edited(
        "m5-laptop",
        _set("memory_configuration", "manufacturer", maker * 20 + chr(0x4E09) * 9),
    )
    found = section(document, "THIS MAC")
    memory = next(line for line in found if line.startswith("  Memory"))
    assert width(memory) <= 80


def test_the_not_read_names_each_surface_as_a_reader_would():
    document = edited(
        "m5-laptop",
        *[
            _unavailable(key, "timeout")
            for key in (
                "os_version",
                "firmware_and_boot",
                "gpu_configuration",
                "memory_configuration",
                "battery_gauge",
                "thermal_warning_level",
                "memory_pressure",
                "virtualization_state",
                "boot_time",
            )
        ],
        _unavailable("panic_report_count", "tool_error"),
    )
    assert glance(document)[-1] == (
        "Not read macOS version: timed out after 10 seconds. Hardware overview: timed out "
        "after 10 seconds. Firmware version: timed out after 10 seconds. GPU: timed out after "
        "10 seconds. Memory type: timed out after 10 seconds. "
        "Battery gauge: timed out after 10 seconds. Thermal warning level: timed out after 10 "
        "seconds. Memory pressure: timed out after 10 seconds. Virtual machine check: timed out "
        "after 10 seconds. Last restart: timed out after 10 seconds. Panic reports: the crash "
        "report folder could not be read. ECC error counters: no public interface on Macs."
    )


@pytest.mark.parametrize(
    ("key", "program"),
    [
        ("os_version", "sw_vers"),
        ("firmware_and_boot", "system_profiler"),
        ("gpu_configuration", "system_profiler"),
        ("memory_configuration", "system_profiler"),
        ("battery_gauge", "ioreg"),
        ("thermal_warning_level", "pmset"),
        ("memory_pressure", "memory_pressure"),
        ("virtualization_state", "sysctl"),
        ("boot_time", "sysctl"),
    ],
)
def test_each_failed_command_is_named(key, program):
    document = edited("m5-laptop", _unavailable(key, "tool_error"))
    assert f": {program} returned an error." in glance(document)[-1]


@pytest.mark.parametrize(
    ("value", "name"),
    [
        (("power_and_thermal_samples", "sample_combined_power_mw"), "Processor power"),
        (("power_and_thermal_samples", "sample_ane_power_mw"), "Neural Engine"),
        (("smart_health_snapshot", "composite_temperature_k"), "SSD temperature"),
        (("battery_gauge", "temperature_centi_c"), "Battery temperature"),
        (("battery_health", "fully_charged"), "Charge now (fully charged)"),
        (("battery_health", "is_charging"), "Power source (charging)"),
    ],
)
def test_the_not_read_names_match_what_the_rows_call_them(value, name):
    document = _value_gap(*value)
    assert f"{name}: " in glance(document)[-1]


def test_thousands_are_grouped_in_decimals_and_core_counts():
    document = edited(
        "m5-laptop",
        _set("gpu_configuration", "core_count", 1024),
        *_series("cpu", ["1000000.0", "1000000.0", "999000.0", "999500.0", "1000000.0"]),
    )
    assert row(document, "THIS MAC", "Chip").endswith("1,024-core GPU")
    assert row(document, "POWER AND THERMAL CHECK", "CPU power").startswith("999.0 to 1,000.0 W")


def test_an_empty_value_says_so():
    # A value made only of characters the terminal drops would print as nothing.
    document = edited(
        "m5-laptop",
        _set("memory_configuration", "manufacturer", chr(0x200B)),
        _set("nvme_devices", "smart_status", " "),
    )
    assert row(document, "THIS MAC", "Memory") == "24 GB LPDDR5 (manufacturer empty)"
    assert row(document, "STORAGE HEALTH AND WEAR", "SMART status") == "(empty) reported"


def test_the_unexpected_reasons_follow_the_collection_line():
    # The metadata table: collection status, counts and unexpected reasons, Terminal Yes.
    assert "Unexpected: a format this version does not recognize." in title(
        load("concerning-desktop")
    )
    assert "Unexpected:" not in title(m5())


def test_every_gap_is_said_exactly_once():
    import random

    from voltry_mac import phrases

    rng = random.Random(349)  # noqa: S311 - a fixed sample of cases, not a secret
    keys = [
        "os_version",
        "hardware_overview",
        "firmware_and_boot",
        "gpu_configuration",
        "memory_configuration",
        "battery_gauge",
        "thermal_warning_level",
        "memory_pressure",
        "sip_status",
        "gatekeeper_status",
        "filevault_status",
        "virtualization_state",
        "boot_time",
        "panic_report_count",
    ]
    # The crash report folder cannot time out; its own failure is a tool error.
    reasons = {key: "tool_error" if key == "panic_report_count" else "timeout" for key in keys}
    for _ in range(60):
        chosen = rng.sample(keys, 3)
        document = edited("m5-laptop", *[_unavailable(key, reasons[key]) for key in chosen])
        said = " ".join(glance(document))
        for key in chosen:
            name = SURFACE_NAMES[key]
            assert said.count(name) == 1, (chosen, name, said)
            assert phrases.gap_name(phrases.Gap(key, reasons[key])) == name


# --- the review of #349, round 2 ---------------------------------------------------------------


@pytest.mark.parametrize("reason", ["tool_error", "timeout", "source_absent", "source_changed"])
def test_a_failed_gauge_still_prints_the_power_reports_cycle_count(reason):
    # Decision 8: when the authoritative source is unavailable and the other is available,
    # the page prints the other and names its source.
    document = edited("m5-laptop", _unavailable("battery_gauge", reason))
    assert row(document, "BATTERY", "Charge cycles") == "57 (macOS's power report) measured"


def test_the_chip_row_keeps_its_cores_and_gpu_without_the_chips_name():
    document = edited("m5-laptop", _value_unavailable("hardware_overview", "chip_type"))
    assert row(document, "THIS MAC", "Chip") == (
        "the chip's name is not reported by macOS; 4 Super and 6 Efficiency cores, 10-core GPU"
    )
    failed = edited("m5-laptop", _unavailable("hardware_overview", "tool_error"))
    assert row(failed, "THIS MAC", "Chip") == (
        "the chip's name was not read (system_profiler returned an error); 4 Super and 6 "
        "Efficiency cores, 10-core GPU"
    )


def test_the_chip_row_with_nothing_read_is_its_gap():
    document = edited(
        "m5-laptop",
        _value_unavailable("hardware_overview", "chip_type"),
        _unavailable("gpu_configuration", "timeout"),
        *[
            _value_unavailable("kernel_and_platform", name)
            for name in ("perf_level_count", "perf_level_names", "perf_level_physical_cpus")
        ],
    )
    assert row(document, "THIS MAC", "Chip") == "Not reported by macOS"


def test_core_clusters_that_do_not_pair_are_left_out():
    # No validated report has them; the row still names the chip and the GPU.
    document = refused(
        edited("m5-laptop", _set("kernel_and_platform", "perf_level_names", ["Super"]))
    )
    assert row(document, "THIS MAC", "Chip") == "Apple M5, 10-core GPU"


def test_a_chip_name_of_the_wrong_type_is_not_reported():
    # The validator refuses a boolean here; the summary still does not fail on one.
    document = refused(edited("m5-laptop", _set("hardware_overview", "chip_type", True)))
    assert row(document, "THIS MAC", "Chip").startswith(
        "the chip's name is not reported by macOS; "
    )


def test_the_startup_disks_name_takes_the_first_part_that_was_not_read():
    document = edited(
        "m5-laptop",
        _unavailable("nvme_devices", "timeout"),
        _set("startup_disk", "physical_store_count", 2),
        _value_unavailable("startup_disk", "physical_store", "unsupported"),
        _value_unavailable("startup_disk", "whole_disk", "unsupported"),
        _unavailable("smart_health_snapshot", "unsupported"),
        _unavailable("smart_wear_attributes", "unsupported"),
    )
    assert row(document, "THIS MAC", "Startup disk") == (
        "the internal SSD; its name was not read (the startup volume spans more than one "
        "physical store)"
    )


def test_the_macos_row_keeps_its_build_without_the_version():
    document = edited("m5-laptop", _value_unavailable("os_version", "product_version"))
    assert row(document, "THIS MAC", "macOS") == (
        "the version is not reported by macOS; build 25G83, firmware 18000.161.10"
    )


def test_a_permanent_failure_still_leads_when_the_power_report_is_unread():
    document = edited(
        "m5-laptop",
        _unavailable("battery_health", "timeout"),
        _set("battery_gauge", "permanent_failure", True),
    )
    assert "Battery The battery reports a permanent failure. reported" in glance(document)


def test_a_value_inside_a_row_is_named_by_its_row_and_its_part():
    document = edited("m5-laptop", _value_unavailable("nvme_devices", "device_revision"))
    assert "Startup disk drive entry (firmware): not reported by macOS." in glance(document)[-1]


def test_parts_of_one_row_with_one_reason_are_named_together():
    both = edited(
        "m5-laptop",
        _value_unavailable("battery_health", "state_of_charge_percent"),
        _value_unavailable("battery_health", "fully_charged"),
    )
    assert "Charge now (charge level and fully charged): not reported by macOS." in (
        glance(both)[-1]
    )
    trunk = edited("m5-laptop", *_trunk_failed("timeout"))
    assert (
        "Startup disk drive entry (name, model, firmware, rounded capacity, capacity in bytes "
        "and TRIM): the startup disk could not be identified." in glance(trunk)[-1]
    )


@pytest.mark.parametrize(
    ("reason", "text"),
    [
        ("source_absent", "Not read: system_profiler is not on this Mac"),
        (
            "source_changed",
            "Could not read: macOS returned a format this version does not recognize",
        ),
        ("timeout", "Not read: timed out after 10 seconds"),
    ],
)
def test_a_drive_entry_whose_own_command_failed_says_how(reason, text):
    document = edited("m5-laptop", _unavailable("nvme_devices", reason), lambda d: r.fail(d, "C3"))
    assert row(document, "STORAGE HEALTH AND WEAR", "SMART status") == text


def test_a_drive_listing_that_did_not_parse_beside_an_unread_trunk_is_a_format():
    document = edited(
        "m5-laptop",
        _unavailable("startup_disk", "timeout"),
        _unavailable("smart_health_snapshot", "timeout"),
        _unavailable("smart_wear_attributes", "timeout"),
        _unavailable("nvme_devices", "source_changed"),
    )
    assert row(document, "STORAGE HEALTH AND WEAR", "SMART status") == (
        "Could not read: macOS returned a format this version does not recognize"
    )


def _memory_entry(document: dict) -> str:
    return next(entry for entry in glance(document) if entry.startswith("Memory "))


def test_a_printed_zero_keeps_its_caveat_when_the_other_count_is_unread():
    document = edited(
        "m5-laptop", _value_unavailable("memory_error_ledger", "correctable_event_rows")
    )
    # The log's own correctable count, 0, stands in (round 3, Major 1): still a zero.
    assert _memory_entry(document) == (
        "Memory 0 uncorrectable records in macOS's private memory error log; the correctable "
        "records were not reported by macOS, and the log's own correctable count is 0. Zero "
        "does not prove the memory never had errors. measured"
    )
    assert "Zero means none are recorded there now, not none ever." in notes(
        document, "MEMORY", "Memory error records"
    )


def test_one_record_is_one_record():
    document = edited(
        "concerning-desktop",
        _set("memory_error_ledger", "uncorrectable_event_rows", 1),
        _set("memory_error_ledger", "uncorrectable_reported_count", 1),
        _value_unavailable("memory_error_ledger", "correctable_event_rows"),
    )
    assert _memory_entry(document).startswith(
        "Memory 1 uncorrectable record in macOS's private memory error log;"
    )


def test_the_power_source_row_never_ends_a_line_like_a_chip():
    document = edited(
        "m5-laptop",
        _set("battery_health", "charger_connected", False),
        _value_unavailable("battery_health", "is_charging"),
    )
    for line in section(document, "BATTERY"):
        found = re.search(r" (measured|reported|derived)$", line)
        if found:
            assert found.start() + 1 == 64, line


def test_an_empty_core_cluster_name_says_so():
    document = edited(
        "m5-laptop", _set("kernel_and_platform", "perf_level_names", ["", "Efficiency"])
    )
    assert row(document, "THIS MAC", "Chip") == (
        "Apple M5: 4 (empty) and 6 Efficiency cores, 10-core GPU"
    )


@pytest.mark.parametrize("blank", [chr(0x3164), chr(0x115F), chr(0xFFA0), chr(0x2800)])
def test_blank_letters_are_nothing_visible(blank):
    document = edited("m5-laptop", _set("battery_health", "condition", blank * 3))
    assert row(document, "BATTERY", "Condition") == "(empty) reported"


def test_the_warning_level_shows_only_when_administrator_reads_were_skipped():
    # The field inventory: Terminal "When administrator reads are skipped".
    document = history("m5-laptop", "power: a payload error")
    assert glance(document)[3] == (
        "Thermal Thermal pressure not read: powermetrics returned an error."
    )


def test_a_panic_folder_for_administrators_only_says_so_on_a_granted_run():
    document = edited("m5-laptop", _unavailable("panic_report_count", "no_admin"))
    assert (
        "1 skipped (the crash report folder is readable by administrator accounts only)"
        in title(document)
    )


@pytest.mark.parametrize(
    ("edits", "name"),
    [
        (_smart_failed("timeout"), "SSD health log"),
        ([_unavailable("battery_health", "tool_error")], "power report"),
        (
            [
                _value_unavailable("battery_health", "condition"),
                _value_unavailable("battery_health", "maximum_capacity_percent"),
            ],
            "Battery condition",
        ),
        (
            [
                _value_unavailable("memory_error_ledger", "correctable_event_rows"),
                _value_unavailable("memory_error_ledger", "uncorrectable_event_rows"),
            ],
            "Memory error records",
        ),
        (
            [
                _value_unavailable("power_and_thermal_samples", name)
                for name in (
                    "sample_thermal_pressure",
                    *(f"thermal_{s}_count" for s in ("nominal", "moderate", "heavy")),
                    *(f"thermal_{s}_count" for s in ("trapping", "sleeping")),
                )
            ],
            "Thermal pressure",
        ),
        ([_unavailable("sip_status", "timeout")], "System Integrity Protection"),
    ],
    ids=[
        "health log",
        "battery report",
        "battery condition",
        "ledger counts",
        "thermal series",
        "security",
    ],
)
def test_a_gap_a_topic_states_is_not_listed_again(edits, name):
    entries = glance(edited("m5-laptop", *edits))
    assert name not in entries[-1], entries[-1]


def test_a_power_sample_a_topic_states_is_not_listed_again():
    entries = glance(history("m5-laptop", "power: a payload error"))
    assert "Power and thermal check" not in entries[-1], entries[-1]


# Every value's name in the Not read line, pinned.
NAMES = {
    ("os_version", "product_name"): "macOS name",
    ("os_version", "product_version"): "macOS version",
    ("os_version", "build_version"): "macOS build",
    ("hardware_overview", "machine_name"): "Model name",
    ("hardware_overview", "machine_model"): "Model identifier",
    ("hardware_overview", "model_number"): "Model number",
    ("hardware_overview", "chip_type"): "Chip (name)",
    ("hardware_overview", "physical_memory_text"): "Memory size",
    ("hardware_overview", "serial_last4"): "Serial number (last 4)",
    ("hardware_overview", "serial_number"): "Serial number (full)",
    ("hardware_overview", "activation_lock_enabled"): "Activation Lock",
    ("firmware_and_boot", "boot_rom_version"): "Firmware version",
    ("firmware_and_boot", "os_loader_version"): "OS loader version",
    ("nvme_devices", "entry_count"): "Drive entries",
    ("nvme_devices", "bsd_name"): "Startup disk drive entry (name)",
    ("nvme_devices", "device_model"): "Startup disk drive entry (model)",
    ("nvme_devices", "device_revision"): "Startup disk drive entry (firmware)",
    ("nvme_devices", "size_text"): "Startup disk drive entry (rounded capacity)",
    ("nvme_devices", "size_bytes"): "Startup disk drive entry (capacity in bytes)",
    ("nvme_devices", "smart_status"): "SMART status",
    ("nvme_devices", "trim_support"): "Startup disk drive entry (TRIM)",
    ("gpu_configuration", "core_count"): "GPU cores",
    ("gpu_configuration", "metal_family"): "Metal support",
    ("memory_configuration", "memory_type"): "Memory type",
    ("memory_configuration", "manufacturer"): "Memory manufacturer",
    ("memory_configuration", "size_text"): "Memory size (memory profile)",
    ("battery_health", "condition"): "Battery condition",
    ("battery_health", "maximum_capacity_percent"): "Maximum capacity",
    ("battery_health", "cycle_count"): "Charge cycles (power report)",
    ("battery_health", "state_of_charge_percent"): "Charge now (charge level)",
    ("battery_health", "fully_charged"): "Charge now (fully charged)",
    ("battery_health", "is_charging"): "Power source (charging)",
    ("battery_health", "charger_connected"): "Power source (charger)",
    ("battery_health", "gauge_device_name"): "Battery gauge revisions (chip)",
    ("battery_health", "gauge_firmware_version"): "Battery gauge revisions (firmware)",
    ("battery_health", "gauge_hardware_revision"): "Battery gauge revisions (hardware)",
    ("battery_gauge", "cycle_count"): "Charge cycles (battery gauge)",
    ("battery_gauge", "design_cycle_count"): "Design cycle count",
    ("battery_gauge", "design_capacity_mah"): "Design capacity",
    ("battery_gauge", "full_charge_capacity_mah"): "Full charge now",
    ("battery_gauge", "temperature_centi_c"): "Battery temperature",
    ("battery_gauge", "temperature_c"): "Battery temperature",
    ("battery_gauge", "permanent_failure"): "Permanent failure flag",
    ("thermal_warning_level", "thermal_warning_recorded"): "Thermal warning level",
    ("thermal_warning_level", "thermal_warning_level"): "Thermal warning level",
    ("memory_pressure", "free_percent"): "Memory pressure",
    ("startup_disk", "physical_store_count"): "Physical stores",
    ("startup_disk", "physical_store"): "Startup disk",
    ("startup_disk", "whole_disk"): "Startup disk",
    ("startup_disk", "internal"): "Internal disk flag",
    ("startup_disk", "solid_state"): "Solid-state flag",
    ("sip_status", "enabled"): "System Integrity Protection",
    ("gatekeeper_status", "assessments_enabled"): "Gatekeeper",
    ("filevault_status", "enabled"): "FileVault",
    ("kernel_and_platform", "hw_model"): "Model identifier (sysctl)",
    ("kernel_and_platform", "hw_target"): "Board ID",
    ("kernel_and_platform", "memory_bytes"): "Memory total",
    ("kernel_and_platform", "cpu_count"): "CPU count",
    ("kernel_and_platform", "cpu_brand"): "CPU brand",
    ("kernel_and_platform", "arm64"): "Apple silicon flag",
    ("kernel_and_platform", "perf_level_count"): "Core clusters (count)",
    ("kernel_and_platform", "perf_level_names"): "Core clusters (names)",
    ("kernel_and_platform", "perf_level_physical_cpus"): "Core clusters (core counts)",
    ("virtualization_state", "vmm_present"): "Virtual machine check",
    ("boot_time", "boot_epoch_seconds"): "Last restart",
    ("boot_time", "boot_time_utc"): "Last restart",
    ("boot_time", "days_since_boot"): "Last restart",
    **{
        ("smart_health_snapshot", name): "Critical warning"
        for name in (
            "critical_warning_byte",
            "spare_below_threshold",
            "temperature_warning",
            "reliability_degraded",
            "read_only_mode",
            "volatile_backup_failed",
            "unknown_warning_bits",
        )
    },
    ("smart_health_snapshot", "composite_temperature_k"): "SSD temperature",
    ("smart_health_snapshot", "composite_temperature_c"): "SSD temperature",
    ("smart_health_snapshot", "available_spare_percent"): "Available spare",
    ("smart_health_snapshot", "available_spare_threshold_percent"): "Available spare threshold",
    ("smart_wear_attributes", "percentage_used"): "Endurance used",
    ("smart_wear_attributes", "data_units_read"): "Data read",
    ("smart_wear_attributes", "bytes_read"): "Data read",
    ("smart_wear_attributes", "data_units_written"): "Data written",
    ("smart_wear_attributes", "bytes_written"): "Data written",
    ("smart_wear_attributes", "power_cycles"): "Power cycles",
    ("smart_wear_attributes", "power_on_hours"): "Power-on hours",
    ("smart_wear_attributes", "unsafe_shutdowns"): "Unsafe shutdowns",
    ("smart_wear_attributes", "media_errors"): "Media errors",
    ("smart_wear_attributes", "error_log_entries"): "Error log entries",
    ("panic_report_count", "count"): "Panic reports",
    ("memory_error_ledger", "correctable_event_rows"): "Memory error records (correctable)",
    ("memory_error_ledger", "uncorrectable_event_rows"): "Memory error records (uncorrectable)",
    ("memory_error_ledger", "correctable_reported_count"): "The log's own counts (correctable)",
    (
        "memory_error_ledger",
        "uncorrectable_reported_count",
    ): "The log's own counts (uncorrectable)",
    ("power_and_thermal_samples", "sample_count"): "Samples",
    ("power_and_thermal_samples", "sample_elapsed_ns"): "Sample times",
    ("power_and_thermal_samples", "sample_thermal_pressure"): "Thermal pressure",
    **{
        ("power_and_thermal_samples", f"thermal_{state}_count"): "Thermal pressure"
        for state in ("nominal", "moderate", "heavy", "trapping", "sleeping")
    },
    **{
        ("power_and_thermal_samples", name): label
        for kind, label in (
            ("cpu", "CPU power"),
            ("gpu", "GPU power"),
            ("ane", "Neural Engine"),
            ("combined", "Processor power"),
        )
        for name in (
            f"sample_{kind}_power_mw",
            *(f"{kind}_power_mw_{end}" for end in ("min", "max", "mean")),
        )
    },
}


def test_every_value_has_its_pinned_name():
    from voltry_mac import phrases, registry

    every = {(spec.key, value.name) for spec in registry.SURFACES for value in spec.values}
    assert set(NAMES) == every
    for (key, name), label in NAMES.items():
        assert phrases.gap_name(phrases.Gap(key, "source_changed", name)) == label, (key, name)


@pytest.mark.parametrize(
    ("key", "program"),
    [
        ("hardware_overview", "system_profiler"),
        ("nvme_devices", "system_profiler"),
        ("battery_health", "system_profiler"),
        ("startup_disk", "diskutil"),
        ("sip_status", "csrutil"),
        ("gatekeeper_status", "spctl"),
        ("filevault_status", "fdesetup"),
    ],
)
def test_each_other_failed_command_is_named(key, program):
    edits = (
        _trunk_failed("tool_error") if key == "startup_disk" else [_unavailable(key, "tool_error")]
    )
    document = edited("m5-laptop", *edits)
    assert f"{program} returned an error" in " ".join(glance(document))


@pytest.mark.parametrize(
    ("reasons", "line"),
    [
        (["source_absent"], "Unexpected: a file or device that is not present."),
        (["source_changed"], "Unexpected: a format this version does not recognize."),
        (["timeout"], "Unexpected: a step that timed out."),
        (["tool_error"], "Unexpected: a tool or step that failed."),
        (
            ["source_changed", "timeout"],
            "Unexpected: a format this version does not recognize and a step that timed out.",
        ),
        (
            ["source_absent", "source_changed", "tool_error"],
            "Unexpected: a file or device that is not present, a format this version does not "
            "recognize and a tool or step that failed.",
        ),
    ],
)
def test_each_unexpected_reason_and_their_joins(reasons, line):
    # A surface each reason can come from on this Mac; the collection block counts them.
    source = {
        "source_absent": "nvme_devices",
        "source_changed": "os_version",
        "timeout": "gpu_configuration",
        "tool_error": "sip_status",
    }
    document = edited("m5-laptop", *[_unavailable(source[reason], reason) for reason in reasons])
    assert document["collection"]["unexpected_reasons"] == reasons
    assert line in title(document)


def test_the_civil_date_matches_the_calendar():
    from datetime import date, timedelta

    from voltry_mac import phrases

    start = date(1970, 1, 1)
    # Every day from 1970 to 2134, the leap days of 2000 and 2100's lack of one included.
    for days in range(0, 60000):
        expected = start + timedelta(days=days)
        assert phrases.civil(days) == (expected.year, expected.month, expected.day), days


def test_the_boot_date_is_the_local_date_at_the_collection_offset():
    # 02:00 UTC on 1 Sep is 19:00 on 31 Aug at the fixture's offset of UTC-7.
    collected = int(datetime(2026, 9, 23, 21, 5, 31, tzinfo=UTC).timestamp())
    epoch = int(datetime(2026, 9, 1, 2, 0, 0, tzinfo=UTC).timestamp())
    document = edited(
        "m5-laptop",
        _set("boot_time", "boot_epoch_seconds", epoch),
        _set("boot_time", "boot_time_utc", "2026-09-01T02:00:00Z"),
        _set("boot_time", "days_since_boot", (collected - epoch) // 86400),
    )
    assert row(document, "SYSTEM RECORDS", "Last restart").startswith("31 Aug 2026, ")


@pytest.mark.parametrize(
    ("text", "width"),
    [("ab", 2), (chr(0x4E09), 2), ("e" + chr(0x0301), 1), (chr(0x0301), 0), (chr(0xFF21), 2)],
)
def test_cells_count_wide_characters_twice_and_combining_marks_none(text, width):
    from voltry_mac import phrases

    assert phrases.cells(text) == width


@pytest.mark.parametrize("word", ["measured", "reported", "derived"])
def test_a_label_word_is_kept_with_the_word_after_it(word):
    assert terminal._kept(["not", word, "by", "macOS."]) == ["not", f"{word} by", "macOS."]


@pytest.mark.parametrize(
    "unit", ["TB", "PB", "GB", "MB", "B)", "W", "W,", "°C", "mAh", "TB,", "GB,", "PB,"]
)
def test_a_unit_is_kept_with_its_number(unit):
    assert terminal._kept(["1.8", unit, "next"]) == [f"1.8 {unit}", "next"]


def _surface_gap(key: str, reason: str) -> dict:
    """m5-laptop with one surface unavailable for one reason, as a run leaves it."""
    candidates = [[_unavailable(key, reason)]]
    if key == "startup_disk":
        candidates.append(_trunk_failed(reason))
    if key in ("smart_health_snapshot", "smart_wear_attributes"):
        candidates.append(_smart_failed(reason))
    document = _legal(*candidates)
    assert document is not None, (key, reason)
    return document


def _gap_documents():
    from voltry_mac import registry

    for key, name, document in VALUE_GAPS:
        yield f"{key}.{name}", document
    for spec in registry.SURFACES:
        if spec.key in ("memory_error_ledger", "power_and_thermal_samples"):
            continue  # the legal histories cover these
        for reason in sorted(spec.reasons):
            yield f"{spec.key}:{reason}", _surface_gap(spec.key, reason)
    level = declined()
    r.set_value(level, "thermal_warning_level", "thermal_warning_recorded", True)
    r.values(level, "thermal_warning_level")["thermal_warning_level"] = {
        "availability": "unavailable",
        "reason": "source_changed",
    }
    yield "thermal level unread", r.finish(level)
    # Two or three of the ledger's four values unread, on each fixture: the log's own counts
    # stand in for its records only then (the pass-3 pre-audit, P3-output-02). One is
    # VALUE_GAPS', and all four make the surface unavailable, which the histories cover.
    for name in r.NAMES:
        for size in (2, 3):
            for unread in itertools.combinations(LEDGER, size):
                edits = [_value_unavailable("memory_error_ledger", each) for each in unread]
                yield f"{name}: {' and '.join(unread)} unread", edited(name, *edits)


LEDGER = (
    "correctable_event_rows",
    "uncorrectable_event_rows",
    "correctable_reported_count",
    "uncorrectable_reported_count",
)
GAP_DOCUMENTS = list(_gap_documents())


@pytest.mark.parametrize(("label", "document"), GAP_DOCUMENTS, ids=[d[0] for d in GAP_DOCUMENTS])
def test_every_gap_phrase_follows_the_copy_policy_and_the_chip_columns(label, document):
    assert prohibited(summary(document)) == []
    in_glance = False
    for line in lines(document):
        if line == "" or not line.startswith(" "):
            in_glance = line == "AT A GLANCE"
            continue
        found = re.search(r" (measured|reported|derived)$", line)
        if found:
            assert found.start() + 1 == (63 if in_glance else 64), line
            assert _word_before_chip(line) not in ("not", "Not"), line


def _copied(node):  # type: ignore[no-untyped-def]
    """A report as JSON holds it, copied as copy.deepcopy would copy it, several times faster."""
    if isinstance(node, dict):
        return {key: _copied(value) for key, value in node.items()}
    if isinstance(node, list):
        return [_copied(value) for value in node]
    return node


@pytest.mark.parametrize("name", r.NAMES)
def test_no_two_values_left_unread_together_make_a_prohibited_construction(name):
    # Every pair of values a report can hold unread together, each with the values that
    # follow it, the whole summary read at once. The line the log's own counts give when
    # both record counts are unread was reached by no single gap and no history (the pass-3
    # pre-audit, P3-output-02, whose sweep this is: 3,660 reports on the two fixtures).
    base = r.load(name)
    gaps = {value: _gap_edits(*value) for value in _registry_values()}
    legal, found = 0, []
    for first, second in itertools.combinations(gaps, 2):
        document = _copied(base)
        for edit in [*gaps[first], *gaps[second]]:
            edit(document)
        document = r.finish(document)
        try:
            validate.validate(document)
        except canonical.Invalid:
            continue  # a pair no report can hold
        legal += 1
        found += [(first, second, *hit) for hit in prohibited(terminal.summary(document))]
    assert legal > 1000, legal
    assert found == []


# --- the display path -------------------------------------------------------------------------

HOME = "/Users/owner"


@pytest.mark.parametrize(
    ("path", "shown"),
    [
        (
            "/Users/owner/Desktop/Voltry Mac Report 2026-09-23 14.05.pdf",
            "~/Desktop/Voltry Mac Report 2026-09-23 14.05.pdf",
        ),
        ("/Users/owner", "~"),
        ("/Users/owner/", "~/"),
        ("/Users/owner2/Desktop/x.pdf", "/Users/owner2/Desktop/x.pdf"),
        ("/Volumes/Backup/x.pdf", "/Volumes/Backup/x.pdf"),
        ("/Users/owner/a\nb", "~/a\\nb"),
        ("/Users/owner/a\tb", "~/a\\tb"),
        ("/Users/owner/a\rb", "~/a\\rb"),
        ("/Users/owner/a\x7fb", "~/a\\x7fb"),
        ("/Users/owner/a\x1b[31mb", "~/a\\x1b[31mb"),
        ("/Users/owner/a" + chr(0x202E) + "fdp.exe", "~/a\\u202efdp.exe"),
        ("/Users/owner/a" + chr(0x2028) + "b", "~/a\\u2028b"),
        ("/Users/owner/a" + chr(0x200B) + "b", "~/a\\u200bb"),
        ("/Users/owner/a" + chr(0x85) + "b", "~/a\\x85b"),
        ("/Users/owner/a\\b", "~/a\\\\b"),
        ("/Users/owner/caf" + chr(0xE9), "~/caf" + chr(0xE9)),
        ("/Users/owner/a" + chr(0x1F600), "~/a" + chr(0x1F600)),
        ("/Users/owner/a" + chr(0xE0001), "~/a\\U000e0001"),
    ],
)
def test_the_display_path(path, shown):
    assert terminal.display_path(path, HOME) == shown


def test_a_home_with_a_trailing_slash_still_matches():
    assert terminal.display_path("/Users/owner/Desktop", "/Users/owner/") == "~/Desktop"


def test_no_home_leaves_the_path():
    assert terminal.display_path("/Users/owner/Desktop", "") == "/Users/owner/Desktop"


def _nfd(text: str) -> str:
    return unicodedata.normalize("NFD", text)


@pytest.mark.parametrize(
    ("path", "home", "shown"),
    [
        ("/users/OWNER/Desktop/x.pdf", "/Users/owner", "~/Desktop/x.pdf"),
        (_nfd("/Users/Jos" + chr(0xE9) + "/Desktop"), "/Users/Jos" + chr(0xE9), "~/Desktop"),
        ("/Users/Jos" + chr(0xE9) + "/Desktop", _nfd("/Users/Jos" + chr(0xE9)), "~/Desktop"),
        ("/Users/owner/a" + chr(0x2029) + "b", "/Users/owner", "~/a\\u2029b"),
        ("/Users/owner/a" + chr(0xDCFF) + "b", "/Users/owner", "~/a\\udcffb"),
        ("/Users/owner/a" + chr(0xE000) + "b", "/Users/owner", "~/a\\ue000b"),
        ("/Users/owner/a" + chr(0x0378) + "b", "/Users/owner", "~/a\\u0378b"),
        ("/Users/owner/a" + chr(0x3164) + "b", "/Users/owner", "~/a\\u3164b"),
        ("/Users/owner/a" + chr(0xA0) + "b", "/Users/owner", "~/a\\xa0b"),
        ("/Users/owner/report  ", "/Users/owner", "~/report\\x20\\x20"),
        ("/Users/owner/" + chr(0x0301) * 2 + "/x", "/Users/owner", "~/\\u0301\\u0301/x"),
        ("/Users/owner2/x", "/Users/OWNER", "/Users/owner2/x"),
        ("~/x", "/Users/owner", "\\x7e/x"),
        ("/Users/owner/a" + chr(0x034F) + "b", "/Users/owner", "~/a\\u034fb"),
        ("/Users/owner/a" + chr(0xFE0F) + "b", "/Users/owner", "~/a\\ufe0fb"),
        ("/Users/owner/a" + chr(0x17B4) + "b", "/Users/owner", "~/a\\u17b4b"),
        ("/Users/owner/a" + chr(0x3000) + "b", "/Users/owner", "~/a\\u3000b"),
        ("/Users/owner/a" + chr(0xE0001) + "b", "/Users/owner", "~/a\\U000e0001b"),
        ("/Users/owner/a\x01b", "/Users/owner", "~/a\\x01b"),
        ("/Users/owner/a" + chr(0x2028) + "b", "/Users/owner", "~/a\\u2028b"),
    ],
    ids=[
        "another case",
        "decomposed accents",
        "a decomposed home",
        "a paragraph separator",
        "a byte that was not UTF-8",
        "private use",
        "unassigned",
        "a Hangul filler",
        "a no-break space",
        "trailing spaces",
        "a name of combining marks only",
        "a longer name is not the home",
        "a relative folder named ~",
        "a combining grapheme joiner",
        "a variation selector",
        "a Khmer inherent vowel",
        "an ideographic space",
        "a tag character past the BMP",
        "a control",
        "a line separator",
    ],
)
def test_the_display_path_hides_the_home_folder_and_shows_the_invisible(path, home, shown):
    assert terminal.display_path(path, home) == shown


# --- the review of #349, round 3 ---------------------------------------------------------------

SURFACE_NAMES = {
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


def test_every_surface_has_its_pinned_name():
    from voltry_mac import phrases, registry

    assert set(SURFACE_NAMES) == {spec.key for spec in registry.SURFACES}
    for key, name in SURFACE_NAMES.items():
        assert phrases.gap_name(phrases.Gap(key, "timeout")) == name, key


def _counts(**entries: object):
    """Set the ledger's four values: an int is read, a reason string is unavailable."""

    def edit(document: dict) -> None:
        values = r.values(document, "memory_error_ledger")
        for name, entry in entries.items():
            if isinstance(entry, str):
                values[name] = {"availability": "unavailable", "reason": entry}
            else:
                values[name] = {
                    "availability": "available",
                    "value": entry,
                    "provenance": "measured",
                }

    return edit


UNREAD = "source_changed"


@pytest.mark.parametrize(
    ("counts", "shown", "glanced"),
    [
        (
            {"correctable_event_rows": UNREAD, "uncorrectable_event_rows": UNREAD},
            "the log counts 14 correctable and 2 uncorrectable; its records were not reported "
            "by macOS measured",
            "Memory macOS's private memory error log counts 14 correctable and 2 uncorrectable; "
            "its records were not reported by macOS. Records exist; how far back the log "
            "reaches is unknown. measured",
        ),
        (
            {
                "correctable_event_rows": UNREAD,
                "uncorrectable_event_rows": UNREAD,
                "uncorrectable_reported_count": UNREAD,
            },
            "the log counts 14 correctable; its records, and the uncorrectable count, were not "
            "reported by macOS measured",
            "Memory macOS's private memory error log counts 14 correctable; its records, and "
            "the uncorrectable count, were not reported by macOS. Records exist; how far back "
            "the log reaches is unknown. measured",
        ),
        (
            {
                "correctable_event_rows": UNREAD,
                "correctable_reported_count": UNREAD,
                "uncorrectable_event_rows": UNREAD,
            },
            "the log counts 2 uncorrectable; its records, and the correctable count, were not "
            "reported by macOS measured",
            "Memory macOS's private memory error log counts 2 uncorrectable; its records, and "
            "the correctable count, were not reported by macOS. Records exist; how far back the "
            "log reaches is unknown. measured",
        ),
    ],
    ids=["both own counts", "the correctable own count", "the uncorrectable own count"],
)
def test_unread_record_counts_give_way_to_the_logs_own(counts, shown, glanced):
    # The field inventory prints the reported counts in the terminal: a count the log gave
    # is never said to be missing.
    document = edited("concerning-desktop", _counts(**counts))
    assert row(document, "MEMORY", "Memory error records") == shown
    assert glanced in glance(document)
    assert "Memory error records" not in glance(document)[-1]
    assert "Whether the memory errors are ongoing." in " ".join(section(document, "WHAT THIS"))


def test_a_kind_with_neither_count_is_said_not_reported():
    document = edited(
        "concerning-desktop",
        _counts(uncorrectable_event_rows=UNREAD, uncorrectable_reported_count=UNREAD),
    )
    assert row(document, "MEMORY", "Memory error records") == (
        "14 correctable, uncorrectable not reported by macOS measured"
    )
    assert (
        "Memory 14 correctable records in macOS's private memory error log; the uncorrectable "
        "count was not reported by macOS. Records exist; how far back the log reaches is "
        "unknown. measured"
    ) in glance(document)
    assert "Memory error records" not in glance(document)[-1]
    assert "The log's own counts" not in glance(document)[-1]


def test_zero_own_counts_keep_the_zero_caveat():
    # The log's own counts, as the row gives them, and never "0 uncorrectable errors", a
    # clean claim the copy policy refuses (the pass-3 pre-audit, P3-output-02).
    document = edited(
        "m5-laptop",
        _counts(correctable_event_rows=UNREAD, uncorrectable_event_rows=UNREAD),
    )
    assert row(document, "MEMORY", "Memory error records") == (
        "the log counts 0 correctable and 0 uncorrectable; its records were not reported by "
        "macOS measured"
    )
    assert notes(document, "MEMORY", "Memory error records") == (
        "From Apple's private memory error log: undocumented, retention unknown. Zero means "
        "none are recorded there now, not none ever."
    )
    assert (
        "Memory macOS's private memory error log counts 0 correctable and 0 uncorrectable; its "
        "records were not reported by macOS. Zero does not prove the memory never had errors. "
        "measured"
    ) in glance(document)
    assert "Whether the memory has ever had errors." in " ".join(section(document, "WHAT THIS"))


def test_a_zero_record_count_beside_a_non_zero_own_count_claims_no_zero():
    document = edited(
        "m5-laptop",
        _counts(correctable_event_rows=UNREAD, correctable_reported_count=3),
    )
    assert (
        "Memory 0 uncorrectable records in macOS's private memory error log; the correctable "
        "records were not reported by macOS, and the log's own correctable count is 3. Records "
        "exist; how far back the log reaches is unknown. measured"
    ) in glance(document)
    assert row(document, "MEMORY", "Memory error records") == (
        "correctable records not reported by macOS (the log counts 3), 0 uncorrectable measured"
    )
    said = notes(document, "MEMORY", "Memory error records")
    # The row prints the log's own count, not a record count (round 4, Minor 2).
    assert "These are what the log holds now; counts are not a rate." in said
    assert "Whether the memory errors are ongoing." in " ".join(section(document, "WHAT THIS"))


def test_the_logs_own_counts_print_from_s3_output_without_record_counts():
    import json

    from voltry_mac import assemble, model, payloads, validate

    output = json.dumps(
        [
            {"class": "correctable", "reported_count": 14},
            {"class": "uncorrectable", "reported_count": 2},
        ]
    )
    values = assemble._elevated_values("memory_error_ledger", payloads.ledger(output))
    document = r.load("concerning-desktop")
    document["surfaces"][r.index(document, "memory_error_ledger")] = model.surface_object(
        "memory_error_ledger", values
    )
    document = r.finish(document)
    validate.validate(document)
    assert row(document, "MEMORY", "Memory error records") == (
        "the log counts 14 correctable and 2 uncorrectable; its records were not reported by "
        "macOS measured"
    )


@pytest.mark.parametrize(
    ("edits", "bullet"),
    [
        ([], "Whether the memory has ever had errors."),
        ([_counts(correctable_event_rows=1)], "Whether the memory errors are ongoing."),
        ([_counts(uncorrectable_event_rows=1)], "Whether the memory errors are ongoing."),
        (
            [_counts(correctable_event_rows=UNREAD, uncorrectable_reported_count=UNREAD)],
            "Whether the memory has ever had errors.",
        ),
    ],
)
def test_the_memory_bullet_follows_the_counts_read(edits, bullet):
    limits = " ".join(section(edited("m5-laptop", *edits), "WHAT THIS"))
    assert bullet in limits
    other = {
        "Whether the memory has ever had errors.": "Whether the memory errors are ongoing.",
        "Whether the memory errors are ongoing.": "Whether the memory has ever had errors.",
    }[bullet]
    assert other not in limits


@pytest.mark.parametrize(
    "edits",
    [
        [
            _set("smart_health_snapshot", "critical_warning_byte", 4),
            _set("smart_health_snapshot", "reliability_degraded", True),
        ],
        [_set("nvme_devices", "smart_status", "Failing")],
    ],
    ids=["a warning bit", "SMART Failing"],
)
def test_the_ssd_bullet_follows_a_warning_or_failing(edits):
    document = edited("m5-laptop", *edits)
    first = section(document, "WHAT THIS")[1]
    assert first.startswith("  - Why the SSD reports a warning, or whether it will fail.")


def test_the_ssd_bullet_is_absent_without_a_warning():
    assert "Why the SSD" not in " ".join(section(m5(), "WHAT THIS"))


# Minor 1: a row built from several reads keeps every read.


@pytest.mark.parametrize(
    ("edits", "text", "listed"),
    [
        (
            [_value_unavailable("kernel_and_platform", "perf_level_names", "tool_error")],
            "Apple M5: clusters of 4 and 6 cores, 10-core GPU; each cluster's name was not read "
            "(sysctl returned an error)",
            "Core clusters (names): sysctl returned an error.",
        ),
        (
            [_value_unavailable("kernel_and_platform", "perf_level_physical_cpus", "timeout")],
            "Apple M5: Super and Efficiency cores, 10-core GPU; each cluster's core count was not "
            "read (timed out after 10 seconds)",
            "Core clusters (core counts): timed out after 10 seconds.",
        ),
    ],
    ids=["names unread", "core counts unread"],
)
def test_the_chip_row_keeps_the_half_of_the_clusters_it_read(edits, text, listed):
    document = edited(
        "m5-laptop", *edits, lambda d: r.fail(d, "C22" if "names" in listed else "C23")
    )
    assert row(document, "THIS MAC", "Chip") == text
    assert listed in glance(document)[-1]


def test_the_startup_disk_row_keeps_the_capacity_in_bytes():
    document = edited("m5-laptop", _value_unavailable("nvme_devices", "size_text"))
    assert row(document, "THIS MAC", "Startup disk") == (
        "APPLE SSD AP1024Z, 1,000,555,581,440 bytes, the internal SSD (disk0)"
    )


@pytest.mark.parametrize(
    ("edits", "text"),
    [
        (
            [_unavailable("os_version", "tool_error"), lambda d: r.fail(d, "C1")],
            "the version and build were not read (sw_vers returned an error); firmware "
            "18000.161.10",
        ),
        (
            [
                _value_unavailable("os_version", "product_version"),
                _value_unavailable("os_version", "build_version"),
            ],
            "the version and build are not reported by macOS; firmware 18000.161.10",
        ),
    ],
    ids=["sw_vers failed", "both omitted"],
)
def test_the_macos_row_keeps_the_firmware_apart_from_its_gap(edits, text):
    assert row(edited("m5-laptop", *edits), "THIS MAC", "macOS") == text


# Minor 2: the Not read line names a row's part when only a part is missing.


@pytest.mark.parametrize(
    ("edits", "listed"),
    [
        (
            [_value_unavailable("hardware_overview", "chip_type")],
            "Chip (name): not reported by macOS.",
        ),
        (
            [_value_unavailable("memory_error_ledger", "uncorrectable_reported_count")],
            "The log's own counts (uncorrectable): not reported by macOS.",
        ),
        (
            [_value_unavailable("battery_health", "gauge_firmware_version")],
            "Battery gauge revisions (firmware): not reported by macOS.",
        ),
        (
            [
                _value_unavailable("kernel_and_platform", "perf_level_names"),
                _value_unavailable("kernel_and_platform", "perf_level_physical_cpus"),
            ],
            "Core clusters (names and core counts): macOS returned a format this version does "
            "not recognize.",
        ),
    ],
)
def test_a_missing_part_is_named_by_its_row_and_part(edits, listed):
    assert listed in glance(edited("m5-laptop", *edits))[-1]


def test_a_full_serial_macos_did_not_give_is_said_so():
    def asked(document: dict) -> None:
        r.values(document, "hardware_overview")["serial_number"] = {
            "availability": "unavailable",
            "reason": "source_changed",
        }

    document = edited("m5-laptop", asked)
    assert row(document, "THIS MAC", "Serial number") == (
        "ending in K7Q2 (the full serial is not reported by macOS)"
    )
    assert "Serial number (full): not reported by macOS." in glance(document)[-1]


# Minor 3: the words and the layout the mutants changed without a test noticing.


def test_a_smart_temperature_outside_its_range_says_so_in_its_row():
    document = edited(
        "m5-laptop",
        _value_unavailable("smart_health_snapshot", "composite_temperature_k"),
        _value_unavailable("smart_health_snapshot", "composite_temperature_c"),
    )
    assert row(document, "STORAGE HEALTH AND WEAR", "Temperature now") == (
        "The drive reported a reading outside its range"
    )


def test_a_drive_listing_beside_a_garbled_store_is_a_format():
    document = edited(
        "m5-laptop",
        _unavailable("nvme_devices", "source_changed"),
        _value_unavailable("startup_disk", "physical_store"),
        _value_unavailable("startup_disk", "whole_disk"),
        _unavailable("smart_health_snapshot", "source_changed"),
        _unavailable("smart_wear_attributes", "source_changed"),
    )
    assert row(document, "STORAGE HEALTH AND WEAR", "SMART status") == (
        "Could not read: macOS returned a format this version does not recognize"
    )


def test_an_unread_battery_condition_and_capacity_are_not_listed_again():
    document = edited(
        "m5-laptop",
        _value_unavailable("battery_health", "condition"),
        _value_unavailable("battery_health", "maximum_capacity_percent"),
    )
    assert "Maximum capacity" not in glance(document)[-1]


@pytest.mark.parametrize(
    ("edits", "text"),
    [
        (
            [
                _value_unavailable("hardware_overview", "physical_memory_text"),
                _value_unavailable("memory_configuration", "size_text"),
                _value_unavailable("memory_configuration", "memory_type"),
            ],
            "the size is not reported by macOS; manufacturer Micron",
        ),
        (
            [
                _value_unavailable("battery_health", "state_of_charge_percent"),
                _set("battery_health", "fully_charged", False),
            ],
            "the charge level is not reported by macOS; not fully charged measured",
        ),
    ],
    ids=["memory: the maker alone", "charge: not fully charged"],
)
def test_a_part_read_beside_one_not_reported(edits, text):
    label = "Memory" if "manufacturer" in text else "Charge now"
    title_ = "THIS MAC" if label == "Memory" else "BATTERY"
    assert row(edited("m5-laptop", *edits), title_, label) == text


@pytest.mark.parametrize(
    ("connected", "charging", "text"),
    [
        (False, None, "charger not connected; whether it is charging is not reported by macOS"),
        (None, True, "whether a charger is connected is not reported by macOS; charging"),
    ],
)
def test_the_power_source_with_one_value(connected, charging, text):
    edits = [
        (
            _set("battery_health", "charger_connected", connected)
            if connected is not None
            else _value_unavailable("battery_health", "charger_connected")
        ),
        (
            _set("battery_health", "is_charging", charging)
            if charging is not None
            else _value_unavailable("battery_health", "is_charging")
        ),
    ]
    assert row(edited("m5-laptop", *edits), "BATTERY", "Power source") == f"{text} measured"


def test_the_boot_date_turns_at_the_minute_of_the_offset():
    # 07:00 UTC is midnight at UTC-7: one minute of the offset moves the date.
    collected = int(datetime(2026, 9, 23, 21, 5, 31, tzinfo=UTC).timestamp())
    epoch = int(datetime(2026, 9, 1, 7, 0, 0, tzinfo=UTC).timestamp())
    document = edited(
        "m5-laptop",
        _set("boot_time", "boot_epoch_seconds", epoch),
        _set("boot_time", "boot_time_utc", "2026-09-01T07:00:00Z"),
        _set("boot_time", "days_since_boot", (collected - epoch) // 86400),
    )
    assert row(document, "SYSTEM RECORDS", "Last restart").startswith("1 Sep 2026, ")


@pytest.mark.parametrize(
    "point",
    [
        0x034F,
        0x115F,
        0x1160,
        0x17B4,
        0x17B5,
        0x2800,
        0x3164,
        0xFFA0,
        0x180B,
        0x180F,
        0xFE00,
        0xFE0F,
        0xE0100,
        0xE01EF,
        0x2029,
    ],
)
def test_each_end_of_each_invisible_range_is_dropped(point):
    from voltry_mac import phrases

    assert phrases.clean(f"a{chr(point)}b") == "ab"


@pytest.mark.parametrize("point", [0x034E, 0x1161, 0x2801, 0xFE10, 0x180A])
def test_the_characters_beside_the_invisible_ranges_stay(point):
    from voltry_mac import phrases

    assert phrases.clean(f"a{chr(point)}b") == f"a{chr(point)}b"


@pytest.mark.parametrize("size", range(1, 61))
def test_each_piece_of_a_split_word_fits_its_width(size):
    word = "".join(chr(0x4E00 + i) if i % 3 == 0 else "x" for i in range(90))
    from voltry_mac import phrases

    pieces = terminal._split(word, size)
    assert "".join(pieces) == word
    assert all(phrases.cells(piece) <= max(size, 2) for piece in pieces)
    assert all(
        phrases.cells(piece) + phrases.cells(after[:1]) > size
        for piece, after in zip(pieces, pieces[1:], strict=False)
    )


def test_a_word_exactly_as_wide_as_its_column_stays_whole():
    assert terminal._split("x" * 20, 20) == ["x" * 20]
    assert terminal._fill(["x" * 20], 20) == ["x" * 20]


def _laid(where: str, text: str) -> list[str]:
    """The lines a row note, a section note or a section's one line takes."""
    from voltry_mac import details

    if where == "section text":
        return terminal._lay(details.Section("Battery", None, (), text=text))[1:]
    row_ = details.Row(
        "Memory error records", "0 correctable", "measured", (text,) if where == "note" else ()
    )
    laid = terminal._lay(
        details.Section("Memory", None, (row_,), note=text if where == "section note" else None)
    )
    return laid[2:]


@pytest.mark.parametrize(
    ("where", "width"),
    [("note", 65), ("section note", 67), ("section text", 67)],
)
def test_notes_and_section_text_wrap_at_their_own_widths(where, width):
    # A row note at column 4, a section's note and its one line at column 2, all within 69.
    assert len(_laid(where, "a" * (width - 2) + " b")) == 1
    assert len(_laid(where, "a" * (width - 1) + " b")) == 2


@pytest.mark.parametrize(
    ("path", "shown"),
    [
        ("/Users/owner/" + chr(0x0903) + "a", "~/\\u0903a"),
        ("/Users/owner/" + chr(0x20DD) + "a", "~/\\u20dda"),
        ("/Users/owner/report~", "~/report~"),
    ],
    ids=["a leading spacing mark", "a leading enclosing mark", "a name ending in ~"],
)
def test_leading_marks_are_escaped_and_a_trailing_tilde_is_not(path, shown):
    assert terminal.display_path(path, HOME) == shown


# The nits.


@pytest.mark.parametrize(
    ("text", "width"),
    [
        (chr(0x0E14) + chr(0x0E35), 1),
        (chr(0x1100) + chr(0x1161) + chr(0x11A8), 2),
        ("a" + chr(0x20DD), 1),
        ("a" + chr(0x0903), 2),
    ],
    ids=[
        "a Thai vowel sign",
        "a conjoining Hangul syllable",
        "an enclosing mark",
        "a spacing mark",
    ],
)
def test_marks_that_join_the_letter_before_take_no_column(text, width):
    from voltry_mac import phrases

    assert phrases.cells(text) == width


@pytest.mark.parametrize("point", [0x2065, 0xFFF0, 0xFFF8, 0xE0000, 0xE0002, 0xE0080, 0xE0FFF])
def test_unassigned_characters_that_print_as_nothing_are_dropped(point):
    from voltry_mac import phrases

    assert phrases.clean(f"a{chr(point)}b") == "ab"


def test_seconds_stay_with_their_number():
    assert terminal._kept(["after", "10", "seconds."]) == ["after", "10 seconds."]
    assert terminal._kept(["after", "10", "seconds,"]) == ["after", "10 seconds,"]


def test_a_permanent_failure_leads_the_battery_lines():
    document = edited(
        "m5-laptop",
        _unavailable("battery_health", "tool_error"),
        _set("battery_gauge", "permanent_failure", True),
    )
    battery = [entry for entry in glance(document) if entry.startswith("Battery ")]
    assert battery == [
        "Battery The battery reports a permanent failure. reported",
        "Battery Power report not read: system_profiler returned an error.",
    ]
    read = edited("m5-laptop", _set("battery_gauge", "permanent_failure", True))
    assert [entry for entry in glance(read) if entry.startswith("Battery ")][0] == (
        "Battery The battery reports a permanent failure. reported"
    )


# --- the review of #349, round 4 ---------------------------------------------------------------

_REACH = " Records exist; how far back the log reaches is unknown."
_NO_PROOF = " Zero does not prove the memory never had errors."
_LOG_NOTE = "From Apple's private memory error log: undocumented, retention unknown."
_ZERO_NOTE = " Zero means none are recorded there now, not none ever."


def _one_record_count_read():
    """One record count read and the other not, with the unread kind's own count unread,
    zero or more."""
    for kind, other in (("correctable", "uncorrectable"), ("uncorrectable", "correctable")):
        for count in (0, 5):
            for stand_in in (None, 0, 3):
                yield kind, other, count, stand_in


@pytest.mark.parametrize(("kind", "other", "count", "stand_in"), list(_one_record_count_read()))
def test_one_record_count_unread_keeps_the_logs_caveat(kind, other, count, stand_in):
    document = edited(
        "m5-laptop",
        _counts(
            **{
                f"{kind}_event_rows": count,
                f"{kind}_reported_count": count,
                f"{other}_event_rows": UNREAD,
                f"{other}_reported_count": UNREAD if stand_in is None else stand_in,
            }
        ),
    )
    if stand_in is None:
        said, printed = f"the {other} count was not reported by macOS", [count]
    else:
        said = (
            f"the {other} records were not reported by macOS, and the log's own {other} "
            f"count is {stand_in}"
        )
        printed = [count, stand_in]
    # A zero beside a count above zero keeps the caveat the both-read line gives it.
    tail = _REACH if any(printed) else _NO_PROOF
    assert _memory_entry(document) == (
        f"Memory {count} {kind} records in macOS's private memory error log; {said}.{tail} measured"
    )
    # The row's note says what the row printed: records, or the log's own counts too.
    first = (
        " These are records present now; counts are not a rate."
        if stand_in is None
        else " These are what the log holds now; counts are not a rate."
    )
    assert notes(document, "MEMORY", "Memory error records") == (
        _LOG_NOTE + (first if any(printed) else "") + (_ZERO_NOTE if 0 in printed else "")
    )


def _own_counts_only():
    for correctable in (None, 0, 1, 3):
        for uncorrectable in (None, 0, 1, 3):
            if correctable is not None or uncorrectable is not None:
                yield correctable, uncorrectable


@pytest.mark.parametrize(("correctable", "uncorrectable"), list(_own_counts_only()))
def test_the_logs_own_counts_alone_keep_the_logs_caveat(correctable, uncorrectable):
    own = {"correctable": correctable, "uncorrectable": uncorrectable}
    document = edited(
        "m5-laptop",
        _counts(
            correctable_event_rows=UNREAD,
            uncorrectable_event_rows=UNREAD,
            **{
                f"{kind}_reported_count": UNREAD if count is None else count
                for kind, count in own.items()
            },
        ),
    )
    said = [(kind, count) for kind, count in own.items() if count is not None]
    listed = " and ".join(f"{count} {kind}" for kind, count in said)
    unread = [kind for kind, count in own.items() if count is None]
    what = f"its records, and the {unread[0]} count," if unread else "its records"
    printed = [count for _, count in said]
    tail = _REACH if any(printed) else _NO_PROOF
    # The counts as the row gives them, with no noun: "0 correctable errors" would be a
    # clean claim (the pass-3 pre-audit, P3-output-02).
    assert _memory_entry(document) == (
        f"Memory macOS's private memory error log counts {listed}; {what} were not "
        f"reported by macOS.{tail} measured"
    )
    first = " These are what the log holds now; counts are not a rate."
    assert notes(document, "MEMORY", "Memory error records") == (
        _LOG_NOTE + (first if any(printed) else "") + (_ZERO_NOTE if 0 in printed else "")
    )


def _word_before_chip(line: str) -> str | None:
    found = re.search(r"(\S+) +(measured|reported|derived)$", line)
    return found[1] if found else None


@pytest.mark.parametrize(
    ("units", "kept"),
    [
        (["off;", "Gatekeeper", "not", "read:"], ["off;", "Gatekeeper", "not read:"]),
        (["is", "not", "reported", "by", "macOS"], ["is", "not reported by", "macOS"]),
        (["Not", "read:", "timed"], ["Not read:", "timed"]),
    ],
)
def test_a_line_with_a_chip_keeps_not_with_the_word_after_it(units, kept):
    assert terminal._kept(units, chip=True) == kept


def test_prose_without_a_chip_may_break_after_not():
    # Transcript 7's limits bullet ends a line on "not"; prose carries no chip.
    assert terminal._kept(["records,", "not", "a", "rate"]) == ["records,", "not", "a", "rate"]


NEGATIONS = [
    ("gatekeeper failed", "concerning-desktop", [_unavailable("gatekeeper_status", "tool_error")]),
    ("filevault failed", "concerning-desktop", [_unavailable("filevault_status", "tool_error")]),
    ("fully charged omitted", "m5-laptop", [_value_unavailable("battery_health", "fully_charged")]),
    ("charger omitted", "m5-laptop", [_value_unavailable("battery_health", "charger_connected")]),
    (
        "own count omitted",
        "concerning-desktop",
        [_value_unavailable("memory_error_ledger", "correctable_reported_count")],
    ),
    *(
        (
            f"uncorrectable omitted, {name}",
            name,
            [
                _value_unavailable("memory_error_ledger", "uncorrectable_event_rows"),
                _value_unavailable("memory_error_ledger", "uncorrectable_reported_count"),
            ],
        )
        for name in ("m5-laptop", "concerning-desktop")
    ),
]


@pytest.mark.parametrize(("label", "name", "edits"), NEGATIONS, ids=[n[0] for n in NEGATIONS])
def test_no_chip_reads_as_the_end_of_a_negation(label, name, edits):
    found = lines(edited(name, *edits))
    assert all(_word_before_chip(line) not in ("not", "Not") for line in found), found


@pytest.mark.parametrize(
    ("point", "width"),
    [(0x115F, 2), (0x1160, 0), (0x11FF, 0), (0x1200, 1), (0xD7AF, 1), (0xD7B0, 0), (0xD7FF, 0)],
)
def test_conjoining_hangul_takes_no_column_to_each_end_of_its_ranges(point, width):
    from voltry_mac import phrases

    assert phrases.cells(chr(point)) == width


@pytest.mark.parametrize(
    ("point", "kept"),
    [
        (0x180F, False),
        (0x1810, True),
        (0xE01EF, False),
        (0xE01F0, False),
        (0xE0FFF, False),
        (0xE1000, True),
    ],
)
def test_the_invisible_ranges_end_where_unicode_ends_them(point, kept):
    from voltry_mac import phrases

    assert (phrases.clean(chr(point)) == chr(point)) is kept


def test_the_last_point_of_the_basic_plane_escapes_in_four_digits():
    assert terminal.display_path(f"{HOME}/a{chr(0xFFFF)}b", HOME) == "~/a\\uffffb"


@pytest.mark.parametrize(
    ("units", "kept"), [(["10", "cores"], ["10", "cores"]), (["the", "TB"], ["the", "TB"])]
)
def test_only_a_unit_after_a_number_is_kept_with_it(units, kept):
    assert terminal._kept(units) == kept


@pytest.mark.parametrize("unit", ["seconds)", "seconds);", "seconds;", "second)."])
def test_seconds_stay_with_their_number_before_a_closing_mark(unit):
    assert terminal._kept(["after", "10", unit]) == ["after", f"10 {unit}"]


@pytest.mark.parametrize(
    ("name", "edits"),
    [
        ("m5-laptop", [_unavailable("os_version", "timeout")]),
        (
            "concerning-desktop",
            [
                _value_unavailable("kernel_and_platform", "perf_level_names", "timeout"),
                lambda document: r.fail(document, "C22"),
            ],
        ),
        (
            "m5-laptop",
            [
                _unavailable("sip_status", "timeout"),
                _unavailable("filevault_status", "source_changed"),
            ],
        ),
    ],
    ids=["sw_vers", "perf level names", "csrutil"],
)
def test_a_timeout_never_leaves_its_seconds_on_the_next_line(name, edits):
    found = [
        re.sub(r" +(measured|reported|derived)$", "", line) for line in lines(edited(name, *edits))
    ]
    for line, following in zip(found, found[1:], strict=False):
        assert not (line[-1:].isdigit() and following.strip().startswith("second")), line


def test_the_rounded_capacity_is_named_apart_from_the_bytes():
    document = edited("m5-laptop", _value_unavailable("nvme_devices", "size_text"))
    assert row(document, "THIS MAC", "Startup disk") == (
        "APPLE SSD AP1024Z, 1,000,555,581,440 bytes, the internal SSD (disk0)"
    )
    assert (
        "Startup disk drive entry (rounded capacity): not reported by macOS."
        in glance(document)[-1]
    )
    one = edited(
        "m5-laptop",
        _set("nvme_devices", "size_bytes", 1),
        _value_unavailable("nvme_devices", "size_text"),
    )
    assert row(one, "THIS MAC", "Startup disk") == (
        "APPLE SSD AP1024Z, 1 byte, the internal SSD (disk0)"
    )


@pytest.mark.parametrize("point", [0x1161, 0x11A8, 0xD7B0])
def test_a_name_that_starts_with_conjoining_hangul_escapes_it(point):
    shown = terminal.display_path(f"{HOME}/{chr(point)}report.pdf", HOME)
    assert shown == f"~/\\u{point:04x}report.pdf"


def test_the_memory_row_with_only_its_type_read():
    document = edited(
        "m5-laptop",
        _value_unavailable("hardware_overview", "physical_memory_text"),
        _value_unavailable("memory_configuration", "size_text"),
        _value_unavailable("memory_configuration", "manufacturer"),
    )
    assert row(document, "THIS MAC", "Memory") == "the size is not reported by macOS; LPDDR5"


def test_an_unread_health_log_keeps_the_storage_sections_source():
    found = section(edited("m5-laptop", *_smart_failed("timeout")), "STORAGE HEALTH AND WEAR")
    assert found[0] == "STORAGE HEALTH AND WEAR" + " " * 24 + "from macOS's disk profile"


def test_charging_without_a_charger_says_charging():
    document = edited(
        "m5-laptop",
        _set("battery_health", "charger_connected", False),
        _set("battery_health", "is_charging", True),
    )
    assert row(document, "BATTERY", "Power source") == "charging measured"


def _multi_store() -> list:
    """The startup volume on more than one physical store: the chain after it is unsupported."""
    return [
        _set("startup_disk", "physical_store_count", 2),
        _value_unavailable("startup_disk", "physical_store", "unsupported"),
        _value_unavailable("startup_disk", "whole_disk", "unsupported"),
        *[
            _value_unavailable("nvme_devices", name, "unsupported")
            for name in (
                "bsd_name",
                "device_model",
                "device_revision",
                "size_text",
                "size_bytes",
                "smart_status",
                "trim_support",
            )
        ],
        _unavailable("smart_health_snapshot", "unsupported"),
        _unavailable("smart_wear_attributes", "unsupported"),
    ]


@pytest.mark.parametrize("flag", ["internal", "solid_state"])
def test_a_startup_disk_with_nothing_read_leads_with_the_stores_words(flag):
    multi = edited("m5-laptop", *_multi_store(), _value_unavailable("startup_disk", flag))
    assert row(multi, "THIS MAC", "Startup disk") == (
        "Not read: the startup volume spans more than one physical store"
    )
    garbled = edited(
        "m5-laptop",
        *_trunk_failed("source_changed", store=True),
        _value_unavailable("startup_disk", flag),
    )
    assert row(garbled, "THIS MAC", "Startup disk") == (
        "Could not read: macOS returned a format this version does not recognize"
    )
