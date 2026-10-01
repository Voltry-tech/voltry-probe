"""The report PDF's rows, chips and notes (docs/VOLTRY_MAC_SPEC.md, Decision 6's two labels
on every observation, the field inventory's PDF rows, "Report outline and PDF layout" and
the fixed notes).

The PDF prints every row the terminal prints, in the same words, with the rows the field
inventory prints in the PDF alone added; every value is labeled one way: a provenance chip
in ink when it was read, the unavailable or not-applicable chip in its own color when it
was not, and no chip only under a header that names the provenance. The fixed notes print
word for word in the caption style, and the power check's samples print as their rows do.
The words are checked on what report_pdf asks the layout to draw, and the chips and notes
on the pages drawn.
"""

from __future__ import annotations

import copy
from decimal import Decimal

import pytest
import voltry_mac_test_pdf_pages as pages
import voltry_mac_test_reports as r

from voltry_mac import (
    appendices,
    details,
    layout,
    numbers,
    pdf,
    phrases,
    report_pdf,
    sections,
    terminal,
    validate,
    wording,
)

T = pages.terminal_tests()
CHIPS = ("measured", "reported", "derived")
INK = layout.INK.operands()
ORANGE = layout.UNAVAILABLE.operands()
UNREAD = (appendices.UNAVAILABLE, layout.UNAVAILABLE)
NOT_APPLICABLE = (appendices.NOT_APPLICABLE, layout.UNAVAILABLE)
# The rows the field inventory prints in the PDF alone.
PDF_ONLY = {"Critical warning", "Data read", "Power cycles", "Permanent failure"}
# The detail sections, as the terminal and the PDF build them.
FULL = ("system_records", "storage", "battery")
SECTION_BUILDERS = ("this_mac", "security", "system_records", "storage", "battery", "memory")


def history(name: str, key: str) -> dict:
    record, count, power = r.LEGAL[key]
    return r.history(name, record, count, power)


HISTORIES = [(f"{name}: {key}", history(name, key)) for key in r.LEGAL for name in r.NAMES]


def _sweep() -> list[tuple[str, dict]]:
    found = list(HISTORIES)
    found += [(f"gap {label}", document) for label, document in T.GAP_DOCUMENTS]
    for key, reason, _label, _text in T.USER_READS:
        document = T.edited("m5-laptop", T._unavailable(key, reason))
        found.append((f"read {key}:{reason}", document))
    for which, ending, detail, _text in T.PAYLOADS:
        found.append((f"payload {which}:{ending}", T._payload_history(ending, detail, which)))
    found.append(("macOS row unread", _macos_unread()))
    # Several values unread at once, each with the values computed from it: the states four
    # At a glance lines reach only this way (the #352 review, round 3).
    found += [(label, build()) for label, build in SEVERAL.items()]
    return found


def _several(*gaps: tuple[str, str]) -> dict:
    edits = []
    for key, name in gaps:
        for each in (name, *T._computed_from(key, name)):
            edits.append(T._value_unavailable(key, each))
    return T.edited("m5-laptop", *edits)


SECURITY = ("sip_status", "gatekeeper_status", "filevault_status")
SEVERAL = {
    "security unread": lambda: T.edited(
        "m5-laptop",
        *[T._unavailable(key, "tool_error") for key in SECURITY],
        T._value_unavailable("hardware_overview", "activation_lock_enabled"),
    ),
    "battery condition and capacity unread": lambda: _several(
        ("battery_health", "condition"), ("battery_health", "maximum_capacity_percent")
    ),
    "thermal pressure unread": lambda: _several(
        ("power_and_thermal_samples", "sample_thermal_pressure")
    ),
}


def _macos_unread() -> dict:
    """Neither the version, the build nor the firmware read: the macOS row is unavailable."""
    return T.edited(
        "m5-laptop",
        T._value_unavailable("os_version", "product_version"),
        T._value_unavailable("os_version", "build_version"),
        T._value_unavailable("firmware_and_boot", "boot_rom_version"),
    )


SWEEP = _sweep()


def section(report: phrases.Report, name: str, *, full: bool) -> details.Section:
    build = getattr(details, name)
    return build(report, full=True) if full and name in FULL else build(report)


def title_of(built: details.Section) -> str:
    return built.title + (f" {built.subtitle}" if built.subtitle else "")


def expected_chip(row: details.Row) -> tuple[str, pdf.Color] | None:
    if row.unavailable:
        return UNREAD
    return None if row.chip is None else (row.chip, layout.INK)


def as_pair(chip: layout.Chip | None) -> tuple[str, pdf.Color] | None:
    return None if chip is None else (chip.word, chip.color)


def plain(text: str) -> str:
    return text.replace(" ", " ")


# --- the terminal's rows, and the PDF's own ------------------------------------------------------


@pytest.mark.parametrize(("label", "document"), HISTORIES, ids=[h[0] for h in HISTORIES])
def test_the_pdf_rows_are_the_terminals_with_the_pdfs_own_added(label, document):
    report = phrases.Report(document)
    _, asked = pages.composed(document)
    for name in SECTION_BUILDERS:
        short = section(report, name, full=False)
        full = section(report, name, full=True)
        if full.text is not None:
            assert short.text == full.text
            continue
        terminal_rows = [item for item in short.items if isinstance(item, details.Row)]
        pdf_rows = [item for item in full.items if isinstance(item, details.Row)]
        labels = [row.label for row in pdf_rows]
        # The terminal's rows are the PDF's, in order; a PDF row may add its formula.
        at = 0
        for row in terminal_rows:
            at = labels.index(row.label, at)
            twin = pdf_rows[at]
            assert (twin.chip, twin.unavailable) == (row.chip, row.unavailable), row
            assert twin.text == row.text or twin.text.startswith(row.text + " ("), row
        assert set(labels) - {row.label for row in terminal_rows} <= PDF_ONLY, name
        # And the PDF asks for exactly the full rows, each with its chip.
        drawn = pages.section_rows(asked, title_of(full))
        assert [(row.label, plain(row.text), as_pair(row.chip)) for row in drawn] == [
            (row.label, row.text, expected_chip(row)) for row in pdf_rows
        ], name


@pytest.mark.parametrize(("label", "document"), HISTORIES, ids=[h[0] for h in HISTORIES])
def test_every_row_the_terminal_prints_the_pdf_prints_in_the_same_words(label, document):
    report = phrases.Report(document)
    made, _ = pages.composed(document)
    words = " ".join(pages.page_words(page) for page in made.pages)
    for entry in sections.glance(report):
        assert entry.text in words, entry
    for bullet in sections.limits(report):
        assert bullet in words, bullet
    for line in (" ".join(sections.collection(report)), sections.validated(report)):
        assert line in words, line
    assert f"Administrator reads: {sections.elevation(report)}" in words
    for name in (*SECTION_BUILDERS, "power"):
        built = section(report, name, full=False)
        if built.text is not None:
            assert built.text in words, name
            continue
        for item in built.items:
            assert item.text in words, item
            if isinstance(item, details.Row):
                for note in item.notes:
                    assert note in words, note


# --- one label for every value ------------------------------------------------------------


def _unread_clause(clause: str) -> bool:
    """A clause that says its subject was not read, before it says anything of it."""
    lowered = clause.lower()
    found = [at for at in (lowered.find("not read"), lowered.find("not reported")) if at >= 0]
    return bool(found) and ":" not in clause[: min(found)]


def _glance_chip(entry: sections.Entry) -> tuple[str, object] | None:
    """A line's chip decided from its words, not from the availability under test (the #352
    review, round 3): a line whose every clause says its subject was not read carries the
    unavailable chip, one saying there is no battery the not-applicable chip, and any other,
    one that read something, its provenance."""
    if entry.text.lower().startswith("not applicable"):
        return NOT_APPLICABLE
    if entry.topic == "Not read" or all(_unread_clause(c) for c in entry.text.split("; ")):
        return UNREAD
    return None if entry.chip is None else (entry.chip, layout.INK)


def _one_way(document: dict) -> None:
    report = phrases.Report(document)
    _, asked = pages.composed(document)
    glance = pages.section_rows(asked, wording.SECTIONS[0])
    entries = sections.glance(report)
    assert len(glance) == len(entries)
    for row, entry in zip(glance, entries, strict=True):
        assert (row.label, plain(row.text), as_pair(row.chip)) == (
            entry.topic,
            entry.text,
            _glance_chip(entry),
        )
    for name in (*SECTION_BUILDERS, "power"):
        built = section(report, name, full=True)
        drawn = pages.section_rows(asked, title_of(built))
        if built.text is not None:
            chip = NOT_APPLICABLE if built.availability == "not_applicable" else UNREAD
            assert as_pair(drawn[0].chip) == chip, name
            continue
        rows = [item for item in built.items if isinstance(item, details.Row)]
        for row, pdf_row in zip(rows, drawn, strict=False):
            pair = as_pair(pdf_row.chip)
            assert pair == expected_chip(row), (name, row)
            if pair is None:
                # No chip: a row read, under a header that names its provenance.
                assert built.source == "as macOS reports it" and not row.unavailable, row
            elif pair == UNREAD:
                assert row.unavailable and row.chip is None, row
            else:
                assert pair[0] in CHIPS and pair[1] is layout.INK and not row.unavailable, row


@pytest.mark.parametrize(("label", "document"), SWEEP, ids=[s[0] for s in SWEEP])
def test_every_row_is_labeled_one_way(label, document):
    _one_way(document)


# Change record 7 (the GPT audit, pass 1, G1-03): the transcripts are normative for the
# terminal. What it did not read carries no chip there: a row, or a section of one line,
# leads with the words that say why, and an At a glance line says so in each clause or under
# Not read. What it read shows its chip, or its section's provenance, as in the PDF.
LEADS = (
    "Not read: ",
    "Could not read: ",
    "Unavailable: ",
    "Not applicable: ",
    "Not reported by macOS",
    "The drive reported a reading outside its range",  # a SMART value its bounds refused
)


@pytest.mark.parametrize(("label", "document"), SWEEP, ids=[s[0] for s in SWEEP])
def test_the_terminal_labels_what_it_did_not_read_by_its_words_and_no_chip(label, document):
    report = phrases.Report(document)
    entries = sections.glance(report)
    shown = T.glance(document)
    assert len(shown) == len(entries)
    for line, entry in zip(shown, entries, strict=True):
        words = " ".join(f"{entry.topic} {entry.text}".split())
        if entry.availability == "available":
            assert line == f"{words} {entry.chip}", line
        else:
            assert line == words and _glance_chip(entry) in (UNREAD, NOT_APPLICABLE), line
    for name in (*SECTION_BUILDERS, "power"):
        built = section(report, name, full=False)
        heading = built.title.upper()
        if built.text is not None:
            printed = " ".join(" ".join(T.section(document, heading)[1:]).split())
            assert built.text.startswith(LEADS) and printed == built.text, name
            continue
        for item in built.items:
            if not isinstance(item, details.Row):
                continue
            line, words = T.row(document, heading, item.label), " ".join(item.text.split())
            if item.unavailable:
                assert item.text.startswith(LEADS) and line == words, (name, line)
            elif built.source == "as macOS reports it":
                assert line == words, (name, line)
            else:
                assert item.chip in CHIPS and line == f"{words} {item.chip}", (name, line)


# Every row and At a glance line a report can leave unread, as the sweep reaches them: a
# value's own gap, a surface collapsed to one row (the health log, the battery gauge, the
# power report), or a section with one line (the power check not run, a desktop's battery).
UNREAD_ROWS = {
    ("Battery", "(not_applicable)"),
    ("Battery", "Battery gauge"),
    ("Battery", "Condition"),
    ("Battery", "Design capacity"),
    ("Battery", "Design cycle count"),
    ("Battery", "Full charge now"),
    ("Battery", "Maximum capacity"),
    ("Battery", "Permanent failure"),
    ("Battery", "Power report"),
    ("Battery", "Temperature"),
    ("Memory", "ECC error counters"),
    ("Memory", "Memory error records"),
    ("Memory", "Memory pressure now"),
    ("Power and thermal check", "(unavailable)"),
    ("Power and thermal check", "CPU power"),
    ("Power and thermal check", "GPU power"),
    ("Power and thermal check", "Neural Engine"),
    ("Power and thermal check", "Processor power"),
    ("Power and thermal check", "Thermal pressure"),
    ("Security settings", "Activation Lock"),
    ("Security settings", "FileVault"),
    ("Security settings", "Gatekeeper"),
    ("Security settings", "System Integrity Protection"),
    ("Storage health and wear", "Health log"),
    ("Storage health and wear", "SMART status"),
    ("Storage health and wear", "Temperature now"),
    ("System records", "Last restart"),
    ("System records", "Panic reports"),
    ("This Mac", "Model"),
    ("This Mac", "Serial number"),
    ("This Mac", "Startup disk"),
    ("This Mac", "macOS"),
}
UNREAD_TOPICS = {
    ("Battery", "not_applicable"),
    ("Battery", "unavailable"),
    ("Memory", "unavailable"),
    ("Not read", "unavailable"),
    ("Security", "unavailable"),
    ("Storage", "unavailable"),
    ("Thermal", "unavailable"),
}


# The words of the At a glance lines the several-values documents reach, pinned.
SEVERAL_GLANCE = {
    "security unread": (
        "Security",
        "System Integrity Protection not read: csrutil returned an error; Gatekeeper not "
        "read: spctl returned an error; FileVault not read: fdesetup returned an error; "
        "Activation Lock not reported by macOS.",
    ),
    "battery condition and capacity unread": (
        "Battery",
        "Battery condition and capacity not reported by macOS.",
    ),
    "thermal pressure unread": ("Thermal", "Thermal pressure not reported by macOS."),
}


@pytest.mark.parametrize("label", list(SEVERAL_GLANCE))
def test_the_several_values_documents_draw_their_line_with_the_unavailable_chip(label):
    document = SEVERAL[label]()
    _, asked = pages.composed(document)
    topic, text = SEVERAL_GLANCE[label]
    drawn = [
        (row.label, plain(row.text), as_pair(row.chip))
        for row in pages.section_rows(asked, wording.SECTIONS[0])
    ]
    assert (topic, text, UNREAD) in drawn


def test_the_gaps_reach_every_unavailable_row_and_glance_line():
    rows, topics = set(), set()
    for _label, document in SWEEP:
        report = phrases.Report(document)
        for name in (*SECTION_BUILDERS, "power"):
            built = section(report, name, full=True)
            for item in built.items:
                if isinstance(item, details.Row) and item.unavailable:
                    rows.add((built.title, item.label))
            if built.text is not None and built.availability != "available":
                rows.add((built.title, f"({built.availability})"))
        for entry in sections.glance(report):
            if entry.availability != "available":
                topics.add((entry.topic, entry.availability))
    assert rows == UNREAD_ROWS
    assert topics == UNREAD_TOPICS


def _chips_on(document: dict) -> dict[int, list[tuple[str, str]]]:
    made, _ = pages.composed(document)
    return {number: pages.chips(page) for number, page in enumerate(made.pages, start=1)}


def test_an_unavailable_row_carries_the_unavailable_chip_in_its_own_color():
    document = T.edited("m5-laptop", T._unavailable("memory_pressure", "tool_error"))
    found = _chips_on(document)
    assert ("unavailable", ORANGE) in found[3]
    made, asked = pages.composed(document)
    (row,) = [row for row in pages.all_rows(asked) if row.label == "Memory pressure now"]
    assert as_pair(row.chip) == UNREAD
    assert row.text == "Not read: memory_pressure returned an error"


def test_available_values_show_their_provenance_in_ink():
    found = _chips_on(r.load("m5-laptop"))
    for number in (2, 3, 4, 6):
        read = [chip for chip in found[number] if chip[0] in CHIPS]
        assert read and all(color == INK for _, color in read), number
    assert [chip for number in (2, 4, 6) for chip in found[number] if chip[0] not in CHIPS] == []


def test_an_unavailable_value_shows_the_unavailable_chip_in_its_own_color():
    document = T.edited("m5-laptop", T._value_unavailable("firmware_and_boot", "os_loader_version"))
    made, asked = pages.composed(document)
    other = pages.section_rows(asked, "Other values")
    (row,) = [row for row in other if row.label.startswith("OS loader")]
    assert as_pair(row.chip) == UNREAD
    assert ("unavailable", ORANGE) in pages.chips(made.pages[5])


def test_a_desktops_battery_shows_the_not_applicable_chip():
    found = _chips_on(r.load("concerning-desktop"))
    counts = {n: [c for c in chips if c[0] == "not applicable"] for n, chips in found.items()}
    assert {n: len(c) for n, c in counts.items() if c} == {1: 1, 3: 1, 6: 4}
    assert all(color == ORANGE for chips in counts.values() for _, color in chips)


def test_rows_under_a_provenance_header_show_no_chip_when_read():
    _, asked = pages.composed(r.load("m5-laptop"))
    for heading in (wording.SECTIONS[2], wording.SECTIONS[3]):
        rows = pages.section_rows(asked, heading)
        assert rows and all(row.chip is None for row in rows), heading
        (call,) = [c for c in asked if c.kind == "heading" and c.args[0] == heading]
        assert call.args[1] == "as macOS reports it"


def test_an_unread_row_under_a_provenance_header_shows_the_unavailable_chip():
    document = T.edited("m5-laptop", T._unavailable("hardware_overview", "tool_error"))
    _, asked = pages.composed(document)
    rows = pages.section_rows(asked, wording.SECTIONS[2])
    assert [(row.label, as_pair(row.chip)) for row in rows] == [
        ("Model", UNREAD),
        ("Chip", None),
        ("Memory", None),
        ("Startup disk", None),
        ("Serial number", UNREAD),
        ("macOS", None),
    ]


def _rows(asked, heading: str) -> list[tuple[str, str, str | None, str | None]]:  # type: ignore[no-untyped-def]
    return [
        (row.label, row.text, None if row.chip is None else row.chip.word, row.source)
        for row in pages.section_rows(asked, heading)
    ]


GAUGE = "from the battery's own gauge"
CONTROLLER = "from the disk's own controller (IOKit)"


def test_storage_in_full_on_the_m5():
    _, asked = pages.composed(r.load("m5-laptop"))
    assert _rows(asked, wording.SECTIONS[5]) == [
        ("SMART status", "Verified", "reported", None),
        ("Critical warning", "none", "reported", CONTROLLER),
        ("Endurance used", "1%", "reported", None),
        ("Available spare", "100% (threshold 99%)", "reported", None),
        ("Data read", "20.9 TB (40,887,215 units of 512,000 B)", "derived", None),
        ("Data written", "13.3 TB (26,019,396 units of 512,000 B)", "derived", None),
        ("Power-on hours", "427", "measured", None),
        ("Power cycles", "147", "measured", None),
        ("Unsafe shutdowns", "5", "measured", None),
        ("Media errors", "0", "measured", None),
        ("Error log entries", "0", "measured", None),
        (
            "Temperature now",
            "35 °C (308 K minus 273.15, to the nearest degree)",
            "derived",
            None,
        ),
    ]


def test_battery_in_full_on_the_m5():
    _, asked = pages.composed(r.load("m5-laptop"))
    assert _rows(asked, wording.SECTIONS[6]) == [
        ("Condition", "Good", "reported", None),
        ("Maximum capacity", "99%", "reported", None),
        ("Charge now", "100%, fully charged", "measured", None),
        ("Power source", "charger connected, not charging", "measured", None),
        ("Charge cycles", "57", "measured", GAUGE),
        ("Design cycle count", "1,000", "reported", None),
        ("Full charge now", "5,954 mAh", "measured", None),
        ("Design capacity", "6,249 mAh", "reported", None),
        ("Temperature", "30.4 °C (3,040 hundredths of a degree)", "derived", None),
        ("Permanent failure", "none set", "reported", None),
    ]


def test_the_last_restart_prints_with_its_formula():
    _, asked = pages.composed(r.load("m5-laptop"))
    assert _rows(asked, wording.SECTIONS[4]) == [
        (
            "Last restart",
            "28 Aug 2026, 26 days ago (macOS's boot time, and the whole days from it to the "
            "collection)",
            "derived",
            None,
        ),
        ("Panic reports", "0 kept on this Mac", "derived", None),
    ]


THIS_MAC_UNREAD = {
    "C2 failed": (
        T._unavailable("hardware_overview", "tool_error"),
        [
            ("Model", "Not read: system_profiler returned an error", "unavailable", None),
            (
                "Chip",
                "the chip's name was not read (system_profiler returned an error); 4 Super "
                "and 6 Efficiency cores, 10-core GPU",
                None,
                None,
            ),
            ("Memory", "24 GB LPDDR5 (Micron); size from the memory profile", None, None),
            ("Startup disk", "APPLE SSD AP1024Z, 1 TB, the internal SSD (disk0)", None, None),
            ("Serial number", "Not read: system_profiler returned an error", "unavailable", None),
            ("macOS", "26.6.2 (25G83)", None, None),
        ],
    ),
    "C1 failed": (
        T._unavailable("os_version", "tool_error"),
        [
            ("Model", "MacBook Pro, Mac17,2, model number MDE34LL/A", None, None),
            ("Chip", "Apple M5: 4 Super and 6 Efficiency cores, 10-core GPU", None, None),
            ("Memory", "24 GB LPDDR5 (Micron)", None, None),
            ("Startup disk", "APPLE SSD AP1024Z, 1 TB, the internal SSD (disk0)", None, None),
            ("Serial number", "ending in K7Q2 (add --show-serial to print it)", None, None),
            (
                "macOS",
                "the version and build were not read (sw_vers returned an error); firmware "
                "18000.161.10",
                None,
                None,
            ),
        ],
    ),
    "the drive entry not found": (
        T._unavailable("nvme_devices", "source_absent"),
        [
            ("Model", "MacBook Pro, Mac17,2, model number MDE34LL/A", None, None),
            ("Chip", "Apple M5: 4 Super and 6 Efficiency cores, 10-core GPU", None, None),
            ("Memory", "24 GB LPDDR5 (Micron)", None, None),
            (
                "Startup disk",
                "the internal SSD; its name was not read (the startup disk could not be "
                "matched to one drive entry)",
                None,
                None,
            ),
            ("Serial number", "ending in K7Q2 (add --show-serial to print it)", None, None),
            ("macOS", "26.6.2 (25G83), firmware 18000.161.10", None, None),
        ],
    ),
}


@pytest.mark.parametrize("case", list(THIS_MAC_UNREAD), ids=list(THIS_MAC_UNREAD))
def test_this_mac_says_which_rows_are_unread(case):
    edit, rows = THIS_MAC_UNREAD[case]
    _, asked = pages.composed(T.edited("m5-laptop", edit))
    assert _rows(asked, wording.SECTIONS[2]) == rows


GAPS = dict(T.GAP_DOCUMENTS)
# A row the PDF prints alone or in full, unread: the gauge's own values, and the two rows a
# surface collapses to.
PDF_ROWS_UNREAD = {
    "Permanent failure": (GAPS["battery_gauge.permanent_failure"], wording.SECTIONS[6]),
    "Temperature": (GAPS["battery_gauge.temperature_centi_c"], wording.SECTIONS[6]),
    "Last restart": (GAPS["boot_time:tool_error"], wording.SECTIONS[4]),
    "Health log": (GAPS["smart_wear_attributes:tool_error"], wording.SECTIONS[5]),
}
PDF_ROWS_SAY = {
    "Permanent failure": "Not reported by macOS",
    "Temperature": "Not reported by macOS",
    "Last restart": "Not read: sysctl returned an error",
    "Health log": "Not read: the startup disk's health log could not be read",
}


@pytest.mark.parametrize("label", list(PDF_ROWS_UNREAD))
def test_a_pdf_row_whose_value_is_unread_says_why(label):
    document, heading = PDF_ROWS_UNREAD[label]
    _, asked = pages.composed(document)
    (row,) = [row for row in pages.section_rows(asked, heading) if row.label == label]
    assert (row.text, as_pair(row.chip)) == (PDF_ROWS_SAY[label], UNREAD)


def _macos_row(*names: str) -> layout.Row:
    document = T.edited("m5-laptop", *[T._value_unavailable(key, name) for key, name in names])
    _, asked = pages.composed(document)
    (row,) = [r_ for r_ in pages.section_rows(asked, wording.SECTIONS[2]) if r_.label == "macOS"]
    return row


def test_a_macos_row_with_only_its_firmware_is_read():
    row = _macos_row(("os_version", "product_version"), ("os_version", "build_version"))
    assert (row.text, row.chip) == (
        "the version and build are not reported by macOS; firmware 18000.161.10",
        None,
    )
    # With the firmware unread too, nothing of the row was read: it is unavailable.
    _, asked = pages.composed(_macos_unread())
    (row,) = [r_ for r_ in pages.section_rows(asked, wording.SECTIONS[2]) if r_.label == "macOS"]
    assert (row.text, as_pair(row.chip)) == ("Not reported by macOS", UNREAD)


def _row(document: dict, heading: str, label: str) -> layout.Row:
    _, asked = pages.composed(document)
    (row,) = [row for row in pages.section_rows(asked, heading) if row.label == label]
    return row


def _terminal_row(document: dict, name: str, label: str) -> details.Row:
    built = section(phrases.Report(document), name, full=False)
    (row,) = [item for item in built.items if isinstance(item, details.Row) and item.label == label]
    return row


def test_a_critical_warning_prints_the_same_either_way():
    document = T.edited(
        "m5-laptop",
        T._set("smart_health_snapshot", "critical_warning_byte", 1),
        T._set("smart_health_snapshot", "spare_below_threshold", True),
    )
    pdf_row = _row(document, wording.SECTIONS[5], "Critical warning")
    terminal_row = _terminal_row(document, "storage", "Critical warning")
    assert (plain(pdf_row.text), pdf_row.chip.word) == (terminal_row.text, terminal_row.chip)
    assert pdf_row.text == "spare capacity below threshold (bit 0)"


def test_a_set_permanent_failure_prints_the_same_either_way():
    document = T.edited("m5-laptop", T._set("battery_gauge", "permanent_failure", True))
    pdf_row = _row(document, wording.SECTIONS[6], "Permanent failure")
    terminal_row = _terminal_row(document, "battery", "Permanent failure")
    assert (plain(pdf_row.text), pdf_row.chip.word) == (terminal_row.text, terminal_row.chip)
    assert as_pair(pdf_row.chip) == ("reported", layout.INK)


def test_an_unread_permanent_failure_flag_says_why_in_the_pdf_alone():
    document = GAPS["battery_gauge.permanent_failure"]
    row = _row(document, wording.SECTIONS[6], "Permanent failure")
    assert as_pair(row.chip) == UNREAD
    built = section(phrases.Report(document), "battery", full=False)
    assert "Permanent failure" not in [
        item.label for item in built.items if isinstance(item, details.Row)
    ]


# --- the notes --------------------------------------------------------------------------------


def test_a_desktop_prints_no_battery_note_and_every_other():
    _, asked = pages.composed(r.load("concerning-desktop"))
    every = [
        call.args[0] for call in asked if call.kind == "lines" and call.args[1:] == (layout.NOTE,)
    ]
    assert wording.FIXED_NOTES["battery"] not in every
    for key in ("storage", "memory", "power_and_thermal"):
        assert every.count(wording.FIXED_NOTES[key]) == 1, key


NOTE_UNDER = {
    "storage": wording.SECTIONS[5],
    "battery": wording.SECTIONS[6],
    "memory": wording.SECTIONS[7],
    "power_and_thermal": f"{wording.SECTIONS[8]} (5 seconds, no load applied)",
}


@pytest.mark.parametrize("name", r.NAMES)
def test_the_fixed_notes_print_word_for_word(name):
    _, asked = pages.composed(r.load(name))
    for key, heading in NOTE_UNDER.items():
        if key == "battery" and name == "concerning-desktop":
            continue
        assert wording.FIXED_NOTES[key] in pages.notes(asked, heading), key


def test_the_notes_are_in_the_caption_style():
    made, _ = pages.composed(r.load("m5-laptop"))
    drawn = [d for page in made.pages for d in pages.body(page)]
    for key in ("storage", "battery", "memory", "power_and_thermal"):
        lines = layout.wrap(wording.FIXED_NOTES[key], layout.NOTE, made.width)
        found = [d for d in drawn if d.text in lines]
        assert [d.text for d in found] == lines, key
        for d in found:
            assert (d.font, d.size, d.color) == (
                layout.NOTE.font,
                layout.NOTE.size,
                layout.NOTE.color.operands(),
            ), (key, d)


def test_the_terminal_summary_leaves_out_the_pdfs_own_rows():
    said = terminal.summary(r.load("m5-laptop"))
    for label in ("Data read", "Power cycles", "Permanent failure", "Critical warning"):
        assert label not in said, label
    assert "(macOS's boot time" not in said and "hundredths of a degree" not in said
    assert "minus 273.15" not in said


def test_the_unexpected_line_follows_the_collection_line():
    made, asked = pages.composed(r.load("concerning-desktop"))
    title = [call.args[0] for call in asked if call.kind == "lines"][:8]
    collection = "Collection: partial. 19 read, 0 skipped, 2 unavailable, 2 not applicable."
    at = title.index(collection)
    assert title[at + 1] == "Unexpected: a format this version does not recognize."
    assert title[at + 2].startswith("Administrator reads: ")
    words = pages.page_words(made.pages[0])
    assert words.index(collection) < words.index("Unexpected: a format this version")
    _, clean = pages.composed(r.load("m5-laptop"))
    assert not [call for call in clean if call.kind == "lines" and "Unexpected" in call.args[0]]


# --- the power and thermal check -----------------------------------------------------------


def _table(document: dict) -> list[list[str]]:
    _, asked = pages.composed(document)
    (table,) = [
        call
        for call in pages.sections(asked)[NOTE_UNDER["power_and_thermal"]]
        if call.kind == "table"
    ]
    assert [column.title for column in table.args[0]] == [spec[0] for spec in report_pdf._SAMPLES]
    return [list(row) for row in table.args[1]]


def _series_document(kind: str, milliwatts: list[str]) -> dict:
    """m5-laptop with one power series set, and its range and mean with it."""
    document = copy.deepcopy(r.load("m5-laptop"))
    exact = [Decimal(value) for value in milliwatts]
    key = "power_and_thermal_samples"
    r.set_value(document, key, f"sample_{kind}_power_mw", [numbers.canonical(v) for v in exact])
    r.set_value(document, key, f"{kind}_power_mw_min", numbers.canonical(min(exact)))
    r.set_value(document, key, f"{kind}_power_mw_max", numbers.canonical(max(exact)))
    r.set_value(document, key, f"{kind}_power_mw_mean", numbers.canonical(numbers.mean(exact)))
    document = r.finish(document)
    validate.validate(document)
    return document


# Round 1's m2 cases, restored (the #352 review, round 3): each column prints at the precision
# its row decides on the lowest, highest and average, never on its own samples.
PRECISION = {
    # 0.09 W on average: two places for the whole column, zeros as 0.0.
    "a mean below 0.1 W": (["0", "0", "0", "0", "450"], ["0.0", "0.0", "0.0", "0.0", "0.45"]),
    # 1.12 to 1.14 W: one decimal would collapse the range. The first two samples are equal,
    # so a column deciding on its own samples would print one place.
    "a range one decimal would collapse": (
        ["1130", "1130", "1120", "1140", "1125"],
        ["1.13", "1.13", "1.12", "1.14", "1.13"],
    ),
    "one decimal": (["2000", "2500", "3000", "2200", "2800"], ["2.0", "2.5", "3.0", "2.2", "2.8"]),
    "all below 0.1 W": (["50", "60", "70", "55", "65"], ["0.05", "0.06", "0.07", "0.06", "0.07"]),
}


@pytest.mark.parametrize("case", list(PRECISION))
def test_a_power_column_prints_at_its_rows_precision(case):
    milliwatts, cells = PRECISION[case]
    document = _series_document("cpu", milliwatts)
    assert [row[3] for row in _table(document)] == cells


@pytest.mark.parametrize(("kind", "column"), [("cpu", 3), ("gpu", 4), ("ane", 5), ("combined", 6)])
def test_each_power_column_prints_at_its_rows_precision(kind, column):
    for name in r.NAMES:
        document = r.load(name)
        report = phrases.Report(document)
        low, high, mean = (
            report.decimal("power_and_thermal_samples", f"{kind}_power_mw_{stat}")
            for stat in ("min", "max", "mean")
        )
        cells = [row[column] for row in _table(document)]
        if low is None:
            assert set(cells) == {"Not reported by macOS"}
            continue
        places = phrases.watt_places([low, high, mean])
        for cell in cells:
            assert cell.split(".")[1:] == ([] if places == 0 else [cell.split(".")[1]])
            assert len(cell.split(".")[1]) == places if places else "." not in cell


@pytest.mark.parametrize(
    ("nanoseconds", "seconds"),
    [
        (1006543000, "1.007"),
        (1011719875, "1.012"),
        (1000500000, "1.001"),
        (1000499999, "1.000"),
        (5000000000, "5.000"),
    ],
)
def test_a_samples_length_prints_in_seconds_to_the_millisecond_half_up(nanoseconds, seconds):
    assert report_pdf._seconds(nanoseconds) == seconds


def test_the_sample_table_on_the_m5():
    rows = _table(r.load("m5-laptop"))
    assert rows == [
        ["1", "1.007", "Nominal", "2.7", "0.05", "0.0", "2.7"],
        ["2", "1.012", "Nominal", "2.5", "0.05", "0.0", "2.6"],
        ["3", "1.009", "Nominal", "1.6", "0.06", "0.0", "1.7"],
        ["4", "1.012", "Nominal", "0.6", "0.06", "0.0", "0.6"],
        ["5", "1.012", "Nominal", "0.7", "0.05", "0.0", "0.7"],
    ]
    made, asked = pages.composed(r.load("m5-laptop"))
    captions = pages.notes(asked, NOTE_UNDER["power_and_thermal"])
    assert captions[0] == (
        "The 5 samples: each length measured, each thermal pressure and power as macOS reports it."
    )
    words = pages.page_words(made.pages[3])
    assert "The 5 samples: each length measured" in words


def test_a_missing_power_series_prints_not_reported_never_zero():
    rows = _table(r.load("concerning-desktop"))
    assert [row[4] for row in rows] == ["Not reported by macOS"] * 5
    assert all(row[4] != "0.0" for row in rows)


def test_no_chart_without_combined_power():
    names = ["sample_combined_power_mw"] + [
        f"combined_power_mw_{stat}" for stat in ("min", "max", "mean")
    ]
    document = T.edited(
        "m5-laptop",
        *[T._value_unavailable("power_and_thermal_samples", name) for name in names],
    )
    _, asked = pages.composed(document)
    assert [call for call in asked if call.kind == "chart"] == []
    assert [row[6] for row in _table(document)] == ["Not reported by macOS"] * 5


def test_the_chart_draws_combined_power_per_sample_to_scale():
    made, asked = pages.composed(r.load("m5-laptop"))
    (chart,) = [call for call in asked if call.kind == "chart"]
    bars = chart.args[0]
    assert [(bar.label, str(bar.value), bar.text) for bar in bars] == [
        ("Sample 1", "2726.16", "2.7 W"),
        ("Sample 2", "2563.95", "2.6 W"),
        ("Sample 3", "1701.53", "1.7 W"),
        ("Sample 4", "621.565", "0.6 W"),
        ("Sample 5", "719.453", "0.7 W"),
    ]
    assert chart.kwargs == {"height": report_pdf.CHART_HEIGHT}
    drawn = pages.rects(made.pages[3])
    green = [box for box in drawn if box[4] == "f" and box[5] == layout.GREEN.operands()]
    heights = [box[3] for box in sorted(green)]
    tallest = max(heights)
    for bar, height in zip(bars, heights, strict=True):
        assert height / tallest == pytest.approx(float(bar.value) / 2726.16, abs=0.01)
    words = pages.page_words(made.pages[3])
    for bar in bars:
        assert bar.label in words and bar.text.replace(" ", " ") in words


def _declined() -> dict:
    return T.declined()


def test_a_power_check_not_run_prints_its_words_with_the_unavailable_chip():
    _, asked = pages.composed(_declined())
    rows = pages.section_rows(asked, wording.SECTIONS[8])
    assert (rows[0].label, rows[0].text, as_pair(rows[0].chip)) == (
        "",
        "Not read: needs administrator access (you chose not to allow it).",
        UNREAD,
    )


def test_a_power_check_not_run_prints_no_power_note():
    _, asked = pages.composed(_declined())
    notes = [
        call.args[0] for call in asked if call.kind == "lines" and call.args[1:] == (layout.NOTE,)
    ]
    assert wording.FIXED_NOTES["power_and_thermal"] not in notes
    assert [call for call in asked if call.kind in ("table", "chart")][:1] == [
        call for call in asked if call.kind == "table"
    ][:1]
    assert not [call for call in asked if call.kind == "chart"]


def test_the_chart_has_its_caption_and_the_estimates_line_follows_it():
    # Restored from round 1 (the #352 review, round 3): the chart's caption, then which of
    # the values are estimates, then the fixed note.
    _, asked = pages.composed(r.load("m5-laptop"))
    calls = pages.sections(asked)[NOTE_UNDER["power_and_thermal"]]
    kinds = [(call.kind, call.args[0] if call.kind == "lines" else None) for call in calls]
    caption = ("lines", "Combined processor power per sample")
    estimates = ("lines", details.power_labels(5))
    note = ("lines", wording.FIXED_NOTES["power_and_thermal"])
    at = kinds.index(caption)
    assert kinds[at + 1][0] == "chart"
    assert kinds.index(estimates) > at + 1 and kinds.index(note) > kinds.index(estimates)
    for call in calls:
        if call.kind == "lines" and call.args[0] in (caption[1], estimates[1], note[1]):
            assert call.args[1] == layout.NOTE


def test_the_power_note_is_said_once():
    _, asked = pages.composed(r.load("m5-laptop"))
    notes = [
        call.args[0] for call in asked if call.kind == "lines" and call.args[1:] == (layout.NOTE,)
    ]
    assert notes.count(wording.FIXED_NOTES["power_and_thermal"]) == 1
    assert sum("wall power" in note for note in notes) == 1


WARNING = ("Thermal warning level", "none recorded", "reported", report_pdf.WARNING_SOURCE)


@pytest.mark.parametrize("which", ["m5-laptop", "declined", "concerning-desktop"])
def test_the_thermal_warning_level_prints_on_page_4_always(which):
    document = _declined() if which == "declined" else r.load(which)
    made, asked = pages.composed(document)
    heading = NOTE_UNDER["power_and_thermal"] if which != "declined" else wording.SECTIONS[8]
    rows = _rows(asked, heading)
    assert rows[-1] == WARNING
    # Its source line sits above it, after the rows the power sample gives.
    assert all(row[3] is None for row in rows[:-1])
    words = pages.page_words(made.pages[3])
    assert words.index(report_pdf.WARNING_SOURCE) < words.index("Thermal warning level")
    if which != "declined":
        assert words.index("Neural Engine") < words.index(report_pdf.WARNING_SOURCE)


def test_the_warning_level_prints_even_when_the_power_check_did_not_run():
    document = T.history("m5-laptop", "the sandbox probe failed")
    made, asked = pages.composed(document)
    rows = _rows(asked, wording.SECTIONS[8])
    assert rows[-1] == WARNING and len(rows) == 2
    assert "Thermal warning level" in pages.page_words(made.pages[3])
