"""The report PDF's appendices (docs/VOLTRY_MAC_SPEC.md, "Page by page": Appendix A, every
surface tried, and Appendix B, how the report was made; Decision 4's render rules; Failure
modes' render row; the Release plan's provenance).

Appendix A lists every surface in registry order with its result in Courier, how it is read
and why any part of it was not, and every other value with its chip. Appendix B prints the
versions that made the report and, when another version or renderer draws it, a note naming
both; the macOS build, the two collection times, the time zone or the offset alone when it
is unknown, the validated flag, the whole elevation record, what the run changed, the
characters printed as "?", the full report ID and the release's links, all at the version
that made the report; then each command with its template from that version's manifest, or
the IDs alone with a note.
"""

from __future__ import annotations

import copy
import io

import pypdf
import pytest
import voltry_mac_test_pdf_goldens as goldens
import voltry_mac_test_pdf_pages as pages
import voltry_mac_test_reports as r

from voltry_mac import (
    appendices,
    canonical,
    layout,
    pdf,
    phrases,
    registry,
    render,
    report_pdf,
    validate,
    wording,
)

T = pages.terminal_tests()
APPENDIX_A = wording.SECTIONS[-2]
APPENDIX_B = wording.SECTIONS[-1]


def _b(asked) -> list[tuple[str, str, bool, bool]]:  # type: ignore[no-untyped-def]
    return [
        (row.label, row.text.replace(" ", " "), row.mono, row.wide)
        for row in pages.section_rows(asked, APPENDIX_B)
    ]


def _b_line(asked, label: str) -> str:  # type: ignore[no-untyped-def]
    (text,) = [text for found, text, _, _ in _b(asked) if found == label]
    return text


def _pdf_text(data: bytes) -> str:
    reader = pypdf.PdfReader(io.BytesIO(data), strict=True)
    return " ".join(" ".join(page.extract_text().split()) for page in reader.pages)


# --- Appendix A ---------------------------------------------------------------------------------


def test_appendix_a_lists_every_surface_with_its_result_in_courier():
    document = r.load("concerning-desktop")
    made, asked = pages.composed(document)
    (table,) = [call for call in pages.sections(asked)[APPENDIX_A] if call.kind == "table"]
    assert [(column.title, column.mono) for column in table.args[0]] == [
        ("Item", False),
        ("Result", True),
        ("How it is read", False),
        ("Why not read", False),
    ]
    tried = appendices.tried(phrases.Report(document))
    assert [row[0] for row in table.args[1]] == [
        appendices.NAMES[spec.key] for spec in registry.SURFACES
    ]
    assert [list(row) for row in table.args[1]] == [
        [report_pdf.tied(cell) for cell in (t.name, t.result, t.how, t.why)] for t in tried
    ]
    words = " ".join(pages.page_words(page) for page in made.pages)
    for t in tried:
        for cell in (t.name, t.how, t.why):
            assert cell in words, cell
    courier = [d.text for page in made.pages for d in pages.body(page) if d.font is pdf.COURIER]
    assert {"available", "not applicable"} <= set(courier)
    assert any("unsupported" in text for text in courier)


def test_appendix_a_values_carry_their_chips():
    document = r.load("m5-laptop")
    _, asked = pages.composed(document)
    rows = pages.section_rows(asked, "Other values")
    found = appendices.values(phrases.Report(document))
    assert [(row.label, row.text.replace(" ", " ")) for row in rows] == [
        (value.label, value.text) for value in found
    ]
    for row, value in zip(rows, found, strict=True):
        assert row.chip == layout.Chip(value.chip), value
    assert ("Memory total", "25,769,803,776 bytes") in [(row.label, row.text) for row in rows]


def test_appendix_a_names_a_values_reason_code():
    document = T.edited(
        "m5-laptop",
        T._value_unavailable("firmware_and_boot", "os_loader_version", "source_changed"),
    )
    _, asked = pages.composed(document)
    (table,) = [call for call in pages.sections(asked)[APPENDIX_A] if call.kind == "table"]
    (row,) = [row for row in table.args[1] if row[0] == "Firmware"]
    assert "(source_changed)" in row[3]
    (value,) = [v for v in pages.section_rows(asked, "Other values") if v.label.startswith("OS")]
    assert value.chip == layout.Chip(appendices.UNAVAILABLE, layout.UNAVAILABLE)


# --- Appendix B ---------------------------------------------------------------------------------

SOURCE_0_1_0 = (
    "https://github.com/Voltry-tech/voltry-probe/tree/voltry-mac-v0.1.0/packages/voltry-mac"
)
PYPI_0_1_0 = "https://pypi.org/project/voltry-mac/0.1.0/"


@pytest.mark.parametrize("cleanup", ["verified", "survivor", "listing_failed"])
def test_appendix_b_states_the_guarantee_beside_each_payloads_cleanup(cleanup):
    # Decision 2's guarantee, stated exactly and conditionally, prints beside the cleanup it
    # qualifies, and a payload that did not run gets none (the GPT audit, pass 3, G3-04).
    record = copy.deepcopy(r.load("m5-laptop")["elevation"])
    record["count"]["cleanup"] = cleanup
    record["power"]["cleanup"] = "not_applicable"
    lines = [(line.label, line.text, line.mono) for line in appendices._elevation(record)]
    at = lines.index(("Memory-error step", f"parsed, cleanup {cleanup}", True))
    assert lines[at + 1] == ("What it covers", phrases.guarantee(cleanup), False)
    power = lines.index(("Power and thermal step", "parsed, cleanup not_applicable", True))
    assert lines[power + 1][0] == "Final clear (sudo -k)"
    assert [label for label, _, _ in lines].count("What it covers") == 1


def test_the_guarantee_names_what_each_cleanup_lets_voltry_say():
    # Decision 2's guarantee for one payload's cleanup: that step's recorded processes
    # alone, and a survivor as the terminal named it, since the saved report names no
    # process (the GPT audit, pass 4, G4-01).
    assert phrases.guarantee("verified") == (
        "Every process the listings recorded for this step, the payload included if it "
        "started, has ended. A process that starts and ends between two listings is never "
        "recorded."
    )
    assert phrases.guarantee("survivor") == (
        "A process recorded for this step may still be running. Voltry named it in its "
        "terminal output when this report was made; nothing else is claimed."
    )
    assert phrases.guarantee("listing_failed") == (
        "The listing after this step failed, so Voltry could not check that the processes "
        "recorded for it ended, and claims nothing about them."
    )
    with pytest.raises(ValueError):
        phrases.guarantee("not_applicable")


# The histories where the two payloads' cleanups differ, each a report the validator takes
# (the GPT audit, pass 4, G4-01): verified beside a survivor, verified beside a failed
# listing, and a survivor beside a power sample that never ran.
MIXED = (
    "power: its runtime deadline, then a survivor",
    "power: a tracking failure, then the listing failed",
    "count: parsed, then a survivor",
)


@pytest.mark.parametrize("key", MIXED)
def test_each_guarantee_speaks_for_its_own_step_in_a_valid_report(key):
    record, count, power = r.LEGAL[key]
    document = r.history("m5-laptop", record, count, power)
    validate.validate(document)
    cleanups = [document["elevation"][step]["cleanup"] for step in ("count", "power")]
    lines = appendices._elevation(document["elevation"])
    covers = [line.text for line in lines if line.label == "What it covers"]
    assert covers == [phrases.guarantee(c) for c in cleanups if c in appendices.GUARANTEED]
    for text in covers:
        # Neither step speaks for the other's processes, and nothing above names a process:
        # only the terminal did, as the run ended.
        assert "this step" in text
        assert "administrator reads" not in text and "payloads" not in text
        assert "above" not in text
    drawn = pages.strings(render.render(canonical.canonical_json(document).encode()).pdf)
    printed = " ".join(" ".join(drawn).split())
    for text in covers:
        assert text in printed


def test_appendix_b_prints_every_line_and_each_commands_template():
    document = r.load("m5-laptop")
    made, asked = pages.composed(document)
    assert _b(asked) == [
        ("Made by", "voltry-mac 0.1.0, renderer 1, Python 3.12.11, arm64", False, False),
        ("macOS", "macOS 26.6.2 (25G83)", False, False),
        ("Collected, UTC", "2026-09-23T21:05:31Z", False, False),
        (
            "Collected, local time",
            "2026-09-23T14:05:31-07:00 (America/Los_Angeles)",
            False,
            False,
        ),
        ("Validated configuration", "yes", False, False),
        ("Consent", "yes", True, False),
        ("Mode", "interactive", True, False),
        ("Service account", "present", True, False),
        ("Sandbox probe", "ok", True, False),
        ("Process listing", "ok", True, False),
        ("Prepare (sudo -k)", "ok", True, False),
        ("Authenticate (sudo -v)", "ok", True, False),
        ("Memory-error step", "parsed, cleanup verified", True, False),
        ("What it covers", phrases.guarantee("verified"), False, False),
        ("Power and thermal step", "parsed, cleanup verified", True, False),
        ("What it covers", phrases.guarantee("verified"), False, False),
        ("Final clear (sudo -k)", "cleared", True, False),
        ("What it changes", appendices.SUDO, False, False),
        ("Characters replaced", "none", False, False),
        ("Report ID", document["report_id"], True, True),
        ("Source", SOURCE_0_1_0, True, True),
        ("PyPI", PYPI_0_1_0, True, True),
    ]
    (table,) = [call for call in pages.sections(asked)["Commands"] if call.kind == "table"]
    templates = pages.templates()
    assert [list(row) for row in table.args[1]] == [
        [
            record["id"],
            phrases.thousands(record["runs"]),
            phrases.thousands(record["failed_runs"]),
            f"{phrases.thousands(record['duration_ms'])} ms",
            templates[record["id"]],
        ]
        for record in document["commands"]
    ]
    assert [(column.title, column.mono) for column in table.args[0]] == [
        ("ID", True),
        ("Runs", False),
        ("Failed", False),
        ("Time", False),
        ("Command", True),
    ]
    courier = {d.text for page in made.pages for d in pages.body(page) if d.font is pdf.COURIER}
    assert document["report_id"] in courier
    assert {record["id"] for record in document["commands"]} <= courier
    assert "/usr/bin/sw_vers" in courier


def test_appendix_b_says_what_the_run_changes_and_links_the_release():
    _, asked = pages.composed(r.load("m5-laptop"))
    assert _b_line(asked, "What it changes") == appendices.SUDO
    assert (_b_line(asked, "Source"), _b_line(asked, "PyPI")) == (SOURCE_0_1_0, PYPI_0_1_0)
    # A run that never prepared sudo changed nothing, and says so.
    for key in ("declined at the question", "--no-root", "the sandbox probe failed"):
        record, count, power = r.LEGAL[key]
        _, asked = pages.composed(r.history("m5-laptop", record, count, power))
        assert _b_line(asked, "Prepare (sudo -k)") == "not_run", key
        assert _b_line(asked, "What it changes") == appendices.UNCHANGED, key
    # One that prepared it, even when that failed, cleared it before and after.
    record, count, power = r.LEGAL["sudo -k failed"]
    _, asked = pages.composed(r.history("m5-laptop", record, count, power))
    assert _b_line(asked, "What it changes") == appendices.SUDO


def test_an_unknown_time_zone_prints_the_offset_alone():
    # Decision 8: with the zone unknown, "the PDF prints the offset alone".
    document = copy.deepcopy(r.load("m5-laptop"))
    document["time_zone"] = "unknown"
    document = r.rehash(document)
    made, asked = pages.composed(document)
    assert _b_line(asked, "Collected, local time") == "2026-09-23T14:05:31-07:00"
    assert [text for _, text, _, _ in _b(asked) if "unknown" in text] == []
    words = " ".join(pages.page_words(page) for page in made.pages)
    assert "time zone" not in words


def test_an_unknown_producing_version_lists_the_commands_by_id_alone():
    document = r.load("m5-laptop")
    made, asked = pages.composed(document, templates=None)
    commands = pages.sections(asked)["Commands"]
    assert commands[0].kind == "lines"
    assert commands[0].args == (appendices.unknown_templates("0.1.0"), layout.NOTE)
    (table,) = [call for call in commands if call.kind == "table"]
    assert [column.title for column in table.args[0]] == ["ID", "Runs", "Failed", "Time"]
    words = " ".join(pages.page_words(page) for page in made.pages)
    for template in pages.templates().values():
        assert template not in words


def test_a_command_missing_from_a_known_manifest_says_so():
    templates = {key: value for key, value in pages.templates().items() if key != "C9"}
    _, asked = pages.composed(r.load("m5-laptop"), templates=templates)
    (table,) = [call for call in pages.sections(asked)["Commands"] if call.kind == "table"]
    (row,) = [row for row in table.args[1] if row[0] == "C9"]
    assert row[4] == "(not in the manifest of voltry-mac 0.1.0)"
    assert [row for row in table.args[1] if row[4].startswith("(not in")] == [row]


def _note(asked) -> str | None:  # type: ignore[no-untyped-def]
    found = [text for label, text, _, _ in _b(asked) if label == "Note"]
    return found[0] if found else None


def test_another_renderer_says_so_in_appendix_b():
    document = copy.deepcopy(r.load("m5-laptop"))
    document["tool"]["renderer_version"] = "0"
    document = r.rehash(document)
    _, asked = pages.composed(document)
    assert _note(asked) == (
        "This PDF was drawn by voltry-mac 0.1.0, renderer 1; the report was made by "
        "voltry-mac 0.1.0, renderer 0, so this file may differ from the original PDF."
    )


NOTE_0_2_0 = (
    "This PDF was drawn by voltry-mac 0.2.0, renderer 1; the report was made by voltry-mac "
    "0.1.0, renderer 1, so this file may differ from the original PDF."
)


@pytest.mark.parametrize("replaced", [False, True], ids=["as made", "with a character replaced"])
def test_another_package_version_is_named_beside_the_one_that_made_the_report(replaced):
    # Failure modes' render row: "A line naming both versions". Read from render()'s own
    # bytes, the note, the drawing version in /Producer and, everywhere else, the version
    # that made the report: page 1, the footers and both release links. With a character
    # replaced, the pages are composed twice, and the second composition names both too.
    document = copy.deepcopy(r.load("m5-laptop"))
    if replaced:
        r.set_value(document, "gpu_configuration", "metal_family", "Metal Ω")
    document = r.finish(document)
    data = report_pdf.render(document, pages.templates(), drawn_by="0.2.0")
    said = _pdf_text(data)
    assert NOTE_0_2_0 in said
    reader = pypdf.PdfReader(io.BytesIO(data), strict=True)
    assert reader.metadata["/Producer"] == "voltry-mac 0.2.0"
    first = " ".join(reader.pages[0].extract_text().split())
    assert "voltry-mac 0.1.0" in first and "0.2.0" not in first
    assert said.count("voltry-mac 0.2.0") == 1  # the note alone
    assert SOURCE_0_1_0 in said.replace(" ", "") and PYPI_0_1_0 in said.replace(" ", "")
    if replaced:
        assert "1 character outside the PDF's character set was printed as ?" in said


def test_the_version_that_made_the_report_draws_the_same_bytes_named_or_not():
    document = r.load("m5-laptop")
    unnamed = report_pdf.render(document, pages.templates())
    assert report_pdf.render(document, pages.templates(), drawn_by="0.1.0") == unnamed
    assert unnamed == goldens.render("m5-laptop")
    _, asked = pages.composed(document, drawn_by="0.1.0")
    assert _note(asked) is None


@pytest.mark.parametrize("drawn_by", ["", " ", "0.1.0 "])
def test_the_drawing_version_is_a_version_or_none(drawn_by, monkeypatch):
    # Refused before any page is laid out (the #352 review, round 3): no Composer is made.
    made: list[bool] = []
    real = layout.Composer
    monkeypatch.setattr(
        report_pdf.layout,
        "Composer",
        lambda *args, **kwargs: made.append(True) or real(*args, **kwargs),
    )
    with pytest.raises(ValueError, match="drawing version"):
        report_pdf.render(r.load("m5-laptop"), pages.templates(), drawn_by=drawn_by)
    assert made == []


def test_characters_outside_the_pdfs_set_print_as_question_marks_and_are_counted():
    document = copy.deepcopy(r.load("m5-laptop"))
    r.set_value(document, "gpu_configuration", "metal_family", "Metal ΩΣЖ")
    document = r.finish(document)
    made, asked = pages.composed(document)
    assert made.replaced == 3
    data = report_pdf.render(document, pages.templates())
    said = _pdf_text(data)
    assert "Metal ???" in said
    assert "3 characters outside the PDF's character set were printed as ?" in said
    _, recount = pages.composed(document, replaced=3)
    assert _b_line(recount, "Characters replaced") == (
        "3 characters outside the PDF's character set were printed as ?"
    )


@pytest.mark.parametrize("name", list(goldens.DOCUMENTS))
def test_nothing_is_replaced_in_the_fixtures(name):
    made, asked = pages.composed(goldens.DOCUMENTS[name]())
    assert made.replaced == 0
    assert _b_line(asked, "Characters replaced") == "none"
