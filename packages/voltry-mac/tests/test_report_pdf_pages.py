"""The report PDF's pages (docs/VOLTRY_MAC_SPEC.md, "Report outline and PDF layout": the page
setup and page by page; Decision 6's section order).

Every page of every legal elevation history, on both papers, and of the widest legal report
is laid out cleanly: inside the body, nothing drawn on anything else, each chip holding its
word alone. Page 1 holds the title block, At a glance and the limits; pages 2 to 4 hold the
sections in Decision 6's order, each group opening its page; the appendices follow. From
page 2 a running header names the report and its ID, always whole, and every footer gives
the version that made the report, the disclaimer and page X of Y. A number keeps its unit
on its line, and the full report ID and the release links print whole on one line; a link
too long for its line, for a version of 16 characters or more, breaks only after a slash.
"""

from __future__ import annotations

import copy
import re

import pytest
import voltry_mac_test_pdf_goldens as goldens
import voltry_mac_test_pdf_pages as pages
import voltry_mac_test_reports as r

from voltry_mac import appendices, layout, pdf, phrases, report_pdf, sections, wording

PAPERS = ("letter", "a4")
HISTORIES = [(f"{name}: {key}", name, key) for key in r.LEGAL for name in r.NAMES]


def history(name: str, key: str) -> dict:
    record, count, power = r.LEGAL[key]
    return r.history(name, record, count, power)


def id12(document: dict) -> str:
    return document["report_id"].removeprefix("sha256:")[:12]


# --- every page laid out cleanly ------------------------------------------------------------


@pytest.mark.parametrize("paper", PAPERS)
@pytest.mark.parametrize(("label", "name", "key"), HISTORIES, ids=[h[0] for h in HISTORIES])
def test_every_page_of_every_history_is_laid_out_cleanly(label, name, key, paper):
    made, _ = pages.composed(pages.on(history(name, key), paper))
    pages.check(made.pages)


@pytest.mark.parametrize("paper", PAPERS)
def test_the_widest_report_is_laid_out_cleanly(paper):
    made, _ = pages.composed(pages.on(pages.widest("m5-laptop"), paper))
    pages.check(made.pages)
    # Fifteen on Letter, as the #352 review found, round 3; sixteen since Appendix B prints
    # the guarantee beside each cleanup (the GPT audit, pass 3, G3-04).
    assert len(made.pages) <= 16


def test_the_geometry_check_sees_text_below_the_body():
    made, _ = pages.composed(r.load("m5-laptop"))
    pages.check(made.pages)
    made.pages[1].text(
        layout.MARGIN,
        layout.MARGIN - 2,
        "below",
        font=pdf.HELVETICA,
        size=9.5,
        color=layout.INK,
    )
    with pytest.raises(AssertionError):
        pages.check(made.pages)


# --- the running header and the footer ----------------------------------------------------------


def _band(page: pdf.Page, which: int) -> list[pages.Drawn]:
    baseline = pages.bands(page.size[1])[which]
    return [
        d
        for d in pages.texts(page)
        if abs(d.y - baseline) < 0.01
        and (d.font, d.size, d.color) == (layout.SMALL.font, layout.SMALL.size, _small())
    ]


def _small() -> str:
    return layout.SMALL.color.operands()


@pytest.mark.parametrize("paper", PAPERS)
def test_the_running_header_and_the_footer(paper):
    document = pages.on(r.load("m5-laptop"), paper)
    made, _ = pages.composed(document)
    header = f"{wording.TITLE}, {sections.model(phrases.Report(document))}, ID {id12(document)}"
    assert header == f"Mac hardware observation report, MacBook Pro (Mac17,2), ID {id12(document)}"
    total = len(made.pages)
    width = made.pages[0].size[0]
    for number, page in enumerate(made.pages, start=1):
        footer = _band(page, 0)
        assert [d.text for d in footer] == [
            f"voltry-mac {document['tool']['version']}",
            wording.DISCLAIMER,
            f"Page {number} of {total}",
        ]
        assert footer[0].x == pytest.approx(layout.MARGIN, abs=0.01)
        assert footer[2].right == pytest.approx(width - layout.MARGIN, abs=0.01)
        assert [d.text for d in _band(page, 1)] == ([] if number == 1 else [header])


def test_a_shortened_running_header_keeps_the_separator_before_the_id():
    document = r.load("m5-laptop")
    r.set_value(document, "hardware_overview", "machine_name", "MacBook Pro " + "W" * 200)
    document = r.finish(document)
    made, _ = pages.composed(document)
    (header,) = _band(made.pages[1], 1)
    assert header.text.startswith(f"{wording.TITLE}, MacBook Pro WWW")
    assert header.text.endswith(f"..., ID {id12(document)}")
    assert header.right <= made.pages[1].size[0] - layout.MARGIN + 0.01


# --- the pages and their sections ---------------------------------------------------------------


def _headings(made) -> list[tuple[str, int]]:  # type: ignore[no-untyped-def]
    """Each heading drawn, with its page."""
    return [
        (d.text, number)
        for number, page in enumerate(made.pages, start=1)
        for d in pages.body(page)
        if (d.font, d.size) == (layout.HEADING.font, layout.HEADING.size)
    ]


POWER = f"{wording.SECTIONS[8]} (5 seconds, no load applied)"
ON_PAGES = {
    "m5-laptop": [1, 1, 2, 2, 2, 2, 3, 3, 4, 5, 6],
    "concerning-desktop": [1, 1, 2, 2, 2, 2, 3, 3, 4, 5, 6],
}


@pytest.mark.parametrize("name", r.NAMES)
def test_the_sections_come_in_decision_6s_order_on_their_pages(name):
    made, _ = pages.composed(r.load(name))
    found = [
        (text, number) for text, number in _headings(made) if text in (*wording.SECTIONS, POWER)
    ]
    titles = [*wording.SECTIONS[:8], POWER, *wording.SECTIONS[9:]]
    assert [text for text, _ in found] == titles
    assert [number for _, number in found] == ON_PAGES[name]


@pytest.mark.parametrize("name", r.NAMES)
def test_each_group_of_sections_opens_its_page(name):
    made, _ = pages.composed(r.load(name))
    firsts = {number: pages.body(page)[0].text for number, page in enumerate(made.pages, 1)}
    assert firsts[1] == wording.TITLE
    assert firsts[2] == wording.SECTIONS[2]  # This Mac
    assert firsts[3] == wording.SECTIONS[6]  # Battery
    assert firsts[4] == POWER
    assert firsts[5] == wording.SECTIONS[9]  # Appendix A
    for number in (2, 3, 4, 5):
        heading = pages.body(made.pages[number - 1])[0]
        assert heading.color == layout.GREEN.operands()


def test_page_one_is_the_title_block_at_a_glance_and_the_limits():
    document = r.load("m5-laptop")
    made, _ = pages.composed(document)
    drawn = pages.body(made.pages[0])
    title = drawn[0]
    assert (title.text, title.font, title.size, title.color) == (
        wording.TITLE,
        pdf.HELVETICA_BOLD,
        16.0,
        layout.GREEN.operands(),
    )
    assert drawn[1].text == wording.DISCLAIMER
    mono = [d for d in drawn if d.font is pdf.COURIER]
    assert [(d.text, d.size) for d in mono] == [(f"ID {id12(document)}, voltry-mac 0.1.0", 8.5)]
    words = pages.page_words(made.pages[0])
    order = [
        wording.DISCLAIMER,
        "MacBook Pro (Mac17,2), Apple M5. 23 Sep 2026, 14:05 (UTC-7).",
        f"ID {id12(document)}, voltry-mac 0.1.0",
        "Collection: complete.",
        "Administrator reads: asked, granted, cleared.",
        "Validated configuration: yes.",
        wording.SECTIONS[0],
        wording.SECTIONS[1],
        "Value or price. Voltry does not assess either.",
    ]
    at = [words.index(each) for each in order]
    assert at == sorted(at)
    assert wording.SECTIONS[2] not in words
    assert len([h for h in _headings(made) if h[1] == 1]) == 2


def test_page_one_draws_the_limits_as_bullets():
    # Restored from round 1 (the #352 review, round 3).
    document = r.load("m5-laptop")
    _, asked = pages.composed(document)
    (bullets,) = [call for call in asked if call.kind == "bullets"]
    assert bullets.args[0] == sections.limits(phrases.Report(document))


# --- a number keeps its unit --------------------------------------------------------------------

UNITS = ["TB", "PB", "GB", "MB", "B", "W", "°C", "mAh"]


@pytest.mark.parametrize("unit", UNITS)
def test_a_number_and_its_unit_share_a_line(unit):
    text = f"{'word ' * 20}12 {unit} and more words after it"
    tied = report_pdf.tied(text)
    assert f"12 {unit}" in tied
    for width in range(30, 400, 5):
        lines = layout.wrap(tied, layout.BODY, width)
        for line, following in zip(lines, lines[1:], strict=False):
            assert not (line.endswith("12") and following.startswith(unit)), (width, lines)
    # A unit's letters starting a longer word are not a unit.
    assert report_pdf.tied(f"12 {unit}x") == f"12 {unit}x"


def _units_split(made) -> list[tuple[str, str]]:  # type: ignore[no-untyped-def]
    unit = re.compile(r"(?:TB|PB|GB|MB|B|W|°C|K|mAh|ms|bytes)(?![A-Za-z0-9])")
    found = []
    for page in made.pages:
        drawn = pages.body(page)
        for line, following in zip(drawn, drawn[1:], strict=False):
            same_column = abs(line.x - following.x) < 0.01 and following.y < line.y
            if same_column and re.search(r"[0-9]$", line.text) and unit.match(following.text):
                found.append((line.text, following.text))
    return found


def test_no_line_ends_with_a_number_whose_unit_starts_the_next():
    documents = [goldens.DOCUMENTS[name]() for name in goldens.DOCUMENTS]
    documents += [pages.on(pages.widest(name), paper) for name in r.NAMES for paper in PAPERS]
    for document in documents:
        made, _ = pages.composed(document)
        assert _units_split(made) == []


def test_table_cells_keep_a_number_with_its_unit():
    made, asked = pages.composed(r.load("m5-laptop"))
    cells = [cell for call in asked if call.kind == "table" for row in call.args[1] for cell in row]
    assert "24 ms" in cells  # C1's time in Appendix B
    loose = re.compile(r"[0-9] (?:TB|PB|GB|MB|B|W|°C|K|mAh|ms|bytes)(?![A-Za-z0-9])")
    assert [cell for cell in cells if loose.search(cell)] == []


# --- the report ID and the links ----------------------------------------------------------------


def _courier(made) -> list[str]:  # type: ignore[no-untyped-def]
    return [d.text for page in made.pages for d in pages.body(page) if d.font is pdf.COURIER]


@pytest.mark.parametrize("paper", PAPERS)
def test_the_full_report_id_and_the_links_print_whole_on_one_line(paper):
    document = pages.on(r.load("m5-laptop"), paper)
    made, _ = pages.composed(document)
    drawn = _courier(made)
    for whole in (
        document["report_id"],
        appendices.SOURCE.format(version="0.1.0"),
        appendices.PYPI.format(version="0.1.0"),
    ):
        assert whole in drawn, whole


def _pieces(drawn: list[str], whole: str) -> list[str]:
    """The consecutive drawn lines that make up whole."""
    for start in range(len(drawn)):
        joined, taken = "", []
        for line in drawn[start:]:
            if not whole.startswith(joined + line):
                break
            joined += line
            taken.append(line)
            if joined == whole:
                return taken
    raise AssertionError(f"{whole} is not drawn")


# A version the validator accepts, at 16, 19 and 32 characters: the Source link no longer
# fits on one line of A4 at 16 and of Letter at 19.
LONG_VERSIONS = ["0.1.0.post1.dev2", "0.1.0rc1.post3.dev4", "1!10.20.30.40rc1.post12.dev12345"]


@pytest.mark.parametrize("paper", PAPERS)
@pytest.mark.parametrize("version", LONG_VERSIONS)
def test_a_link_too_long_for_its_line_breaks_only_after_a_slash(paper, version):
    document = copy.deepcopy(r.load("m5-laptop"))
    document["tool"]["version"] = version
    document = pages.on(r.rehash(document), paper)
    made, _ = pages.composed(document)
    drawn = _courier(made)
    source = _pieces(drawn, appendices.SOURCE.format(version=version))
    assert all(piece.endswith("/") for piece in source[:-1]), source
    assert appendices.PYPI.format(version=version) in drawn
    assert document["report_id"] in drawn
