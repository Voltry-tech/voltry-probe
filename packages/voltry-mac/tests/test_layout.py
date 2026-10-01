"""The PDF's page layout (docs/VOLTRY_MAC_SPEC.md, "Report outline and PDF layout": the
page setup; Decision 4: the writer's layout scope).

18 mm margins; body Helvetica 9.5 pt on 13 pt leading; headings Helvetica-Bold 12 pt;
commands and IDs Courier 8.5 pt; the spec's colors; label chips as small outlined boxes
carrying their word; word wrap by the AFM widths; key-value rows; tables with wrapped cells
and repeated header rows; a heading never ends a page alone; one small bar chart; a running
header from page 2 and a footer with the tool version, the disclaimer and page X of Y.

The tests read what was drawn back from each page's content stream, whose operators the
writer's own tests pin.
"""

from __future__ import annotations

import ast
import contextlib
import random
import re
import signal
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

import pytest

from voltry_mac import layout, pdf, wording

W, H = pdf.LETTER
BODY_TOP = H - layout.MARGIN
TEXT = re.compile(rb"BT /(F\d) ([\d.]+) Tf ([\d. ]+) rg (-?[\d.]+) (-?[\d.]+) Td \((.*?)\) Tj ET\n")
RECT = re.compile(
    rb"(?:([\d. ]+) rg )?(?:([\d.]+) w ([\d. ]+) RG )?"
    rb"(-?[\d.]+) (-?[\d.]+) (-?[\d.]+) (-?[\d.]+) re ([fSB])\n"
)
LINE = re.compile(rb"([\d.]+) w ([\d. ]+) RG (-?[\d.]+) (-?[\d.]+) m (-?[\d.]+) (-?[\d.]+) l S\n")
FONTS = {b"F1": pdf.HELVETICA, b"F2": pdf.HELVETICA_BOLD, b"F3": pdf.COURIER}


@dataclass(frozen=True)
class Drawn:
    text: str
    x: float
    y: float
    font: pdf.Font
    size: float
    color: str

    @property
    def right(self) -> float:
        return self.x + pdf.width(self.text, self.font, self.size)


def _unescape(raw: bytes) -> str:
    out, index = bytearray(), 0
    while index < len(raw):
        if raw[index] == 0x5C:
            nxt = raw[index + 1 : index + 4]
            if nxt[:1].isdigit():
                out.append(int(nxt, 8))
                index += 4
                continue
            out.append(raw[index + 1])
            index += 2
            continue
        out.append(raw[index])
        index += 1
    return out.decode("cp1252")


def texts(page: pdf.Page) -> list[Drawn]:
    return [
        Drawn(
            _unescape(found[6]),
            float(found[4]),
            float(found[5]),
            FONTS[found[1]],
            float(found[2]),
            found[3].decode(),
        )
        for found in TEXT.finditer(page.content)
    ]


def rects(page: pdf.Page) -> list[tuple[float, float, float, float, str, str | None, str | None]]:
    """Each rectangle: its box, its operator, the color that paints it (the stroke's when it
    is stroked), and its fill."""
    return [
        (
            float(found[4]),
            float(found[5]),
            float(found[6]),
            float(found[7]),
            found[8].decode(),
            (found[3] or found[1] or b"").decode() or None,
            found[1].decode() if found[1] else None,
        )
        for found in RECT.finditer(page.content)
    ]


def lines_of(page: pdf.Page) -> list[tuple[float, float, float, float]]:
    return [tuple(float(v) for v in found.groups()[2:]) for found in LINE.finditer(page.content)]


def operands(color: pdf.Color) -> str:
    return color.operands()


def composer(paper: tuple[float, float] = pdf.LETTER) -> layout.Composer:
    # keep carries its separator, so a shortened header still reads "..., ID 5331136e3e93".
    return layout.Composer(
        paper,
        header="Mac hardware observation report, MacBook Pro",
        keep=", ID 5331136e3e93",
        version="voltry-mac 0.1.0",
    )


ASCENT, DESCENT = 0.72, 0.21  # Helvetica's cap height and descent, near enough for boxes


def box(drawn: Drawn) -> tuple[float, float, float, float]:
    return (
        drawn.x,
        drawn.y - DESCENT * drawn.size,
        drawn.right,
        drawn.y + ASCENT * drawn.size,
    )


def _overlap(a: tuple[float, ...], b: tuple[float, ...], slack: float = 0.01) -> bool:
    return (
        a[0] < b[2] - slack and b[0] < a[2] - slack and a[1] < b[3] - slack and b[1] < a[3] - slack
    )


def _inside(x0: float, y0: float, x1: float, y1: float, size: tuple[float, float]) -> bool:
    width, height = size
    return (
        x0 >= layout.MARGIN - 0.01
        and x1 <= width - layout.MARGIN + 0.01
        and y0 >= layout.MARGIN - 0.01
        and y1 <= height - layout.MARGIN + 0.01
    )


def _bands(height: float) -> tuple[float, float]:
    """The baselines of the footer and of the running header."""
    footer = layout.MARGIN - layout.FOOTER_DROP + layout.SMALL.leading / 2
    header = height - layout.MARGIN + layout.HEADER_RISE + layout.SMALL.leading / 2
    return layout._baseline(footer, layout.SMALL), layout._baseline(header, layout.SMALL)


def check(pages: list[pdf.Page]) -> None:
    """The layout's geometry: the footer's three texts on its baseline and, from page 2,
    the running header alone on its own; every other text, and every rule, box and fill,
    inside the body; no two texts on each other; no rule through a text; each chip box
    holding its word alone; no text on a bar and no two bars on each other."""
    for number, page in enumerate(pages, start=1):
        width, height = page.size
        drawn = texts(page)
        footer_y, header_y = _bands(height)
        small = [d for d in drawn if (d.font, d.size) == (layout.SMALL.font, layout.SMALL.size)]
        footer = [d for d in small if abs(d.y - footer_y) < 0.01]
        header = [d for d in small if abs(d.y - header_y) < 0.01]
        assert [d.text for d in footer[1:]] == [
            wording.DISCLAIMER,
            f"Page {number} of {len(pages)}",
        ], footer
        assert footer[0].x == pytest.approx(layout.MARGIN, abs=0.01), footer
        assert len(header) == (0 if number == 1 else 1), header
        assert all(d.x == pytest.approx(layout.MARGIN, abs=0.01) for d in header), header
        for d in drawn:
            if d not in footer and d not in header:
                assert _inside(*box(d), page.size), d
        for x1, y1, x2, y2 in lines_of(page):
            assert _inside(min(x1, x2), min(y1, y2), max(x1, x2), max(y1, y2), page.size), y1
        for x, y, w, h, _operator, _color, _fill in rects(page):
            assert _inside(x, y, x + w, y + h, page.size), (x, y, w, h)
        for index, first in enumerate(drawn):
            for second in drawn[index + 1 :]:
                assert not _overlap(box(first), box(second)), (first, second)
        for x1, y1, x2, _y2 in lines_of(page):
            for d in drawn:
                bx = box(d)
                crosses = bx[1] + 0.01 < y1 < bx[3] - 0.01 and bx[0] < max(x1, x2)
                assert not (crosses and min(x1, x2) < bx[2]), (d, y1)
        for x, y, w, h, operator, color, _fill in rects(page):
            if operator == "S":
                held = [
                    d
                    for d in drawn
                    if x <= box(d)[0]
                    and box(d)[2] <= x + w
                    and y <= box(d)[1]
                    and box(d)[3] <= y + h
                ]
                assert len(held) == 1, (x, y, held)
            if operator == "f" and color == operands(layout.GREEN):
                assert x >= layout.MARGIN - 0.01 and x + w <= width - layout.MARGIN + 0.01
                assert y >= layout.MARGIN - 0.01 and y + h <= height - layout.MARGIN + 0.01
                for d in drawn:
                    assert not _overlap(box(d), (x, y, x + w, y + h)), (d, "on a bar")
        bars = [
            (r[0], r[1], r[0] + r[2], r[1] + r[3])
            for r in rects(page)
            if r[4] == "f" and r[5] == operands(layout.GREEN)
        ]
        for index, first in enumerate(bars):
            for second in bars[index + 1 :]:
                assert not _overlap(first, second), "two bars on each other"


def body(pages: list[pdf.Page]) -> list[list[Drawn]]:
    """The text inside each page's body box: not the running header or the footer."""
    return [
        [d for d in texts(page) if layout.MARGIN <= d.y <= page.size[1] - layout.MARGIN]
        for page in pages
    ]


# --- the page setup -------------------------------------------------------------------------------


def test_the_margins_are_18_mm_and_the_colors_are_the_specs():
    assert pytest.approx(18 * 72 / 25.4) == layout.MARGIN
    assert {
        "ink": pdf.Color.hex("#15171A"),
        "caption": pdf.Color.hex("#5D6166"),
        "rule": pdf.Color.hex("#D7DAD4"),
        "fill": pdf.Color.hex("#EBEDE8"),
        "heading": pdf.Color.hex("#16633F"),
        "unavailable": pdf.Color.hex("#C2602F"),
    } == {
        "ink": layout.INK,
        "caption": layout.CAPTION,
        "rule": layout.RULE,
        "fill": layout.FILL,
        "heading": layout.GREEN,
        "unavailable": layout.UNAVAILABLE,
    }


def test_the_type_is_the_specs():
    assert (layout.BODY.font, layout.BODY.size, layout.BODY.leading) == (pdf.HELVETICA, 9.5, 13)
    assert (layout.HEADING.font, layout.HEADING.size) == (pdf.HELVETICA_BOLD, 12)
    assert layout.HEADING.color == layout.GREEN
    assert (layout.MONO.font, layout.MONO.size) == (pdf.COURIER, 8.5)


@pytest.mark.parametrize("paper", [pdf.LETTER, pdf.A4], ids=["Letter", "A4"])
def test_the_body_is_the_page_less_its_margins(paper):
    made = composer(paper)
    assert made.width == pytest.approx(paper[0] - 2 * layout.MARGIN)
    made.lines("One line.")
    (page,) = made.finish()
    assert page.size == paper
    (drawn,) = body([page])[0]
    assert drawn.x == pytest.approx(layout.MARGIN, abs=0.01)
    assert paper[1] - layout.MARGIN - layout.BODY.leading < drawn.y < paper[1] - layout.MARGIN


# --- wrapping -------------------------------------------------------------------------------------


def test_short_text_is_one_line_and_spaces_collapse():
    assert layout.wrap("  Apple   M5  ", layout.BODY, 200) == ["Apple M5"]


def test_empty_text_is_one_empty_line():
    assert layout.wrap("", layout.BODY, 200) == [""]


def test_lines_fill_greedily_by_the_afm_widths():
    text = "Endurance used is the SSD controller's own estimate, not a prediction of life."
    found = layout.wrap(text, layout.BODY, 150)
    assert " ".join(found) == text
    for index, line in enumerate(found):
        assert pdf.width(line, pdf.HELVETICA, 9.5) <= 150
        if index + 1 < len(found):
            first = found[index + 1].split()[0]
            assert pdf.width(f"{line} {first}", pdf.HELVETICA, 9.5) > 150


@pytest.mark.parametrize("width", [50, 60, 65])
def test_a_word_wider_than_the_column_breaks_after_a_comma_when_it_can(width):
    number = f"{2**128 - 1:,}"
    found = layout.wrap(number, layout.BODY, width)
    assert "".join(found) == number
    for line in found[:-1]:
        assert line.endswith(",")
    for line in found:
        assert pdf.width(line, pdf.HELVETICA, 9.5) <= width


def test_a_word_with_no_comma_breaks_where_it_must():
    found = layout.wrap("X" * 80, layout.BODY, 50)
    assert "".join(found) == "X" * 80
    assert all(pdf.width(line, pdf.HELVETICA, 9.5) <= 50 for line in found)
    assert all(pdf.width(line + "X", pdf.HELVETICA, 9.5) > 50 for line in found[:-1])


def test_no_line_is_ever_wider_than_its_column():
    rng = random.Random(3)  # noqa: S311 - a fixed sample of cases, not a secret
    alphabet = "abcdefghijklmnopqrstuvwxyz ,.-W" + chr(0xE9) + chr(0x4E09)
    for _ in range(300):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 200)))
        width = rng.uniform(20, 400)
        for line in layout.wrap(text, layout.BODY, width):
            assert pdf.width(line, pdf.HELVETICA, 9.5) <= width + 1e-9, (text, width)


# --- flowing text ---------------------------------------------------------------------------------


def test_lines_step_down_by_the_leading():
    made = composer()
    made.lines("First.")
    made.lines("Second.")
    first, second = body(made.finish())[0]
    assert first.y - second.y == pytest.approx(layout.BODY.leading, abs=0.01)
    assert (first.font, first.size, first.color) == (pdf.HELVETICA, 9.5, operands(layout.INK))


def test_text_flows_onto_a_new_page_and_stays_inside_the_body():
    made = composer()
    for number in range(120):
        made.lines(f"Line {number} of a long appendix.")
    pages = made.finish()
    assert len(pages) >= 3
    shown = [d.text for page in body(pages) for d in page]
    assert shown == [f"Line {n} of a long appendix." for n in range(120)]
    check(pages)


def test_a_page_break_starts_a_page_unless_the_page_is_empty():
    made = composer()
    made.page_break()
    made.lines("Page one.")
    made.page_break()
    made.page_break()
    made.lines("Page two.")
    assert [[d.text for d in page] for page in body(made.finish())] == [
        ["Page one."],
        ["Page two."],
    ]


def test_a_heading_is_bold_green_and_never_ends_a_page_alone():
    made = composer()
    # Too little room for the heading, its space and the first line after it.
    need = layout.HEADING_SPACE + layout.HEADING.leading + layout.BODY.leading
    while made.room() >= need:
        made.lines("Filler.")
    made.heading("Storage health and wear")
    made.lines("The first row.")
    first, second = body(made.finish())
    assert second[0].text == "Storage health and wear"
    assert (second[0].font, second[0].size) == (pdf.HELVETICA_BOLD, 12)
    assert second[0].color == operands(layout.GREEN)
    assert all(d.text == "Filler." for d in first)


def test_a_heading_with_room_below_stays():
    made = composer()
    made.heading("This Mac")
    made.lines("Model: MacBook Pro")
    (page,) = body(made.finish())
    assert [d.text for d in page] == ["This Mac", "Model: MacBook Pro"]


def test_lines_in_another_style_and_indent():
    made = composer()
    made.lines("/usr/bin/sqlite3 -readonly", style=layout.MONO, indent=12)
    (drawn,) = body(made.finish())[0]
    assert (drawn.font, drawn.size) == (pdf.COURIER, 8.5)
    assert drawn.x == pytest.approx(layout.MARGIN + 12, abs=0.01)


# --- key-value rows -------------------------------------------------------------------------------


def test_a_row_has_its_label_its_value_and_its_chip():
    made = composer()
    made.rows([layout.Row("Endurance used", "1%", layout.Chip("reported"))], label_width=110)
    (page,) = made.finish()
    label, value, chip = body([page])[0]
    assert (label.text, label.x, label.color) == (
        "Endurance used",
        pytest.approx(layout.MARGIN, abs=0.01),
        operands(layout.CAPTION),
    )
    assert (value.text, value.x) == ("1%", pytest.approx(layout.MARGIN + 110, abs=0.01))
    assert chip.text == "reported" and chip.size == layout.CHIP_SIZE
    boxes = [r for r in rects(page) if r[4] == "S"]
    (box,) = boxes
    x, y, w, h = box[:4]
    assert x + w == pytest.approx(layout.MARGIN + made.width, abs=0.02)
    assert x < chip.x and chip.right < x + w and y < chip.y < y + h
    assert box[5] == operands(layout.INK)


def test_an_unavailable_row_has_an_availability_chip_in_its_own_color():
    made = composer()
    made.rows(
        [layout.Row("Memory error records", "Not read: needs administrator access",
                    layout.Chip("unavailable", layout.UNAVAILABLE))],
        label_width=110,
    )  # fmt: skip
    (page,) = made.finish()
    chip = body([page])[0][-1]
    assert (chip.text, chip.color) == ("unavailable", operands(layout.UNAVAILABLE))
    (box,) = [r for r in rects(page) if r[4] == "S"]
    assert box[5] == operands(layout.UNAVAILABLE)


def test_a_row_without_a_chip_draws_no_box():
    made = composer()
    made.rows([layout.Row("Model", "MacBook Pro, Mac17,2")], label_width=110)
    (page,) = made.finish()
    assert [d.text for d in body([page])[0]] == ["Model", "MacBook Pro, Mac17,2"]
    assert not [r for r in rects(page) if r[4] == "S"]


def test_a_long_value_wraps_inside_its_column_and_the_next_row_moves_down():
    made = composer()
    long = "Could not read: macOS returned a format this version does not recognize " * 3
    made.rows([layout.Row("Memory pressure now", long), layout.Row("Next", "row")], label_width=110)
    (page,) = made.finish()
    drawn = body([page])[0]
    values = [d for d in drawn if d.x == pytest.approx(layout.MARGIN + 110, abs=0.01)]
    assert len(values) >= 3
    column_right = layout.MARGIN + made.width - layout.CHIP_COLUMN
    assert all(d.right <= column_right + 0.01 for d in values)
    assert " ".join(d.text for d in values[:-1]) == " ".join(long.split())
    assert values[-1].text == "row" and values[-1].y < values[-2].y


def test_rows_are_separated_by_rules():
    made = composer()
    made.rows([layout.Row("A", "1"), layout.Row("B", "2")], label_width=110)
    (page,) = made.finish()
    rules = lines_of(page)
    assert len(rules) >= 2
    for x1, y1, x2, y2 in rules[:2]:
        assert (x1, x2) == (
            pytest.approx(layout.MARGIN, abs=0.01),
            pytest.approx(W - layout.MARGIN, abs=0.01),
        )
        assert y1 == y2


def test_a_row_note_prints_under_it_in_the_caption_color():
    made = composer()
    made.rows(
        [layout.Row("Memory error records", "0 correctable, 0 uncorrectable",
                    layout.Chip("measured"), ("From Apple's private memory error log.",))],
        label_width=110,
    )  # fmt: skip
    (page,) = made.finish()
    note = body([page])[0][-1]
    assert (note.text, note.color) == (
        "From Apple's private memory error log.",
        operands(layout.CAPTION),
    )


def test_a_row_never_splits_across_pages():
    made = composer()
    while made.room() > 2 * layout.BODY.leading:
        made.lines("Filler.")
    made.rows([layout.Row("Label", "word " * 60)], label_width=110)
    first, second = body(made.finish())
    assert all(d.text == "Filler." for d in first)
    assert second[0].text == "Label"


def test_a_row_taller_than_a_page_is_refused():
    # No valid report has one: every string is at most 256 characters.
    with pytest.raises(ValueError, match="a block taller than a page"):
        composer().rows([layout.Row("Label", "word " * 3000)], label_width=110)


# --- tables ---------------------------------------------------------------------------------------


COLUMNS = [
    layout.Column("Sample", 60),
    layout.Column("Thermal pressure", 120),
    layout.Column("CPU W", 70, right=True),
]


def test_a_table_has_a_filled_header_and_its_cells():
    made = composer()
    made.table(COLUMNS, [["1", "Nominal", "1.2"], ["2", "Nominal", "12.3"]])
    (page,) = made.finish()
    drawn = body([page])[0]
    header = drawn[:3]
    assert [d.text for d in header] == ["Sample", "Thermal pressure", "CPU W"]
    assert all(d.font == pdf.HELVETICA_BOLD for d in header)
    fills = [r for r in rects(page) if r[4] == "f"]
    assert fills and fills[0][5] == operands(layout.FILL)
    cells = drawn[3:]
    assert [d.text for d in cells] == ["1", "Nominal", "1.2", "2", "Nominal", "12.3"]
    right = layout.MARGIN + 60 + 120 + 70 - layout.CELL_PAD
    assert cells[2].right == pytest.approx(right, abs=0.02)
    assert cells[5].right == pytest.approx(right, abs=0.02)


def test_a_cell_wraps_and_its_row_grows():
    made = composer()
    made.table(COLUMNS, [["1", "Heavy " * 12, "3.0"], ["2", "Nominal", "1.0"]])
    (page,) = made.finish()
    drawn = body([page])[0][3:]
    pressure = [d for d in drawn if "Heavy" in d.text]
    assert len(pressure) >= 3
    assert all(d.right <= layout.MARGIN + 60 + 120 for d in pressure)
    second = next(d for d in drawn if d.text == "2")
    assert second.y < min(d.y for d in pressure)


def test_a_table_that_continues_repeats_its_header():
    made = composer()
    made.table(COLUMNS, [[str(n), "Nominal", "1.0"] for n in range(1, 90)])
    pages = made.finish()
    assert len(pages) >= 2
    for page in body(pages):
        assert [d.text for d in page[:3]] == ["Sample", "Thermal pressure", "CPU W"]
    rows = [
        d.text
        for page in body(pages)
        for d in page
        if d.x < layout.MARGIN + 60 and d.font == pdf.HELVETICA
    ]
    assert rows == [str(n) for n in range(1, 90)]


def test_a_table_wider_than_the_body_is_refused():
    with pytest.raises(ValueError, match="a table wider than the body"):
        composer().table([layout.Column("Wide", 600)], [["x"]])


def test_a_row_with_the_wrong_number_of_cells_is_refused():
    with pytest.raises(ValueError, match="a row with a cell for each column"):
        composer().table(COLUMNS, [["1", "Nominal"]])


# --- the bar chart --------------------------------------------------------------------------------


def test_the_bars_are_proportional_and_labeled():
    made = composer()
    bars = [
        layout.Bar("1", Decimal("18.4"), "18.4 W"),
        layout.Bar("2", Decimal("41.9"), "41.9 W"),
        layout.Bar("3", Decimal("0"), "0.0 W"),
        layout.Bar("4", None, "not reported"),
        layout.Bar("5", Decimal("20.95"), "21.0 W"),
    ]
    made.chart(bars, height=60)
    (page,) = made.finish()
    filled = [r for r in rects(page) if r[4] == "f" and r[5] == operands(layout.GREEN)]
    heights = [r[3] for r in filled]
    assert heights == pytest.approx([60 * 18.4 / 41.9, 60, 60 * 20.95 / 41.9], abs=0.02)
    widths = {r[2] for r in filled}
    assert len(widths) == 1
    drawn = [d.text for d in body([page])[0]]
    for bar in bars:
        assert bar.label in drawn and bar.text in drawn


def test_a_chart_of_zeros_draws_no_bars():
    made = composer()
    made.chart([layout.Bar(str(n), Decimal(0), "0.0 W") for n in range(1, 6)], height=60)
    (page,) = made.finish()
    assert not [r for r in rects(page) if r[4] == "f" and r[5] == operands(layout.GREEN)]


def test_a_chart_moves_to_a_new_page_whole():
    made = composer()
    while made.room() > 40:
        made.lines("Filler.")
    made.chart([layout.Bar("1", Decimal(1), "1.0 W")], height=60)
    first, second = made.finish()
    assert not [r for r in rects(first) if r[4] == "f" and r[5] == operands(layout.GREEN)]
    assert [r for r in rects(second) if r[4] == "f" and r[5] == operands(layout.GREEN)]


# --- the running header and the footer ------------------------------------------------------------


def test_every_page_has_the_footer_and_page_two_on_the_header():
    made = composer()
    for number in range(90):
        made.lines(f"Line {number}.")
    pages = made.finish()
    total = len(pages)
    assert total >= 2
    for number, page in enumerate(pages, start=1):
        drawn = texts(page)
        footer = [d for d in drawn if d.y < layout.MARGIN]
        assert [d.text for d in footer] == [
            "voltry-mac 0.1.0",
            "Point-in-time observations, not a diagnosis, grade or certificate.",
            f"Page {number} of {total}",
        ]
        assert footer[0].x == pytest.approx(layout.MARGIN, abs=0.01)
        assert footer[2].right == pytest.approx(W - layout.MARGIN, abs=0.02)
        assert all(d.color == operands(layout.CAPTION) for d in footer)
        header = [d for d in drawn if d.y > BODY_TOP]
        if number == 1:
            assert header == []
        else:
            assert [d.text for d in header] == [
                "Mac hardware observation report, MacBook Pro, ID 5331136e3e93"
            ]


def test_a_running_header_wider_than_the_page_is_shortened_to_fit():
    made = layout.Composer(
        pdf.LETTER, header="Mac hardware observation report, " + "Mac " * 80, keep="", version="v"
    )
    made.page_break()
    made.lines("One.")
    made.page_break()
    made.lines("Two.")
    second = made.finish()[1]
    (header,) = [d for d in texts(second) if d.y > BODY_TOP]
    assert header.text.startswith("Mac hardware observation report, Mac")
    assert header.text.endswith("...")
    assert header.right <= W - layout.MARGIN + 0.01


def test_finish_is_once():
    made = composer()
    made.finish()
    with pytest.raises(RuntimeError, match="the pages are finished"):
        made.lines("Too late.")
    with pytest.raises(RuntimeError, match="the pages are finished"):
        made.finish()


def test_the_replaced_characters_are_counted_over_every_page():
    made = composer()
    made.lines("Three " + chr(0x4E09) * 3)
    made.page_break()
    made.lines("One " + chr(0x1F600))
    made.finish()
    assert made.replaced == 4


# --- the whole ------------------------------------------------------------------------------------


def _compose() -> bytes:
    made = composer()
    made.heading("This Mac")
    made.rows([layout.Row("Model", "MacBook Pro, Mac17,2", None)], label_width=110)
    made.table(COLUMNS, [["1", "Nominal", "1.2"]])
    made.chart([layout.Bar("1", Decimal("1.2"), "1.2 W")], height=40)
    return pdf.document(
        made.finish(),
        title="t",
        producer="p",
        created="D:20260923140531-07'00'",
        identifier=bytes(32),
        compress=False,
    )


def test_the_same_composition_gives_the_same_bytes():
    assert _compose() == _compose()


# --- the review of #351, round 1 ------------------------------------------------------------


PAPERS = [pdf.LETTER, pdf.A4]
PAPER_IDS = ["Letter", "A4"]


def _headings(page: pdf.Page) -> list[Drawn]:
    return [d for d in texts(page) if d.font == pdf.HELVETICA_BOLD and d.size == 12]


def _fill_to(made: layout.Composer, room: float) -> None:
    """Lines until the room left is at most ``room``, and more than it less one line."""
    while made.room() - layout.BODY.leading >= room:
        made.lines("Filler.")


BLOCKS = {
    "a line": lambda made: made.lines("The first line."),
    "a two-line row": lambda made: made.rows(
        [layout.Row("Label", "word " * 30, layout.Chip("measured"))], label_width=110
    ),
    "a row with a note": lambda made: made.rows(
        [layout.Row("Label", "One line.", layout.Chip("measured"), ("A note under it.",))],
        label_width=110,
    ),
    "a table": lambda made: made.table(
        [layout.Column("Sample", 60), layout.Column("Neural Engine W", 60, right=True)],
        [["1", "0.0"]],
    ),
    "the chart": lambda made: made.chart(
        [layout.Bar(str(n), Decimal(n), f"{n}.0 W") for n in range(1, 6)], height=60
    ),
    "another heading and a line": lambda made: (
        made.heading("Memory"),
        made.lines("Memory pressure now"),
    ),
}


@pytest.mark.parametrize("paper", PAPERS, ids=PAPER_IDS)
@pytest.mark.parametrize("block", list(BLOCKS), ids=list(BLOCKS))
@pytest.mark.parametrize("room", [30, 40, 50, 60, 70, 80, 100, 120, 160])
def test_a_heading_moves_with_the_first_unit_of_any_block(paper, block, room):
    made = composer(paper)
    _fill_to(made, room)
    made.heading("Storage health and wear")
    BLOCKS[block](made)
    pages = made.finish()
    check(pages)
    for page in pages:
        found = [d for d in texts(page) if layout.MARGIN <= d.y <= page.size[1] - layout.MARGIN]
        if found and found[-1] in _headings(page):
            pytest.fail(f"a heading ends page {pages.index(page) + 1} alone: {found[-1].text}")


def test_a_heading_left_at_the_end_is_still_drawn():
    made = composer()
    made.lines("One line.")
    made.heading("A last heading")
    (page,) = made.finish()
    assert [d.text for d in _headings(page)] == ["A last heading"]


@pytest.mark.parametrize("paper", PAPERS, ids=PAPER_IDS)
@pytest.mark.parametrize("missing", [1, 5], ids=["one bar", "every bar"])
def test_the_charts_text_fits_its_slot_even_not_reported_by_macos(paper, missing):
    made = composer(paper)
    bars = [
        (
            layout.Bar(str(n), None, "not reported by macOS")
            if n <= missing
            else layout.Bar(str(n), Decimal(n), f"{n}.0 W")
        )
        for n in range(1, 6)
    ]
    made.chart(bars, height=60)
    made.lines("The note under the chart.")
    check(made.finish())


@pytest.mark.parametrize(
    ("bars", "height", "guard"),
    [
        ([], 60, "a chart needs bars and a height"),
        ([layout.Bar("1", Decimal(1), "1.0 W")], 0, "a chart needs bars and a height"),
        ([layout.Bar("1", Decimal(1), "1.0 W")], -60, "a chart needs bars and a height"),
        (
            [layout.Bar(str(n), Decimal(n), "1 W") for n in range(40)],
            60,
            "more bars than the body holds",
        ),
        ([layout.Bar("1", Decimal(1), "word " * 40)], 60, "a bar's text or label past two lines"),
    ],
    ids=["no bars", "no height", "a negative height", "more than fit", "text past two lines"],
)
def test_a_chart_that_cannot_be_drawn_is_refused(bars, height, guard):
    with pytest.raises(ValueError, match=guard):
        composer().chart(bars, height=height)


@contextlib.contextmanager
def _within(seconds: float):
    """Fail, rather than hang, if the body does not return in time."""

    def expired(_signum: int, _frame: object) -> None:
        raise TimeoutError("the call did not return")

    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


@pytest.mark.parametrize("width", [0, -1, -50])
def test_wrap_refuses_a_width_that_holds_nothing(width):
    with _within(1.0), pytest.raises(ValueError, match="a width that holds nothing"):
        layout.wrap("a b c", layout.BODY, width)


def test_blocks_refuse_columns_that_hold_nothing():
    made = composer()
    with pytest.raises(ValueError, match="a width that holds nothing"):
        made.lines("text", indent=made.width)
    with pytest.raises(ValueError, match="a row with no room for its label or its value"):
        made.rows([layout.Row("A", "b")], label_width=layout.GAP)
    with pytest.raises(ValueError, match="a row with no room for its label or its value"):
        made.rows([layout.Row("A", "b")], label_width=made.width - layout.CHIP_COLUMN)
    with pytest.raises(ValueError, match="a width that holds nothing"):
        made.table([layout.Column("A", 2 * layout.CELL_PAD)], [["x"]])
    (page,) = made.finish()
    assert body([page]) == [[]], "nothing drawn before a refusal"


def test_a_last_page_break_leaves_no_empty_page():
    made = composer()
    made.lines("Page one.")
    made.page_break()
    assert len(made.finish()) == 1


def test_a_block_that_fills_its_page_exactly_leaves_no_empty_page():
    made = composer()
    while made.room() >= layout.BODY.leading:
        made.lines("Filler.")
    assert len(made.finish()) == 1


def test_a_block_taller_than_a_page_opens_no_page():
    made = composer()
    made.lines("One.")
    with pytest.raises(ValueError, match="a block taller than a page"):
        made.rows([layout.Row("Label", "word " * 3000)], label_width=110)
    assert len(made.finish()) == 1


def test_a_block_exactly_the_room_left_fits():
    made = composer()
    row = layout.Row("A", "b")
    while made.room() > 2 * layout.ROW_PAD + layout.BODY.leading + 13:
        made.lines("Filler.")
    made.space(made.room() - (2 * layout.ROW_PAD + layout.BODY.leading))
    made.rows([row], label_width=110)
    assert len(made.finish()) == 1


@pytest.mark.parametrize("paper", PAPERS, ids=PAPER_IDS)
@pytest.mark.parametrize("model", ["Mac " * 60, "W" * 256], ids=["long words", "one long word"])
def test_the_running_header_keeps_the_report_id_whole(paper, model):
    made = layout.Composer(
        paper,
        header=f"Mac hardware observation report, {model}",
        keep=", ID 5331136e3e93",
        version="voltry-mac 0.1.0",
    )
    made.lines("One.")
    made.page_break()
    made.lines("Two.")
    second = made.finish()[1]
    (header,) = [d for d in texts(second) if d.y > second.size[1] - layout.MARGIN]
    assert header.text.startswith("Mac hardware observation report, ")
    assert header.text.endswith("..., ID 5331136e3e93")
    assert not header.text.endswith(",..., ID 5331136e3e93")
    assert header.right <= second.size[0] - layout.MARGIN + 0.01


@pytest.mark.parametrize("paper", PAPERS, ids=PAPER_IDS)
def test_the_footers_parts_never_meet(paper):
    made = layout.Composer(paper, header="h", keep="", version="voltry-mac " + "9" * 32)
    made.lines("One.")
    (page,) = made.finish()
    footer = sorted((d for d in texts(page) if d.y < layout.MARGIN), key=lambda d: d.x)
    assert len(footer) == 3
    for left, right in zip(footer, footer[1:], strict=False):
        assert left.right + 6 <= right.x, (left.text, right.text)
    assert footer[0].text.endswith("...")


def test_a_character_the_header_replaces_is_counted_once():
    made = layout.Composer(pdf.LETTER, header="Model " + chr(0x4E09), keep="", version="v")
    for _ in range(4):
        made.lines("Page.")
        made.page_break()
    made.lines("Last.")
    made.finish()
    assert made.replaced == 1


def test_the_count_before_finish_is_the_bodys_so_far():
    made = composer()
    made.lines("One " + chr(0x4E09))
    assert made.replaced == 1


@pytest.mark.parametrize("space", [chr(0x3000), chr(0x2028), chr(0x85), chr(0x2003)])
def test_whitespace_outside_winansi_is_replaced_and_counted(space):
    made = composer()
    made.lines(f"a{space}b")
    (page,) = made.finish()
    (drawn,) = body([page])[0]
    assert drawn.text == "a?b"
    assert made.replaced == 1


def test_a_no_break_space_keeps_a_number_with_its_unit():
    text = "13.3" + chr(0xA0) + "TB"
    width = pdf.width(text, pdf.HELVETICA, 9.5) + 1  # the unit fits alone, not after "x"
    assert layout.wrap(f"x {text}", layout.BODY, width) == ["x", text]


def test_a_row_value_or_a_cell_can_be_courier():
    made = composer()
    made.rows([layout.Row("Report ID", "sha256:5331136e", mono=True)], label_width=110)
    made.table(
        [layout.Column("ID", 40), layout.Column("Command", 300, mono=True)],
        [["C1", "/usr/bin/sw_vers"]],
    )
    (page,) = made.finish()
    drawn = {d.text: d for d in body([page])[0]}
    assert (drawn["sha256:5331136e"].font, drawn["sha256:5331136e"].size) == (pdf.COURIER, 8.5)
    assert (drawn["/usr/bin/sw_vers"].font, drawn["/usr/bin/sw_vers"].size) == (pdf.COURIER, 8.5)
    assert drawn["C1"].font == pdf.HELVETICA
    check([page])


def test_a_chip_word_wider_than_its_column_is_refused():
    with pytest.raises(ValueError, match="a chip word wider than its column"):
        composer().rows(
            [layout.Row("A", "b", layout.Chip("unavailable, not granted"))], label_width=110
        )


def test_space_is_dropped_at_the_top_and_clamped_at_the_bottom():
    made = composer()
    made.space(20)
    made.lines("First.")
    (first,) = body(made.pages)[0]
    assert made.pages[0].size[1] - layout.MARGIN - layout.BODY.leading < first.y
    made.space(10_000)
    assert made.room() == 0
    with pytest.raises(ValueError, match="a space that is negative or not a number"):
        made.space(-1)


def test_nothing_is_laid_out_after_finish():
    made = composer()
    made.finish()
    for call in (made.page_break, lambda: made.space(10), lambda: made.heading("x")):
        with pytest.raises(RuntimeError, match="the pages are finished"):
            call()


def test_text_with_parentheses_backslashes_and_accents_reads_back():
    made = composer()
    made.lines("(a) \\b caf" + chr(0xE9))
    (page,) = made.finish()
    assert [d.text for d in body([page])[0]] == ["(a) \\b caf" + chr(0xE9)]


def test_the_labels_headers_and_rules_are_the_specs():
    made = composer()
    made.rows([layout.Row("Label", "Value", layout.Chip("reported"))], label_width=110)
    made.table([layout.Column("Head", 100)], [["cell"]])
    (page,) = made.finish()
    drawn = {d.text: d for d in body([page])[0]}
    assert (drawn["Label"].font, drawn["Label"].size) == (pdf.HELVETICA, 9.5)
    assert (drawn["Head"].font, drawn["Head"].size) == (pdf.HELVETICA_BOLD, 9.5)
    for found in LINE.finditer(page.content):
        assert (float(found[1]), found[2].decode()) == (0.5, operands(layout.RULE))
    fill = next(r for r in rects(page) if r[4] == "f")
    head = box(drawn["Head"])
    assert fill[1] <= head[1] and head[3] <= fill[1] + fill[3], "the fill holds its header"
    cell = drawn["cell"]
    assert cell.right <= layout.MARGIN + 100 - layout.CELL_PAD + 0.01


def test_a_table_one_point_wider_than_the_body_is_refused():
    made = composer()
    with pytest.raises(ValueError, match="a table wider than the body"):
        made.table([layout.Column("Wide", made.width + 1)], [["x"]])


def _random_composition(rng, paper):
    made = composer(paper)
    words = ["Storage", "not reported by macOS", "13.3" + chr(0xA0) + "TB", "8,984,412"]
    words += ["W" * 30, "caf" + chr(0xE9), chr(0x4E09) * 3, "(x)", "\\"]
    for _ in range(rng.randint(3, 25)):
        kind = rng.choice(["heading", "lines", "rows", "table", "chart", "break", "space"])
        text = " ".join(rng.choice(words) for _ in range(rng.randint(1, 30)))
        if kind == "heading":
            made.heading(text[:60])
        elif kind == "lines":
            made.lines(text, style=rng.choice([layout.BODY, layout.MONO, layout.NOTE]))
        elif kind == "rows":
            rows = []
            for _ in range(rng.randint(1, 4)):
                chip = rng.choice(
                    [None, layout.Chip("measured"), layout.Chip("unavailable", layout.UNAVAILABLE)]
                )
                notes = (text[:80],) if rng.random() < 0.3 else ()
                rows.append(layout.Row(text[:30], text, chip, notes, mono=rng.random() < 0.2))
            made.rows(rows, label_width=rng.choice([90, 110, 160]))
        elif kind == "table":
            columns = [layout.Column("Sample", 60), layout.Column("Text", 200)]
            columns.append(layout.Column("W", 70, right=True, mono=rng.random() < 0.5))
            made.table(columns, [[str(n), text[:90], "1.0"] for n in range(rng.randint(0, 40))])
        elif kind == "chart":
            count = rng.randint(1, 8)
            values = [
                None if rng.random() < 0.2 else Decimal(rng.randint(0, 50)) for _ in range(count)
            ]
            made.chart(
                [
                    layout.Bar(
                        rng.choice([str(n), "Sample 12 of the check"]),
                        v,
                        "not reported by macOS" if v is None else f"{v}.0 W",
                    )
                    for n, v in enumerate(values, 1)
                ],
                height=rng.choice([30, 60, 120]),
            )
        elif kind == "break":
            made.page_break()
        else:
            made.space(rng.randint(0, 40))
    return made.finish()


@pytest.mark.parametrize("paper", PAPERS, ids=PAPER_IDS)
def test_random_compositions_keep_the_geometry_and_their_headings(paper):
    rng = random.Random(351)  # noqa: S311 - a fixed sample of cases, not a secret
    for _ in range(60):
        pages = _random_composition(rng, paper)
        check(pages)
        for number, page in enumerate(pages[:-1], start=1):
            found = [d for d in texts(page) if layout.MARGIN <= d.y <= page.size[1] - layout.MARGIN]
            assert found, f"page {number} of {len(pages)} is empty"
            assert found[-1] not in _headings(page), f"a heading ends page {number} alone"


def test_the_layout_reads_no_clock_file_process_or_network():
    tree = ast.parse(Path(layout.__file__).read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
            if node.module == "voltry_mac":
                assert {alias.name for alias in node.names} <= {"pdf", "wording"}
    assert imported <= {
        "__future__",
        "collections.abc",
        "dataclasses",
        "decimal",
        "typing",
        "voltry_mac",
    }


# --- the review of #351, round 2 ------------------------------------------------------------


def _base(top: float, style: layout.Style) -> float:
    """The baseline of a line whose box starts at top, as the layout centers it."""
    return top - (style.leading + 0.51 * style.size) / 2


def test_the_layouts_measures():
    # The design's measures: a change to one is a change to every report's pages.
    assert (layout.GAP, layout.ROW_PAD, layout.CELL_PAD, layout.RULE_WIDTH) == (6, 3, 4, 0.5)
    assert (layout.CHIP_SIZE, layout.CHIP_PAD, layout.CHIP_HEIGHT) == (7, 3, 10)
    assert layout.CHIP_COLUMN == 60
    assert (layout.BAR_SLOT, layout.BAR_PAD, layout.BAR_LINES) == (60, 2, 2)
    assert (layout.HEADER_RISE, layout.FOOTER_DROP, layout.FOOTER_GAP) == (14, 18, 6)
    assert layout.HEADING_SPACE == 6.5
    styles = {
        "strong": (layout.STRONG, pdf.HELVETICA_BOLD, 9.5, 13, layout.INK),
        "label": (layout.LABEL, pdf.HELVETICA, 9.5, 13, layout.CAPTION),
        "heading": (layout.HEADING, pdf.HELVETICA_BOLD, 12, 18, layout.GREEN),
        "mono": (layout.MONO, pdf.COURIER, 8.5, 12, layout.INK),
        "note": (layout.NOTE, pdf.HELVETICA, 8.5, 11.5, layout.CAPTION),
        "small": (layout.SMALL, pdf.HELVETICA, 7.5, 10, layout.CAPTION),
    }
    for name, (style, font, size, leading, color) in styles.items():
        assert (style.font, style.size, style.leading, style.color) == (
            font,
            size,
            leading,
            color,
        ), name


# The eight tests round 2 proposed, for its survivors.


def test_a_page_break_takes_effect_once():
    made = composer()
    made.lines("Page one.")
    made.page_break()
    for n in range(3):
        made.lines(f"Line {n}.")
    assert [len(page) for page in body(made.finish())] == [1, 3]


def test_the_bars_sit_in_their_slots():
    made = composer()
    made.chart([layout.Bar(str(n), Decimal(n), f"{n}.0 W") for n in range(1, 6)], height=60)
    (page,) = made.finish()
    bars = sorted(r for r in rects(page) if r[4] == "f")
    assert len(bars) == 5
    for index, (x, _y, w, _h, *_rest) in enumerate(bars):
        left = layout.MARGIN + index * layout.BAR_SLOT
        assert x == pytest.approx(left + layout.BAR_SLOT / 4, abs=0.01)
        assert w == pytest.approx(layout.BAR_SLOT / 2, abs=0.01)


def test_a_bars_two_lines_read_top_down():
    made = composer()
    made.chart([layout.Bar("1", None, "not reported by macOS")], height=60)
    drawn = [d.text for d in sorted(body(made.finish())[0], key=lambda d: -d.y)]
    assert drawn.index("not reported by") < drawn.index("macOS")


def test_the_chip_sits_on_its_rows_first_line():
    made = composer()
    made.rows([layout.Row("Endurance used", "1%", layout.Chip("reported"))], label_width=110)
    (page,) = made.finish()
    label = body([page])[0][0]
    (chip,) = [r for r in rects(page) if r[4] == "S"]
    (rule,) = lines_of(page)
    assert rule[1] < chip[1] and chip[1] < label.y < chip[1] + chip[3]


def test_table_rows_and_the_chart_have_their_rules():
    made = composer()
    made.table([layout.Column("Sample", 60)], [["1"], ["2"]])
    made.chart([layout.Bar("1", Decimal(1), "1.0 W")], height=40)
    assert len(lines_of(made.finish()[0])) == 3


def test_a_value_and_a_cell_default_to_helvetica_and_the_left():
    made = composer()
    made.rows([layout.Row("Model", "MacBook Pro")], label_width=110)
    made.table([layout.Column("Sample", 60), layout.Column("Pressure", 120)], [["1", "Nominal"]])
    drawn = {d.text: d for d in body(made.finish())[0]}
    assert drawn["MacBook Pro"].font == pdf.HELVETICA
    assert drawn["Nominal"].x == pytest.approx(layout.MARGIN + 60 + layout.CELL_PAD, abs=0.01)


def test_a_block_taller_than_the_body_is_refused():
    made = composer()
    with pytest.raises(ValueError, match="a block taller than a page"):
        made.chart([layout.Bar("1", Decimal(1), "1.0 W")], height=made.room())


def test_a_heading_has_its_space_above_it_but_not_at_a_pages_top():
    made = composer()
    made.heading("First")
    made.lines("One.")
    made.heading("Second")
    made.lines("Two.")
    first, one, second, _two = body(made.finish())[0]
    top = H - layout.MARGIN
    assert first.y == pytest.approx(_base(top, layout.HEADING), abs=0.01)
    expected = (
        layout.BODY.leading
        + layout.HEADING_SPACE
        + (layout.HEADING.leading + 0.51 * 12) / 2
        - (layout.BODY.leading + 0.51 * 9.5) / 2
    )
    assert one.y - second.y == pytest.approx(expected, abs=0.02)


# Minor 1: space asked for while a heading waits goes under the heading, with its block.


def test_space_asked_for_while_a_heading_waits_goes_under_it():
    plain = composer()
    plain.lines("Before.")
    plain.heading("Heading")
    plain.lines("After.")
    before0, heading0, after0 = body(plain.finish())[0]
    made = composer()
    made.lines("Before.")
    made.heading("Heading")
    made.space(30)
    made.lines("After.")
    before, heading, after = body(made.finish())[0]
    assert before.y - heading.y == pytest.approx(before0.y - heading0.y, abs=0.01)
    assert heading.y - after.y == pytest.approx(heading0.y - after0.y + 30, abs=0.01)


def test_a_heading_and_the_space_under_it_move_to_the_next_page_together():
    made = composer()
    while made.room() >= 60:
        made.lines("Filler.")
    made.heading("Heading")
    made.space(40)
    made.lines("After.")
    first, second = body(made.finish())
    assert all(d.text == "Filler." for d in first)
    heading, after = second
    assert heading.text == "Heading"
    # The heading's line, the space under it, and the two baselines' offsets in their lines.
    drop = layout.HEADING.leading + 40 + _base(0, layout.HEADING) - _base(0, layout.BODY)
    assert heading.y - after.y == pytest.approx(drop, abs=0.01)


# Minor 2: a refused block leaves nothing behind.


@pytest.mark.parametrize("block", ["rows", "chart", "table"])
def test_a_refused_block_after_a_page_break_opens_no_page(block):
    made = composer()
    made.lines("Page one.")
    made.page_break()
    tall = {
        "rows": lambda: made.rows([layout.Row("Label", "word " * 3000)], label_width=110),
        "chart": lambda: made.chart([layout.Bar("1", Decimal(1), "1 W")], height=2000),
        "table": lambda: made.table([layout.Column("A", 200)], [["word " * 3000]]),
    }[block]
    with pytest.raises(ValueError, match="a block taller than a page"):
        tall()
    assert len(made.finish()) == 1


def test_rows_are_all_measured_before_any_is_drawn():
    made = composer()
    with pytest.raises(ValueError, match="a block taller than a page"):
        made.rows(
            [layout.Row("Drawn", "first"), layout.Row("Label", "word " * 3000)], label_width=110
        )
    (page,) = made.finish()
    assert body([page]) == [[]]
    assert lines_of(page) == []


def test_a_table_is_measured_before_any_row_is_drawn():
    made = composer()
    with pytest.raises(ValueError, match="a block taller than a page"):
        made.table([layout.Column("A", 200)], [["one"], ["two"], ["word " * 3000]])
    (page,) = made.finish()
    assert body([page]) == [[]]
    assert rects(page) == [] and lines_of(page) == []


# Minor 3: a column narrower than one character is refused, never drawn past its edge.


@pytest.mark.parametrize("width", [0.5, 3.0, 8.0])
def test_a_width_narrower_than_one_character_is_refused(width):
    with _within(1.0), pytest.raises(ValueError, match="a width narrower than one character"):
        layout.wrap("WWW", layout.BODY, width)


def test_a_width_of_one_character_holds_one_character():
    assert layout.wrap("WWW", layout.BODY, pdf.width("W", pdf.HELVETICA, 9.5)) == ["W", "W", "W"]


def test_blocks_refuse_a_column_narrower_than_their_text():
    made = composer()
    with pytest.raises(ValueError, match="a width narrower than one character"):
        made.lines("Wide", indent=made.width - 1)
    last = [layout.Column("Sample", 100), layout.Column("W", 2 * layout.CELL_PAD + 1)]
    with pytest.raises(ValueError, match="a width narrower than one character"):
        made.table(last, [["1", "W"]])
    first = [layout.Column("W", 2 * layout.CELL_PAD + 1, right=True)]
    with pytest.raises(ValueError, match="a width narrower than one character"):
        made.table(first, [["W"]])
    (page,) = made.finish()
    assert body([page]) == [[]]


# Minor 4: the bars do not depend on the caller's decimal context.


def test_the_bars_are_the_same_under_any_decimal_context():
    import decimal

    def draw() -> bytes:
        made = composer()
        made.chart(
            [layout.Bar("1", Decimal(1), "1 W"), layout.Bar("3", Decimal(3), "3 W")], height=60
        )
        return made.finish()[0].content

    before = draw()
    with decimal.localcontext(decimal.Context(prec=2)):
        assert draw() == before
    with decimal.localcontext(decimal.Context(traps=[decimal.Inexact])):
        assert draw() == before


# The nits.


def test_room_is_what_the_next_block_gets():
    made = composer()
    full = H - 2 * layout.MARGIN
    assert made.room() == pytest.approx(full)
    made.lines("One.")
    assert made.room() == pytest.approx(full - layout.BODY.leading)
    made.page_break()
    assert made.room() == pytest.approx(full)
    made.heading("Heading")
    assert made.room() == pytest.approx(full - layout.HEADING.leading)
    made.space(10)
    assert made.room() == pytest.approx(full - layout.HEADING.leading - 10)


def test_a_break_with_only_a_heading_after_it_keeps_the_heading_on_the_page_before():
    made = composer()
    made.lines("Page one.")
    made.page_break()
    made.heading("A heading with nothing after it")
    (page,) = made.finish()
    assert [d.text for d in body([page])[0]] == ["Page one.", "A heading with nothing after it"]


def test_a_courier_value_shares_its_labels_baseline():
    made = composer()
    made.rows([layout.Row("Report ID", "sha256:5331136e", mono=True)], label_width=110)
    label, value = body(made.finish())[0]
    assert value.y == pytest.approx(label.y, abs=0.01)


def test_the_cells_of_a_row_share_a_baseline():
    made = composer()
    made.table(
        [layout.Column("ID", 40), layout.Column("Command", 300, mono=True)],
        [["C1", "/usr/bin/sw_vers"], ["C2", "/usr/sbin/system_profiler"]],
    )
    drawn = {d.text: d for d in body(made.finish())[0]}
    assert drawn["C1"].y == pytest.approx(drawn["/usr/bin/sw_vers"].y, abs=0.01)
    assert drawn["C2"].y == pytest.approx(drawn["/usr/sbin/system_profiler"].y, abs=0.01)


def test_the_running_header_needs_its_kept_part():
    with pytest.raises(TypeError):
        layout.Composer(pdf.LETTER, header="h", version="v")  # type: ignore[call-arg]


# The survivors round 2 counted as gaps, pinned.


def test_text_exactly_as_wide_as_its_column_fits():
    for text in ("Apple M5", "aa bb"):
        assert layout.wrap(text, layout.BODY, pdf.width(text, pdf.HELVETICA, 9.5)) == [text]


def test_a_comma_that_starts_a_word_is_not_a_break():
    width = pdf.width(",1234", pdf.HELVETICA, 9.5)
    assert layout.wrap(",1234567890", layout.BODY, width)[0] == ",1234"


def test_a_number_breaks_after_its_first_group():
    width = pdf.width("1,23", pdf.HELVETICA, 9.5)
    assert layout.wrap("1,234,567", layout.BODY, width) == ["1,", "234,", "567"]


@pytest.mark.parametrize("mark", [" ", ",", ";", ":"])
def test_a_shortened_header_never_ends_on_a_mark(mark):
    text = f"Mac Studio{mark}M2 Ultra"
    width = pdf.width(f"Mac Studio{mark}...", pdf.HELVETICA, 7.5) + 0.01
    assert layout._shortened(text, "", layout.SMALL, width) == "Mac Studio..."


@pytest.mark.parametrize("kept", ["abcdefg", "abcdefgh"])
def test_a_shortened_header_keeps_every_character_that_fits(kept):
    width = pdf.width(f"{kept}...", pdf.HELVETICA, 7.5) + 0.01
    assert layout._shortened("abcdefghijklm", "", layout.SMALL, width) == f"{kept}..."


def test_a_kept_part_wider_than_its_room_ends_the_shortening():
    with _within(1.0):
        assert layout._shortened("abc", "KEEP", layout.SMALL, 1.0) == "...KEEP"


def test_two_headings_at_a_pages_top_take_one_space_between_them():
    made = composer()
    made.heading("First")
    made.heading("Second")
    made.lines("Text.")
    first, second, _text = body(made.finish())[0]
    assert first.y == pytest.approx(_base(H - layout.MARGIN, layout.HEADING), abs=0.01)
    assert first.y - second.y == pytest.approx(
        layout.HEADING.leading + layout.HEADING_SPACE, abs=0.01
    )


def test_a_heading_and_a_block_that_fill_a_page_exactly_stay_on_it():
    full = H - 2 * layout.MARGIN
    around = 2 * layout.SMALL.leading + layout.ROW_PAD
    made = composer()
    made.heading("Heading")
    made.chart([layout.Bar("1", Decimal(1), "1 W")], height=full - layout.HEADING.leading - around)
    assert len(made.finish()) == 1


def test_a_block_exactly_a_page_tall_fits_and_one_point_more_is_refused():
    full = H - 2 * layout.MARGIN
    around = 2 * layout.SMALL.leading + layout.ROW_PAD
    made = composer()
    made.chart([layout.Bar("1", Decimal(1), "1 W")], height=full - around)
    assert len(made.finish()) == 1
    with pytest.raises(ValueError, match="a block taller than a page"):
        composer().chart([layout.Bar("1", Decimal(1), "1 W")], height=full - around + 1)


def test_a_chip_is_its_word_and_padding_centered_on_the_first_line():
    made = composer()
    made.rows([layout.Row("Endurance used", "1%", layout.Chip("reported"))], label_width=110)
    (page,) = made.finish()
    (box_,) = [r for r in rects(page) if r[4] == "S"]
    x, y, w, h = box_[:4]
    word = pdf.width("reported", pdf.HELVETICA, layout.CHIP_SIZE)
    assert w == pytest.approx(word + 2 * layout.CHIP_PAD, abs=0.01)
    assert h == pytest.approx(layout.CHIP_HEIGHT, abs=0.01)
    top = H - layout.MARGIN - layout.ROW_PAD
    assert y + h / 2 == pytest.approx(top - layout.BODY.leading / 2, abs=0.01)
    (chip,) = [d for d in body([page])[0] if d.text == "reported"]
    assert chip.x == pytest.approx(x + layout.CHIP_PAD, abs=0.01)
    assert chip.y == pytest.approx(y + (layout.CHIP_HEIGHT - 0.72 * layout.CHIP_SIZE) / 2, abs=0.01)


def test_the_widest_availability_chip_is_drawn():
    made = composer()
    chip = layout.Chip("not applicable", layout.UNAVAILABLE)
    made.rows([layout.Row("Battery", "No battery.", chip)], label_width=110)
    assert "not applicable" in [d.text for d in body(made.finish())[0]]


def test_a_cell_as_wide_as_its_inner_width_is_one_line():
    width = pdf.width("Nominal", pdf.HELVETICA, 9.5) + 2 * layout.CELL_PAD
    made = composer()
    made.table([layout.Column("T", width)], [["Nominal"]])
    assert [d.text for d in body(made.finish())[0]] == ["T", "Nominal"]


def test_a_tables_rows_are_their_lines_and_padding():
    made = composer()
    made.table([layout.Column("Sample", 60)], [["1"], ["2"]])
    (page,) = made.finish()
    top = H - layout.MARGIN
    header = 2 * layout.ROW_PAD + layout.STRONG.leading
    row = 2 * layout.ROW_PAD + layout.BODY.leading
    ys = sorted((y1 for _x1, y1, _x2, _y2 in lines_of(page)), reverse=True)
    assert ys == pytest.approx([top - header - row, top - header - 2 * row], abs=0.01)
    (fill,) = [r for r in rects(page) if r[4] == "f"]
    assert fill[3] == pytest.approx(header, abs=0.01)


def test_a_table_row_that_exactly_fills_the_page_stays_on_it():
    made = composer()
    full = H - 2 * layout.MARGIN
    header = 2 * layout.ROW_PAD + layout.STRONG.leading
    row = 2 * layout.ROW_PAD + layout.BODY.leading
    made.lines("Before.")
    made.space(full - layout.BODY.leading - header - 3 * row)
    made.table([layout.Column("Sample", 60)], [[str(n)] for n in range(1, 5)])
    first, second = body(made.finish())
    assert [d.text for d in first] == ["Before.", "Sample", "1", "2", "3"]
    assert [d.text for d in second] == ["Sample", "4"]


def test_a_chart_of_any_height_above_zero_draws():
    made = composer()
    made.chart([layout.Bar("1", Decimal(1), "1 W")], height=0.5)
    assert [r for r in rects(made.finish()[0]) if r[4] == "f"]


def test_a_zero_bar_beside_a_positive_one_draws_nothing():
    made = composer()
    made.chart(
        [layout.Bar("1", Decimal(0), "0.0 W"), layout.Bar("2", Decimal(5), "5.0 W")], height=60
    )
    assert len([r for r in rects(made.finish()[0]) if r[4] == "f"]) == 1


def test_a_bars_text_wraps_at_its_slot_less_its_padding():
    inside = layout.BAR_SLOT - 2 * layout.BAR_PAD

    def text_of(low: float, high: float) -> str:
        found = "W" * 7
        while pdf.width(found, pdf.HELVETICA, 7.5) <= low:
            found += "i"
        assert pdf.width(found, pdf.HELVETICA, 7.5) <= high
        return found

    for low, high, lines in ((inside - 2, inside, 1), (inside, inside + 3, 2)):
        text = text_of(low, high)
        made = composer()
        made.chart([layout.Bar("1", Decimal(1), text)], height=60)
        drawn = [d for d in body(made.finish())[0] if d.text != "1"]
        assert len(drawn) == lines, (text, lines)


def test_a_bars_text_is_centered_in_its_slot():
    made = composer()
    made.chart([layout.Bar("1", Decimal(1), "2.7 W")], height=60)
    (text,) = [d for d in body(made.finish())[0] if d.text == "2.7 W"]
    assert (text.x + text.right) / 2 == pytest.approx(layout.MARGIN + layout.BAR_SLOT / 2, abs=0.01)


def test_a_missing_bars_text_sits_on_the_rule():
    made = composer()
    made.chart([layout.Bar("1", None, "n/a"), layout.Bar("2", Decimal(1), "1 W")], height=60)
    (page,) = made.finish()
    (rule,) = lines_of(page)
    (text,) = [d for d in body([page])[0] if d.text == "n/a"]
    assert text.y == pytest.approx(_base(rule[1] + layout.SMALL.leading, layout.SMALL), abs=0.01)


def test_the_charts_rule_spans_its_bars_and_the_next_line_follows_it():
    made = composer()
    made.chart([layout.Bar(str(n), Decimal(n), f"{n} W") for n in range(1, 6)], height=60)
    made.lines("After.")
    (page,) = made.finish()
    (rule,) = lines_of(page)
    assert rule[2] - rule[0] == pytest.approx(5 * layout.BAR_SLOT, abs=0.01)
    (after,) = [d for d in body([page])[0] if d.text == "After."]
    top = rule[1] - layout.SMALL.leading - layout.ROW_PAD
    assert after.y == pytest.approx(_base(top, layout.BODY), abs=0.01)


def test_the_header_and_the_footer_sit_on_their_baselines():
    made = composer()
    made.lines("One.")
    made.page_break()
    made.lines("Two.")
    first, second = made.finish()
    top = H - layout.MARGIN
    (header,) = [d for d in texts(second) if d.y > top]
    rise = top + layout.HEADER_RISE + layout.SMALL.leading / 2
    assert header.y == pytest.approx(_base(rise, layout.SMALL), abs=0.01)
    footer = [d for d in texts(first) if d.y < layout.MARGIN]
    drop = layout.MARGIN - layout.FOOTER_DROP + layout.SMALL.leading / 2
    assert [d.y for d in footer] == pytest.approx([_base(drop, layout.SMALL)] * 3, abs=0.01)
    disclaimer = footer[1]
    assert (disclaimer.x + disclaimer.right) / 2 == pytest.approx(W / 2, abs=0.01)


def test_a_header_character_on_a_one_page_report_is_not_counted():
    made = layout.Composer(pdf.LETTER, header="Model " + chr(0x4E09), keep="", version="v")
    made.lines("One.")
    made.finish()
    assert made.replaced == 0


def test_a_header_character_over_two_pages_counts_once_and_the_version_too():
    made = layout.Composer(
        pdf.LETTER, header="Model " + chr(0x4E09), keep="", version="v" + chr(0x4E09)
    )
    made.lines("One.")
    made.page_break()
    made.lines("Two.")
    made.finish()
    assert made.replaced == 2


# --- the review of #351, round 3 ------------------------------------------------------------

# Minor 1: space between two waiting headings stays between them.


def test_space_between_two_waiting_headings_stays_between_them():
    made = composer()
    made.heading("First")
    made.space(30)
    made.heading("Second")
    made.lines("Text.")
    first, second, text = body(made.finish())[0]
    between = layout.HEADING.leading + layout.HEADING_SPACE + 30
    assert first.y - second.y == pytest.approx(between, abs=0.01)
    plain = composer()
    plain.heading("Second")
    plain.lines("Text.")
    second0, text0 = body(plain.finish())[0]
    assert second.y - text.y == pytest.approx(second0.y - text0.y, abs=0.01)


def test_space_after_the_second_waiting_heading_goes_under_the_second():
    made = composer()
    made.heading("First")
    made.heading("Second")
    made.space(30)
    made.lines("Text.")
    first, second, text = body(made.finish())[0]
    plain = composer()
    plain.heading("First")
    plain.heading("Second")
    plain.lines("Text.")
    first0, second0, text0 = body(plain.finish())[0]
    assert first.y - second.y == pytest.approx(first0.y - second0.y, abs=0.01)
    assert second.y - text.y == pytest.approx(second0.y - text0.y + 30, abs=0.01)


# Minor 2: space under a waiting heading gives way at a page's bottom, as any space does.


@pytest.mark.parametrize("amount", [665, 680, 10_000])
def test_space_under_a_waiting_heading_gives_way_like_any_space(amount):
    made = composer()
    made.lines("Before.")
    made.heading("Heading")
    made.space(amount)
    assert made.room() == 0
    made.lines("After.")
    made.rows([layout.Row("Label", "Value")], label_width=110)
    made.chart([layout.Bar("1", Decimal(1), "1 W")], height=40)
    pages = made.finish()
    shown = [d.text for page in body(pages) for d in page]
    assert shown[:3] == ["Before.", "Heading", "After."]
    assert "Label" in shown and "1 W" in shown
    check(pages)


def test_space_under_a_heading_is_cut_to_what_its_page_leaves():
    made = composer()
    made.heading("Heading")
    made.space(10_000)
    made.lines("After.")
    heading, after = body(made.finish())[0]
    bottom = layout.MARGIN + layout.BODY.leading
    assert after.y == pytest.approx(layout._baseline(bottom, layout.BODY), abs=0.01)
    assert heading.y == pytest.approx(layout._baseline(BODY_TOP, layout.HEADING), abs=0.01)


def test_room_counts_the_waiting_headings_and_their_space():
    fresh = composer()
    full = H - 2 * layout.MARGIN
    fresh.heading("Heading")
    # The first heading at a page's top has no space above it.
    assert fresh.room() == pytest.approx(full - layout.HEADING.leading)
    made = composer()
    made.lines("One.")
    made.heading("Heading")
    lead = layout.HEADING_SPACE + layout.HEADING.leading
    assert made.room() == pytest.approx(full - layout.BODY.leading - lead)
    made.space(20)
    assert made.room() == pytest.approx(full - layout.BODY.leading - lead - 20)


# Minor 3: the geometry check sees what is pushed past the body, and the survivors.


def _finished_row() -> list[pdf.Page]:
    made = composer()
    made.rows([layout.Row("Endurance used", "1%", layout.Chip("reported"))], label_width=110)
    return made.finish()


@pytest.mark.parametrize(
    "intruder",
    [
        lambda page: page.text(
            layout.MARGIN,
            41,
            "A row below the body",
            font=pdf.HELVETICA,
            size=9.5,
            color=layout.INK,
        ),
        lambda page: page.line(layout.MARGIN, 37.5, 200, 37.5, color=layout.RULE, width=0.5),
        lambda page: page.rect(300, 38.5, 40, 10, stroke=layout.INK, line_width=0.5),
        lambda page: page.rect(300, 38.5, 40, 10, fill=layout.FILL),
        lambda page: page.text(
            layout.MARGIN, 41, "Small", font=pdf.HELVETICA, size=layout.SMALL.size, color=layout.INK
        ),
    ],
    ids=["text", "rule", "chip box", "fill", "small text"],
)
def test_the_geometry_check_sees_anything_below_the_body(intruder):
    pages = _finished_row()
    check(pages)
    intruder(pages[0])
    with pytest.raises(AssertionError):
        check(pages)


def test_a_heading_and_a_chart_a_point_too_tall_together_are_refused():
    rise = drop = layout.SMALL.leading
    room = H - 2 * layout.MARGIN - layout.HEADING.leading - rise - drop - layout.ROW_PAD
    bars = [layout.Bar("1", Decimal(1), "1 W")]
    made = composer()
    made.heading("Heading")
    with pytest.raises(ValueError, match="a block taller than a page"):
        made.chart(bars, height=room + 1)
    made.chart(bars, height=room)
    pages = made.finish()
    assert len(pages) == 1
    check(pages)


def _chip_word(fits: bool) -> str:
    """The longest word of "i"s a chip holds, or one "i" longer."""
    limit = layout.CHIP_COLUMN - layout.GAP - 2 * layout.CHIP_PAD
    word = "i"
    while pdf.width(word + "i", layout.BODY.font, layout.CHIP_SIZE) <= limit:
        word += "i"
    return word if fits else word + "i"


def test_a_chip_word_is_held_to_its_column_on_either_side_of_the_limit():
    made = composer()
    made.rows([layout.Row("Label", "Value", layout.Chip(_chip_word(True)))], label_width=110)
    check(made.finish())
    with pytest.raises(ValueError, match="a chip word wider than its column"):
        composer().rows(
            [layout.Row("Label", "Value", layout.Chip(_chip_word(False)))], label_width=110
        )


def test_a_later_row_as_tall_as_a_page_less_the_heading_is_drawn():
    full = H - 2 * layout.MARGIN
    text = max(layout.LABEL.leading, layout.BODY.leading)
    count = int((full - 2 * layout.ROW_PAD - text) // layout.NOTE.leading)
    tall = 2 * layout.ROW_PAD + text + count * layout.NOTE.leading
    assert full - layout.HEADING.leading < tall <= full
    made = composer()
    made.heading("Heading")
    made.rows(
        [layout.Row("Short", "x"), layout.Row("Tall", "x", notes=("n",) * count)], label_width=110
    )
    pages = made.finish()
    assert len(pages) == 2
    check(pages)


def test_a_later_table_row_as_tall_as_a_page_less_the_heading_is_drawn():
    full = H - 2 * layout.MARGIN
    header = 2 * layout.ROW_PAD + layout.STRONG.leading
    count = int((full - header - 2 * layout.ROW_PAD) // layout.BODY.leading)
    tall = 2 * layout.ROW_PAD + count * layout.BODY.leading
    assert full - layout.HEADING.leading < header + tall <= full
    made = composer()
    made.heading("Heading")
    made.table([layout.Column("A", 200)], [["short"], [" ".join(["W" * 12] * count)]])
    pages = made.finish()
    assert len(pages) == 2
    check(pages)


def test_columns_that_share_out_the_body_width_are_drawn():
    made = composer()
    shares = (0.1, 0.2, 0.7)
    made.table(
        [layout.Column(str(n), made.width * share) for n, share in enumerate(shares)],
        [["a", "b", "c"]],
    )
    check(made.finish())


# The nits.


@pytest.mark.parametrize("indent", [-40, float("nan")])
def test_an_indent_that_is_negative_or_not_a_number_is_refused(indent):
    with pytest.raises(ValueError, match="an indent that is negative or not a number"):
        composer().lines("Wide words here " * 8, indent=indent)


@pytest.mark.parametrize("call", ["chart", "space"])
def test_a_size_that_is_not_a_number_is_refused_before_anything_is_drawn(call):
    made = composer()
    made.heading("Heading")
    if call == "chart":
        with pytest.raises(ValueError, match="a chart needs bars and a height"):
            made.chart([layout.Bar("1", Decimal(1), "1 W")], height=float("nan"))
    else:
        with pytest.raises(ValueError, match="a space that is negative or not a number"):
            made.space(float("nan"))
    assert made.pages[0].content == b""


# --- the PDF's pages (MAC 3.9d): sources beside headings and above rows, and lists --------


def test_a_heading_carries_its_source_at_the_right_on_its_baseline():
    made = composer()
    made.heading("Storage health and wear", "from macOS's disk profile")
    made.lines("SMART status")
    heading, source, _line = body(made.finish())[0]
    assert (heading.text, source.text) == ("Storage health and wear", "from macOS's disk profile")
    assert (source.font, source.size, source.color) == (
        pdf.HELVETICA,
        8.5,
        operands(layout.CAPTION),
    )
    assert source.y == pytest.approx(heading.y, abs=0.01)
    assert source.right == pytest.approx(W - layout.MARGIN, abs=0.01)


def test_a_source_too_wide_to_sit_beside_its_heading_is_refused():
    made = composer()
    with pytest.raises(ValueError, match="a source wider than the room beside its heading"):
        made.heading("Storage health and wear", "from " + "the disk's own controller " * 8)


def test_a_row_source_sits_above_its_row_at_the_right():
    made = composer()
    made.rows(
        [
            layout.Row("SMART status", "Verified", layout.Chip("reported")),
            layout.Row(
                "Endurance used",
                "1%",
                layout.Chip("reported"),
                source="from the disk's own controller (IOKit)",
            ),
        ],
        label_width=110,
    )
    (page,) = made.finish()
    drawn = {d.text: d for d in body([page])[0]}
    source = drawn["from the disk's own controller (IOKit)"]
    assert (source.font, source.size, source.color) == (
        pdf.HELVETICA,
        8.5,
        operands(layout.CAPTION),
    )
    assert source.right == pytest.approx(W - layout.MARGIN, abs=0.01)
    first_rule = max(y for _x1, y, _x2, _y2 in lines_of(page))
    assert drawn["Endurance used"].y < source.y < first_rule
    assert drawn["Endurance used"].y == pytest.approx(
        drawn["1%"].y, abs=0.01
    ), "the row's value on its label's baseline"
    check([page])


def test_a_row_and_its_source_move_to_the_next_page_together():
    made = composer()
    while made.room() >= 2 * layout.ROW_PAD + layout.BODY.leading + 4:
        made.lines("Filler.")
    made.rows(
        [layout.Row("Charge cycles", "57", layout.Chip("measured"), source="from the gauge")],
        label_width=110,
    )
    first, second = body(made.finish())
    assert all(d.text == "Filler." for d in first)
    assert [d.text for d in second] == ["from the gauge", "Charge cycles", "57", "measured"]


def test_bullets_hang_their_lines_right_of_the_bullet():
    made = composer()
    made.bullets(["Whether the memory has ever had errors. " * 4, "Value or price."])
    drawn = body(made.finish())[0]
    bullets = [d for d in drawn if d.text == layout.BULLET]
    assert len(bullets) == 2
    assert all(d.x == pytest.approx(layout.MARGIN, abs=0.01) for d in bullets)
    lines = [d for d in drawn if d.text != layout.BULLET]
    assert all(d.x == pytest.approx(layout.MARGIN + layout.BULLET_INDENT, abs=0.01) for d in lines)
    assert len(lines) > 2, "the first item wraps"
    assert bullets[0].y == pytest.approx(lines[0].y, abs=0.01)
    assert bullets[1].y == pytest.approx(lines[-1].y, abs=0.01)
    assert all(d.right <= W - layout.MARGIN + 0.01 for d in lines)


def test_a_heading_before_bullets_moves_with_their_first_line():
    made = composer()
    while made.room() >= layout.HEADING_SPACE + layout.HEADING.leading + layout.BODY.leading:
        made.lines("Filler.")
    made.heading("What this report cannot tell you")
    made.bullets(["Value or price."])
    first, second = body(made.finish())
    assert all(d.text == "Filler." for d in first)
    assert [d.text for d in second] == [
        "What this report cannot tell you",
        layout.BULLET,
        "Value or price.",
    ]


@pytest.mark.parametrize("paper", PAPERS, ids=PAPER_IDS)
def test_random_pages_with_sources_and_lists_keep_the_geometry(paper):
    rng = random.Random(3519)  # noqa: S311 - a fixed sample of cases, not a secret
    words = ["Storage", "not reported by macOS", "13.3" + chr(0xA0) + "TB", "W" * 30, "(x)"]
    for _ in range(40):
        made = composer(paper)
        for _ in range(rng.randint(3, 20)):
            kind = rng.choice(["heading", "rows", "bullets", "lines", "break"])
            text = " ".join(rng.choice(words) for _ in range(rng.randint(1, 25)))
            if kind == "heading":
                made.heading(
                    rng.choice(["This Mac", "Battery"]), rng.choice([None, "as macOS reports it"])
                )
            elif kind == "rows":
                made.rows(
                    [
                        layout.Row(
                            text[:20],
                            text,
                            layout.Chip("measured"),
                            source=rng.choice([None, "from the battery's own gauge"]),
                            mono=rng.random() < 0.2,
                        )
                        for _ in range(rng.randint(1, 4))
                    ],
                    label_width=130,
                )
            elif kind == "bullets":
                made.bullets([text, text[:40]])
            elif kind == "lines":
                made.lines(text)
            else:
                made.page_break()
        pages = made.finish()
        check(pages)
        for number, page in enumerate(pages[:-1], start=1):
            found = [d for d in texts(page) if layout.MARGIN <= d.y <= page.size[1] - layout.MARGIN]
            assert found, f"page {number} of {len(pages)} is empty"
            assert found[-1] not in _headings(page), f"a heading ends page {number} alone"


# --- the review of #352, round 1: rows set across the body ---------------------------------------

LINK = "https://github.com/Voltry-tech/voltry-probe/tree/voltry-mac-v0.1.0/packages/voltry-mac"


@pytest.mark.parametrize("paper", PAPERS, ids=PAPER_IDS)
def test_a_wide_row_sets_its_value_under_its_label_across_the_body(paper):
    made = composer(paper)
    made.rows(
        [layout.Row("Source", LINK, mono=True, wide=True), layout.Row("After", "x")],
        label_width=140,
    )
    pages = made.finish()
    check(pages)
    label, value, after, _ = body(pages)[0]
    assert (label.text, value.text) == ("Source", LINK)
    assert value.x == pytest.approx(layout.MARGIN, abs=0.01)
    assert (value.font, value.size) == (pdf.COURIER, 8.5)
    assert label.y - value.y == pytest.approx(
        layout.LABEL.leading + _base(0, layout.LABEL) - _base(0, layout.MONO), abs=0.01
    )
    assert after.text == "After"


def test_a_wide_value_wraps_to_the_whole_body():
    made = composer()
    long = "word " * 60
    made.rows([layout.Row("Label", long.strip(), wide=True)], label_width=140)
    lines = [d for d in body(made.finish())[0] if d.text != "Label"]
    assert len(lines) > 1
    assert max(d.right for d in lines) > layout.MARGIN + made.width - 60
    assert all(d.right <= layout.MARGIN + made.width + 0.01 for d in lines)


# The review of #352, round 2: a link too long for the body, for a version of 16 characters or
# more, breaks only after a slash.
LONG_LINK = (
    "https://github.com/Voltry-tech/voltry-probe/tree/voltry-mac-v1!10.20.30.40rc1.post12"
    ".dev12345/packages/voltry-mac"
)


@pytest.mark.parametrize("paper", PAPERS, ids=PAPER_IDS)
def test_a_wide_value_too_long_for_the_body_breaks_only_after_a_slash(paper):
    made = composer(paper)
    made.rows([layout.Row("Source", LONG_LINK, mono=True, wide=True)], label_width=140)
    pages = made.finish()
    check(pages)
    lines = [d.text for d in body(pages)[0] if d.font is pdf.COURIER]
    assert len(lines) == 2 and "".join(lines) == LONG_LINK
    assert lines[0].endswith("/")


@pytest.mark.parametrize("width", [60, 90, 150])
def test_a_word_breaks_after_the_characters_it_is_given(width):
    word = "aaaa/bbbb/cccc/dddd/eeee"
    found = layout.wrap(word, layout.MONO, width, breaks="/")
    assert "".join(found) == word
    assert all(line.endswith("/") for line in found[:-1])
    assert all(pdf.width(line, pdf.COURIER, 8.5) <= width for line in found)
    # By default a word breaks after a comma, and a slash is an ordinary character.
    plain = layout.wrap(word, layout.MONO, width)
    assert "".join(plain) == word
    # Given only the slash, a comma is an ordinary character.
    numbers = layout.wrap(f"{2**64:,}", layout.BODY, 40, breaks="/")
    assert "".join(numbers) == f"{2**64:,}"
    assert not all(line.endswith(",") for line in numbers[:-1])


# The #352 review, round 3: a word broken after an early comma or slash, whose next piece is
# cut by width, must not be joined back to its first piece with a space it never had.
REJOINED = [
    ("i," + "m" * 60, layout.BODY, ","),
    ("l," + "@" * 60, layout.BODY, ","),
    ("i," + "\u0152" * 31, layout.BODY, ","),
    ("i/" + "W" * 60, layout.BODY, "/"),
    ("i/" + "W" * 60, layout.MONO, "/"),
]


@pytest.mark.parametrize(("word", "style", "breaks"), REJOINED, ids=lambda value: str(value)[:8])
def test_a_word_is_never_joined_to_its_own_pieces_with_a_space(word, style, breaks):
    width = 10.0
    while width <= 400:
        lines = layout.wrap(word, style, width, breaks=breaks)
        assert "".join(lines) == word, (width, lines)
        width += 0.5


def test_a_wide_row_carries_no_chip():
    with pytest.raises(ValueError, match="a wide row with a chip"):
        composer().rows(
            [layout.Row("Label", "Value", layout.Chip("reported"), wide=True)], label_width=140
        )
