"""The PDF's page layout: the page setup, word wrap, rows, tables, the bar chart, and the
running header and footer.

docs/VOLTRY_MAC_SPEC.md, "Report outline and PDF layout" (page setup) and Decision 4 (the
writer's layout scope). 18 mm margins; body Helvetica 9.5 pt on 13 pt leading; headings
Helvetica-Bold 12 pt; commands and IDs Courier 8.5 pt; the spec's colors. Text wraps by the
fonts' AFM widths, breaking at spaces, so a no-break space keeps a number with its unit; a
word wider than its line breaks after a comma, or after a slash in a wide row, and by width
only where it has neither. A key-value row sets its label, its value and a label chip, a
small outlined box carrying its word, so color is never the only signal; a source line
naming where rows come from sits at the right, beside a heading or above the row it names.
A list sets a bullet beside each item's first line. A table wraps its cells and repeats its
header row on each page it continues to. A heading waits for the block after it and is
drawn with that block's first line, row or header, so it never ends a page alone; a row, a
table row and the chart never split across pages; a page break takes effect only when
something follows it. A block is measured whole before anything of it is drawn, so one
that cannot be set leaves nothing behind. From page 2 a running header names the report,
its report ID always whole, and every page's footer gives the tool version, the disclaimer
and page X of Y. Pure: pdf.py draws, and nothing here reads a clock, a file, a process or
the network, and no caller's decimal context changes a byte.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Context, Decimal, localcontext
from typing import Final

from voltry_mac import pdf, wording

MARGIN: Final = 18 * 72 / 25.4
INK: Final = pdf.Color.hex("#15171A")
CAPTION: Final = pdf.Color.hex("#5D6166")
RULE: Final = pdf.Color.hex("#D7DAD4")
FILL: Final = pdf.Color.hex("#EBEDE8")
GREEN: Final = pdf.Color.hex("#16633F")
UNAVAILABLE: Final = pdf.Color.hex("#C2602F")


@dataclass(frozen=True)
class Style:
    font: pdf.Font
    size: float
    leading: float
    color: pdf.Color


BODY: Final = Style(pdf.HELVETICA, 9.5, 13, INK)
STRONG: Final = Style(pdf.HELVETICA_BOLD, 9.5, 13, INK)
LABEL: Final = Style(pdf.HELVETICA, 9.5, 13, CAPTION)
HEADING: Final = Style(pdf.HELVETICA_BOLD, 12, 18, GREEN)
MONO: Final = Style(pdf.COURIER, 8.5, 12, INK)
NOTE: Final = Style(pdf.HELVETICA, 8.5, 11.5, CAPTION)
SMALL: Final = Style(pdf.HELVETICA, 7.5, 10, CAPTION)

GAP: Final = 6.0  # between a label and its value
ROW_PAD: Final = 3.0  # above and below a row's text
CELL_PAD: Final = 4.0  # each side of a table cell's text
RULE_WIDTH: Final = 0.5
CHIP_SIZE: Final = 7.0
CHIP_PAD: Final = 3.0
CHIP_HEIGHT: Final = 10.0
CHIP_COLUMN: Final = 60.0  # the chip column at the right of a row
BAR_SLOT: Final = 60.0
BAR_PAD: Final = 2.0  # each side of a bar's text in its slot
BAR_LINES: Final = 2  # the most lines a bar's text or label may take
HEADER_RISE: Final = 14.0  # the running header's baseline above the body
FOOTER_DROP: Final = 18.0  # the footer's baseline below the body
FOOTER_GAP: Final = 6.0  # the least space between the footer's three parts
HEADING_SPACE: Final = BODY.leading / 2  # above a heading, dropped at a page's top
BULLET: Final = "\u2022"
BULLET_INDENT: Final = 12.0  # an item's text, right of its bullet
EPSILON: Final = 1e-6  # so a block exactly the room left fits
_ELLIPSIS: Final = "..."
_EXACT: Final = Context(prec=60, rounding=ROUND_HALF_UP)


def _fits(text: str, style: Style, width: float) -> bool:
    return pdf.width(text, style.font, style.size) <= width


def _pieces(word: str, style: Style, width: float, breaks: str) -> list[str]:
    """A word wider than width in whole pieces: each as wide as fits, and at least one
    character, ending after the last of the breaks characters in it when there is one, so a
    number breaks only between its thousands groups (a comma) and a link only between its
    parts (a slash)."""
    pieces = []
    while not _fits(word, style, width):
        if not _fits(word[:1], style, width):
            raise ValueError("a width narrower than one character")
        end = 1
        while end < len(word) and _fits(word[: end + 1], style, width):
            end += 1
        after = max((word.rfind(each, 0, end) for each in breaks), default=-1)
        end = after + 1 if after > 0 else end
        pieces.append(word[:end])
        word = word[end:]
    return [*pieces, word]


def wrap(text: str, style: Style, width: float, *, breaks: str = ",") -> list[str]:
    """Greedy lines no wider than width, by the AFM widths. Lines break at spaces (U+0020),
    which collapse, and a word wider than a line breaks after one of the breaks characters
    when it holds one: any other character, a no-break space or whitespace outside WinAnsi
    included, stays inside its word, where it prints as itself or as a counted "?". A width
    that holds nothing, or not one character of a word, is refused."""
    if width <= 0:
        raise ValueError("a width that holds nothing")
    lines: list[str] = []
    for word in (word for word in text.split(" ") if word):
        for index, piece in enumerate(_pieces(word, style, width, breaks)):
            # Only a word's first piece may join the line before it: the rest of the word
            # starts new lines, so no space ever comes between a word's own pieces.
            if index == 0 and lines and _fits(f"{lines[-1]} {piece}", style, width):
                lines[-1] += f" {piece}"
            else:
                lines.append(piece)
    return lines or [""]


def _shortened(text: str, keep: str, style: Style, width: float) -> str:
    """text, then keep, within width: text cut at the last character that lets it fit,
    ending with an ellipsis, and keep always whole. keep carries its own separator
    (", ID 5331136e3e93"), since the cut drops one at the text's end."""
    if _fits(text + keep, style, width):
        return text + keep
    cut = len(text)
    while cut > 0 and not _fits(text[:cut].rstrip(" ,;:") + _ELLIPSIS + keep, style, width):
        cut -= 1
    return text[:cut].rstrip(" ,;:") + _ELLIPSIS + keep


@dataclass(frozen=True)
class Chip:
    """A label chip: a provenance word in ink, or an availability word in its own color."""

    word: str
    color: pdf.Color = INK


@dataclass(frozen=True)
class Row:
    """A key-value row; ``mono`` sets the value in Courier, for codes, IDs and commands,
    ``source`` names where it and the rows after it come from, above it at the right, and
    ``wide`` sets the value under its label across the whole body, for a link or an ID that
    must stay on one line, and breaks one too long for it only after a slash; a wide row
    carries no chip."""

    label: str
    text: str
    chip: Chip | None = None
    notes: tuple[str, ...] = ()
    mono: bool = False
    source: str | None = None
    wide: bool = False


@dataclass(frozen=True)
class Column:
    """A table column; ``right`` aligns its cells right, and ``mono`` sets them in Courier."""

    title: str
    width: float
    right: bool = False
    mono: bool = False


@dataclass(frozen=True)
class Bar:
    """One bar: its label below, its value (None when there is none), its text above."""

    label: str
    value: Decimal | None
    text: str


def _baseline(top: float, style: Style) -> float:
    """The baseline of a line whose box starts at top, the text centered in its leading."""
    return top - (style.leading + 0.51 * style.size) / 2


def _aligned(top: float, style: Style, first: Style) -> float:
    """The top that gives a line in style the baseline a line in first has at top, so a
    Courier value or cell sits on its row's baseline."""
    return top + _baseline(top, first) - _baseline(top, style)


class Composer:
    """Places blocks down the pages of one paper size, top to bottom."""

    def __init__(self, paper: tuple[float, float], *, header: str, keep: str, version: str) -> None:
        self.paper = paper
        self.width = paper[0] - 2 * MARGIN
        self.pages: list[pdf.Page] = []
        self._header = header
        self._keep = keep
        self._version = version
        self._finished = False
        self._break = False  # a page break waiting for something to follow it
        # Headings waiting for their block: each one's lines, the source beside it, and the
        # space asked for under it.
        self._pending: list[tuple[list[str], str | None, float]] = []
        self._replaced: int | None = None
        self._new_page()

    # --- the cursor --------------------------------------------------------------------------

    @property
    def _top(self) -> float:
        return self.paper[1] - MARGIN

    def _new_page(self) -> None:
        self.pages.append(pdf.Page(self.paper))
        self.y = self._top

    def _open(self) -> pdf.Page:
        if self._finished:
            raise RuntimeError("the pages are finished")
        return self.pages[-1]

    def _left(self) -> float:
        """The height left on this page's body."""
        return self.y - MARGIN

    def _breaking(self) -> bool:
        """Whether a page break waits: the next block opens a page."""
        return self._break and self.y < self._top

    def room(self) -> float:
        """The height the next block has: on this page, or on the next when a page break
        waits, below the headings waiting for it and the space asked for under them, that
        space cut to what the page leaves."""
        if self._breaking():
            left, at_top = self._top - MARGIN, True
        else:
            left, at_top = self._left(), self.y >= self._top
        return max(left - self._lead(at_top) - self._wanted(), 0.0)

    def _lead(self, at_top: bool) -> float:
        """The height the waiting headings take, each with its space above it but the
        first at a page's top."""
        spaces = len(self._pending) - (1 if at_top and self._pending else 0)
        lines = sum(len(heading) for heading, _, _ in self._pending)
        return spaces * HEADING_SPACE + lines * HEADING.leading

    def _wanted(self) -> float:
        """The space asked for under the waiting headings."""
        return sum(under for _, _, under in self._pending)

    def _refuse_taller(self, height: float, *, lead: bool = True) -> None:
        """Refuse a unit taller than a fresh page, with the waiting headings when lead; the
        space under them gives way instead (_fit)."""
        if (self._lead(True) if lead else 0.0) + height > self._top - MARGIN + EPSILON:
            raise ValueError("a block taller than a page")

    def _fit(self, height: float) -> pdf.Page:
        """The page for a block's first unit of this height: this one, or a new one when
        it, the waiting headings and the space under them do not fit here. The headings are
        drawn first, each with its space under it cut to what the page leaves, as space()
        is at a page's bottom. A unit no page could hold is refused before any page opens."""
        self._open()
        self._refuse_taller(height)
        if self._breaking():
            self._new_page()
        self._break = False
        at_top = self.y >= self._top
        if not at_top and self._lead(False) + self._wanted() + height > self._left() + EPSILON:
            self._new_page()
            at_top = True
        page = self.pages[-1]
        spare = self._left() - self._lead(at_top) - height
        for heading, source, under in self._pending:
            if self.y < self._top:
                self.y -= HEADING_SPACE
            for line in heading:
                self._line(page, MARGIN, self.y, line, HEADING)
                self.y -= HEADING.leading
            if source is not None:
                # On the heading's last baseline, at the right.
                right = MARGIN + self.width - pdf.width(source, NOTE.font, NOTE.size)
                base = _baseline(self.y + HEADING.leading, HEADING)
                page.text(right, base, source, font=NOTE.font, size=NOTE.size, color=NOTE.color)
            given = min(under, max(spare, 0.0))
            self.y -= given
            spare -= given
        self._pending = []
        return page

    def page_break(self) -> None:
        """Start a new page for whatever comes next, unless this one is still empty."""
        self._open()
        self._break = self.y < self._top

    def space(self, height: float) -> None:
        """Vertical space, dropped at the top of a page and clamped at its bottom; asked
        for while a heading waits, it goes under that heading, with its block, and gives
        way at the bottom of the page they are drawn on."""
        self._open()
        if not height >= 0:
            raise ValueError("a space that is negative or not a number")
        if self._pending:
            heading, source, under = self._pending[-1]
            self._pending[-1] = (heading, source, under + height)
        elif self.y < self._top:
            self.y = max(self.y - height, MARGIN)

    # --- text --------------------------------------------------------------------------------

    def _line(self, page: pdf.Page, x: float, top: float, text: str, style: Style) -> None:
        page.text(
            x, _baseline(top, style), text, font=style.font, size=style.size, color=style.color
        )

    def lines(self, text: str, style: Style = BODY, *, indent: float = 0) -> None:
        """A paragraph, wrapped to the body less indent, flowing onto new pages."""
        self._open()
        if not indent >= 0:
            raise ValueError("an indent that is negative or not a number")
        for line in wrap(text, style, self.width - indent):
            page = self._fit(style.leading)
            self._line(page, MARGIN + indent, self.y, line, style)
            self.y -= style.leading

    def heading(self, text: str, source: str | None = None) -> None:
        """A heading, drawn with the first unit of the block after it; a source line beside
        its last line, at the right, names where the section's rows come from."""
        self._open()
        lines = wrap(text, HEADING, self.width)
        if source is not None:
            beside = self.width - pdf.width(lines[-1], HEADING.font, HEADING.size) - GAP
            if pdf.width(source, NOTE.font, NOTE.size) > beside:
                raise ValueError("a source wider than the room beside its heading")
        self._pending.append((lines, source, 0.0))

    def bullets(self, items: Sequence[str], style: Style = BODY) -> None:
        """A list: each item wrapped right of its bullet, the bullet beside its first line;
        an item's lines may flow onto a new page, as a paragraph's do."""
        self._open()
        for item in items:
            for index, line in enumerate(wrap(item, style, self.width - BULLET_INDENT)):
                page = self._fit(style.leading)
                if index == 0:
                    self._line(page, MARGIN, self.y, BULLET, style)
                self._line(page, MARGIN + BULLET_INDENT, self.y, line, style)
                self.y -= style.leading

    def _rule(self, page: pdf.Page, y: float, width: float | None = None) -> None:
        right = MARGIN + (self.width if width is None else width)
        page.line(MARGIN, y, right, y, color=RULE, width=RULE_WIDTH)

    # --- rows ----------------------------------------------------------------------------------

    def _chip(self, page: pdf.Page, chip: Chip, top: float) -> None:
        wide = pdf.width(chip.word, BODY.font, CHIP_SIZE) + 2 * CHIP_PAD
        x = MARGIN + self.width - wide
        y = top - BODY.leading / 2 - CHIP_HEIGHT / 2
        page.rect(x, y, wide, CHIP_HEIGHT, stroke=chip.color, line_width=RULE_WIDTH)
        page.text(
            x + CHIP_PAD,
            y + (CHIP_HEIGHT - 0.72 * CHIP_SIZE) / 2,
            chip.word,
            font=BODY.font,
            size=CHIP_SIZE,
            color=chip.color,
        )

    def rows(self, rows: Sequence[Row], *, label_width: float) -> None:
        """Key-value rows: a source line when a row has one, then the label, the value
        wrapped in its column, the chip at the right of the first line, notes under the
        value, and a rule under each row. Every row is measured before any is drawn, so a row
        that cannot be set draws nothing."""
        self._open()
        value_x = MARGIN + label_width
        value_width = self.width - label_width - CHIP_COLUMN
        if label_width <= GAP or value_width <= 0:
            raise ValueError("a row with no room for its label or its value")
        laid: list[tuple[Row, Style, list[str], list[str], list[str], list[str], float, float]] = []
        for row in rows:
            chip_wide = 0.0 if row.chip is None else pdf.width(row.chip.word, BODY.font, CHIP_SIZE)
            if chip_wide + 2 * CHIP_PAD > CHIP_COLUMN - GAP:
                raise ValueError("a chip word wider than its column")
            if row.wide and row.chip is not None:
                raise ValueError("a wide row with a chip")
            style = MONO if row.mono else BODY
            across = self.width if row.wide else value_width
            labels = wrap(row.label, LABEL, self.width if row.wide else label_width - GAP)
            values = wrap(row.text, style, across, breaks="/" if row.wide else ",")
            notes = [line for note in row.notes for line in wrap(note, NOTE, across)]
            sources = [] if row.source is None else wrap(row.source, NOTE, self.width)
            text = (
                len(labels) * LABEL.leading + len(values) * style.leading
                if row.wide
                else max(len(labels) * LABEL.leading, len(values) * style.leading)
            )
            above = len(sources) * NOTE.leading
            height = 2 * ROW_PAD + above + text + len(notes) * NOTE.leading
            self._refuse_taller(height, lead=not laid)
            laid.append((row, style, labels, values, notes, sources, text, height))
        for row, style, labels, values, notes, sources, text, height in laid:
            page = self._fit(height)
            top = self.y - ROW_PAD
            for index, line in enumerate(sources):
                right = MARGIN + self.width - pdf.width(line, NOTE.font, NOTE.size)
                self._line(page, right, top - index * NOTE.leading, line, NOTE)
            top -= len(sources) * NOTE.leading
            for index, line in enumerate(labels):
                self._line(page, MARGIN, top - index * LABEL.leading, line, LABEL)
            # A wide row's value starts under its label, at the margin.
            x, first = value_x, _aligned(top, style, LABEL)
            if row.wide:
                x, first = MARGIN, top - len(labels) * LABEL.leading
            for index, line in enumerate(values):
                self._line(page, x, first - index * style.leading, line, style)
            if row.chip is not None:
                self._chip(page, row.chip, top)
            for index, line in enumerate(notes):
                self._line(page, x, top - text - index * NOTE.leading, line, NOTE)
            self.y -= height
            self._rule(page, self.y)

    # --- tables --------------------------------------------------------------------------------

    def _cells(
        self,
        page: pdf.Page,
        columns: Sequence[Column],
        cells: Sequence[list[str]],
        style_of: Callable[[Column], Style],
    ) -> None:
        x, top = MARGIN, self.y - ROW_PAD
        for column, lines in zip(columns, cells, strict=True):
            style = style_of(column)
            first = _aligned(top, style, BODY)
            for index, line in enumerate(lines):
                left = x + CELL_PAD
                if column.right:
                    left = x + column.width - CELL_PAD - pdf.width(line, style.font, style.size)
                self._line(page, left, first - index * style.leading, line, style)
            x += column.width

    def table(self, columns: Sequence[Column], rows: Sequence[Sequence[str]]) -> None:
        """A table: a filled header row, then rows of wrapped cells with a rule under each;
        the header repeats at the top of each page the table continues to."""
        self._open()
        wide = sum(column.width for column in columns)
        if wide > self.width + EPSILON:
            raise ValueError("a table wider than the body")
        if any(len(row) != len(columns) for row in rows):
            raise ValueError("a row with a cell for each column")

        def header_style(_column: Column) -> Style:
            return STRONG

        def cell_style(column: Column) -> Style:
            return MONO if column.mono else BODY

        def wrapped(texts: Sequence[str], style_of: Callable[[Column], Style]) -> list[list[str]]:
            return [
                wrap(text, style_of(column), column.width - 2 * CELL_PAD)
                for column, text in zip(columns, texts, strict=True)
            ]

        def height_of(cells: list[list[str]], style_of: Callable[[Column], Style]) -> float:
            tallest = max(
                len(lines) * style_of(column).leading
                for column, lines in zip(columns, cells, strict=True)
            )
            return 2 * ROW_PAD + tallest

        header = wrapped([column.title for column in columns], header_style)
        header_height = height_of(header, header_style)
        body = [wrapped(row, cell_style) for row in rows]
        heights = [height_of(cells, cell_style) for cells in body]
        # Every row, with the header it repeats under, fits a page, before anything draws.
        for index, height in enumerate(heights or [0.0]):
            self._refuse_taller(header_height + height, lead=index == 0)

        def draw_header(page: pdf.Page) -> None:
            page.rect(MARGIN, self.y - header_height, wide, header_height, fill=FILL)
            self._cells(page, columns, header, header_style)
            self.y -= header_height

        page = self._fit(header_height + (heights[0] if heights else 0))
        draw_header(page)
        for cells, height in zip(body, heights, strict=True):
            if height > self._left() + EPSILON:
                page = self._fit(header_height + height)
                draw_header(page)
            self._cells(page, columns, cells, cell_style)
            self.y -= height
            self._rule(page, self.y, wide)

    # --- the chart -----------------------------------------------------------------------------

    def chart(self, bars: Sequence[Bar], *, height: float) -> None:
        """Vertical bars scaled to the largest value, each with its text above and its
        label below, each wrapped to its slot in at most two lines, on a rule; a bar with no
        value, or none above zero, is not drawn."""
        self._open()
        if not bars or not height > 0:
            raise ValueError("a chart needs bars and a height")
        if len(bars) * BAR_SLOT > self.width + EPSILON:
            raise ValueError("more bars than the body holds")
        inside = BAR_SLOT - 2 * BAR_PAD
        above = [wrap(bar.text, SMALL, inside) for bar in bars]
        below = [wrap(bar.label, SMALL, inside) for bar in bars]
        if any(len(lines) > BAR_LINES for lines in above + below):
            raise ValueError("a bar's text or label past two lines")
        rise = max(map(len, above)) * SMALL.leading
        drop = max(map(len, below)) * SMALL.leading
        page = self._fit(rise + height + drop + ROW_PAD)
        peak = max((bar.value for bar in bars if bar.value is not None), default=Decimal(0))
        floor = self.y - rise - height
        for index, bar in enumerate(bars):
            left = MARGIN + index * BAR_SLOT
            tall = 0.0
            if bar.value is not None and bar.value > 0 and peak > 0:
                with localcontext(_EXACT):
                    tall = float(bar.value / peak) * height
                page.rect(left + BAR_SLOT / 4, floor, BAR_SLOT / 2, tall, fill=GREEN)
            first = floor + tall + len(above[index]) * SMALL.leading
            for lines, top in ((above[index], first), (below[index], floor)):
                for number, line in enumerate(lines):
                    shift = (BAR_SLOT - pdf.width(line, SMALL.font, SMALL.size)) / 2
                    self._line(page, left + shift, top - number * SMALL.leading, line, SMALL)
        self._rule(page, floor, BAR_SLOT * len(bars))
        self.y = floor - drop - ROW_PAD

    # --- the header, the footer and the end ----------------------------------------------------

    @property
    def replaced(self) -> int:
        """Characters outside WinAnsi drawn as "?": each in the body once per time it is
        drawn, and the running header's and the footer's once, however many pages repeat
        them."""
        if self._replaced is not None:
            return self._replaced
        return sum(page.replaced for page in self.pages)

    def finish(self) -> list[pdf.Page]:
        """The pages, each with its footer, and from page 2 the running header. A heading
        still waiting is drawn; a page break still waiting is dropped."""
        self._open()
        if self._pending:
            self._break = False
            self._fit(0.0)
        self._finished = True
        body = sum(page.replaced for page in self.pages)
        total = len(self.pages)
        header = _shortened(self._header, self._keep, SMALL, self.width)
        disclaimer = pdf.width(wording.DISCLAIMER, SMALL.font, SMALL.size)
        middle = (self.width - disclaimer) / 2
        version = _shortened(self._version, "", SMALL, middle - FOOTER_GAP)
        for number, page in enumerate(self.pages, start=1):
            if number > 1:
                top = self._top + HEADER_RISE + SMALL.leading / 2
                self._line(page, MARGIN, top, header, SMALL)
            base = MARGIN - FOOTER_DROP + SMALL.leading / 2
            count = f"Page {number} of {total}"
            right = self.width - pdf.width(count, SMALL.font, SMALL.size)
            for x, text in ((0.0, version), (middle, wording.DISCLAIMER), (right, count)):
                self._line(page, MARGIN + x, base, text, SMALL)
        once = (pdf.encode(header)[1] if total > 1 else 0) + pdf.encode(version)[1]
        self._replaced = body + once
        return list(self.pages)
