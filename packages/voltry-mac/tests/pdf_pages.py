"""Reading the report PDF back, for the PDF's tests: what each page drew, the layout's
geometry check, what the pages were asked to draw, and the documents the sweeps render.

conftest.py registers this module as ``voltry_mac_test_pdf_pages``. The pages are read from
each page's content stream, whose operators the PDF writer's own tests pin, and what
report_pdf asks the layout to draw is recorded as it composes, so a test can say which
row, chip, style or note the PDF carries without parsing geometry. The document sets are
the terminal tests' own (test_terminal.py, loaded once as a module), so the PDF and the
terminal are checked over the same reports.
"""

from __future__ import annotations

import contextlib
import copy
import importlib.util
import re
import sys
import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest

from voltry_mac import canonical, layout, numbers, pdf, registry, report_pdf, validate, wording

TESTS = Path(__file__).resolve().parent
TEXT = re.compile(rb"BT /(F\d) ([\d.]+) Tf ([\d. ]+) rg (-?[\d.]+) (-?[\d.]+) Td \((.*?)\) Tj ET\n")
RECT = re.compile(
    rb"(?:([\d. ]+) rg )?(?:([\d.]+) w ([\d. ]+) RG )?"
    rb"(-?[\d.]+) (-?[\d.]+) (-?[\d.]+) (-?[\d.]+) re ([fSB])\n"
)
LINE = re.compile(rb"([\d.]+) w ([\d. ]+) RG (-?[\d.]+) (-?[\d.]+) m (-?[\d.]+) (-?[\d.]+) l S\n")
FONTS = {b"F1": pdf.HELVETICA, b"F2": pdf.HELVETICA_BOLD, b"F3": pdf.COURIER}
ASCENT, DESCENT = 0.72, 0.21  # Helvetica's cap height and descent, near enough for boxes


def terminal_tests():  # type: ignore[no-untyped-def]
    """test_terminal.py as a module: its document sets and edits, built once."""
    name = "voltry_mac_test_terminal_module"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, TESTS / "test_terminal.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


def templates() -> dict[str, str]:
    return sys.modules["voltry_mac_test_pdf_goldens"].templates()


def _reports():  # type: ignore[no-untyped-def]
    return sys.modules["voltry_mac_test_reports"]


def on(document: dict, paper: str) -> dict:
    """The document on the other paper."""
    document = copy.deepcopy(document)
    document["render"]["paper"] = paper
    return _reports().rehash(document)


# --- the widest legal report -------------------------------------------------------------------

# U+0152 is one of the widest glyphs the pages print (1000 units in Helvetica, W is 944) and,
# above 0x7E in WinAnsi, is written as a four-byte escape: the heaviest character by bytes.
HEAVIEST = "\u0152"
LONGEST = {
    ("tool", "version"): "1!10.20.30.40rc1.post12.dev12345",
    ("tool", "python"): "99.999.999mm999",
    ("time_zone",): "W" * 64,
}


def _valid(document: dict) -> dict | None:
    document = _reports().finish(document)
    try:
        validate.validate(document)
    except canonical.Invalid:
        return None
    return document


def _widest_value(shape: str, name: str, value: object) -> object | None:
    """A value's widest legal form: text at its longest in the heaviest character, a number
    at the top of its range, an array of them; None for a value no wider form fits."""
    if shape == "str":
        return HEAVIEST * registry.MAX_STRING
    if shape == "array of str" and isinstance(value, list):
        return [HEAVIEST * registry.MAX_STRING] * len(value)
    if shape == "u128":
        return str(2**128 - 1)
    if name in registry.INT_RANGES and shape == "int":
        return registry.INT_RANGES[name][1]
    if name in registry.INT_RANGES and shape == "array of int" and isinstance(value, list):
        return [registry.INT_RANGES[name][1]] * len(value)
    return None


def _set(document: dict, key: str, name: str, value: object) -> None:
    entry = _reports().values(document, key).get(name)
    if isinstance(entry, dict) and entry.get("availability") == "available":
        entry["value"] = value


def _warning(document: dict) -> None:
    """A drive that reports every warning: the byte at 255, each flag set to match."""
    _set(document, "smart_health_snapshot", "critical_warning_byte", 255)
    for flag in (
        "spare_below_threshold",
        "temperature_warning",
        "reliability_degraded",
        "read_only_mode",
        "volatile_backup_failed",
        "unknown_warning_bits",
    ):
        _set(document, "smart_health_snapshot", flag, True)


def _chain(document: dict) -> None:
    """The storage counters at 2^128-1 units, with their byte totals."""
    top = 2**128 - 1
    for kind in ("read", "written"):
        _set(document, "smart_wear_attributes", f"data_units_{kind}", str(top))
        bytes_ = str(numbers.data_units_to_bytes(top))
        _set(document, "smart_wear_attributes", f"bytes_{kind}", bytes_)


def _temperatures(document: dict) -> None:
    _set(document, "smart_health_snapshot", "composite_temperature_k", 400)
    _set(
        document, "smart_health_snapshot", "composite_temperature_c", numbers.kelvin_to_celsius(400)
    )
    _set(document, "battery_gauge", "temperature_centi_c", -4000)
    degrees = numbers.canonical(numbers.centi_to_degrees(-4000))
    _set(document, "battery_gauge", "temperature_c", degrees)


def _boot(document: dict) -> None:
    """The earliest boot the registry allows, and its days since."""
    epoch = registry.BOOT_EPOCH_MIN
    at = datetime.strptime(document["collected_at_utc"], "%Y-%m-%dT%H:%M:%SZ")
    instant = int(at.replace(tzinfo=UTC).timestamp())
    _set(document, "boot_time", "boot_epoch_seconds", epoch)
    booted = datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    _set(document, "boot_time", "boot_time_utc", booted)
    _set(document, "boot_time", "days_since_boot", (instant - epoch) // 86400)


POWER_SERIES = {
    "cpu": ["999999.97", "999998.91", "999997.83", "999996.79", "999995.73"],
    "gpu": ["0.01", "0.03", "0.07", "0.09", "0.05"],
    "ane": ["123456.78", "234567.89", "345678.91", "456789.12", "567891.23"],
    "combined": ["999999.99", "999998.93", "999997.87", "999996.81", "999995.77"],
}
THERMAL = ["Trapping", "Sleeping", "Moderate", "Heavy", "Nominal"]


def _power(document: dict) -> None:
    """Each power series at every fraction digit, near the top, with its range and mean,
    and five different thermal states with their counts."""
    key = "power_and_thermal_samples"
    for kind, values in POWER_SERIES.items():
        exact = [Decimal(value) for value in values]
        _set(document, key, f"sample_{kind}_power_mw", values)
        _set(document, key, f"{kind}_power_mw_min", numbers.canonical(min(exact)))
        _set(document, key, f"{kind}_power_mw_max", numbers.canonical(max(exact)))
        _set(document, key, f"{kind}_power_mw_mean", numbers.canonical(numbers.mean(exact)))
    _set(document, key, "sample_thermal_pressure", THERMAL)
    for state in registry.THERMAL_STATES:
        _set(document, key, f"thermal_{state.lower()}_count", THERMAL.count(state))


def _listings(document: dict) -> None:
    for record in document["commands"]:
        if record["id"] == "P1":
            record["runs"] = 4000


def _clear_failed(document: dict) -> None:
    document["elevation"]["cleared"] = "failed"
    document["elevation"]["clear_error"] = "spawn_error"
    for record in document["commands"]:
        if record["id"] == "S5":
            record["failed_runs"] = 1


def _another_renderer(document: dict) -> None:
    """Made by another renderer, so Appendix B carries the note naming both."""
    document["tool"]["renderer_version"] = "9999"


def _one_replaced(document: dict) -> None:
    """One character outside the PDF's set, so Appendix B counts it."""
    entry = _reports().values(document, "gpu_configuration")["metal_family"]
    entry["value"] = entry["value"][:-1] + "\u2603"


# Values the validator ties together, widened together (the #352 review, round 3): each
# edit is kept only if the report stays legal.
JOINT = (
    _warning,
    _chain,
    _temperatures,
    _boot,
    _power,
    _listings,
    _clear_failed,
    _another_renderer,
    _one_replaced,
)


def widest(name: str) -> dict:
    """The fixture at its widest: every value the validator accepts in its widest form (the
    longest text in the heaviest character, the largest number), then the values it ties
    together, widened together (JOINT), every command's time at the largest the schema
    allows, and the longest version, Python and time zone."""
    r = _reports()
    document = r.load(name)
    for spec in registry.SURFACES:
        for value in spec.values:
            entry = r.values(document, spec.key).get(value.name)
            if not isinstance(entry, dict) or entry.get("availability") != "available":
                continue
            wider = _widest_value(value.shape, value.name, entry["value"])
            if wider is None:
                continue
            trial = copy.deepcopy(document)
            r.values(trial, spec.key)[value.name]["value"] = wider
            done = _valid(trial)
            if done is not None:
                document = done
    for edit in JOINT:
        trial = copy.deepcopy(document)
        edit(trial)
        done = _valid(trial)
        if done is not None:
            document = done
    for record in document["commands"]:
        record["duration_ms"] = 2**63 - 1
    for path, text in LONGEST.items():
        target = document
        for step in path[:-1]:
            target = target[step]
        target[path[-1]] = text
    done = _valid(document)
    assert done is not None
    return done


# --- what a page drew ----------------------------------------------------------------------


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


# A stream as pdf.document writes one: its length, and the Flate filter when it is compressed.
_STREAM = re.compile(rb"<< /Length ([0-9]+)( /Filter /FlateDecode)? >>\nstream\n")


def streams(data: bytes) -> list[bytes]:
    """Each content stream of a PDF pdf.document wrote, decompressed when it is compressed
    (Decision 4 allows the Flate filter)."""
    found = []
    for head in _STREAM.finditer(data):
        body = data[head.end() : head.end() + int(head[1])]
        found.append(zlib.decompress(body) if head[2] else body)
    return found


def strings(data: bytes) -> list[str]:
    """Every string a PDF's content streams draw, in drawing order."""
    return [_unescape(found[6]) for stream in streams(data) for found in TEXT.finditer(stream)]


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


def bands(height: float) -> tuple[float, float]:
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
        footer_y, header_y = bands(height)
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
                assert _inside(*box(d), page.size), (number, d)
        for x1, y1, x2, y2 in lines_of(page):
            assert _inside(min(x1, x2), min(y1, y2), max(x1, x2), max(y1, y2), page.size), y1
        for x, y, w, h, _operator, _color, _fill in rects(page):
            assert _inside(x, y, x + w, y + h, page.size), (x, y, w, h)
        for index, first in enumerate(drawn):
            for second in drawn[index + 1 :]:
                assert not _overlap(box(first), box(second)), (number, first, second)
        for x1, y1, x2, _y2 in lines_of(page):
            for d in drawn:
                bx = box(d)
                crosses = bx[1] + 0.01 < y1 < bx[3] - 0.01 and bx[0] < max(x1, x2)
                assert not (crosses and min(x1, x2) < bx[2]), (d, y1)
        for x, y, w, h, operator, _color, _fill in rects(page):
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
        bars = [
            (r[0], r[1], r[0] + r[2], r[1] + r[3])
            for r in rects(page)
            if r[4] == "f" and r[5] == layout.GREEN.operands()
        ]
        for bar in bars:
            for d in drawn:
                assert not _overlap(box(d), bar), (d, "on a bar")
        for index, first in enumerate(bars):
            for second in bars[index + 1 :]:
                assert not _overlap(first, second), "two bars on each other"


def body(page: pdf.Page) -> list[Drawn]:
    """The text inside a page's body box: not the running header or the footer."""
    return [d for d in texts(page) if layout.MARGIN <= d.y <= page.size[1] - layout.MARGIN]


def page_words(page: pdf.Page) -> str:
    """A page's body text in drawing order, joined by spaces, a no-break space read as one."""
    return " ".join(d.text.replace(" ", " ") for d in body(page))


def chips(page: pdf.Page) -> list[tuple[str, str]]:
    """Each chip on a page: its word and its color, from the outlined box holding it."""
    drawn = texts(page)
    found = []
    for x, y, w, h, operator, color, _fill in rects(page):
        if operator != "S" or h != layout.CHIP_HEIGHT:
            continue
        held = [
            d for d in drawn if x <= box(d)[0] and box(d)[2] <= x + w and y <= box(d)[1] <= y + h
        ]
        assert len(held) == 1, held
        assert held[0].color == color, (held[0], color)
        found.append((held[0].text, color or ""))
    return found


# --- what the pages were asked to draw ----------------------------------------------------------


@dataclass
class Asked:
    """One call report_pdf made on the layout: what it was, on which page it ended, and its
    arguments."""

    kind: str
    page: int
    args: tuple[object, ...]
    kwargs: dict[str, object] = field(default_factory=dict)


_ASKED = ("heading", "lines", "bullets", "rows", "table", "chart", "page_break", "space")


@contextlib.contextmanager
def recording() -> Iterator[list[Asked]]:
    """Every layout call report_pdf makes while composing, in order."""
    asked: list[Asked] = []
    originals = {name: getattr(layout.Composer, name) for name in _ASKED}

    def spy(name: str):  # type: ignore[no-untyped-def]
        real = originals[name]

        def call(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            result = real(self, *args, **kwargs)
            asked.append(Asked(name, len(self.pages), args, kwargs))
            return result

        return call

    patch = pytest.MonkeyPatch()
    try:
        for name in _ASKED:
            patch.setattr(layout.Composer, name, spy(name))
        yield asked
    finally:
        patch.undo()


def composed(document: dict, **options) -> tuple[layout.Composer, list[Asked]]:
    """The composed pages of a validated document and what they were asked to draw; the
    PDF is only ever drawn from a report the validator accepts."""
    validate.validate(document)
    options.setdefault("templates", templates())
    chosen = options.pop("templates")
    with recording() as asked:
        made = report_pdf.compose(document, chosen, **options)
    return made, asked


def all_rows(asked: list[Asked]) -> list[layout.Row]:
    return [row for call in asked if call.kind == "rows" for row in call.args[0]]


def sections(asked: list[Asked]) -> dict[str, list[Asked]]:
    """The calls under each heading, by the heading's text."""
    found: dict[str, list[Asked]] = {}
    current: list[Asked] | None = None
    for call in asked:
        if call.kind == "heading":
            current = found.setdefault(str(call.args[0]), [])
            continue
        if current is not None:
            current.append(call)
    return found


def section_rows(asked: list[Asked], heading: str) -> list[layout.Row]:
    return [row for call in sections(asked)[heading] if call.kind == "rows" for row in call.args[0]]


def notes(asked: list[Asked], heading: str) -> list[str]:
    return [
        str(call.args[0])
        for call in sections(asked)[heading]
        if call.kind == "lines" and len(call.args) > 1 and call.args[1] is layout.NOTE
    ]
