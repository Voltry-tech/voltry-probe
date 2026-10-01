"""A small PDF 1.4 writer from the standard library.

docs/VOLTRY_MAC_SPEC.md, Decision 4: a catalog, a page tree, the standard Helvetica,
Helvetica-Bold and Courier as Type1 fonts with WinAnsiEncoding and nothing embedded,
content streams (Flate when asked), an info dictionary, a cross-reference table and a
trailer. Text is measured with the fonts' published AFM widths (metrics.py). The info
dictionary holds the title, the producer and the report's own collection time, and /ID is
the report's SHA-256, so the same pages give the same bytes. Text is WinAnsi, from the
writer's own table of Appendix D of the PDF Reference: a character outside it prints as
"?" and is counted, so a page can say how many it replaced, and what composes into it is
composed first by the character table (characters.py), the same on every Python. Numbers
are written in a fixed decimal context, so no caller's context can change a byte. Pure: it
reads no clock, file, process or network, and returns the document as bytes.
"""

from __future__ import annotations

import re
import zlib
from collections.abc import Sequence
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Context, Decimal, localcontext
from typing import Final

from voltry_mac import characters, metrics

LETTER: Final = (612.0, 792.0)
A4: Final = (595.28, 841.89)
LINE_WIDTH: Final = 0.5


@dataclass(frozen=True)
class Font:
    """A standard font: its resource name on every page, its PostScript name and its
    WinAnsi widths in thousandths of the size."""

    resource: str
    base: str
    widths: tuple[int | None, ...]


HELVETICA: Final = Font("F1", "Helvetica", metrics.HELVETICA)
HELVETICA_BOLD: Final = Font("F2", "Helvetica-Bold", metrics.HELVETICA_BOLD)
COURIER: Final = Font("F3", "Courier", metrics.COURIER)
FONTS: Final = (HELVETICA, HELVETICA_BOLD, COURIER)

# WinAnsiEncoding's characters by code (PDF Reference, Appendix D): ASCII 32 to 126, these
# 27 of the codes 128 to 159, and Latin-1 160 to 255. Two are left out: the soft hyphen,
# which WinAnsi draws as a hyphen though it means nothing visible, and the currency sign,
# which Preview draws as the euro.
_HIGH: Final = {
    0x80: 0x20AC, 0x82: 0x201A, 0x83: 0x0192, 0x84: 0x201E, 0x85: 0x2026, 0x86: 0x2020,
    0x87: 0x2021, 0x88: 0x02C6, 0x89: 0x2030, 0x8A: 0x0160, 0x8B: 0x2039, 0x8C: 0x0152,
    0x8E: 0x017D, 0x91: 0x2018, 0x92: 0x2019, 0x93: 0x201C, 0x94: 0x201D, 0x95: 0x2022,
    0x96: 0x2013, 0x97: 0x2014, 0x98: 0x02DC, 0x99: 0x2122, 0x9A: 0x0161, 0x9B: 0x203A,
    0x9C: 0x0153, 0x9E: 0x017E, 0x9F: 0x0178,
}  # fmt: skip
_LEFT_OUT: Final = frozenset({0xA4, 0xAD})
WINANSI: Final[dict[str, int]] = {
    **{chr(code): code for code in range(32, 127)},
    **{chr(point): code for code, point in _HIGH.items()},
    **{chr(code): code for code in range(160, 256) if code not in _LEFT_OUT},
}

_HEX: Final = re.compile(r"#([0-9A-Fa-f]{2})([0-9A-Fa-f]{2})([0-9A-Fa-f]{2})")
_HUNDREDTH: Final = Decimal("0.01")
_THOUSANDTH: Final = Decimal("0.001")
# Wide enough that nothing here rounds by precision instead of by rule.
_EXACT: Final = Context(prec=60, rounding=ROUND_HALF_UP)
# PDF 1.4, Appendix C: a real number is at most 32,767 in size.
_LIMIT: Final = 32767


def _trimmed(value: Decimal) -> str:
    """A rounded decimal without trailing zeros, and zero never signed."""
    if value.is_zero():
        return "0"
    text = f"{value:f}"
    return text.rstrip("0").rstrip(".") if "." in text else text


def number(value: float) -> str:
    """A coordinate or size as the content stream writes it: at most two decimals, half
    up, from the number's shortest decimal spelling, within PDF 1.4's limits."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError(f"not a number: {value!r}")
    with localcontext(_EXACT):
        exact = Decimal(repr(value))
        if not exact.is_finite() or abs(exact) > _LIMIT:
            raise ValueError(f"not a finite number within PDF 1.4's limits: {value!r}")
        return _trimmed(exact.quantize(_HUNDREDTH, rounding=ROUND_HALF_UP))


@dataclass(frozen=True)
class Color:
    """An sRGB color from 0 to 255 per channel, written as fractions of 1 to three places."""

    red: int
    green: int
    blue: int

    def __post_init__(self) -> None:
        for channel in (self.red, self.green, self.blue):
            if isinstance(channel, bool) or not isinstance(channel, int) or not 0 <= channel <= 255:
                raise ValueError("a color channel is an integer from 0 to 255")

    @classmethod
    def hex(cls, token: str) -> Color:
        found = _HEX.fullmatch(token)
        if found is None:
            raise ValueError(f"not a #RRGGBB color: {token!r}")
        return cls(*(int(channel, 16) for channel in found.groups()))

    def operands(self) -> str:
        with localcontext(_EXACT):
            return " ".join(
                _trimmed((Decimal(c) / 255).quantize(_THOUSANDTH, rounding=ROUND_HALF_UP))
                for c in (self.red, self.green, self.blue)
            )


def encode(text: str) -> tuple[bytes, int]:
    """Text as WinAnsi bytes by the writer's table, and how many characters became "?":
    controls, format characters, anything outside the table, and the two it leaves out.
    A letter and the one combining mark after it, or a character canonically equivalent to
    one in the table, print as that character (characters.composed)."""
    encoded, replaced = bytearray(), 0
    for character in characters.composed(text):
        code = WINANSI.get(character)
        if code is None:
            encoded += b"?"
            replaced += 1
        else:
            encoded.append(code)
    return bytes(encoded), replaced


def _advance(font: Font, code: int) -> int:
    found = font.widths[code - metrics.FIRST]
    assert found is not None  # noqa: S101 - encode() never keeps an undefined code
    return found


def width(text: str, font: Font, size: float) -> float:
    """How wide text prints, in points, as encode() writes it."""
    encoded, _ = encode(text)
    return sum(_advance(font, code) for code in encoded) * size / 1000


def _literal(encoded: bytes) -> bytes:
    """A PDF literal string: parentheses and backslashes escaped, bytes above 127 as
    octal, so the content stream stays ASCII."""
    out = bytearray(b"(")
    for code in encoded:
        if code in b"()\\":
            out += b"\\" + bytes([code])
        elif code > 0x7E:
            out += b"\\%03o" % code
        else:
            out.append(code)
    return bytes(out + b")")


class Page:
    """One page's size and drawing operations, in points from the bottom left."""

    def __init__(self, size: tuple[float, float]) -> None:
        self.size = size
        self.replaced = 0
        self._operations: list[str] = []

    @property
    def content(self) -> bytes:
        return "".join(f"{operation}\n" for operation in self._operations).encode("ascii")

    def text(self, x: float, y: float, text: str, *, font: Font, size: float, color: Color) -> None:
        if font not in FONTS:
            raise ValueError("only the three standard fonts draw")
        # Every operand is checked before anything is drawn or counted.
        start = (
            f"BT /{font.resource} {number(size)} Tf {color.operands()} rg "
            f"{number(x)} {number(y)} Td "
        )
        encoded, replaced = encode(text)
        self._operations.append(f"{start}{_literal(encoded).decode('ascii')} Tj ET")
        self.replaced += replaced

    def rect(
        self,
        x: float,
        y: float,
        w: float,
        h: float,
        *,
        fill: Color | None = None,
        stroke: Color | None = None,
        line_width: float = LINE_WIDTH,
    ) -> None:
        if fill is None and stroke is None:
            raise ValueError("a rectangle is filled, stroked or both")
        paint = []
        if fill is not None:
            paint.append(f"{fill.operands()} rg")
        if stroke is not None:
            paint.append(f"{number(line_width)} w {stroke.operands()} RG")
        operator = "B" if fill and stroke else "f" if fill else "S"
        box = " ".join(number(v) for v in (x, y, w, h))
        self._operations.append(f"{' '.join(paint)} {box} re {operator}")

    def line(
        self, x1: float, y1: float, x2: float, y2: float, *, color: Color, width: float
    ) -> None:
        self._operations.append(
            f"{number(width)} w {color.operands()} RG "
            f"{number(x1)} {number(y1)} m {number(x2)} {number(y2)} l S"
        )


_DATE: Final = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})([+-])(\d{2}):(\d{2})", re.ASCII
)


_PDF_DATE: Final = re.compile(r"D:[0-9]{14}[+-][0-9]{2}'[0-9]{2}'", re.ASCII)
_MONTH_DAYS: Final = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def _days(year: int, month: int) -> int:
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    return 29 if month == 2 and leap else _MONTH_DAYS[month - 1]


def creation_date(local: str) -> str:
    """collected_at_local (2026-09-23T14:05:31-07:00) as a PDF date with its offset."""
    found = _DATE.fullmatch(local)
    if found is None:
        raise ValueError("not a local time with an offset")
    year, month, day, hour, minute, second, sign, hours, minutes = found.groups()
    fields = (int(month), int(day), int(hour), int(minute), int(second), int(hours))
    month_, day_, hour_, minute_, second_, offset_ = fields
    if not (
        1 <= month_ <= 12
        and 1 <= day_ <= _days(int(year), month_)
        and hour_ <= 23
        and minute_ <= 59
        and second_ <= 59
        and offset_ <= 23
        and int(minutes) <= 59
    ):
        raise ValueError("a local time with an impossible date, time or offset")
    return f"D:{year}{month}{day}{hour}{minute}{second}{sign}{hours}'{minutes}'"


def _metadata(text: str) -> bytes:
    if not text.isascii() or not text.isprintable():
        raise ValueError("the document's metadata is printable ASCII")
    return _literal(text.encode("ascii"))


def document(
    pages: Sequence[Page],
    *,
    title: str,
    producer: str,
    created: str,
    identifier: bytes,
    compress: bool,
) -> bytes:
    """The PDF: the catalog (1), the page tree (2), the three fonts (3 to 5), each page and
    its content stream, then the info dictionary; the same arguments give the same bytes."""
    if not pages:
        raise ValueError("a document needs a page")
    if len(identifier) != 32:
        raise ValueError("the identifier is the 32 bytes of a SHA-256")
    if not _PDF_DATE.fullmatch(created):
        raise ValueError("the creation date is a PDF date with its offset")
    info = b" ".join(
        [
            b"<< /Title",
            _metadata(title),
            b"/Producer",
            _metadata(producer),
            b"/CreationDate",
            _metadata(created),
            b">>",
        ]
    )
    first_page = 3 + len(FONTS)
    kids = " ".join(f"{first_page + 2 * index} 0 R" for index in range(len(pages)))
    fonts = " ".join(f"/{font.resource} {3 + index} 0 R" for index, font in enumerate(FONTS))
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>".encode("ascii"),
        *(
            f"<< /Type /Font /Subtype /Type1 /BaseFont /{font.base} "
            f"/Encoding /WinAnsiEncoding >>".encode("ascii")
            for font in FONTS
        ),
    ]
    for index, page in enumerate(pages):
        width_, height = (number(v) for v in page.size)
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {width_} {height}] "
            f"/Resources << /Font << {fonts} >> >> "
            f"/Contents {first_page + 2 * index + 1} 0 R >>".encode("ascii")
        )
        content = page.content
        stream = zlib.compress(content, 9) if compress else content
        flate = " /Filter /FlateDecode" if compress else ""
        objects.append(
            f"<< /Length {len(stream)}{flate} >>\nstream\n".encode("ascii")
            + stream
            + b"\nendstream"
        )
    objects.append(info)
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for number_, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number_} 0 obj\n".encode("ascii") + body + b"\nendobj\n"
    table = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode("ascii") + b"0000000000 65535 f \n"
    out += b"".join(f"{offset:010d} 00000 n \n".encode("ascii") for offset in offsets)
    hexed = identifier.hex().upper()
    out += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R /Info {len(objects)} 0 R "
        f"/ID [<{hexed}> <{hexed}>] >>\nstartxref\n{table}\n%%EOF\n"
    ).encode("ascii")
    return bytes(out)
