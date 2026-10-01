"""The PDF writer (docs/VOLTRY_MAC_SPEC.md, Decision 4: the writer's scope, reproducibility,
and the WinAnsi limit; Test strategy part 4).

A small PDF 1.4 writer from the standard library: a catalog, a page tree, the standard
Helvetica, Helvetica-Bold and Courier as Type1 fonts with WinAnsiEncoding and nothing
embedded, content streams, an info dictionary, a cross-reference table and a trailer.
Text is measured with the fonts' published AFM widths. The same pages give the same bytes.
Its output is read back here with pypdf, a test-only dependency, as an independent parser.
"""

from __future__ import annotations

import decimal
import hashlib
import io
import re
import unicodedata
import zlib
from decimal import Decimal
from pathlib import Path

import pytest
from pypdf import PdfReader
from pypdf._codecs.core_font_metrics import CORE_FONT_METRICS

from voltry_mac import metrics, pdf

INK = pdf.Color.hex("#15171A")
GREEN = pdf.Color.hex("#16633F")
IDENTIFIER = bytes.fromhex("5331136e3e932f1cdfa6d2ebccea18d34bb6eed15b3eac3fad5dc648e161d557")
CREATED = "D:20260923140531-07'00'"


def sample(size: tuple[float, float] = pdf.LETTER, pages: int = 2) -> list[pdf.Page]:
    found = []
    for number in range(1, pages + 1):
        page = pdf.Page(size)
        page.text(
            51.02,
            740,
            "Mac hardware observation report",
            font=pdf.HELVETICA_BOLD,
            size=12,
            color=GREEN,
        )
        page.text(
            51.02, 720, f"Page {number}: 23 (°C) \\ done", font=pdf.HELVETICA, size=9.5, color=INK
        )
        page.text(51.02, 700, "/usr/bin/sqlite3 -readonly", font=pdf.COURIER, size=8.5, color=INK)
        page.rect(51.02, 680, 40, 10, stroke=INK, line_width=0.5)
        page.rect(51.02, 660, 100, 12, fill=pdf.Color.hex("#EBEDE8"))
        page.line(51.02, 650, 560.98, 650, color=pdf.Color.hex("#D7DAD4"), width=0.5)
        found.append(page)
    return found


def write(pages: list[pdf.Page] | None = None, *, compress: bool = False) -> bytes:
    return pdf.document(
        pages if pages is not None else sample(),
        title="Mac hardware observation report",
        producer="voltry-mac 0.1.0",
        created=CREATED,
        identifier=IDENTIFIER,
        compress=compress,
    )


def reader(data: bytes) -> PdfReader:
    return PdfReader(io.BytesIO(data), strict=True)


# --- the widths --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("table", "font"),
    [
        (metrics.HELVETICA, "Helvetica"),
        (metrics.HELVETICA_BOLD, "Helvetica-Bold"),
        (metrics.COURIER, "Courier"),
    ],
)
def test_the_widths_are_adobes_as_pypdf_carries_them(table, font):
    # pypdf's copy of the Core 14 AFM data is keyed by character; WinAnsi's 160 and 173 draw
    # the space and hyphen glyphs, which it keys only as those characters.
    theirs = CORE_FONT_METRICS[font].character_widths
    assert len(table) == 224
    for code, width in enumerate(table, start=metrics.FIRST):
        if code in metrics.UNDEFINED:
            assert width is None
            continue
        character = {160: " ", 173: "-"}.get(code, bytes([code]).decode("cp1252"))
        assert width == theirs[character], (font, code)


def test_courier_is_fixed_pitch():
    assert {w for w in metrics.COURIER if w is not None} == {600}


def test_the_adobe_notices_are_kept_unmodified():
    source = Path(metrics.__file__).read_text()
    for notice in (
        "Copyright (c) 1985, 1987, 1989, 1990, 1997 Adobe\nSystems Incorporated.",
        "Copyright (c) 1989, 1990, 1991, 1992, 1993, 1997 Adobe Systems Incorporated.",
        "Helvetica is a trademark of Linotype-Hell AG",
        "This file and the 14 PostScript(R) AFM files it accompanies may be used, copied, and\n"
        "distributed for any purpose and without charge, with or without modification, provided "
        "that\nall copyright notices are retained;",
        "Adobe Systems has no\nresponsibility or obligation to support the use of the AFM files.",
    ):
        assert notice in source, notice
    # The ReadMe's paragraph, which it says may not be modified, whole.
    readme = (
        "This file and the 14 PostScript(R) AFM files it accompanies may be used, copied, and "
        "distributed for any purpose and without charge, with or without modification, provided "
        "that all copyright notices are retained; that the AFM files are not distributed "
        "without this file; that all modifications to this file or any of the AFM files are "
        "prominently noted in the modified file(s); and that this paragraph is not modified. "
        "Adobe Systems has no responsibility or obligation to support the use of the AFM files."
    )
    assert readme in " ".join(source.split())


@pytest.mark.parametrize(
    ("text", "font", "size", "points"),
    [
        ("Hello", pdf.HELVETICA, 10, 22.78),
        ("W", pdf.HELVETICA, 10, 9.44),
        ("W", pdf.HELVETICA_BOLD, 10, 9.44),
        ("i", pdf.HELVETICA_BOLD, 10, 2.78),
        ("any text!", pdf.COURIER, 10, 54.0),
        ("", pdf.HELVETICA, 12, 0.0),
        ("35 °C", pdf.HELVETICA, 9.5, 23.864),
    ],
)
def test_width_is_the_sum_of_the_advances(text, font, size, points):
    assert pdf.width(text, font, size) == pytest.approx(points)


def test_a_replaced_character_is_as_wide_as_the_question_mark():
    assert pdf.width(chr(0x4E09), pdf.HELVETICA, 10) == pdf.width("?", pdf.HELVETICA, 10)


# --- WinAnsi -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "encoded", "replaced"),
    [
        ("Apple M5", b"Apple M5", 0),
        ("35 °C", b"35 \xb0C", 0),
        ("caf" + chr(0xE9), b"caf\xe9", 0),
        (chr(0x20AC) + "5", b"\x805", 0),
        (chr(0x2019), b"\x92", 0),
        (chr(0xA0), b"\xa0", 0),
        (chr(0x4E09) + "x", b"?x", 1),
        ("a\nb\tc", b"a?b?c", 2),
        ("\x7f" + chr(0x81) + chr(0x8D), b"???", 3),
        (chr(0x1F600), b"?", 1),
        (chr(0x202E) + "x", b"?x", 1),
        ("", b"", 0),
        ("Mac" + chr(0xAD) + "Book", b"Mac?Book", 1),
        (chr(0xA4), b"?", 1),
        ("e" + chr(0x0301), b"\xe9", 0),
    ],
    ids=[
        "ASCII",
        "a degree sign",
        "Latin-1",
        "the euro",
        "a curly quote",
        "a no-break space",
        "outside WinAnsi",
        "controls",
        "DEL and codes WinAnsi leaves undefined",
        "outside the BMP",
        "a bidirectional control",
        "empty",
        "a soft hyphen, which WinAnsi draws as a hyphen",
        "the currency sign, which Preview draws as the euro",
        "a decomposed accent, composed first",
    ],
)
def test_text_is_winansi_and_everything_else_is_replaced_and_counted(text, encoded, replaced):
    assert pdf.encode(text) == (encoded, replaced)


def test_the_winansi_table_is_appendix_ds_less_two_characters():
    # WinAnsiEncoding draws 218 characters (PDF Reference, Appendix D): ASCII 32 to 126, 27
    # of the codes 128 to 159, and Latin-1 160 to 255. The writer keeps its own table, so
    # encoding reads no codec, and refuses the soft hyphen, which would draw as a hyphen, and
    # the currency sign, which Preview draws as the euro.
    expected = {}
    for code in range(32, 256):
        try:
            character = bytes([code]).decode("cp1252")
        except UnicodeDecodeError:
            continue
        if code != 127:
            expected[character] = code
    assert len(expected) == 218
    del expected[chr(0xAD)], expected[chr(0xA4)]
    assert dict(pdf.WINANSI) == expected
    assert "cp1252" not in Path(pdf.__file__).read_text()


def test_every_character_is_drawn_from_the_table_or_replaced_and_counted():
    drawn = set(pdf.WINANSI.values())
    for point in range(0x10000):
        character = chr(point)
        if character == "?":
            continue
        encoded, replaced = pdf.encode(character)
        assert set(encoded) <= drawn | {ord("?")}, point
        assert replaced == encoded.count(b"?"), point
        if character in pdf.WINANSI:
            assert (encoded, replaced) == (bytes([pdf.WINANSI[character]]), 0), point
        elif unicodedata.normalize("NFC", character) == character:
            assert (encoded, replaced) == (b"?", 1), point


def test_a_page_counts_what_it_replaced():
    page = pdf.Page(pdf.LETTER)
    page.text(10, 10, chr(0x4E09) * 3, font=pdf.HELVETICA, size=10, color=INK)
    page.text(10, 20, "fine", font=pdf.HELVETICA, size=10, color=INK)
    assert page.replaced == 3


# --- content streams ---------------------------------------------------------------------------


def test_a_page_draws_text_rectangles_and_lines_with_exact_operators():
    page = pdf.Page(pdf.LETTER)
    page.text(51.02, 740.5, "(a) \\b é", font=pdf.HELVETICA_BOLD, size=12, color=GREEN)
    page.rect(10, 20, 30.125, 40, fill=pdf.Color.hex("#EBEDE8"))
    page.rect(10, 20, 30, 40, stroke=INK, line_width=0.75)
    page.rect(10, 20, 30, 40, fill=INK, stroke=GREEN)
    page.line(0, 0.004, 612, 792, color=INK, width=0.5)
    assert page.content == (
        b"BT /F2 12 Tf 0.086 0.388 0.247 rg 51.02 740.5 Td (\\(a\\) \\\\b \\351) Tj ET\n"
        b"0.922 0.929 0.91 rg 10 20 30.13 40 re f\n"
        b"0.75 w 0.082 0.09 0.102 RG 10 20 30 40 re S\n"
        b"0.082 0.09 0.102 rg 0.5 w 0.086 0.388 0.247 RG 10 20 30 40 re B\n"
        b"0.5 w 0.082 0.09 0.102 RG 0 0 m 612 792 l S\n"
    )


@pytest.mark.parametrize(
    ("value", "spelled"),
    [
        (0, "0"),
        (-0.001, "0"),
        (12.5, "12.5"),
        (3.0, "3"),
        (0.125, "0.13"),
        (-7.255, "-7.26"),
        (595.28, "595.28"),
    ],
)
def test_numbers_are_written_with_at_most_two_decimals_half_up(value, spelled):
    assert pdf.number(value) == spelled


def test_a_rectangle_is_filled_stroked_or_both():
    with pytest.raises(ValueError):
        pdf.Page(pdf.LETTER).rect(10, 20, 30, 40)


def test_a_number_that_is_not_finite_is_refused():
    for value in (float("nan"), float("inf")):
        with pytest.raises(ValueError):
            pdf.number(value)


@pytest.mark.parametrize("value", [True, Decimal("12.5"), "3", 32767.5, -40000, 1e26])
def test_a_number_outside_pdf_14s_limits_or_not_a_number_is_refused(value):
    # PDF 1.4, Appendix C: a real number is at most 32,767 in size.
    with pytest.raises(ValueError):
        pdf.number(value)


def test_the_bytes_do_not_depend_on_the_callers_decimal_context():
    with decimal.localcontext(decimal.Context(prec=4, rounding=decimal.ROUND_DOWN)):
        assert hashlib.sha256(write()).hexdigest() == PINNED
    with decimal.localcontext(decimal.Context(prec=3, rounding=decimal.ROUND_FLOOR)):
        assert pdf.number(12345.675) == "12345.68"
        assert pdf.Color(32, 32, 32).operands() == "0.125 0.125 0.125"


def test_a_refused_text_draws_and_counts_nothing():
    page = pdf.Page(pdf.LETTER)
    with pytest.raises(ValueError):
        page.text(float("nan"), 10, chr(0x4E09) * 2, font=pdf.HELVETICA, size=10, color=INK)
    assert (page.replaced, page.content) == (0, b"")


def test_only_the_three_standard_fonts_draw():
    other = pdf.Font("F9", "Times-Roman", pdf.HELVETICA.widths)
    with pytest.raises(ValueError):
        pdf.Page(pdf.LETTER).text(10, 10, "x", font=other, size=10, color=INK)


@pytest.mark.parametrize("channels", [(256, 0, 0), (0, -1, 0), (0, 0, 1.5), (True, 0, 0)])
def test_a_color_channel_is_an_integer_from_0_to_255(channels):
    with pytest.raises(ValueError):
        pdf.Color(*channels)


def test_colors_come_from_the_specs_hex_tokens():
    assert pdf.Color.hex("#15171A") == pdf.Color(0x15, 0x17, 0x1A)
    for token in ("15171A", "#15171G", "#G5171A", "#15G71A", "#1517GA", "#15171A0", "#1517"):
        with pytest.raises(ValueError):
            pdf.Color.hex(token)
    assert pdf.Color.hex("#16633f") == GREEN


# --- the document --------------------------------------------------------------------------------


@pytest.mark.parametrize("compress", [False, True], ids=["plain", "compressed"])
def test_an_independent_parser_reads_the_document(compress):
    found = reader(write(compress=compress))
    assert len(found.pages) == 2
    text = found.pages[0].extract_text()
    assert "Mac hardware observation report" in text
    assert "Page 1: 23 (°C) \\ done" in text
    assert "/usr/bin/sqlite3 -readonly" in text


@pytest.mark.parametrize(
    ("size", "box"), [(pdf.LETTER, [0, 0, 612, 792]), (pdf.A4, [0, 0, 595.28, 841.89])]
)
def test_letter_and_a4(size, box):
    page = reader(write(sample(size, pages=1))).pages[0]
    assert [float(v) for v in page.mediabox] == pytest.approx(box)


def test_the_fonts_are_the_standard_ones_with_nothing_embedded():
    found = reader(write())
    for page in found.pages:
        fonts = page["/Resources"]["/Font"]
        assert sorted(fonts) == ["/F1", "/F2", "/F3"]
        bases = {key: fonts[key].get_object() for key in fonts}
        assert {key: str(font["/BaseFont"]) for key, font in bases.items()} == {
            "/F1": "/Helvetica",
            "/F2": "/Helvetica-Bold",
            "/F3": "/Courier",
        }
        for font in bases.values():
            assert (str(font["/Subtype"]), str(font["/Encoding"])) == ("/Type1", "/WinAnsiEncoding")
            assert "/FontDescriptor" not in font and "/Widths" not in font


def test_the_metadata_is_the_reports_own():
    data = write()
    found = reader(data)
    info = found.metadata
    assert info["/Title"] == "Mac hardware observation report"
    assert info["/Producer"] == "voltry-mac 0.1.0"
    assert info["/CreationDate"] == CREATED
    ids = found.trailer["/ID"]
    assert [bytes(entry) for entry in ids] == [IDENTIFIER, IDENTIFIER]
    assert set(info) == {"/Title", "/Producer", "/CreationDate"}, "nothing else, no clock"


def test_the_version_and_the_header():
    data = write()
    assert data.startswith(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    assert data.endswith(b"%%EOF\n")


def test_every_cross_reference_points_at_its_object():
    data = write()
    start = int(re.search(rb"startxref\n(\d+)\n%%EOF\n$", data)[1])
    table = data[start:]
    assert table.startswith(b"xref\n0 ")
    count = int(re.match(rb"xref\n0 (\d+)\n", table)[1])
    entries = re.findall(rb"(\d{10}) (\d{5}) ([nf]) \n", table)
    assert len(entries) == count
    assert entries[0] == (b"0000000000", b"65535", b"f")
    for number, (offset, generation, kind) in enumerate(entries[1:], start=1):
        assert (generation, kind) == (b"00000", b"n")
        assert data[int(offset) :].startswith(f"{number} 0 obj\n".encode())


def test_the_same_pages_give_the_same_bytes():
    assert write() == write()
    assert write(compress=True) == write(compress=True)


def test_the_plain_bytes_are_pinned():
    # Decision 4: the same JSON, paper and renderer version give the same bytes; a
    # renderer change re-pins this, never silently.
    assert hashlib.sha256(write()).hexdigest() == PINNED


PINNED = "b24d5d275b40dd4fcd7253583031a2a668eef099b749d2557f1e4d9e8d8ce3a5"


def test_compression_changes_only_the_encoding_of_the_streams():
    plain, packed = write(), write(compress=True)
    plain_streams = re.findall(rb"stream\n(.*?)\nendstream", plain, re.S)
    packed_streams = re.findall(rb"stream\n(.*?)\nendstream", packed, re.S)
    assert [zlib.decompress(s) for s in packed_streams] == plain_streams
    assert b"/Filter /FlateDecode" in packed and b"/Filter" not in plain


@pytest.mark.parametrize("field", ["title", "producer"])
@pytest.mark.parametrize(
    "extra", [chr(0xE9), "\n", "\x00", "\x7f"], ids=["e-acute", "LF", "NUL", "DEL"]
)
def test_the_metadata_strings_are_printable_ascii(field, extra):
    strings = {"title": "Mac hardware observation report", "producer": "voltry-mac 0.1.0"}
    strings[field] += extra
    with pytest.raises(ValueError):
        pdf.document(sample(), created=CREATED, identifier=IDENTIFIER, compress=False, **strings)


def test_metadata_with_parentheses_and_backslashes_stays_in_its_string():
    title, producer = "x) /Author (evil \\) \\", "p (\\)"
    data = pdf.document(
        sample(), title=title, producer=producer, created=CREATED, identifier=IDENTIFIER,
        compress=False,
    )  # fmt: skip
    info = reader(data).metadata
    assert (info["/Title"], info["/Producer"]) == (title, producer)
    assert set(info) == {"/Title", "/Producer", "/CreationDate"}


@pytest.mark.parametrize("created", ["2026-09-23T14:05:31-07:00", "D:2026", "D:20260923140531Z"])
def test_a_creation_date_not_in_the_pdf_grammar_is_refused(created):
    with pytest.raises(ValueError):
        pdf.document(
            sample(), title="t", producer="p", created=created, identifier=IDENTIFIER,
            compress=False,
        )  # fmt: skip


@pytest.mark.parametrize("compress", [False, True], ids=["plain", "compressed"])
def test_each_stream_length_is_its_own(compress):
    data = write(compress=compress)
    found = list(re.finditer(rb"/Length (\d+)(?: /Filter /FlateDecode)? >>\nstream\n", data))
    assert len(found) == 2
    for stream in found:
        end = stream.end() + int(stream[1])
        assert data[end : end + 10] == b"\nendstream"


def test_a_document_needs_a_page():
    with pytest.raises(ValueError):
        write([])


def test_an_identifier_is_the_32_bytes_of_a_sha_256():
    with pytest.raises(ValueError):
        pdf.document(
            sample(), title="t", producer="p", created=CREATED, identifier=b"short", compress=False
        )


@pytest.mark.parametrize(
    ("local", "created"),
    [
        ("2026-09-23T14:05:31-07:00", "D:20260923140531-07'00'"),
        ("2026-09-24T02:35:31+05:30", "D:20260924023531+05'30'"),
        ("2026-09-23T21:05:31+00:00", "D:20260923210531+00'00'"),
    ],
)
def test_the_creation_date_is_the_collection_time_with_its_offset(local, created):
    assert pdf.creation_date(local) == created


@pytest.mark.parametrize(
    "local",
    [
        "2026-09-23T21:05:31Z",
        "2026-09-23 14:05:31-07:00",
        "",
        "2026-13-45T25:61:61+99:99",
        "2026-00-10T10:00:00+00:00",
        "2026-02-29T10:00:00+00:00",
        "2026-04-31T10:00:00+00:00",
        "2026-09-23T24:00:00+00:00",
        "2026-09-23T10:00:60+00:00",
        "2026-09-23T10:00:00+24:00",
        "2026-09-23T10:00:00+05:60",
    ],
)
def test_a_time_without_its_offset_or_out_of_range_is_refused(local):
    with pytest.raises(ValueError):
        pdf.creation_date(local)


def test_the_writer_reads_no_clock_file_process_or_network():
    import ast

    tree = ast.parse(Path(pdf.__file__).read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
            if node.module == "voltry_mac":
                assert {alias.name for alias in node.names} <= {"characters", "metrics"}
    # Not unicodedata: what a character composes to is the character table's (the first
    # audit's G1-08).
    assert imported <= {
        "__future__",
        "collections.abc",
        "dataclasses",
        "decimal",
        "re",
        "typing",
        "zlib",
        "voltry_mac",
    }
