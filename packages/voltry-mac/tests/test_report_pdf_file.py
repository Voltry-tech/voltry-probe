"""The report PDF as a file (docs/VOLTRY_MAC_SPEC.md, Decision 4, Test strategy part 4, and
the size budget of spike MAC 2.4, #311).

Each golden renders to its pinned SHA-256 and matches its reference images tile by tile, so
a change as small as one digit fails once the goldens are drawn again; it opens strictly,
with its pages, the report's own metadata and the three standard fonts, none embedded; it
stays under the size budget with plain pages; two renders are the same bytes; and the
renderer reads no clock, file, process or network and leaves the document as it was. The
widest legal report, every free text at its longest in the widest and heaviest character
the pages can print, stays near the budget.
"""

from __future__ import annotations

import ast
import copy
import io
import re
import struct
import zlib
from pathlib import Path

import pypdf
import pytest
import voltry_mac_test_pdf_goldens as goldens
import voltry_mac_test_pdf_pages as pages
import voltry_mac_test_reports as r

from voltry_mac import layout, pdf, registry, report_pdf, wording

NAMES = list(goldens.DOCUMENTS)
PAPERS = ("letter", "a4")


def reference_pages(name: str) -> int:
    return len(list((goldens.GOLDEN / name).glob("page-*.png")))


# --- the widest legal report -------------------------------------------------------------------


def test_the_widest_report_is_as_wide_as_the_validator_allows():
    document = pages.widest("m5-laptop")
    heavy = [
        value
        for surface in document["surfaces"]
        for value in (surface.get("values") or {}).values()
        if isinstance(value, dict) and value.get("value") == pages.HEAVIEST * registry.MAX_STRING
    ]
    assert len(heavy) >= 20
    assert document["tool"]["version"] == pages.LONGEST[("tool", "version")]
    assert r.values(document, "smart_wear_attributes")["power_on_hours"]["value"] == str(2**128 - 1)
    assert {record["duration_ms"] for record in document["commands"]} == {2**63 - 1}


# --- the goldens -----------------------------------------------------------------------------


@pytest.mark.parametrize("name", NAMES)
def test_each_golden_matches_its_pinned_sha256(name):
    pinned = (goldens.GOLDEN / f"{name}.sha256").read_text().strip()
    assert goldens.sha256(goldens.render(name)) == pinned


@pytest.mark.parametrize("name", NAMES)
def test_each_page_matches_its_reference_image(name):
    drawn = goldens.raster(goldens.render(name))
    assert len(drawn) == reference_pages(name)
    for number, (width, height, pixels) in enumerate(drawn, start=1):
        ref_width, ref_height, ref_pixels = goldens.read_png(goldens.image(name, number))
        assert (width, height) == (ref_width, ref_height), number
        assert goldens.worst_tile(pixels, ref_pixels, width) <= goldens.TILE_MISSES, number


def test_the_image_check_draws_the_golden_unchanged():
    data = goldens.render("m5-laptop")
    assert goldens.raster(data) == goldens.raster(data)
    for number, (width, _height, pixels) in enumerate(goldens.raster(data), start=1):
        reference = goldens.read_png(goldens.image("m5-laptop", number))[2]
        assert goldens.worst_tile(pixels, reference, width) <= goldens.TILE_MISSES


def _replace(data: bytes, old: bytes, new: bytes, *, every: bool = False) -> bytes:
    """The PDF with one piece of a content stream changed in place, the same length, so the
    cross-reference table still holds."""
    assert len(old) == len(new) and old in data, old
    return data.replace(old, new) if every else data.replace(old, new, 1)


def _no_bars(data: bytes) -> bytes:
    green = layout.GREEN.operands().encode()
    changed = re.sub(rb"(" + re.escape(green) + rb" rg [-\d. ]+ re) f\n", rb"\1 n\n", data)
    assert changed != data
    return changed


EDITS = {
    "a percentage on page 3": lambda d: _replace(d, b"(99%)", b"(98%)"),
    "a percentage on page 2": lambda d: _replace(d, b"(1%)", b"(7%)"),
    "a sample cell": lambda d: _replace(d, b"(0.05)", b"(0.06)"),
    "a word in a note": lambda d: _replace(d, b"wall", b"well"),
    "a word in the sample table": lambda d: _replace(d, b"(Nominal)", b"(Nominel)"),
    "a word in a row": lambda d: _replace(d, b"(Verified)", b"(Vorified)"),
    "the table headers' fill": lambda d: _replace(
        d, layout.FILL.operands().encode() + b" rg", b"1.000 1.000 1.00 rg", every=True
    ),
    "one rule": lambda d: _replace(d, b" l S\n", b" l n\n"),
    "one chip's box": lambda d: _replace(d, b" re S\n", b" re n\n"),
    "the chart's bars": _no_bars,
    "a page number": lambda d: _replace(d, b"Page 1 of", b"Page 7 of"),
    # The #352 review, round 3: the two swaps nearest the threshold.
    "a bar's text": lambda d: _replace(d, b"(2.6\\240W)", b"(2.0\\240W)"),
    "a thousands comma": lambda d: _replace(d, b"5,954", b"5.954"),
}


@pytest.mark.parametrize("edit", list(EDITS), ids=list(EDITS))
def test_the_image_check_sees_a_small_change(edit):
    changed = goldens.raster(EDITS[edit](goldens.render("m5-laptop")))
    worst = [
        goldens.worst_tile(pixels, goldens.read_png(goldens.image("m5-laptop", number))[2], width)
        for number, (width, _height, pixels) in enumerate(changed, start=1)
    ]
    assert max(worst) > goldens.TILE_MISSES, edit


# --- the file --------------------------------------------------------------------------------


@pytest.mark.parametrize("name", NAMES)
def test_each_golden_opens_strictly_with_its_pages(name):
    data = goldens.render(name)
    assert data.startswith(b"%PDF-1.4\n")
    reader = pypdf.PdfReader(io.BytesIO(data), strict=True)
    assert len(reader.pages) == reference_pages(name)
    assert 6 <= len(reader.pages) <= 10


@pytest.mark.parametrize("name", NAMES)
def test_the_metadata_is_the_reports_own(name):
    document = goldens.DOCUMENTS[name]()
    data = goldens.render(name)
    reader = pypdf.PdfReader(io.BytesIO(data), strict=True)
    info = reader.metadata
    assert info["/Title"] == wording.TITLE
    assert info["/Producer"] == f"voltry-mac {document['tool']['version']}"
    assert info["/CreationDate"] == pdf.creation_date(document["collected_at_local"])
    identifier = bytes.fromhex(document["report_id"].removeprefix("sha256:"))
    found = [getattr(each, "original_bytes", each) for each in reader.trailer["/ID"]]
    assert [bytes(each) for each in found] == [identifier, identifier]
    assert data.count(b"/ID [") == 1


@pytest.mark.parametrize("name", NAMES)
def test_the_fonts_are_the_three_standard_ones_and_none_is_embedded(name):
    data = goldens.render(name)
    reader = pypdf.PdfReader(io.BytesIO(data), strict=True)
    found = set()
    for page in reader.pages:
        fonts = page["/Resources"]["/Font"]
        found |= {str(fonts[key]["/BaseFont"]) for key in fonts}
    assert found == {"/Helvetica", "/Helvetica-Bold", "/Courier"}
    for marker in (b"/FontFile", b"/FontFile2", b"/FontFile3", b"/FontDescriptor"):
        assert marker not in data


# The size budget of spike MAC 2.4 (#311): each golden under 100 KB with plain pages.
BUDGET = 100_000


@pytest.mark.parametrize("name", NAMES)
def test_each_golden_is_under_the_size_budget(name):
    assert len(goldens.render(name)) < BUDGET


# The widest legal report, measured with this renderer: about 132 KB on Letter, sixteen
# pages since Appendix B prints the guarantee beside each cleanup (the GPT audit, pass 3,
# G3-04), and 133 KB on A4, for the M5 fixture with the values the validator ties
# together widened together. Real reports are far smaller (the goldens are 57 to 69 KB); the
# bounds keep that edge in sight.
WIDEST_BOUND = 135_000
WIDEST_PAGES = 16


@pytest.mark.parametrize("paper", PAPERS)
def test_the_widest_report_stays_near_the_budget(paper):
    document = pages.on(pages.widest("m5-laptop"), paper)
    data = report_pdf.render(document, pages.templates())
    assert len(data) < WIDEST_BOUND
    assert len(pypdf.PdfReader(io.BytesIO(data), strict=True).pages) <= WIDEST_PAGES


def test_the_widest_report_widens_the_values_the_validator_ties_together():
    # The #352 review, round 3: one value at a time left the warning byte, the storage
    # chain, the temperatures, the boot, the power series and more at the fixture's.
    document = pages.widest("m5-laptop")
    health = r.values(document, "smart_health_snapshot")
    assert health["critical_warning_byte"]["value"] == 255
    wear = r.values(document, "smart_wear_attributes")
    assert wear["data_units_written"]["value"] == str(2**128 - 1)
    power = r.values(document, "power_and_thermal_samples")
    assert power["sample_thermal_pressure"]["value"] == pages.THERMAL
    assert document["elevation"]["cleared"] == "failed"
    assert document["tool"]["renderer_version"] == "9999"
    data = report_pdf.render(pages.on(document, "letter"), pages.templates())
    assert len(pypdf.PdfReader(io.BytesIO(data), strict=True).pages) == WIDEST_PAGES


@pytest.mark.parametrize("name", NAMES)
def test_two_renders_are_the_same_bytes(name):
    assert goldens.render(name) == goldens.render(name)


@pytest.mark.parametrize("name", NAMES)
def test_the_pages_are_not_compressed(name):
    assert report_pdf.COMPRESS is False
    assert b"/FlateDecode" not in goldens.render(name)


def test_the_renderer_is_version_1():
    assert report_pdf.RENDERER == "1"
    for name in NAMES:
        assert goldens.DOCUMENTS[name]()["tool"]["renderer_version"] == "1", name


def _png(width: int, height: int, rows: list[tuple[int, bytes]]) -> bytes:
    """A grayscale PNG whose rows carry the given filter types and filtered bytes."""
    raw = b"".join(bytes([kind]) + line for kind, line in rows)

    def chunk(kind: bytes, data: bytes) -> bytes:
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    header = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


def test_the_png_reader_reads_what_the_writer_wrote(tmp_path):
    for width, height in ((5, 3), (4, 4), (1, 1)):
        pixels = bytes((7 * index) % 256 for index in range(width * height))
        path = tmp_path / f"{width}x{height}.png"
        goldens.write_png(path, width, height, pixels)
        assert goldens.read_png(path) == (width, height, pixels)
    # Every filter an optimizer may use: none, sub, up, average and Paeth.
    path = tmp_path / "filtered.png"
    path.write_bytes(
        _png(
            3,
            5,
            [
                (0, bytes([10, 20, 30])),
                (1, bytes([10, 10, 10])),
                (2, bytes([1, 1, 1])),
                (3, bytes([5, 5, 5])),
                (4, bytes([0, 0, 0])),
            ],
        )
    )
    width, height, pixels = goldens.read_png(path)
    assert (width, height) == (3, 5)
    assert pixels == bytes([10, 20, 30, 10, 20, 30, 11, 21, 31, 10, 20, 30, 10, 20, 30])
    with pytest.raises(ValueError, match="one byte per pixel"):
        goldens.write_png(tmp_path / "bad.png", 2, 2, b"\x00")


def test_the_pdf_pages_read_no_clock_file_process_or_network():
    # The standard library modules each PDF module may import; none reads a clock, a file,
    # a process or the network (zlib compresses, bisect looks up the character table). Not
    # unicodedata: a character is what the table says on every Python (the first audit's
    # G1-08).
    package = Path(report_pdf.__file__).parent
    allowed = {
        "__future__",
        "bisect",
        "collections.abc",
        "dataclasses",
        "decimal",
        "re",
        "types",
        "typing",
        "zlib",
        "voltry_mac",
    }
    for module in (
        "report_pdf",
        "layout",
        "pdf",
        "appendices",
        "details",
        "sections",
        "wording",
        "phrases",
        "versions",
        "characters",
    ):
        tree = ast.parse((package / f"{module}.py").read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {alias.name for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
        assert imported <= allowed, (module, imported - allowed)
    tree = ast.parse((package / "report_pdf.py").read_text(encoding="utf-8"))
    used = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "voltry_mac"
        for alias in node.names
    }
    assert used == {"appendices", "details", "layout", "pdf", "phrases", "sections", "wording"}
    # And appendices: the version rule from a leaf module, not the validator's whole chain
    # (the #352 review, round 3).
    tree = ast.parse((package / "appendices.py").read_text(encoding="utf-8"))
    used = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "voltry_mac"
        for alias in node.names
    }
    assert used == {"phrases", "registry", "versions"}


def test_rendering_leaves_the_document_as_it_was():
    document = goldens.DOCUMENTS["concerning-desktop"]()
    before = copy.deepcopy(document)
    report_pdf.render(document, pages.templates())
    assert document == before


@pytest.mark.parametrize(("paper", "size"), [("letter", pdf.LETTER), ("a4", pdf.A4)])
def test_the_paper_is_the_reports_setting(paper, size):
    data = report_pdf.render(pages.on(r.load("m5-laptop"), paper), pages.templates())
    reader = pypdf.PdfReader(io.BytesIO(data), strict=True)
    for page in reader.pages:
        assert [float(v) for v in page.mediabox] == [0.0, 0.0, *size]
