"""The golden PDFs: the documents they render, their pinned SHA-256 and their reference images.

docs/VOLTRY_MAC_SPEC.md, Test strategy part 4: a fixture JSON renders to a pinned SHA-256,
re-pinned with each renderer version bump and never silently, and each golden PDF is
rasterized with pypdfium2 and compared with its reference images at a small tolerance, so
clipping, overlap and bad pagination fail the build. The concerning fixture is one of the
goldens. conftest.py registers this module as ``voltry_mac_test_pdf_goldens``.

pdfium draws a standard font with a system font when it finds one (Helvetica on a Mac, some
other face on Linux), so the images are drawn with pdfium's built-in fonts, which have the
standard fonts' widths and are the same on every platform.

To re-pin the SHA-256s after a renderer version bump, run from agents/voltry-mac:

    uv run python tests/pdf_goldens.py

which leaves the reference images as they are, so they still check the new pages; add
--images to draw them again too, and look at every image that changed before committing
it. The images are 8-bit grayscale PNGs at 72 dots per inch, written and read with the
standard library only, and compared tile by tile, so a change as small as one digit, a
comma, one rule or a table's fill fails.
"""

from __future__ import annotations

import hashlib
import struct
import sys
import zlib
from collections.abc import Callable
from pathlib import Path

GOLDEN = Path(__file__).resolve().parent / "golden" / "pdf"
SCALE = 1.0  # of 72 dots per inch
# A reference pixel matches when it is within DARKER levels of the new one; a page matches
# when no TILE by TILE square of it (16 points on a side) has more than TILE_MISSES pixels
# that do not. At this scale a table's fill differs from the page by 20 levels and a rule
# by 21, and a thousands comma turned into a period changes two pixels in its tile.
DARKER = 16
TILE = 16
TILE_MISSES = 1

_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _reports():  # type: ignore[no-untyped-def]
    return sys.modules["voltry_mac_test_reports"]


def m5() -> dict:
    return _reports().load("m5-laptop")


def concerning() -> dict:
    return _reports().load("concerning-desktop")


def declined_a4() -> dict:
    """Transcript 2's run, administrator reads declined, on A4 paper."""
    r = _reports()
    document = r.history(
        "m5-laptop",
        r.declined_record("no"),
        ("declined", "not_attempted"),
        ("declined", "not_attempted"),
    )
    document["render"]["paper"] = "a4"
    return r.rehash(document)


DOCUMENTS: dict[str, Callable[[], dict]] = {
    "m5-laptop": m5,
    "concerning-desktop": concerning,
    "m5-laptop-declined-a4": declined_a4,
}


def templates() -> dict[str, str]:
    """The templates of the version the fixtures say made them, from 0.1.0's manifest
    itself, never the lookup: at a package version of exactly 0.1.0 the lookup takes the
    running allow-list, so an allow-list edit would move the goldens. The manifest tests pin
    the manifest and the allow-list together at the release."""
    from voltry_mac import manifests

    return dict(manifests.RELEASED["0.1.0"])


def render(name: str) -> bytes:
    from voltry_mac import report_pdf

    return report_pdf.render(DOCUMENTS[name](), templates())


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --- the images -----------------------------------------------------------------------------


def raster(data: bytes) -> list[tuple[int, int, bytes]]:
    """Each page drawn in grayscale with pdfium's built-in fonts."""
    import pypdfium2
    import pypdfium2.raw as pdfium_c

    pdfium_c.FPDF_SetSystemFontInfo(None)  # the built-in fonts, the same everywhere
    document = pypdfium2.PdfDocument(data)
    pages = []
    for page in document:
        bitmap = page.render(scale=SCALE, grayscale=True)
        width, height, stride = bitmap.width, bitmap.height, bitmap.stride
        buffer = bytes(bitmap.buffer)
        pages.append(
            (
                width,
                height,
                b"".join(buffer[y * stride : y * stride + width] for y in range(height)),
            )
        )
    document.close()
    return pages


def _chunk(kind: bytes, data: bytes) -> bytes:
    body = kind + data
    return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))


def write_png(path: Path, width: int, height: int, pixels: bytes) -> None:
    """One grayscale byte per pixel, row after row."""
    if len(pixels) != width * height:
        raise ValueError("one byte per pixel")
    rows = b"".join(b"\x00" + pixels[y * width : (y + 1) * width] for y in range(height))
    header = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)
    path.write_bytes(
        _SIGNATURE
        + _chunk(b"IHDR", header)
        + _chunk(b"IDAT", zlib.compress(rows, 9))
        + _chunk(b"IEND", b"")
    )


def _paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    return a if pa <= pb and pa <= pc else b if pb <= pc else c


def read_png(path: Path) -> tuple[int, int, bytes]:
    """The width, the height and one grayscale byte per pixel; every filter type is read,
    so a PNG an optimizer rewrote still loads."""
    data = path.read_bytes()
    if not data.startswith(_SIGNATURE):
        raise ValueError("not a PNG")
    at, found, width, height = len(_SIGNATURE), b"", 0, 0
    while at < len(data):
        (length,) = struct.unpack(">I", data[at : at + 4])
        kind, body = data[at + 4 : at + 8], data[at + 8 : at + 8 + length]
        at += 12 + length
        if kind == b"IHDR":
            width, height, depth, color, _, _, interlace = struct.unpack(">IIBBBBB", body)
            if (depth, color, interlace) != (8, 0, 0):
                raise ValueError("an 8-bit grayscale PNG without interlace")
        elif kind == b"IDAT":
            found += body
    raw = zlib.decompress(found)
    out = bytearray()
    previous = bytearray(width)
    for y in range(height):
        start = y * (width + 1)
        kind, line = raw[start], bytearray(raw[start + 1 : start + 1 + width])
        for x in range(width):
            left = line[x - 1] if x else 0
            up, corner = previous[x], previous[x - 1] if x else 0
            add = {0: 0, 1: left, 2: up, 3: (left + up) // 2, 4: _paeth(left, up, corner)}[kind]
            line[x] = (line[x] + add) & 0xFF
        out += line
        previous = line
    return width, height, bytes(out)


def worst_tile(new: bytes, reference: bytes, width: int) -> int:
    """The most pixels more than DARKER levels apart in any one tile of the page."""
    counts: dict[tuple[int, int], int] = {}
    for index, (a, b) in enumerate(zip(new, reference, strict=True)):
        if abs(a - b) > DARKER:
            y, x = divmod(index, width)
            tile = (y // TILE, x // TILE)
            counts[tile] = counts.get(tile, 0) + 1
    return max(counts.values(), default=0)


def image(name: str, number: int) -> Path:
    return GOLDEN / name / f"page-{number}.png"


def make(*, images: bool = False) -> None:
    """Write each golden's SHA-256, and with images its reference images too, replacing
    the old ones."""
    for name in DOCUMENTS:
        data = render(name)
        (GOLDEN / f"{name}.sha256").write_text(sha256(data) + "\n")
        if images:
            folder = GOLDEN / name
            folder.mkdir(parents=True, exist_ok=True)
            for old in folder.glob("page-*.png"):
                old.unlink()
            for number, (width, height, pixels) in enumerate(raster(data), start=1):
                write_png(image(name, number), width, height, pixels)
        print(f"{name}: {sha256(data)}, {len(data):,} bytes")  # noqa: T201 - a script


if __name__ == "__main__":
    import importlib.util

    _spec = importlib.util.spec_from_file_location(
        "voltry_mac_test_reports", Path(__file__).resolve().parent / "reports.py"
    )
    assert _spec is not None and _spec.loader is not None
    _module = importlib.util.module_from_spec(_spec)
    sys.modules["voltry_mac_test_reports"] = _module
    _spec.loader.exec_module(_module)
    make(images="--images" in sys.argv[1:])
