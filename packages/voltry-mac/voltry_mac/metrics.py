"""The widths of Helvetica, Helvetica-Bold and Courier over WinAnsiEncoding.

docs/VOLTRY_MAC_SPEC.md, Decision 4: text is measured with Helvetica's published AFM widths,
and the fonts are the standard ones every PDF viewer has, so nothing is embedded. Each table
gives the advance width, in thousandths of the font size, of WinAnsi codes 32 to 255 in
order; "-" marks the six codes WinAnsiEncoding leaves undefined (127, 129, 141, 143, 144 and
157), which the writer never draws. Codes 160 and 173 draw the space and hyphen glyphs.

The numbers come from Adobe's Core 14 AFM files (Helvetica.afm, Helvetica-Bold.afm and
Courier.afm), read by glyph name through WinAnsiEncoding's glyph names; nothing else of
the files is kept. Their notices follow, as the ReadMe requires:

Helvetica.afm and Helvetica-Bold.afm: Copyright (c) 1985, 1987, 1989, 1990, 1997 Adobe
Systems Incorporated. All Rights Reserved. Helvetica is a trademark of Linotype-Hell AG
and/or its subsidiaries.

Courier.afm: Copyright (c) 1989, 1990, 1991, 1992, 1993, 1997 Adobe Systems Incorporated.
All Rights Reserved.

Core 14 AFM Files - ReadMe:

This file and the 14 PostScript(R) AFM files it accompanies may be used, copied, and
distributed for any purpose and without charge, with or without modification, provided that
all copyright notices are retained; that the AFM files are not distributed without this file;
that all modifications to this file or any of the AFM files are prominently noted in the
modified file(s); and that this paragraph is not modified. Adobe Systems has no
responsibility or obligation to support the use of the AFM files.
"""

from __future__ import annotations

from typing import Final

FIRST: Final = 32
UNDEFINED: Final = frozenset({127, 129, 141, 143, 144, 157})


def _table(text: str) -> tuple[int | None, ...]:
    return tuple(None if width == "-" else int(width) for width in text.split())


HELVETICA: Final = _table(
    "278 278 355 556 556 889 667 191 333 333 389 584 278 333 278 278 "
    "556 556 556 556 556 556 556 556 556 556 278 278 584 584 584 556 "
    "1015 667 667 722 722 667 611 778 722 278 500 667 556 833 722 778 "
    "667 778 722 667 611 722 667 944 667 667 611 278 278 278 469 556 "
    "333 556 556 500 556 556 278 556 556 222 222 500 222 833 556 556 "
    "556 556 333 500 278 556 500 722 500 500 500 334 260 334 584 - "
    "556 - 222 556 333 1000 556 556 333 1000 667 333 1000 - 611 - "
    "- 222 222 333 333 350 556 1000 333 1000 500 333 944 - 500 667 "
    "278 333 556 556 556 556 260 556 333 737 370 556 584 333 737 333 "
    "400 584 333 333 333 556 537 278 333 333 365 556 834 834 834 611 "
    "667 667 667 667 667 667 1000 722 667 667 667 667 278 278 278 278 "
    "722 722 778 778 778 778 778 584 778 722 722 722 722 667 667 611 "
    "556 556 556 556 556 556 889 500 556 556 556 556 278 278 278 278 "
    "556 556 556 556 556 556 556 584 611 556 556 556 556 500 556 500"
)
HELVETICA_BOLD: Final = _table(
    "278 333 474 556 556 889 722 238 333 333 389 584 278 333 278 278 "
    "556 556 556 556 556 556 556 556 556 556 333 333 584 584 584 611 "
    "975 722 722 722 722 667 611 778 722 278 556 722 611 833 722 778 "
    "667 778 722 667 611 722 667 944 667 667 611 333 278 333 584 556 "
    "333 556 611 556 611 556 333 611 611 278 278 556 278 889 611 611 "
    "611 611 389 556 333 611 556 778 556 556 500 389 280 389 584 - "
    "556 - 278 556 500 1000 556 556 333 1000 667 333 1000 - 611 - "
    "- 278 278 500 500 350 556 1000 333 1000 556 333 944 - 500 667 "
    "278 333 556 556 556 556 280 556 333 737 370 556 584 333 737 333 "
    "400 584 333 333 333 611 556 278 333 333 365 556 834 834 834 611 "
    "722 722 722 722 722 722 1000 722 667 667 667 667 278 278 278 278 "
    "722 722 778 778 778 778 778 584 778 722 722 722 722 667 667 611 "
    "556 556 556 556 556 556 889 556 556 556 556 556 278 278 278 278 "
    "611 611 611 611 611 611 611 584 611 611 611 611 611 556 611 556"
)
COURIER: Final = _table(
    "600 600 600 600 600 600 600 600 600 600 600 600 600 600 600 600 "
    "600 600 600 600 600 600 600 600 600 600 600 600 600 600 600 600 "
    "600 600 600 600 600 600 600 600 600 600 600 600 600 600 600 600 "
    "600 600 600 600 600 600 600 600 600 600 600 600 600 600 600 600 "
    "600 600 600 600 600 600 600 600 600 600 600 600 600 600 600 600 "
    "600 600 600 600 600 600 600 600 600 600 600 600 600 600 600 - "
    "600 - 600 600 600 600 600 600 600 600 600 600 600 - 600 - "
    "- 600 600 600 600 600 600 600 600 600 600 600 600 - 600 600 "
    "600 600 600 600 600 600 600 600 600 600 600 600 600 600 600 600 "
    "600 600 600 600 600 600 600 600 600 600 600 600 600 600 600 600 "
    "600 600 600 600 600 600 600 600 600 600 600 600 600 600 600 600 "
    "600 600 600 600 600 600 600 600 600 600 600 600 600 600 600 600 "
    "600 600 600 600 600 600 600 600 600 600 600 600 600 600 600 600 "
    "600 600 600 600 600 600 600 600 600 600 600 600 600 600 600 600"
)
