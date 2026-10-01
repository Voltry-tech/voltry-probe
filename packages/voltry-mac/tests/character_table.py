"""The character table in voltry_mac/characters.py, written from this Python's unicodedata.

docs/VOLTRY_MAC_SPEC.md, Decision 4: another Python reproduces the same content. The
renderers take what a character is from the table in voltry_mac/characters.py, never from
the running Python's unicodedata, whose Unicode version differs between the Pythons the
package supports. This script writes that table: the runs of the general categories the
renderers act on, the runs of wide characters, the letter and mark pairs and the single
characters that compose to a WinAnsi character (pdf.WINANSI), and for the display path's
match with the home folder, each character's canonical decomposition and full case
folding and the runs of the canonical combining classes.

`uv run python tests/character_table.py` writes the table again, between its two marker
lines, under the Python the repository pins (.python-version, 3.12), whose database is the
table's Unicode version; under another it refuses, since the table would change version.
test_characters.py compares the table with what this script writes whenever the running
Python's database is that version. conftest.py registers this module as
``voltry_mac_test_character_table``.
"""

from __future__ import annotations

import sys
import unicodedata
from collections.abc import Callable, Hashable
from pathlib import Path

UNICODE = "15.0.0"
MODULE = Path(__file__).resolve().parents[1] / "voltry_mac" / "characters.py"
BEGIN = "# --- The table, written by tests/character_table.py. Do not edit it by hand. ---\n"
END = "# --- The end of the table. ---\n"
# The general categories the renderers act on: what the terminal strips (Cc, Cf, Zl, Zp),
# the spaces (Zs), the marks (Mn, Mc, Me), and code points with no character every font
# draws alike (Cs, Co, Cn).
CATEGORIES = ("Cc", "Cf", "Zl", "Zp", "Zs", "Mn", "Mc", "Me", "Cs", "Co", "Cn")
POINTS = range(0x110000)
# The Hangul syllables, which characters.py decomposes by the Unicode Standard's algorithm.
SYLLABLES = range(0xAC00, 0xAC00 + 11172)
# The characters the PDF writer's table draws (pdf.WINANSI): what cp1252 decodes from 32 to
# 255, less DEL and the two the writer leaves out, the soft hyphen and the currency sign.
# Read from the codec here, not imported, so the script still runs while the table it
# rewrites cannot be imported; test_characters.py checks that the two agree.
WINANSI = frozenset(
    character
    for character in bytes(range(32, 256)).decode("cp1252", errors="ignore")
    if character not in "\x7f\xa4\xad"
)
WIDTH = 100


def _runs(key: Callable[[str], Hashable]) -> list[tuple[int, Hashable]]:
    """Where each run of code points with the same key starts, and the key."""
    runs: list[tuple[int, Hashable]] = []
    for point in POINTS:
        found = key(chr(point))
        if not runs or runs[-1][1] != found:
            runs.append((point, found))
    return runs


def _category(character: str) -> str:
    found = unicodedata.category(character)
    return found if found in CATEGORIES else "-"


def categories() -> list[str]:
    """Each run's start and its category, or "-" for one the renderers do not act on."""
    return [f"{start:x} {name}" for start, name in _runs(_category)]


def wide() -> list[str]:
    """Where each run of wide characters (East Asian Width W or F) starts, then where it
    ends, in turn: a code point is wide when an odd number of these are at or below it."""
    runs = _runs(lambda c: unicodedata.east_asian_width(c) in ("W", "F"))
    bounds = [f"{start:x}" for start, is_wide in runs if start or is_wide]
    return [" ".join(bounds[index : index + 2]) for index in range(0, len(bounds), 2)]


def pairs() -> list[str]:
    """Each letter and combining mark that NFC composes to one WinAnsi letter, and the
    letter: the two a WinAnsi letter decomposes to, or a character canonically equivalent
    to either (U+0341 COMBINING ACUTE TONE MARK is the acute accent, U+0301)."""
    targets = {}
    for letter in WINANSI:
        decomposed = unicodedata.normalize("NFD", letter)
        if len(decomposed) == 2:
            targets[letter] = decomposed
    same: dict[str, list[str]] = {part: [] for parts in targets.values() for part in parts}
    for point in POINTS:
        decomposed = unicodedata.normalize("NFD", chr(point))
        if decomposed in same:
            same[decomposed].append(chr(point))
    found = sorted(
        (ord(first), ord(second), ord(letter))
        for letter, (base, mark) in targets.items()
        for first in same[base]
        for second in same[mark]
        if unicodedata.normalize("NFC", first + second) == letter
    )
    return [" ".join(f"{point:x}" for point in triple) for triple in found]


def singles() -> list[str]:
    """Each character outside WinAnsi whose NFC is one WinAnsi character, and it."""
    found = []
    for point in POINTS:
        character = chr(point)
        if character in WINANSI:
            continue
        composed = unicodedata.normalize("NFC", character)
        if composed != character and composed in WINANSI:
            found.append(f"{point:x} {ord(composed):x}")
    return found


def _points(text: str) -> str:
    return ".".join(f"{ord(character):x}" for character in text)


def decompositions() -> list[str]:
    """Each character NFD changes, but a Hangul syllable, and what NFD gives it: its
    canonical decomposition, whole and in canonical order."""
    found = []
    for point in POINTS:
        decomposed = unicodedata.normalize("NFD", chr(point))
        if decomposed != chr(point) and point not in SYLLABLES:
            found.append(f"{point:x}:{_points(decomposed)}")
    return found


def foldings() -> list[str]:
    """Each character str.casefold() changes, and what it gives: Unicode's full case
    folding, one character or more."""
    found = []
    for point in POINTS:
        folded = chr(point).casefold()
        if folded != chr(point):
            found.append(f"{point:x}:{_points(folded)}")
    return found


def classes() -> list[str]:
    """Where each run of code points with one canonical combining class starts, and the
    class."""
    return [f"{start:x} {value}" for start, value in _runs(unicodedata.combining)]


def _constant(name: str, comment: str, groups: list[str]) -> str:
    """A string constant of the groups, as black sets it: on one line when it fits, or in
    parentheses, lines of at most WIDTH columns that never split a group."""
    one = f'{name}: Final = "{" ".join(groups)}"'
    if len(one) <= WIDTH:
        return f"{comment}{one}\n"
    lines: list[str] = []
    for group in groups:
        # Four spaces, the quotes and the space that ends each line: seven columns more.
        if lines and len(lines[-1]) + 1 + len(group) + 7 <= WIDTH:
            lines[-1] += f" {group}"
        else:
            lines.append(group)
    body = "".join(f'    "{line} "\n' for line in lines[:-1]) + f'    "{lines[-1]}"\n'
    return f"{comment}{name}: Final = (\n{body})\n"


def block() -> str:
    """The table, as it stands between the marker lines."""
    if unicodedata.unidata_version != UNICODE:
        raise RuntimeError(
            f"this Python's database is Unicode {unicodedata.unidata_version}; the table is "
            f"Unicode {UNICODE}, the database of the Python the repository pins"
        )
    return "".join(
        [
            f'UNICODE: Final = "{UNICODE}"\n',
            _constant(
                "_CATEGORIES",
                "# Each run of code points, from where its number (in hexadecimal) says to the\n"
                "# next run, and its general category, or - for one the renderers do not act on.\n",
                categories(),
            ),
            _constant(
                "_WIDE",
                "# Where each run of wide characters (East Asian Width W or F) starts and ends.\n",
                wide(),
            ),
            _constant(
                "_PAIRS",
                "# A letter, a combining mark and the WinAnsi letter the two compose to.\n",
                pairs(),
            ),
            _constant(
                "_SINGLES",
                "# A character canonically equivalent to one WinAnsi character, and that one.\n",
                singles(),
            ),
            _constant(
                "_DECOMPOSITIONS",
                "# A character and its canonical decomposition, whole and in canonical order, but\n"
                "# the Hangul syllables, which the algorithm decomposes.\n",
                decompositions(),
            ),
            _constant(
                "_FOLDINGS",
                "# A character and its full case folding.\n",
                foldings(),
            ),
            _constant(
                "_CLASSES",
                "# Each run of code points with one canonical combining class: where it starts\n"
                "# (hexadecimal) and the class (decimal, as UnicodeData.txt gives it).\n",
                classes(),
            ),
        ]
    )


def written() -> str:
    """The table between the marker lines of voltry_mac/characters.py, as the file has it."""
    text = MODULE.read_text(encoding="utf-8")
    if text.count(BEGIN) != 1 or text.count(END) != 1:
        raise ValueError(f"{MODULE.name} does not hold the table's two marker lines once each")
    return text.split(BEGIN, 1)[1].split(END, 1)[0].removeprefix("\n").removesuffix("\n")


def make() -> None:
    text = MODULE.read_text(encoding="utf-8")
    head, rest = text.split(BEGIN, 1)
    _, tail = rest.split(END, 1)
    MODULE.write_text(f"{head}{BEGIN}\n{block()}\n{END}{tail}", encoding="utf-8")


if __name__ == "__main__":
    try:
        make()
    except RuntimeError as error:
        sys.exit(str(error))
