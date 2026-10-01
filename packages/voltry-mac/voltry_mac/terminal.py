"""The terminal summary and the display path.

docs/VOLTRY_MAC_SPEC.md, "CLI transcripts" and the Architecture's renderers row. The summary
lays out sections.py's and details.py's content at 80 columns, as transcript 1 does: prose
at most 69 columns; At a glance topics at column 2 and text at 12, wrapped at 50 with the
label chip at column 63, or at 56 without one; detail rows with the label chip at column 64,
and source lines ending at column 72. It is a pure function of the report document. The
display path is how every path the tool prints is shown.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Final

from voltry_mac import characters, details, phrases, sections, wording

WIDTH: Final = 80
PROSE: Final = 69
GLANCE_TEXT: Final = 12
GLANCE_CHIP: Final = 63
ROW_CHIP: Final = 64
SOURCE_END: Final = 72
_GLANCE_WITH_CHIP: Final = GLANCE_CHIP - 1 - GLANCE_TEXT
_GLANCE_WITHOUT_CHIP: Final = 56


_CHIPS: Final = frozenset({"measured", "reported", "derived"})
# In a line with a chip, "not" stays with the word after it too, so the chip never reads as
# the end of a negation ("Gatekeeper not" and then "reported").
_NEGATION: Final = frozenset({"not", "Not"})
# Units the report prints after a number; each stays on the number's line.
# (Its closing marks aside: "1 TB," and "10 seconds);" are the number and its unit too.)
_UNITS: Final = frozenset({"TB", "PB", "GB", "MB", "B", "W", "°C", "mAh", "second", "seconds"})


def _split(word: str, size: int) -> list[str]:
    """A word wider than size in whole pieces: each as wide as fits, ending after a
    thousands comma when there is one, so a number breaks only between its groups."""
    pieces = []
    while phrases.cells(word) > size:
        end = 0
        while end < len(word) and phrases.cells(word[: end + 1]) <= size:
            end += 1
        comma = word.rfind(",", 0, end)
        end = comma + 1 if comma > 0 else max(end, 1)
        pieces.append(word[:end])
        word = word[end:]
    return [*pieces, word]


def _kept(units: Iterable[str], *, chip: bool = False) -> list[str]:
    """Units with each label word joined to the word after it, so the report's own words
    ("not reported by macOS") never end a line where a label chip would sit; in a line
    with a chip, "not" joined to the word after it too; and each unit of measure joined to
    its number, one that ends in an ASCII digit, as the PDF's rule reads a number
    (report_pdf.tied): str.isdigit follows the running Python's Unicode database."""
    forward = _CHIPS | _NEGATION if chip else _CHIPS
    kept: list[str] = []
    for unit in units:
        last = kept[-1] if kept else ""
        tied = unit.rstrip(",.;)") in _UNITS and "0" <= last[-1:] <= "9"
        if last.rsplit(" ", 1)[-1] in forward or tied:
            kept[-1] += " " + unit
        else:
            kept.append(unit)
    return kept


def _fill(units: Iterable[str], size: int, *, chip: bool = False) -> list[str]:
    """Greedy lines of at most size columns; a unit never breaks unless it alone is wider."""
    lines: list[str] = []
    for unit in _kept(units, chip=chip):
        for piece in _split(unit, size) if phrases.cells(unit) > size else [unit]:
            if lines and phrases.cells(lines[-1]) + 1 + phrases.cells(piece) <= size:
                lines[-1] += " " + piece
            else:
                lines.append(piece)
    return lines or [""]


def _wrap(text: str, size: int, *, chip: bool = False) -> list[str]:
    return _fill(text.split(), size, chip=chip)


def _pad(text: str, column: int) -> str:
    return text + " " * max(1, column - phrases.cells(text))


def _title_block(report: phrases.Report) -> list[str]:
    unexpected = phrases.unexpected(report)
    return [
        wording.TITLE.upper(),
        wording.DISCLAIMER,
        *_fill(sections.identity(report), WIDTH),
        *_fill(sections.collection(report), PROSE),
        *(_wrap(unexpected, PROSE) if unexpected else []),
        *_wrap(f"Administrator reads: {sections.elevation(report)}", PROSE),
        *_wrap(sections.validated(report), PROSE),
    ]


def _glance_lines(entries: Sequence[sections.Entry]) -> list[str]:
    lines = ["AT A GLANCE"]
    for entry in entries:
        size = _GLANCE_WITH_CHIP if entry.chip else _GLANCE_WITHOUT_CHIP
        wrapped = _wrap(entry.text, size, chip=bool(entry.chip))
        first = f"  {entry.topic:<8}  {wrapped[0]}"
        if entry.chip:
            first = _pad(first, GLANCE_CHIP) + entry.chip
        lines.append(first)
        lines += [" " * GLANCE_TEXT + line for line in wrapped[1:]]
    return lines


def _header(title: str, source: str | None) -> list[str]:
    if source is None:
        return [title]
    return [
        title + " " * max(2, SOURCE_END - phrases.cells(title) - phrases.cells(source)) + source
    ]


def _limits_lines(bullets: Sequence[str]) -> list[str]:
    lines = ["WHAT THIS REPORT CANNOT TELL YOU"]
    for bullet in bullets:
        first, *rest = _wrap(bullet, PROSE - 4)
        lines += [f"  - {first}", *[f"    {line}" for line in rest]]
    return lines


# Each section's label column, as transcript 1 sets it.
_LABELS: Final = {
    "This Mac": 18,
    "Security settings": 29,
    "System records": 18,
    "Storage health and wear": 20,
    "Battery": 20,
    "Memory": 22,
    "Power and thermal check": 20,
}


def _lay(section: details.Section) -> list[str]:
    title = section.title.upper() + (f" {section.subtitle}" if section.subtitle else "")
    lines = _header(title, section.source)
    if section.text is not None:
        return lines + ["  " + line for line in _wrap(section.text, PROSE - 2)]
    column = 2 + _LABELS[section.title]
    for item in section.items:
        if isinstance(item, details.Source):
            lines.append(" " * max(0, SOURCE_END - phrases.cells(item.text)) + item.text)
            continue
        size = (ROW_CHIP - 1 - column) if item.chip else (WIDTH - column)
        wrapped = _wrap(item.text, size, chip=bool(item.chip))
        first = _pad(f"  {item.label}", column) + wrapped[0]
        if item.chip:
            first = _pad(first, ROW_CHIP) + item.chip
        lines.append(first)
        lines += [" " * column + line for line in wrapped[1:]]
        for note in item.notes:
            lines += ["    " + line for line in _wrap(note, PROSE - 4)]
    if section.note is not None:
        lines += ["  " + line for line in _wrap(section.note, PROSE - 2)]
    return lines


def summary(document: Mapping[str, object]) -> str:
    """The terminal summary of a validated report document, one newline at its end."""
    report = phrases.Report(document)
    blocks = [
        _title_block(report),
        _glance_lines(sections.glance(report)),
        _limits_lines(sections.limits(report)),
        *(
            _lay(build(report))
            for build in (
                details.this_mac,
                details.security,
                details.system_records,
                details.storage,
                details.battery,
                details.memory,
                details.power,
            )
        ),
    ]
    lines: list[str] = []
    for block in blocks:
        if lines:
            lines.append("")
        lines += [line.rstrip() for line in block]
    return "\n".join(lines) + "\n"


_MARKS: Final = ("Mn", "Mc", "Me")


def _code(character: str) -> str:
    point = ord(character)
    if point <= 0xFF:
        return f"\\x{point:02x}"
    if point <= 0xFFFF:
        return f"\\u{point:04x}"
    return f"\\U{point:08x}"


def _escaped(character: str) -> str:
    named = {"\\": "\\\\", "\n": "\\n", "\t": "\\t", "\r": "\\r"}
    if character in named:
        return named[character]
    category = characters.category(character)
    if (
        category in ("Cc", "Cf", "Zl", "Zp", "Cs", "Co", "Cn")
        or ord(character) in phrases.INVISIBLE
    ):
        return _code(character)
    if category == "Zs" and character != " ":
        return _code(character)
    return character


def _name(part: str) -> str:
    """One path component with nothing in it invisible: combining marks and conjoining
    Hangul with no letter before them, and spaces at its end, are escaped too, since they
    would print as nothing or join the character before the name."""
    end = len(part.rstrip(" "))
    shown, lead = [], True
    for index, character in enumerate(part):
        joins = characters.category(character) in _MARKS or phrases.cells(character) == 0
        lead = lead and joins
        if lead or index >= end:
            shown.append(_code(character))
        else:
            shown.append(_escaped(character))
    return "".join(shown)


def _folded(name: str) -> str:
    """A name as _same compares it: decomposed, case folded and decomposed again by the
    character table (characters.folded), as Python 3.12's unicodedata and str.casefold
    fold it, on every Python. The running Python's own folding would show a path under ~
    on one version and in full on another (a capital Unicode 16.0.0 added, U+A7CB, folds
    on 3.14 and not on 3.12)."""
    return characters.folded(name)


def _same(one: str, other: str) -> bool:
    """Whether two names fold to the same text by the character table (_folded): canonical
    decomposition, full case folding and decomposition again, as Unicode 15.0.0 defines
    them. That is close to how a case-insensitive volume compares names, and not the same:
    APFS on a newer macOS follows a later Unicode, and a case-sensitive volume keeps case
    apart. So the run finds the home folder in a path by the file system, and when it
    cannot look the home folder up, takes only the home folder's own spelling for it
    (run._home_in; the review of #326, round 2, m1, and the GPT audit, pass 2, G2-05):
    what the run hands display_path already is the path's own leading part."""
    return _folded(one) == _folded(other)


def display_path(path: str, home: str) -> str:
    """A path as the tool prints it: the home folder as ~, and control, format, separator
    and blank characters escaped, so a name cannot move the cursor, reorder the line or
    hide. ``home`` is the home folder as the path's first names give it, whose names they
    must match (_same): the run hands it the leading part the file system found to be the
    home folder, or, when the home folder cannot be looked up, its own path, which the
    path's first names then spell exactly. An empty one shortens nothing. The original path
    is for filesystem calls only."""
    parts, home_parts = path.split("/"), home.rstrip("/").split("/")
    inside = len(parts) >= len(home_parts) and all(
        _same(part, own) for part, own in zip(parts, home_parts, strict=False)
    )
    if home.rstrip("/") and inside:
        return "/".join(["~", *(_name(part) for part in parts[len(home_parts) :])])
    shown = "/".join(_name(part) for part in parts)
    # A path that is not the home folder never starts as if it were.
    return "\\x7e" + shown[1:] if shown.startswith("~") else shown
