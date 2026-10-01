"""The character table and what the renderers take from it (docs/VOLTRY_MAC_SPEC.md,
Decision 4: another Python reproduces the same content, and text is limited to WinAnsi,
any other character replaced and counted in Appendix B; the Architecture's renderers row:
control characters from system output are stripped before printing, and the display path
escapes what would hide).

The renderers read what a character is from voltry_mac/characters.py, a table of Unicode
15.0.0 that tests/character_table.py writes, never from the running Python's unicodedata,
whose version differs between the Pythons the package supports: 14.0.0 on 3.11, 15.0.0 on
3.12, 16.0.0 on 3.14 (the first audit's G1-08). The table is compared with the database
whenever the running Python has its version. Every other test here holds on every Python,
so the same report prints the same everywhere: the terminal drops what it strips, the PDF
prints every character outside WinAnsi as "?" and counts it, a letter with one combining
mark composes the same way, a unit stays with a number the same way, the two renderers
choose the same words, and the home folder is matched the same way, by Unicode 15.0.0's
decomposition and case folding (the review of #326, round 1, M1 to M3).
"""

from __future__ import annotations

import copy
import io
import itertools
import unicodedata

import pypdf
import pytest
import voltry_mac_test_character_table as table
import voltry_mac_test_pdf_pages as pages
import voltry_mac_test_reports as r

from voltry_mac import pdf, report_pdf, terminal, validate

T = pages.terminal_tests()


def _table():  # type: ignore[no-untyped-def]
    from voltry_mac import characters

    return characters


def _this_database(characters) -> None:  # type: ignore[no-untyped-def]
    if unicodedata.unidata_version != characters.UNICODE:
        pytest.skip(
            f"this Python's database is Unicode {unicodedata.unidata_version}, "
            f"not the table's {characters.UNICODE}"
        )


def _named(name: str) -> dict:
    """The m5-laptop report with this machine name, as the validator accepts it."""
    document = copy.deepcopy(r.load("m5-laptop"))
    r.set_value(document, "hardware_overview", "machine_name", name)
    document = r.finish(document)
    validate.validate(document)
    return document


def _pdf_text(document: dict) -> str:
    data = report_pdf.render(document, pages.templates())
    reader = pypdf.PdfReader(io.BytesIO(data), strict=True)
    return " ".join(" ".join(page.extract_text().split()) for page in reader.pages)


def _replaced(document: dict) -> int:
    made, _ = pages.composed(document)
    return made.replaced


# --- the table and the database it names -------------------------------------------------


def test_the_table_is_unicode_15():
    characters = _table()
    assert characters.UNICODE == table.UNICODE == "15.0.0"


def test_the_table_is_what_the_script_writes_from_this_database():
    characters = _table()
    _this_database(characters)
    assert table.written() == table.block()


def test_the_script_reads_the_pdf_writers_characters():
    # The script reads WinAnsi from the codec, so it runs while the table cannot be imported.
    assert frozenset(pdf.WINANSI) == table.WINANSI


def _nfd_folded(text: str) -> str:
    """What the display path compared names by before the table: this Python's own NFD and
    case folding."""
    return unicodedata.normalize("NFD", unicodedata.normalize("NFD", text).casefold())


def test_each_character_folds_as_this_database_folds_it():
    # Every code point, one at a time: its decomposition, its folding and its class.
    characters = _table()
    _this_database(characters)
    assert [
        hex(point)
        for point in range(0x110000)
        if characters.folded(chr(point)) != _nfd_folded(chr(point))
    ] == []


# Marks of many combining classes (1, 10, 202, 216, 220, 230, 232, 233, 234, 240) and
# letters that decompose, fold to more than one letter or take a mark into their folding.
_MARKS = ("\u0334", "\u05b0", "\u0327", "\u031b", "\u0323", "\u0301", "\u0302", "\u035c")
_MARKS += ("\u0360", "\u0345", "\u0f71")
_BASES = ("e", "E", "\u00c9", "\u1ec7", "\u03b1", "\u1f88", "\u0130", "\u00df", "\u1e9e")
_BASES += ("\ufb01", "\u212a", "\u1e9b", "\ud55c", "\u1112", "\u0f73", "\u0390")


def test_a_run_of_marks_folds_as_this_database_folds_it():
    # Up to three marks after each letter, in every order: the table sorts them by class
    # before and after the folding, as NFD does.
    characters = _table()
    _this_database(characters)
    found = [
        ascii(text)
        for base in _BASES
        for count in (1, 2, 3)
        for marks in itertools.permutations(_MARKS, count)
        for text in [base + "".join(marks) + "x"]
        if characters.folded(text) != _nfd_folded(text)
    ]
    assert found == []


def test_each_run_of_the_table_starts_where_the_database_says():
    # Each code point where a category the renderers act on, or the width, changes, and
    # the one before it: the lookups read the table as the database has it.
    characters = _table()
    _this_database(characters)
    starts, before = [], None
    for point in range(0x110000):
        character = chr(point)
        found = (
            unicodedata.category(character),
            unicodedata.east_asian_width(character) in ("W", "F"),
        )
        if found != before:
            starts.append(point)
            before = found
    assert len(starts) > 2000
    for start in starts:
        for point in {max(start - 1, 0), start}:
            character = chr(point)
            name = unicodedata.category(character)
            assert characters.category(character) == (
                name if name in table.CATEGORIES else None
            ), hex(point)
            assert characters.wide(character) is (
                unicodedata.east_asian_width(character) in ("W", "F")
            ), hex(point)


# --- a character is what the table says, on every Python ------------------------------------


@pytest.mark.parametrize(
    ("point", "category", "wide"),
    [
        (0x0041, None, False),
        (0x0020, "Zs", False),
        (0x00A0, "Zs", False),
        (0x00AD, "Cf", False),
        (0x0301, "Mn", False),
        (0x0903, "Mc", False),
        (0x20DD, "Me", False),
        (0x200B, "Cf", False),
        (0x2028, "Zl", False),
        (0x2029, "Zp", False),
        (0x2060, "Cf", False),
        (0x3000, "Zs", True),
        (0x4E09, None, True),
        (0xD7AF, "Cn", False),
        (0xDCFF, "Cs", False),
        (0xE000, "Co", False),
        (0xFEFF, "Cf", False),
        (0x0378, "Cn", False),
        (0xA7CB, "Cn", False),
        (0x13439, "Cf", False),
        (0x1F600, None, True),
        (0xE0001, "Cf", False),
        (0x10FFFF, "Cn", False),
    ],
    ids=[
        "a letter",
        "the space",
        "a no-break space",
        "a soft hyphen",
        "a combining acute",
        "a spacing mark",
        "an enclosing mark",
        "a zero width space",
        "a line separator",
        "a paragraph separator",
        "a word joiner",
        "an ideographic space",
        "a CJK ideograph",
        "past the last Hangul syllable, wide on 3.11",
        "a lone surrogate",
        "private use",
        "a byte order mark",
        "unassigned, wide on 3.11",
        "a capital from Unicode 16.0.0",
        "a format character from Unicode 15.0.0, unassigned and wide on 3.11",
        "an emoji",
        "a tag",
        "the last code point",
    ],
)
def test_a_character_is_what_the_table_says(point, category, wide):
    characters = _table()
    assert characters.category(chr(point)) == category
    assert characters.wide(chr(point)) is wide


def test_the_spaces_a_terminal_value_loses_at_its_ends_are_the_tables():
    characters = _table()
    spaces = [0x20, 0xA0, 0x1680, *range(0x2000, 0x200B), 0x202F, 0x205F, 0x3000]
    assert [ord(space) for space in characters.SPACES] == spaces


def test_the_whitespace_and_line_breaks_python_splits_on_are_the_same_on_every_python():
    # split, strip, rstrip and lstrip with no argument, and splitlines, choose their
    # characters by the running Python's database, and the static guard lets them through
    # (tests/test_static_guards.py, unicode_violations): the renderers split words and
    # strip lines that way. These are the sets 3.11, 3.12 and 3.14 give, so a Python that
    # gives other ones fails here (the review of #326, round 2, n1).
    spaces = [*range(0x09, 0x0E), *range(0x1C, 0x21), 0x85, 0xA0, 0x1680]
    spaces += [*range(0x2000, 0x200B), 0x2028, 0x2029, 0x202F, 0x205F, 0x3000]
    breaks = [*range(0x0A, 0x0E), 0x1C, 0x1D, 0x1E, 0x85, 0x2028, 0x2029]
    points = range(0x110000)
    assert [point for point in points if chr(point).isspace()] == spaces
    assert [point for point in points if len(f"a{chr(point)}b".split()) == 2] == spaces
    assert [point for point in points if f"{chr(point)}a{chr(point)}".strip() == "a"] == spaces
    assert [point for point in points if len(f"a{chr(point)}b".splitlines()) == 2] == breaks


# --- a unit stays with an ASCII number, on every Python --------------------------------------

# Digits by str.isdigit on some Pythons and not others, or on all of them: a unit is never
# kept with one (the review of #326, round 1, M1).
DIGITS = [0x0663, 0x00B2, 0xFF15, 0x11F50, 0x16D70]
DIGIT_IDS = [
    "Arabic-Indic three",
    "superscript two",
    "fullwidth five",
    "a Kawi digit from Unicode 15.0.0",
    "a Kirat Rai digit from Unicode 16.0.0",
]


@pytest.mark.parametrize("point", DIGITS, ids=DIGIT_IDS)
def test_a_unit_stays_with_an_ascii_digit_only(point):
    assert terminal._kept(["5", "GB"]) == ["5 GB"]
    assert terminal._kept([f"5{chr(point)}", "GB"]) == [f"5{chr(point)}", "GB"]


@pytest.mark.parametrize(
    ("number", "tied"),
    [("10", True), ("19", True), ("1/", False), ("1:", False)],
    ids=[
        "ending in 0",
        "ending in 9",
        "ending in the slash before 0",
        "ending in the colon after 9",
    ],
)
def test_a_unit_stays_with_a_number_ending_in_either_end_of_the_ascii_digits(number, tied):
    # The review of #326, round 2, n2: the two ends of the digit test, and the characters
    # on either side of them.
    assert terminal._kept([number, "GB"]) == ([f"{number} GB"] if tied else [number, "GB"])


@pytest.mark.parametrize("point", [0x11F50, 0x16D70], ids=DIGIT_IDS[3:])
def test_a_name_ending_in_a_digit_of_one_python_wraps_the_same_on_every_python(point):
    # The reviewer's case: 3.11 and 3.12, or 3.12 and 3.14, wrapped this row apart.
    document = _named("x" * 55 + f" 5{chr(point)} GB")
    found = terminal.summary(document).splitlines()
    at = next(index for index, line in enumerate(found) if line.startswith("  Model"))
    assert found[at : at + 2] == [
        "  Model             " + "x" * 55 + f" 5{chr(point)}",
        " " * 20 + "GB, Mac17,2, model number MDE34LL/A",
    ]


# --- the PDF composes by the table ---------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "encoded", "replaced"),
    [
        ("e" + chr(0x0301), b"\xe9", 0),
        ("E" + chr(0x0341), b"\xc9", 0),
        ("A" + chr(0x030A), b"\xc5", 0),
        ("S" + chr(0x030C), b"\x8a", 0),
        (chr(0x212A), b"K", 0),
        (chr(0x212B), b"\xc5", 0),
        (chr(0x037E), b";", 0),
        (chr(0x0387), b"\xb7", 0),
        (chr(0x1FEF), b"`", 0),
        (chr(0x1FFD), b"\xb4", 0),
        # Only the mark right after a letter composes with it, and marks are never sorted.
        # NFC prints these three the same way:
        ("e" + chr(0x0301) * 2, b"\xe9?", 1),
        ("e" + chr(0x034F) + chr(0x0301), b"e??", 2),
        (chr(0x0301) + "e", b"?e", 1),
        # And these otherwise, as it sorts the marks by combining class first and composes
        # across one: U+1EB9 and U+0301 for the first two ("??"), U+1E09 and U+1E30 for the
        # last two ("?").
        ("e" + chr(0x0301) + chr(0x0323), b"\xe9?", 1),
        ("e" + chr(0x0323) + chr(0x0301), b"e??", 2),
        ("c" + chr(0x0327) + chr(0x0301), b"\xe7?", 1),
        (chr(0x212A) + chr(0x0301), b"K?", 1),
    ],
    ids=[
        "a letter and its mark",
        "a mark canonically the acute",
        "a ring above",
        "a caron, to WinAnsi's 0x8A",
        "the Kelvin sign",
        "the Angstrom sign",
        "the Greek question mark",
        "the Greek ano teleia",
        "the Greek varia",
        "the Greek oxia",
        "a second mark",
        "a grapheme joiner between",
        "a mark before its letter",
        "a mark that sorts first, after",
        "a mark that composes to no WinAnsi letter, first",
        "a mark after a cedilla",
        "a mark after the Kelvin sign",
    ],
)
def test_the_pdf_composes_a_letter_and_the_mark_after_it_and_nothing_more(text, encoded, replaced):
    # characters.composed: one pass from the left, by the table alone, so the output is the
    # same on every Python.
    assert pdf.encode(text) == (encoded, replaced)


# --- the PDF counts every character outside WinAnsi, and the terminal drops what it strips ---

FORMATS = [0x200B, 0x2060, 0xFEFF, 0x00AD, 0x13439]
FORMAT_IDS = [
    "a zero width space",
    "a word joiner",
    "a byte order mark",
    "a soft hyphen",
    "a format character from Unicode 15.0.0",
]


@pytest.mark.parametrize("point", FORMATS, ids=FORMAT_IDS)
def test_a_format_character_in_a_name_prints_as_a_question_mark_in_the_pdf(point):
    document = _named(f"AB{chr(point)}CD")
    said = _pdf_text(document)
    assert "AB?CD (Mac17,2), Apple M5. 23 Sep 2026, 14:05 (UTC-7)." in said
    assert "Model AB?CD, Mac17,2, model number MDE34LL/A" in said
    # The identity line, the row and the running header, which counts once.
    assert _replaced(document) == 3
    assert "Characters replaced 3 characters outside the PDF's character set were" in said


@pytest.mark.parametrize("point", FORMATS, ids=FORMAT_IDS)
def test_the_terminal_drops_a_format_character_in_a_name(point):
    found = terminal.summary(_named(f"AB{chr(point)}CD")).splitlines()
    assert found[2].startswith("ABCD (Mac17,2), Apple M5. 23 Sep 2026, 14:05 (UTC-7).")
    assert "  Model             ABCD, Mac17,2, model number MDE34LL/A" in found


def test_a_letter_and_its_mark_in_a_name_print_as_one_letter_in_the_pdf():
    document = _named("Mace" + chr(0x0301))
    said = _pdf_text(document)
    assert "Mac\u00e9 (Mac17,2), Apple M5." in said
    assert _replaced(document) == 0
    assert "Characters replaced none" in said
    found = terminal.summary(document).splitlines()
    assert found[2].startswith("Mace\u0301 (Mac17,2), Apple M5.")


def test_a_space_outside_winansi_in_a_name_is_counted_in_the_pdf_and_kept_in_the_terminal():
    # The identity line parts the names at U+0020 alone, so the PDF never prints another
    # space as one it does not count.
    document = _named("Mac" + chr(0x3000) + "Pro")
    said = _pdf_text(document)
    assert "Mac?Pro (Mac17,2), Apple M5." in said
    assert _replaced(document) == 3
    found = terminal.summary(document).splitlines()
    assert found[2].startswith("Mac\u3000Pro (Mac17,2), Apple M5.")


@pytest.mark.parametrize(
    ("maker", "in_terminal", "in_pdf", "replaced"),
    [
        (" ", "(manufacturer empty)", "(manufacturer empty)", 0),
        (chr(0xA0) * 2, "(manufacturer empty)", "(manufacturer empty)", 0),
        (chr(0x200B), "(manufacturer empty)", "(\u200b)", 1),
        (chr(0x3164), "(manufacturer empty)", "(\u3164)", 1),
        (chr(0x3000), "(manufacturer empty)", "(\u3000)", 1),
        (chr(0x3000) + "Micron" + chr(0x3000), "(Micron)", "(\u3000Micron\u3000)", 2),
        (" Micron" + chr(0xA0), "(Micron)", "(Micron)", 0),
    ],
    ids=[
        "a space",
        "no-break spaces",
        "a zero width space",
        "a Hangul filler",
        "an ideographic space",
        "ideographic spaces at the ends",
        "spaces at the ends",
    ],
)
def test_a_value_is_empty_by_what_each_renderer_would_print(maker, in_terminal, in_pdf, replaced):
    # The terminal drops what clean() drops and the spaces at either end; the PDF drops
    # only the spaces it draws blank, and prints every other character or counts it.
    document = T.edited("m5-laptop", T._set("memory_configuration", "manufacturer", maker))
    assert T.row(document, "THIS MAC", "Memory") == f"24 GB LPDDR5 {in_terminal}"
    made, asked = pages.composed(document)
    (memory,) = [row for row in pages.section_rows(asked, "This Mac") if row.label == "Memory"]
    assert memory.text == f"24\u00a0GB LPDDR5 {in_pdf}"
    assert made.replaced == replaced


def test_a_status_is_read_as_the_terminal_prints_it_in_both_renderers():
    # The limits bullet turns on the status the terminal shows, so the PDF, which prints
    # the zero width space as "?", gives the same bullets.
    document = T.edited("m5-laptop", T._set("nvme_devices", "smart_status", "Fail\u200bing"))
    bullet = "Why the SSD reports a warning, or whether it will fail."
    assert T.row(document, "STORAGE HEALTH AND WEAR", "SMART status") == "Failing reported"
    assert bullet in terminal.summary(document)
    made, asked = pages.composed(document)
    (status,) = [
        row
        for row in pages.section_rows(asked, "Storage health and wear")
        if row.label == "SMART status"
    ]
    assert status.text == "Fail\u200bing"
    assert bullet in " ".join(pages.page_words(page) for page in made.pages)


@pytest.mark.parametrize(
    "profile",
    ["24 GB\u200b", "24 GB\u3000", "\u200b24 GB", "24\u200b GB"],
    ids=[
        "a zero width space at the end",
        "an ideographic space at the end",
        "at the start",
        "inside",
    ],
)
def test_the_memory_sizes_are_compared_as_the_terminal_prints_them_in_both_renderers(profile):
    # The review of #326, round 1, M3: the PDF, which prints the format character or the
    # space as a counted "?", said the two sizes disagreed, and the terminal did not.
    document = T.edited("m5-laptop", T._set("memory_configuration", "size_text", profile))
    assert T.row(document, "THIS MAC", "Memory") == "24 GB LPDDR5 (Micron)"
    _, asked = pages.composed(document)
    (memory,) = [row for row in pages.section_rows(asked, "This Mac") if row.label == "Memory"]
    assert memory.text == "24\u00a0GB LPDDR5 (Micron)"


def test_sizes_that_disagree_are_named_in_both_renderers():
    document = T.edited("m5-laptop", T._set("memory_configuration", "size_text", "32 GB\u200b"))
    said = "24 GB LPDDR5 (Micron); the memory profile says 32 GB"
    assert T.row(document, "THIS MAC", "Memory") == said
    _, asked = pages.composed(document)
    (memory,) = [row for row in pages.section_rows(asked, "This Mac") if row.label == "Memory"]
    assert memory.text == "24\u00a0GB LPDDR5 (Micron); the memory profile says 32\u00a0GB\u200b"


# --- the home folder is matched by the table ------------------------------------------------


@pytest.mark.parametrize(
    ("path", "home", "shown"),
    [
        ("/Users/OWNER/x", "/users/owner", "~/x"),
        ("/Users/JOSE" + chr(0x0301) + "/x", "/Users/jos\u00e9", "~/x"),
        ("/Users/\u00c9MILE/x", "/Users/\u00e9mile", "~/x"),
        ("/Users/\u0160/x", "/Users/\u0161", "~/x"),
        ("/Users/" + chr(0x212A) + "im/x", "/Users/kim", "~/x"),
        ("/Users/" + chr(0xA7CB) + "/x", "/Users/\u0264", "/Users/\\ua7cb/x"),
        ("/Users/\u0141ukasz/x", "/Users/\u0142ukasz", "~/x"),
        ("/Users/e" + chr(0x0323) + chr(0x0301) + "/x", "/Users/e\u0301\u0323", "~/x"),
    ],
    ids=[
        "ASCII capitals",
        "a decomposed capital",
        "a Latin-1 capital",
        "a WinAnsi capital past Latin-1",
        "the Kelvin sign",
        "a capital from Unicode 16.0.0, unassigned in the table",
        "another script's capital",
        "two marks in another order",
    ],
)
def test_the_home_folder_is_matched_by_the_table(path, home, shown):
    # Folding by the running Python showed a path under ~ on one Python and in full on
    # another (U+A7CB folds to U+0264 on 3.14 only). The table folds as Unicode 15.0.0 does.
    assert terminal.display_path(path, home) == shown


# The review of #326, round 1, M2: each path names the home folder in another case or
# normalization, as the default APFS volume matches it. Made-up names.
TILDE = [
    ("/Users/jane", "/Users/JANE/Desktop/r.pdf", "~/Desktop/r.pdf"),
    ("/Volumes/Donn\u00e9es/jane", "/Volumes/DONN\u00c9ES/jane/r.pdf", "~/r.pdf"),
    ("/Volumes/\u03a9mega/jane", "/Volumes/\u03c9mega/jane/r.pdf", "~/r.pdf"),
    ("/Users/\u0418\u0432\u0430\u043d", "/Users/\u0438\u0432\u0430\u043d/r.pdf", "~/r.pdf"),
    ("/Users/Jos\u00e9", "/Users/Jose\u0301/r.pdf", "~/r.pdf"),
    ("/Users/\u1ec7x", "/Users/e\u0323\u0302x/r.pdf", "~/r.pdf"),
    ("/Users/\ud55c", "/Users/\u1112\u1161\u11ab/r.pdf", "~/r.pdf"),
    ("/Users/stra\u00dfe", "/Users/STRASSE/r.pdf", "~/r.pdf"),
    ("/Users/Kate", "/Users/\u212aate/r.pdf", "~/r.pdf"),
    ("/Users/J\u0101nis", "/Users/Ja\u0304nis/r.pdf", "~/r.pdf"),
    ("/Users/\u010cech", "/Users/C\u030cech/r.pdf", "~/r.pdf"),
]
TILDE_IDS = [
    "ASCII case",
    "WinAnsi case",
    "Greek case",
    "Cyrillic case",
    "one mark, decomposed",
    "two marks, decomposed",
    "a Hangul syllable, decomposed",
    "sharp s",
    "the Kelvin sign",
    "a macron, outside WinAnsi",
    "a caron, outside WinAnsi",
]


@pytest.mark.parametrize(("home", "path", "shown"), TILDE, ids=TILDE_IDS)
def test_a_path_under_the_home_folder_prints_with_a_tilde_whatever_its_case_or_form(
    home, path, shown
):
    # The spec's renderers row: "the home folder as ~". The table's folding printed the
    # account name for seven of these (the review of #326, round 1, M2).
    assert terminal.display_path(path, home) == shown
