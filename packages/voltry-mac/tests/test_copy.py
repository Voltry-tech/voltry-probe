"""The copy (docs/VOLTRY_MAC_SPEC.md: the copy policy under "Fixed notes", Test strategy
"Copy", the Acceptance line on prohibited constructions, "What the README will say", and
the Architecture's "Terminal summary at 80 columns").

Every message voltry-mac prints around the report is golden text in
tests/golden/copy/transcripts.txt, made by tests/copy_golden.py, beside the terminal
summaries in tests/golden/terminal and the golden PDFs; the words no scenario prints whole
(render's problems, the output writer's reasons, the command line's help and refusals) are in
tests/golden/copy/strings.txt, read from the source with every space and line break kept.
Each scenario prints exactly its golden, down to where each stream ends, and every line fits
80 columns but the kinds never wrapped, so they copy whole: a --debug line, a "Saved:" line,
and on a line of its own a path, the field render refuses or a command; indented prose is
measured. --help fits too, and so does the usage block a usage error prints, the spec's. No
golden, the dry run and the usage included, no fixture's JSON, terminal summary or PDF, and
not the README carries a prohibited construction outside the fixed lines that say what the
report does not do, an em or en dash, or the stock AI phrasing; render's refusal may name
the report's value keys, as the copy policy allows for the JSON key, and nothing else by
that word. The README says what the spec says it will: a preview, the uv-first install word
for word and pipx second, the command's usage, the validated configurations the run itself
uses, the pinned install and the uninstall, what the product contract says about files, the
network and a run that is killed, and where to report a problem and what to send.
"""

from __future__ import annotations

import io
import itertools
import json
import os
import re
from pathlib import Path

import pypdf
import pytest
import voltry_mac_test_copy_golden as golden
import voltry_mac_test_pdf_goldens as pdf_goldens
import voltry_mac_test_pdf_pages as pages

import voltry_mac
from voltry_mac import allowlist, appendices, cli, preflight, run, spawn, tracking, wording, writer

T = pages.terminal_tests()
PACKAGE = Path(__file__).resolve().parents[1]
README = (PACKAGE / "README.md").read_text(encoding="utf-8")
CHANGELOG = (PACKAGE / "CHANGELOG.md").read_text(encoding="utf-8")
SPEC = (PACKAGE.parents[1] / "docs" / "VOLTRY_MAC_SPEC.md").read_text(encoding="utf-8")
TRANSCRIPTS = golden.GOLDEN.read_text(encoding="utf-8")
STRINGS = golden.STRINGS.read_text(encoding="utf-8")
STRING_SECTIONS = dict(
    block.split("\n", 1) for block in STRINGS.removeprefix("=== ").split("\n=== ")
)
PROBE_README = (PACKAGE.parent / "voltry-probe" / "README.md").read_text(encoding="utf-8")
DRY_RUN = (PACKAGE / "tests" / "golden" / "dry_run.txt").read_text(encoding="utf-8")
SECTIONS = golden.sections(TRANSCRIPTS)
TERMINAL = sorted((PACKAGE / "tests" / "golden" / "terminal").glob("*.txt"))
DEBUG_LINE = re.compile(r"[CXPSO][0-9]+n? ")
# The other lines never wrapped, so they copy whole, each kind named: a transcript's own
# command line, a Saved: line, and, indented on a line of its own, a path (absolute, under the
# home folder, or a name as a scenario typed it), the field render refuses, and the survivor
# note's two commands. Any other indented line is prose, and is measured (the copy pass's
# review, round 3, n5).
WHOLE = re.compile(
    r"\$ voltry-mac|Saved: "
    r"|  (~?/|report\.json$|missing)"
    r"|  (time_zone$|surfaces\[|\(top level\)$)"
    r"|  (ps -p|sudo /bin/kill -TERM) [0-9]+"
)

# The stock phrasing of generated text, which the copy rule keeps out of anything a person
# reads: exact patterns, like the prohibited constructions.
AI_PHRASING = [
    r"\bdelv\w*",
    r"\btapestry\b",
    r"\btestament\b",
    r"\bin today's\b",
    r"\bseamless(ly)?\b",
    r"\brobust\w*",
    r"\bleverag\w*",
    r"\bcomprehensive\b",
    r"\bunlock(s|ed|ing)?\b",
    r"\bempower\w*",
    # "elevated" is the spec's own word for the administrator reads, so it stays allowed.
    r"\belevat(e|es|ing)\b(?! (access|privileges?|reads?))",
    r"\bcutting[- ]edge\b",
    r"\bgame[- ]chang",
    r"\bnavigat\w* the\b",
    r"\bit('?s| is) (important|worth) (to note|noting)\b",
    r"\brest assured\b",
    r"\bembark",
    r"\brealms?\b",
    r"\bvibrant\b",
    r"\bfurthermore\b",
    r"\bmoreover\b",
    r"\bin conclusion\b",
    r"\bcrucial\w*",
    r"\bpivotal\b",
    r"\bstreamlin",
    r"\bholistic\b",
    r"\bsynerg",
    r"\bbest[- ]in[- ]class\b",
    r"\bstate[- ]of[- ]the[- ]art\b",
    r"\bmeticulous",
    r"\bparamount\b",
    r"\bground[- ]?breaking\b",
    r"\brevolutioni[sz]",
    r"\btransformative\b",
    r"\bsupercharg",
    r"\bfoster\w*",
    r"\bbolster",
    r"\bshowcas",
    r"\bdive (in|into|deep)\b",
    r"\bdeep dive\b",
    r"\bpeace of mind\b",
    r"\bhassle[- ]free\b",
    r"\beffortless",
    r"\bworld[- ]class\b",
    r"\bgo-to\b",
    r"\bstand(s|ing)? out\b",
    # Common tells the first list missed (the copy pass's review, round 1, m4).
    r"\butiliz\w*",
    r"\bfacilitat\w*",
    r"\bharness\w*",
    r"\bmyriad\b",
    r"\bplethora\b",
    r"\blandscape\b",
    r"\bever[- ]evolving\b",
    r"\btailored\b",
    r"\bboasts?\b",
    r"\bunderscor\w*",
    r"\badditionally\b",
    # And more the second round found (the copy pass's review, round 2, m3).
    r"\bin summary\b",
    r"\bnotably\b",
    r"\bintricate\b",
    r"\bnuanced\b",
    r"\bunparalleled\b",
    # And the third's (the copy pass's review, round 3, m3).
    r"\bworth mentioning\b",
    r"\bin essence\b",
    r"\bat its core\b",
    r"\bintricac(y|ies)\b",
    r"\bnuances?\b",
    r"\bunprecedented\b",
    r"\bunleash\w*",
    r"\bembrac\w*",
    r"\blet's explore\b",
    r"\bpave(s|d)? the way\b",
    r"\bshed(s|ding)? light\b",
    r"\btreasure trove\b",
]
# The fixed lines that say what the report does not do: the only place the prohibited
# constructions may appear (the copy policy), in the tool and in the README alike.
FIXED = (
    wording.DISCLAIMER,
    *wording.FIXED_NOTES.values(),
    "Value or price. Voltry does not assess either.",
    "nothing here shows how it was used, or how long it will last.",
)
DASHES = ("–", "—")
# The Product contract's "Instead of" column: claims the tool does not control, so no copy it
# publishes may make them, in any form (the GPT audit, pass 5, G5-01: the 0.1.0 release notes
# said it changed nothing, when it clears the remembered sudo authorization; pass 6, G6-01;
# pass 7, G7-01). Each claim may take up to three words between its parts, auxiliaries
# ("has been", "will have") or adverbs, and a colon or a comma after the verb. Leaving is about
# the Mac itself: nothing is left on a disk the save could not use.
_WORDS = r"(?:[\w']+\s+){0,3}"
_CHANGE = r"(?:change|changes|changed|changing)"
REPLACED = re.compile(
    rf"\b{_CHANGE}[\s:,]+(?:[\w']+[\s,]+){{0,2}}nothing\b"
    rf"|\bnothing\s+{_WORDS}{_CHANGE}\b"
    rf"|\b(?:nothing|no\s+(?:report\s+)?data)\s+{_WORDS}(?:leave|leaves|left|leaving)"
    r"\s+(?:this|the|your)\s+Mac\b"
    rf"|\bnothing\s+{_WORDS}(?:persist|persists|persisted|persisting)\b"
    rf"|(?:\bnot|n't|\bnever)\s+{_WORDS}{_CHANGE}\s+anything\b"
    r"|\bmakes?\s+no\s+changes?\b",
    re.IGNORECASE,
)
# Appendix B's row for a run that never prepared sudo, as flattened text reads it: the label
# runs into the value's first sentence, "Nothing: the administrator reads did not run, so
# voltry-mac left the sudo authorization as it was.", a statement of that run. That row,
# exactly, is the one text the check sets aside; anything else under the label is checked.
UNCHANGED_ROW = " ".join(f"What it changes {appendices.UNCHANGED.split('. ', 1)[0]}.".split())


def _replaced(said: str) -> re.Match[str] | None:
    """The first claim the Product contract replaced, with Appendix B's one row set aside."""
    return REPLACED.search(said.replace(UNCHANGED_ROW, " "))


# The phrases in which render's problems name the report's own values, the spec's word for
# them, as the copy policy allows for the JSON key; any other "value" is still refused (the
# copy pass's review, round 2, m4).
VALUE_KEYS = (
    r"\bvalue keys?\b",
    r"\bcomputed value\b",
    r"\b(un)?available value\b",
    r"\bthis value (may carry|is unavailable)\b",
    r"\bno value is not applicable\b",
    r"\bfirst value's command\b",
)
# render's refusal, from its first line to the field or file below it: the only lines of the
# transcripts those phrases pass in (the copy pass's review, round 3, n3).
RENDER_REFUSAL = re.compile(r"^Could not render this file.*?(?=^  )", re.MULTILINE | re.DOTALL)


def _flat(text: str) -> str:
    """Text with its line breaks and runs of spaces as single spaces, as it reads, a curly
    apostrophe, either way round, as a straight one, and no soft hyphen inside a word."""
    said = re.sub(r"\s+", " ", text).replace(chr(0xAD), "")
    return said.replace(chr(0x2018), "'").replace(chr(0x2019), "'")


def _check(label: str, text: str, *, prohibited: bool = True, exempt: tuple[str, ...] = ()) -> None:
    for dash in DASHES:
        assert dash not in text, (label, "a dash")
    said = _flat(text)
    replaced = _replaced(said)
    assert replaced is None, (
        label,
        "a claim the Product contract replaced",
        said[max(0, replaced.start() - 40) : replaced.end() + 40],
    )
    for pattern in AI_PHRASING:
        found = re.search(pattern, said, re.IGNORECASE)
        assert found is None, (label, pattern, said[max(0, found.start() - 40) : found.end() + 40])
    if prohibited:
        for fixed in FIXED:
            said = said.replace(fixed, " ")
        for phrase in exempt:
            said = re.sub(phrase, " ", said, flags=re.IGNORECASE)
        for pattern in T.PROHIBITED:
            found = re.search(pattern, said, re.IGNORECASE)
            assert found is None, (
                label,
                pattern,
                said[max(0, found.start() - 40) : found.end() + 40],
            )


def _check_transcripts(text: str) -> None:
    """The copy rules over the transcripts: render's refusals may name a value key, and no
    other line may."""
    for refusal in RENDER_REFUSAL.findall(text):
        _check("render's refusal", refusal, exempt=VALUE_KEYS)
    _check("the transcripts", RENDER_REFUSAL.sub("\n", text))


# --- the messages ---------------------------------------------------------------------------


@pytest.mark.parametrize("scenario", golden.SCENARIOS, ids=[s.name for s in golden.SCENARIOS])
def test_each_scenario_prints_its_golden(scenario):
    assert golden.transcript(scenario) == SECTIONS[scenario.name]


def test_the_golden_holds_every_scenario_once_in_order():
    assert list(SECTIONS) == [s.name for s in golden.SCENARIOS]


def test_a_transcript_shows_where_each_stream_ends():
    # A lost last line break, or a blank line after it, changes the golden, --version's
    # included (the copy pass's review, round 3, m1).
    assert golden._stream("Rosetta no\n") == "Rosetta no"
    assert golden._stream("Rosetta no\n\n") == "Rosetta no\n"
    assert golden._stream("Rosetta no") == f"Rosetta no\n{golden.NO_LINE_BREAK}"
    assert SECTIONS["--version"].endswith("\nRosetta {rosetta}\n--- exit 0\n")


def test_every_line_fits_80_columns_but_a_debug_line_a_path_or_a_command():
    long = [
        line
        for line in TRANSCRIPTS.splitlines()
        if len(line) > 80 and not DEBUG_LINE.match(line) and not WHOLE.match(line)
    ]
    assert long == []
    # The explanation's indented lines are prose, so they are measured too (the copy pass's
    # review, round 3, n5).
    steps = [line for line in run.EXPLANATION.split("\n") if line.startswith("  ")]
    assert len(steps) == 7 and [line for line in steps if WHOLE.match(line)] == []


def test_a_path_longer_than_80_columns_is_printed_whole():
    # Wrapping it would break a copy and paste; so the three kinds above are never wrapped.
    folder = "  ~/" + "/".join(["a folder with a long name"] * 3)
    assert len(folder) > 80
    assert f"\n{folder}\n" in SECTIONS["--output a long folder that does not exist"]


def test_the_dry_run_prose_fits_80_columns():
    # The command lines print whole, exactly as they run; the words around them wrap, the
    # in-process reads' first lines included (the copy pass's review, round 2, n6).
    prose = [line for line in DRY_RUN.splitlines() if not re.match(r"  [CXPSO][0-9]+n? ", line)]
    assert [line for line in prose if len(line) > 80] == []


@pytest.mark.parametrize("argv", [["--help"], ["render", "--help"]], ids=str)
def test_help_fits_80_columns(capsys, monkeypatch, argv):
    # Every line, the epilog's two (the copy pass's review, round 2, M1) and the usage
    # block's included: its dry-run line says "print every command it can run; run none",
    # as the owner chose on 2026-09-28 for round 1's m2 (change record 24). --help prints on
    # a Mac the preflight lets through (change record 2).
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    monkeypatch.setattr(preflight, "read", lambda **_: golden.fm.SUPPORTED)
    assert cli.main(argv) == 0
    assert [line for line in capsys.readouterr().out.splitlines() if len(line) > 80] == []


@pytest.mark.parametrize(
    "argv", [["--frobnicate"], ["render"], ["--json", "render", "report.json"]], ids=str
)
def test_a_usage_error_fits_80_columns(capsys, monkeypatch, argv):
    # A usage error prints the usage block above its own line, on a Mac the preflight lets
    # through: an unknown flag, render with no file, and render's own refusal (change record
    # 24). The line below the block is the tool's own, the same on every Python (the GPT
    # audit, pass 2, G2-01); only an argument it names, which prints whole on a line of its
    # own as a path does, can pass 80.
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    monkeypatch.setattr(preflight, "read", lambda **_: golden.fm.SUPPORTED)
    assert cli.main(argv) == cli.EXIT_USAGE
    said = capsys.readouterr().err
    assert said.startswith("usage: voltry-mac ")
    assert [line for line in said.splitlines() if len(line) > 80] == []


def test_the_usage_block_is_the_specs():
    # --help prints the spec's block after "usage: ", with the lines below it indented to
    # match, so the golden and the spec change together (change record 24).
    block = _fenced_after(SPEC, "## CLI transcripts", "text").split("\n\n")[0].split("\n")
    shown = [("usage: " if k == 0 else " " * 7) + line for k, line in enumerate(block)]
    usage = (PACKAGE / "tests" / "golden" / "usage.txt").read_text(encoding="utf-8")
    assert "\n".join(shown) + "\n" == usage


def test_record_24_says_what_prints_below_the_usage_block_now():
    # The line below the block is the tool's own since the GPT audit's pass 2 (G2-01), and
    # record 24 says so, as a correction (the pre-audit of the audit's pass 3, control 08).
    start = SPEC.index("### Change record 24, ")
    end = SPEC.find("\n### ", start + 1)
    record = SPEC[start:] if end < 0 else SPEC[start:end]
    assert "argparse's own error line below the block, whose words are Python's" not in record
    assert "that line is the tool's own, the same on every Python" in record
    assert "Corrected on 2026-09-28, as a correction rather than part of the owner's" in record


def test_a_word_longer_than_80_columns_is_never_split():
    # A message wraps at spaces only, so a word longer than a line keeps a line of its own.
    word = "k" * 90
    assert run._wrapped(f"Could not render this file: {word} is not allowed.") == (
        f"Could not render this file:\n{word}\nis not allowed."
    )


def test_a_path_or_a_command_stands_on_a_line_of_its_own():
    # So wrapping never splits one: the survivor note's two commands, and the folder or file a
    # refusal names (the copy pass of MAC 3.11).
    said = SECTIONS["a process outlives the power sample"]
    assert "\n  ps -p 4242 -o pid,uid,lstart,comm\n" in said
    assert "\n  sudo /bin/kill -TERM 4242\n" in said
    assert "\n  missing\\x1b[2J\n" in SECTIONS["--output a folder that does not exist"]
    assert "\n  report.json\n" in SECTIONS["render a folder"]
    # And the field render refuses, above the file, however long its path or its key's spaces
    # (the copy pass's review, round 2, m2).
    spaced = SECTIONS["render a report with an unknown key that has spaces"]
    assert (
        "\nnot a value key of this surface.\n"
        "  surfaces[0].values['a key with spaces in it, as a report can hold']\n"
        "  report.json\n"
    ) in spaced
    long = SECTIONS["render a report with an unknown key of 64 characters"]
    assert f"\n  surfaces[0].values.{'k' * 64}\n  report.json\n" in long


def test_renders_refusal_says_the_field_below_is_wrong_then_why():
    # A problem is mostly written to follow its field, so the line above it gives it its
    # subject, and the field keeps a line of its own (the copy pass's review, round 3, n1).
    assert (
        "Could not render this file. The field below is wrong:\n"
        "must be an IANA identifier or unknown.\n"
        "  time_zone\n"
        "  report.json\n"
    ) in SECTIONS["render a report that fails validation"]


def test_a_refused_top_level_key_names_the_top_level_as_its_field():
    # Both ways the reader refuses a top-level key print one label, which only canonical.py
    # spells, and the strings golden reads it where a field falls back to it, so a label
    # spelled at any of the four places that refuse the top level changes a golden (the copy
    # pass's review, round 3, m1).
    assert "(top level)" in golden.texts(STRING_SECTIONS["render's problems"])
    for problem, key in (
        ("a key longer than 64 characters", "a top-level key of 65 characters"),
        (
            "a control, separator, bidirectional or surrogate character",
            "a top-level key that holds a control character",
        ),
    ):
        said = SECTIONS[f"render a report with {key}"]
        assert f"\n{problem}.\n  (top level)\n  report.json\n" in said
    spelled = [
        path.name
        for path in sorted(golden.PACKAGE.glob("*.py"))
        for _ in range(path.read_text(encoding="utf-8").count('"(top level)"'))
    ]
    assert spelled == ["canonical.py"]


def test_the_survivor_note_leaves_no_word_alone_and_keeps_its_start_time_whole():
    # The check starts a line of its own, so wrapping never leaves "with" alone above its
    # command, whatever the process ID, user ID, name and start time, and no line passes 80
    # (the copy pass's review, round 3, n4).
    for pid, uid, name, started in itertools.product(
        (1, 42, 4242, 99998),
        (0, 1, 283, 501, 4294967294),
        (*tracking.SUBTREE_NAMES, "Jane's Helper"),
        ("Wed Sep 23 14:05:40 2026", "Thu Oct  1 09:00:00 2026", "Sun Oct 11 23:59:59 2026"),
    ):
        survivor = tracking.Survivor(pid=pid, uid=uid, name=name, started=started)
        lines = run._wrapped(tracking.survivor_note(survivor)).split("\n")
        assert [line for line in lines if len(line.split()) < 2] == [], lines
        assert [line for line in lines if len(line) > 80] == [], lines
        assert any(started in line for line in lines), lines


def test_the_messages_follow_the_copy_rules():
    _check_transcripts(TRANSCRIPTS)


def test_only_renders_refusal_may_name_a_value_key():
    # Anywhere else the word is refused, even in a phrase render may use (the copy pass's
    # review, round 3, n3).
    for line in (
        "The computed value of this Mac could not be read.",
        "Voltry's computed value for this Mac is 900.",
    ):
        with pytest.raises(AssertionError):
            _check_transcripts(f"{TRANSCRIPTS}{line}\n")


def test_the_words_no_scenario_prints_whole_are_golden():
    assert golden.strings() == STRINGS


def test_the_strings_golden_spells_each_text_as_the_source_does():
    # Every space and line break as the source has it, so a doubled space or a line break
    # added or taken away changes the golden (the copy pass's review, round 2, M1).
    reasons = golden.texts(STRING_SECTIONS["the output writer's reasons"])
    command_line = golden.texts(STRING_SECTIONS["the command line"])
    assert sorted(reasons) == sorted(writer.REASONS)
    assert cli._EPILOG in command_line and cli.RENDER_ONLY in command_line
    # A line break shows as \n, so the golden stays one text to a line.
    assert "for this Mac. Point-in-time\\nobservations, not a diagnosis" in STRINGS


def test_every_usage_error_is_golden_in_the_tools_own_words():
    # The GPT audit, pass 2, G2-01: argparse's own lines echoed what was typed and differed
    # between Pythons; every usage error is the tool's now, and each is golden, in the
    # strings and in a transcript.
    command_line = golden.texts(STRING_SECTIONS["the command line"])
    words = (
        cli.NOT_TAKEN_ONE,
        cli.NOT_TAKEN_MANY,
        cli.PAPER_SIZES,
        cli.NEEDS_FOLDER,
        cli.NEEDS_REPORT,
        cli.NO_ARGUMENT,
        cli.UNREAD,
        cli.RENDER_ONLY,
    )
    for each in words:
        assert each in command_line, each
        said = each.format(option="--json")
        assert any(f"\n{said}\n" in section for section in SECTIONS.values()), said
        assert len(said) <= 80
    assert "error:" not in TRANSCRIPTS


def test_the_words_no_scenario_prints_whole_follow_the_copy_rules():
    assert list(STRING_SECTIONS) == [
        "render's problems",
        "the output writer's reasons",
        "the command line",
    ]
    # A problem may name the report's own values by their value keys, as the copy policy
    # allows for the JSON key; never a figure of what the Mac is worth.
    for title, section in STRING_SECTIONS.items():
        exempt = VALUE_KEYS if title == "render's problems" else ()
        for text in golden.texts(section):
            _check(f"{title}: {text}", text, exempt=exempt)


@pytest.mark.parametrize("name", ["dry_run.txt", "usage.txt", "help.txt", "render_help.txt"])
def test_the_dry_run_and_the_usage_follow_the_copy_rules(name):
    # The copy pass's review, round 2, m4: every golden the tool prints, the whole help too.
    _check(name, (PACKAGE / "tests" / "golden" / name).read_text(encoding="utf-8"))


def test_every_debug_ending_follows_the_copy_rules():
    # Every way --debug can say a command or a payload ended, beyond what the scenarios show:
    # words the README asks an owner to send (the copy pass's review, round 2, M1).
    ended = spawn.Ending
    results = [
        spawn.Result("C1", ending, code, "", "", 3, False, reaped, eperm=eperm)
        for ending, code in (
            (ended.EXITED, 1),
            (ended.SIGNALED, -6),
            (ended.NOT_STARTED, None),
            (ended.DEADLINE, -9),
            (ended.DEADLINE, 0),
            (ended.OUTPUT_CAP, -15),
            (ended.CANCELLED, -15),
        )
        for reaped, eperm in ((True, False), (False, False), (False, True))
    ]
    stranger = tracking.Survivor(4243, 0, "Wed Sep 23 14:05:40 2026", "Jane's Helper")
    runs = [
        *(golden.fm.payload_run("S4", forced=forced) for forced in sorted(spawn.FORCED_ENDINGS)),
        golden.fm.payload_run("S4", started=False, returncode=None),
        golden.fm.payload_run("S4", cancelled=True, returncode=None),
        golden.fm.payload_run("S4", returncode=-15, cleanup="listing_failed"),
        golden.fm.payload_run("S4", returncode=1, cleanup="survivor", survivors=(stranger,)),
    ]
    lines = [spawn.debug_line(result) for result in results]
    _check("--debug", "\n".join([*lines, *(run._payload_line(each) for each in runs)]))


# render's problems that name a value, as the strings golden holds them.
VALUE_PROBLEMS = [
    text
    for text in golden.texts(STRING_SECTIONS["render's problems"])
    if re.search(r"\bvalue\b", text)
]


def test_render_names_a_value_key_and_never_a_worth():
    # Each problem that names a value passes as render prints it, at a field above the file;
    # any other use of the word is still refused (the copy pass's review, round 2, m4).
    assert len(VALUE_PROBLEMS) == 10
    for problem in VALUE_PROBLEMS:
        field, path = "surfaces[0].values.x", "report.json"
        _check_transcripts(run.RENDER_REFUSED_AT.format(problem=problem, field=field, path=path))
    for worth in (
        "the value of this Mac could not be read",
        "a value for this Mac: 900",
        "It holds its value.",
        "It has no value.",
        "this value is fair",
    ):
        with pytest.raises(AssertionError):
            _check(worth, worth, exempt=VALUE_KEYS)


# What the copy rules must refuse (the copy pass's review, round 2, m3): the verdicts,
# grades, prices and predictions the copy policy forbids, and the stock phrasing.
SLIPS = [
    "Memory: no errors.",
    "No issues found.",
    "The SSD is passing.",
    "Rated 9 out of 10.",
    "A rating of B+.",
    "Its valuation is about 900.",
    "A valuable Mac.",
    "Worthless after five years.",
    "This Mac is overpriced.",
    "The battery's lifespan is about two years.",
    "It should last three more years.",
    "In mint condition.",
    "In pristine condition.",
    "Like-new battery.",
    "Healthier than most.",
    "The Mac is reliable.",
    "Verdict: fine.",
    "It is safe.",
    "It is important to note the limits.",
    "It\u2018s important to note the limits.",
    "Let's dive in.",
    "In summary, the report is complete.",
    "Notably, the battery reads well.",
    "An intricate report.",
    "A nuanced report.",
    "An unparalleled look at your Mac.",
    "Standing out from the crowd.",
    "Let's del\u00adve into the data.",
    # And the third round's (the copy pass's review, round 3, m3): the Acceptance line's "no
    # errors or any clean claim" in its forms, fail as Voltry's judgment, a price with no
    # dollar sign, a prediction, a verdict or a grade, and more stock phrasing.
    "Memory: no memory errors.",
    "No memory errors recorded.",
    "No ECC errors.",
    "Memory: 0 errors.",
    "Zero errors found.",
    "The memory is clean.",
    "Memory: clean.",
    "A clean bill of health.",
    "Error-free memory.",
    "Free of errors.",
    "Battery health: good.",
    "Condition: excellent.",
    "Result: FAIL.",
    "The SSD fails our check.",
    "Looks good.",
    "Nothing to worry about.",
    "No red flags.",
    "A flawless SSD.",
    "A trustworthy Mac.",
    "Diagnosis: normal.",
    "It is safe to buy.",
    "4 out of 5 stars.",
    "Battery: 9/10.",
    "A B+ rating.",
    "Top tier.",
    "About 900 dollars.",
    "USD 900.",
    "900 EUR on the used market.",
    "\u20ac900 at most.",
    "A trade-in credit of 300.",
    "An invaluable Mac.",
    "It sells for about 900.",
    "Costs about 500 euros.",
    "The battery will fail within a year.",
    "It can last three more years.",
    "About two years left.",
    "Its life expectancy is five years.",
    "Near the end of its life.",
    "It is worth mentioning that",
    "In essence, the report is short.",
    "At its core, a simple report.",
    "The intricacies of Apple silicon.",
    "A nuance worth noting.",
    "An unprecedented look.",
    "Unleash your Mac.",
    "Embrace the details.",
    "Let's explore the data.",
    "This paves the way.",
    "It sheds light on the SSD.",
    "A treasure trove of data.",
]


@pytest.mark.parametrize("text", SLIPS)
def test_the_copy_rules_refuse_each_known_slip(text):
    with pytest.raises(AssertionError):
        _check(text, text)


def test_the_copy_rules_leave_a_file_safe_to_delete_alone():
    _check("the files left", f"{run.LEFT_ONE}\n{run.LEFT_MANY}")


def test_each_allowance_passes_only_the_words_the_tool_prints():
    # "uv cache clean", the uninstall the README gives as the spec does, and the SSD's limits
    # line, which says the report cannot tell whether it will fail, pass; the same words said
    # of the Mac do not (the copy pass's review, round 3, m3).
    _check("the uninstall", "uv tool uninstall voltry-mac\nuv cache clean")
    _check("the limits", "Why the SSD reports a warning, or whether it will fail.")
    for said in ("The cache is clean.", "Its SSD is clean.", "We checked whether it will fail."):
        with pytest.raises(AssertionError):
            _check(said, said)


# --- the report's own words ---------------------------------------------------------------------


@pytest.mark.parametrize("path", TERMINAL, ids=[p.name for p in TERMINAL])
def test_the_terminal_goldens_have_no_dash_and_no_stock_phrasing(path):
    # The prohibited constructions over every summary are test_terminal's.
    _check(path.name, path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", list(pdf_goldens.DOCUMENTS))
def test_the_golden_pdfs_have_no_stock_phrasing(name):
    reader = pypdf.PdfReader(io.BytesIO(pdf_goldens.render(name)), strict=True)
    _check(name, " ".join(page.extract_text() for page in reader.pages), prohibited=False)


def _strings(value: object) -> list[str]:
    """Every string value in a JSON document, never its keys: `value` is an ordinary key."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for item in value.values() for s in _strings(item)]
    if isinstance(value, list):
        return [s for item in value for s in _strings(item)]
    return []


FIXTURE_JSON = sorted((PACKAGE / "tests" / "fixtures" / "reports").glob("*.json"))
DOCUMENTS = [(label, document) for label, document in T.DOCUMENTS] + [
    (f"gap {label}", document) for label, document in T.GAP_DOCUMENTS
]


@pytest.mark.parametrize("path", FIXTURE_JSON, ids=[p.name for p in FIXTURE_JSON])
def test_each_saved_report_json_follows_the_copy_rules(path):
    _check(path.name, " | ".join(_strings(json.loads(path.read_text(encoding="utf-8")))))


def test_every_fixture_documents_json_follows_the_copy_rules():
    for label, document in DOCUMENTS:
        _check(label, " | ".join(_strings(document)))


def _report_words(document: dict) -> tuple[str, str]:
    """A fixture document's terminal summary, and the words its PDF draws, as
    test_report_pdf_copy reads them."""
    made, _ = pages.composed(document)
    drawn = " ".join(pages.page_words(page) for page in made.pages)
    footers = " ".join(d.text for page in made.pages for d in pages.texts(page))
    return T.summary(document), f"{drawn} {footers}"


def test_every_fixture_documents_terminal_and_pdf_words_follow_the_copy_rules():
    # The stock phrasing too, beside the prohibited constructions test_terminal and
    # test_report_pdf_copy check there (the copy pass's review, round 3, m3).
    for label, document in DOCUMENTS:
        summary, drawn = _report_words(document)
        _check(f"{label}: the terminal", summary)
        _check(f"{label}: the PDF", drawn)


def test_the_words_check_refuses_a_slip_set_among_a_reports_own_words():
    # The negative control for the test above: a slip is found among real words, across a
    # line break too.
    label, document = DOCUMENTS[0]
    for words in _report_words(document):
        for slip in ("The memory is\nclean.", "In essence, the SSD\nreads well."):
            with pytest.raises(AssertionError):
                _check(label, f"{words}\n{slip}")


# --- the README -----------------------------------------------------------------------------------


def _fenced_after(text: str, marker: str, language: str) -> str:
    start = text.index(f"```{language}\n", text.index(marker)) + len(f"```{language}\n")
    return text[start : text.index("\n```", start)]


def _pinned(text: str) -> str:
    # The uv installer's version is the one current at release (the spec's 0.12.18 on
    # 2026-09-24), so the block is compared with the version set aside.
    return re.sub(r"astral\.sh/uv/[0-9]+\.[0-9]+\.[0-9]+/", "astral.sh/uv/X/", text)


def test_the_readme_gives_the_specs_install_block_word_for_word():
    block = _fenced_after(SPEC, "What the README will say:", "bash")
    found = _fenced_after(README, "## Install", "bash")
    assert _pinned(found) == _pinned(block)
    versions = set(re.findall(r"astral\.sh/uv/([0-9.]+)/install\.sh", found))
    assert len(versions) == 1, "both installer links name one version"


def test_the_readme_gives_the_other_ways_to_get_uv_and_the_pinned_install():
    base = re.match(r"[0-9]+\.[0-9]+\.[0-9]+", voltry_mac.__version__)
    assert base is not None
    assert "brew install uv" in README
    assert "curl -LsSf https://astral.sh/uv/install.sh | sh" in README
    assert "uv tool update-shell" in README
    assert f"uv tool install --compile-bytecode voltry-mac=={base.group()}\n" in README


def test_every_install_the_readme_gives_compiles_the_bytecode():
    # Change record 8 (the GPT audit, pass 1, G1-05): uv compiles nothing by default, so the
    # first run would write Python's compiled copies into the tool's install folder.
    installs = re.findall(r"uv tool install (\S+)", README)
    assert len(installs) == 2 and set(installs) == {"--compile-bytecode"}
    block = _fenced_after(README, "## Install", "bash")
    assert "\nuv tool install --compile-bytecode voltry-mac\nvoltry-mac\n" in f"\n{block}\n"


def test_the_readme_uninstalls_with_the_two_commands_the_spec_keeps():
    block = _fenced_after(README, "## Uninstall", "bash")
    assert block == "uv tool uninstall voltry-mac\nuv cache clean"


def test_the_readme_usage_is_the_specs():
    usage = _fenced_after(SPEC, "## CLI transcripts", "text")
    assert _fenced_after(README, "## Run it", "text") == usage


def test_the_readme_names_the_validated_configurations_the_run_uses():
    table = README[README.index("## Which Macs") :]
    body = [line for line in table.splitlines() if line.startswith("| ")][1:]
    rows = [
        (found[1], found[2])
        for line in body
        if (found := re.fullmatch(r"\| [^|]+ \| ([A-Za-z]+[0-9]+,[0-9]+) \| ([0-9.]+) \|", line))
    ]
    # Every row read, M1 identifiers such as MacBookAir10,1 included (review, round 1, m5).
    assert rows and len(rows) == len(body) - 1  # the header's divider is not a row
    assert set(rows) == set(run.VALIDATED)


def test_the_readme_quotes_the_prompt_the_tool_gives_sudo():
    assert f'"{allowlist.PROMPT.rstrip()}"' in README


def test_the_readme_says_what_the_report_cannot_tell_you_in_the_reports_words():
    limits = _flat(README[README.index("## What it cannot tell you") : README.index("## Which")])
    summary = (PACKAGE / "tests" / "golden" / "terminal" / "m5-laptop.txt").read_text()
    said = summary[summary.index("WHAT THIS REPORT CANNOT TELL YOU") :]
    items = [_flat(item) for item in said.split("\n\n")[0].split("  - ")[1:]]
    assert items and all(item.strip() in limits for item in items)


def test_the_readme_points_at_voltry_probe_and_back():
    # Decision 1: the two READMEs point at each other.
    assert "`voltry-probe`" in README
    assert "voltry-mac" in PROBE_README


def test_the_readme_says_what_the_product_contract_says_about_files_and_the_network():
    said = _flat(README)
    # The product contract's words, never the claims it retired (the review, round 1, M2).
    assert "nothing is sent anywhere" not in said and "Nothing else is written" not in said
    assert "sends no report data over the network" in said
    assert "syncs the way any file there does" in said
    assert "plus one temporary file beside them while it writes" in said
    assert "mode 0600" in said and "access rules" in said


def test_the_readme_says_what_a_killed_run_can_leave():
    killed = _flat(
        README[README.index("## If a run is killed") : README.index("## What it cannot")]
    )
    for residue in (".voltry-mac-<random>.tmp", "a JSON without its PDF", "sudo -k", "timeout"):
        assert residue in killed, residue
    # A kill just before the PDF's link leaves both, and a run names every file it made and
    # could not remove, not only a temporary (the copy pass's review, round 2, n1).
    assert "a JSON without its PDF, or both" in killed
    assert "A run that cannot remove a file it made says so and prints its path." in killed
    # Change record 21: and a file the file system would not let it remove, which it named.
    assert (
        "After an ordinary run, voltry-mac leaves only the reports you chose to keep, plus any "
        "file it told you it could not remove."
    ) in _flat(README)


def test_the_readme_defines_the_three_labels_as_the_spec_does():
    said = _flat(README)
    assert "measured (a reading, or a counter the source samples or accumulates)" in said
    assert "reported (the source's own statement" in said
    assert "derived (computed by voltry-mac from measured or reported values" in said


def test_the_readme_names_the_reads_voltry_mac_makes_itself():
    said = _flat(README)
    for read in (
        "/Library/Logs/DiagnosticReports",
        "/etc/localtime",
        "~/Library/Preferences/.GlobalPreferences.plist",
        "sysctlbyname",
        "_mmaintenanced",
    ):
        assert read in said, read
    assert "two variable arguments shown as placeholders" in said


def test_the_readme_says_how_to_reach_uv_before_updating_the_shell():
    said = _flat(README[README.index("## Install") : README.index("## Run it")])
    assert said.index('source "$HOME/.local/bin/env"') < said.rindex("uv tool update-shell")
    assert 'in that window run `source "$HOME/.local/bin/env"`' in said


def test_the_readme_gives_renders_options_and_explains_sudos_first_warning():
    said = _flat(README)
    assert "`voltry-mac render REPORT.json [--output DIR] [--no-open]`" in said
    # render collects nothing, as its help says; the preflight still reads the platform (the
    # copy pass's review, round 2, n2).
    assert "saved and opened by the same rules. It collects nothing." in said
    assert "reads nothing from the Mac" not in said
    assert "a short lecture about using administrator rights carefully" in said


def test_the_readme_says_attestations_are_not_checked_at_install():
    assert "uv and pip do not check them when they install" in _flat(README)


def test_the_readme_says_where_to_report_a_problem():
    reporting = _flat(README[README.index("## Reporting a problem") : README.index("## Related")])
    assert "https://www.voltry.io" in reporting
    # What helps, for both commands: the message that asked for the report, which no --debug
    # line shows, and the version; for a run, the lines --debug adds, never its summary or
    # what a command read (the copy pass's review, round 3, m2).
    assert (
        "For a run, send the message that asked you to report it, and what "
        "`voltry-mac --version` prints."
    ) in reporting
    assert "as in `voltry-mac --debug`, and send the lines `--debug` adds." in reporting
    assert "Each starts with a command ID, such as C1," in reporting
    assert "never what it read. Leave out the summary." in reporting
    assert (
        "`voltry-mac render` has no `--debug`. For it, send the message it printed, the "
        "command you ran, and what `voltry-mac --version` prints."
    ) in reporting


def test_the_readme_says_the_release_is_a_preview_and_names_pipx_second():
    # Release step 8: the README says preview. Decision 3: uv first, then pipx, for people
    # who already have Python 3.11 or later (the copy pass's review, round 2, m5).
    top = _flat(README[: README.index("## Install")])
    assert "voltry-mac is an English-language command-line preview" in top
    install = README[README.index("## Install") : README.index("## Run it")]
    second = "pipx is the second path, for people who already have Python 3.11 or later"
    assert second in _flat(install)
    assert _fenced_after(install, second, "bash") == "pipx install voltry-mac"
    assert install.index("uv tool install --compile-bytecode voltry-mac") < install.index(second)
    assert "`pipx uninstall voltry-mac`" in _flat(README[README.index("## Uninstall") :])


def test_the_readme_follows_the_copy_rules():
    _check("README.md", README)


@pytest.mark.parametrize("label", ["README.md", "CHANGELOG.md", "strings.txt"])
def test_no_copy_makes_a_claim_the_product_contract_replaced(label):
    text = {"README.md": README, "CHANGELOG.md": CHANGELOG, "strings.txt": STRINGS}[label]
    assert _replaced(" ".join(text.split())) is None, f"{label} makes a replaced claim"


# Each form of the three claims the contract replaced, with an auxiliary where English takes
# one (the GPT audit, pass 6, G6-01).
RETIRED = (
    "It changes nothing on the Mac.",
    "Reads this Mac and changed nothing.",
    "It is changing nothing.",
    "Nothing leaves this Mac.",
    "Nothing left this Mac.",
    "Nothing is leaving this Mac.",
    "Nothing has left your Mac.",
    "No report data leaves the Mac.",
    "Nothing persists except reports.",
    "Nothing persisted.",
    "Nothing is persisting.",
    "Nothing will persist.",
    "What it changes: it changes nothing.",
    # The GPT audit, pass 7, G7-01: a bare answer under Appendix B's row label, a chain of
    # auxiliaries, and the other forms the same claims take.
    "What it changes: Nothing.",
    "What it changes Nothing.",
    "Nothing has been persisting.",
    "Nothing will have left this Mac.",
    "It changes absolutely nothing.",
    "Nothing changes on your Mac.",
    "Nothing is changed on this Mac.",
    "It does not change anything on your Mac.",
    "It doesn't change anything.",
    "Voltry never changes anything.",
    "It makes no changes to your Mac.",
)
# Words the tool prints, or the contract gives, which the check must let through.
KEPT = (
    "Reads system information without changing system settings.",
    "Voltry itself sends no report data over the network.",
    "Stopped. Nothing was saved.",
    "A disk with no hard links cannot take the report, and nothing is left on it.",
    "Nothing: the administrator reads did not run, so voltry-mac left the sudo authorization "
    "as it was.",
    # Appendix B's row as the PDF prints it, label and value, for a run that never prepared
    # sudo and for one that did: the only text after the label the check lets through.
    f"What it changes {appendices.UNCHANGED}",
    f"What it changes {appendices.SUDO}",
)


@pytest.mark.parametrize("prohibited", [True, False], ids=["copy", "changelog"])
@pytest.mark.parametrize("claim", RETIRED)
def test_every_surface_refuses_a_claim_the_product_contract_replaced(claim, prohibited):
    # _check is the check of every surface: the transcripts, --help, --dry-run, the usage
    # block, the terminal summaries, the PDF's text, the JSON, the README, the CHANGELOG and
    # the strings, whatever its prohibited flag. A message edited to a retired claim, with
    # its golden refreshed, passed the whole suite (the GPT audit, pass 6, G6-01).
    with pytest.raises(AssertionError, match="a claim the Product contract replaced"):
        _check("probe", f"Voltry reads this Mac. {claim}", prohibited=prohibited)


def test_a_retired_claim_added_to_a_scanned_surface_fails_its_check():
    # Mutations of real surfaces, as a copy edit with its golden refreshed would make them.
    with pytest.raises(AssertionError, match="a claim the Product contract replaced"):
        _check("CHANGELOG.md", CHANGELOG + "\n- What it changes: Nothing.\n", prohibited=False)
    assert run.NONE_ANSWERED in TRANSCRIPTS
    mutated = TRANSCRIPTS.replace(run.NONE_ANSWERED, "Nothing has been persisting.")
    with pytest.raises(AssertionError, match="a claim the Product contract replaced"):
        _check_transcripts(mutated)


@pytest.mark.parametrize("fine", KEPT)
def test_the_words_the_tool_and_the_contract_use_pass(fine):
    assert _replaced(fine) is None
    _check("probe", fine, prohibited=False)


def test_the_changelog_has_no_dash_and_no_stock_phrasing():
    _check("CHANGELOG.md", CHANGELOG, prohibited=False)


def _entries(text: str) -> list[str]:
    """The CHANGELOG's entries, each as one line of words."""
    entries: list[str] = []
    within = False
    for line in text.splitlines():
        if line.startswith("- "):
            entries.append(line[2:])
            within = True
        elif line.startswith("  ") and within:
            entries[-1] += " " + line.strip()
        else:
            within = False
    return entries


def test_this_items_changelog_entries_repeat_no_run_of_six_words():
    # A restack that keeps both sides leaves an entry's old words beside its new ones, as it
    # once did in render's entry (the copy pass's review, round 2, m1).
    ours = [
        entry
        for entry in _entries(CHANGELOG)
        if entry.startswith(("`voltry-mac render REPORT.json`", "The copy pass"))
    ]
    assert len(ours) == 2
    for entry in ours:
        words = re.findall(r"[a-z0-9_`'.-]+", entry.lower())
        runs = [" ".join(words[k : k + 6]) for k in range(len(words) - 5)]
        assert len(runs) == len(set(runs)), entry[:40]
