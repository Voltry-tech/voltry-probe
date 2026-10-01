"""The pinned templates held to sudo's own source (docs/VOLTRY_MAC_SPEC.md, Decision 2's
classifier table, its template and source file columns; Test strategy part 5, "Live macOS
CI", its second bullet; change records 12 and 13; board item MAC 4.2, issue #324).

The capture job reproduces what it can of sudo's messages on each image. A template no case
reproduces there, the ssh hint under sudo 1.9.13p2 or an account-state line on stock macOS,
is held here instead, to the source file the spec names. fixtures/sudo/strings-1.9.17p2.json
holds the string literals and include names of the three files at sudo-project/sudo's tag
v1.9.17p2, in file order, adjacent literals joined and escapes decoded as the compiler does,
each with the calls it sits in, innermost first; each file's SHA-256; and each file's own
copyright and permission notice. Core's tools/voltry_mac_sudo_strings.py derives it from
the three files, and tests/ci/test_voltry_mac_sudo_strings.py derives it again there and
compares it whole.

A template is one of its file's format strings once the string's trailing newline is
dropped, a run of %s conversions is read as one %s and a quoted run as '...'; and its
"sudo: " is the one the call that prints the string puts first: sudo's warning functions,
log_warningx and sudo_warnx, write the program's name and ": " before the message, and
sudo_printf, the plugin's own printf, writes nothing (sudo 1.9.17p2's lib/util/fatal.c and
plugins/sudoers/logging.c). One template's string is formatted by one call and printed by
another: the attempts line, which the capture reproduces on every image. The capture names
this test in its log for each template it did not reproduce.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import re
import sys
from pathlib import Path
from types import ModuleType

import pytest

from voltry_mac import sudo_messages

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "fixtures" / "sudo" / "strings-1.9.17p2.json"
LIVE = HERE.parent / "tests_live"
PINNED = [text for _, text in sudo_messages.TEMPLATES]
ATTEMPTS = "sudo: %u incorrect password attempt"
# The calls that print a message to the terminal, and what each puts before it.
PRINTERS = {"log_warningx": "sudo: ", "sudo_warnx": "sudo: ", "sudo_printf": ""}
# The sudo versions whose messages differ (change record 12): 1.9.13p2, then the monitor in
# 1.9.14, cmddenial_message in 1.9.16, and the ssh hint in 1.9.17.
VERSIONS = [(1, 9, 13, 2), (1, 9, 14, 0), (1, 9, 16, 0), (1, 9, 17, 2)]


def as_template(string: str) -> str:
    """A format string as the spec writes a template: its trailing newline dropped, a quoted
    run of %s as '...', and any other run of %s as one %s."""
    string = string.removesuffix("\n")
    string = re.sub(r"'(?:%s)+'", "'...'", string)
    return re.sub(r"(?:%s)+", "%s", string)


def _messages() -> ModuleType:
    """tests_live/messages.py, loaded by its path: the live folder is not on the import
    path, and nothing in it runs anything."""
    name = "voltry_mac_live_messages"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, LIVE / "messages.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


def _fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _printer(calls: list[str]) -> str | None:
    """The first call among ``calls``, innermost first, that prints to the terminal."""
    return next((call for call in calls if call in PRINTERS), None)


def _problem(template: str, source: str) -> str | None:
    """Why ``template`` is not a format string of ``source`` as sudo prints it, or None."""
    body = template.removeprefix("sudo: ")
    found = [
        calls for text, calls in _fixture()["files"][source]["strings"] if as_template(text) == body
    ]
    if not found:
        return f"{template!r} is not a format string of sudo 1.9.17p2's {source}"
    printed = {PRINTERS[printer] for printer in map(_printer, found) if printer is not None}
    prefix = "sudo: " if template.startswith("sudo: ") else ""
    if printed and printed != {prefix}:
        return f"{template!r}: the call that prints it puts {sorted(printed)} before it"
    return None


def _unprinted(template: str) -> bool:
    """Whether no call around the template's string prints it."""
    body = template.removeprefix("sudo: ")
    source = _messages().SOURCES[template]
    strings = _fixture()["files"][source]["strings"]
    return all(_printer(calls) is None for text, calls in strings if as_template(text) == body)


def test_the_fixture_is_the_three_files_the_spec_names_at_sudo_1_9_17p2():
    fixture = _fixture()
    assert fixture["sudo"] == "1.9.17p2" == _messages().SOURCE_VERSION
    assert fixture["tag"] == "v1.9.17p2"
    assert re.fullmatch(r"[0-9a-f]{40}", fixture["commit"])
    assert sorted(fixture["files"]) == sorted(set(_messages().SOURCES.values()))
    for name, file in fixture["files"].items():
        assert re.fullmatch(r"[0-9a-f]{64}", file["sha256"]), name
        assert file["strings"], name
        for text, calls in file["strings"]:
            assert isinstance(text, str) and all(isinstance(call, str) for call in calls), name


def test_each_file_carries_its_own_copyright_and_permission_notice():
    # sudo's ISC license asks that "the above copyright notice and this permission notice
    # appear in all copies": each file's header comment, as the file gives it.
    for name, file in _fixture()["files"].items():
        notice = file["notice"]
        assert "Copyright (c)" in notice and "Todd C. Miller" in notice, name
        assert "Permission to use, copy, modify, and distribute this software" in notice, name
        assert 'THE SOFTWARE IS PROVIDED "AS IS"' in notice, name


@pytest.mark.parametrize("template", PINNED, ids=[text[:40] for text in PINNED])
def test_each_template_is_a_format_string_of_the_file_it_is_pinned_to(template):
    messages = _messages()
    assert _problem(template, messages.SOURCES[template]) is None
    if _unprinted(template):
        # Formatted by one call and printed by another, so its string cannot show its
        # prefix: the capture then reproduces it on every image, "sudo: " and all.
        for version in VERSIONS:
            asked = {
                text
                for case in messages.CASES
                for planned, _ in [messages.plan(case, version)]
                if planned is not None
                for text in planned.expects
            }
            assert template in asked, version


def test_only_the_attempts_line_is_printed_by_another_call_than_its_own():
    # sudo 1.9.17p2's plugins/sudoers/logging.c: fmt_authfail_message() formats it with
    # asprintf and ngettext, and log_auth_failure() prints the result with sudo_warnx.
    assert [template for template in PINNED if _unprinted(template)] == [ATTEMPTS]


@pytest.mark.parametrize(
    "template",
    [text for text in PINNED if text != ATTEMPTS],
    ids=[text[:40] for text in PINNED if text != ATTEMPTS],
)
def test_a_template_with_its_prefix_turned_around_is_refused(template):
    # "sudo: " added where sudo_printf prints the line, or dropped where a warning function
    # prints it.
    flipped = (
        template.removeprefix("sudo: ") if template.startswith("sudo: ") else f"sudo: {template}"
    )
    assert _problem(flipped, _messages().SOURCES[template]) is not None


@pytest.mark.parametrize(
    ("template", "source"),
    [
        ("sudo: account validation failure, is your account locked!", "plugins/sudoers/auth/pam.c"),
        ("Sorry, user %s is not allowed to run '...' as %s on %s.", "plugins/sudoers/logging.c"),
        (
            "sudo: a terminal is required to read the password; either use ssh's -T option or "
            "configure an askpass helper",
            "src/tgetpass.c",
        ),
        ("sudo: timed out reading password", "plugins/sudoers/logging.c"),
    ],
    ids=["a mark off", "a word off", "a letter off", "another file"],
)
def test_a_template_off_by_a_mark_or_in_another_file_is_not_found(template, source):
    assert _problem(template, source) is not None


def test_the_capture_names_this_test_for_a_template_it_did_not_reproduce():
    path, _, name = _messages().HELD_BY.partition("::")
    assert path == f"agents/voltry-mac/tests/{Path(__file__).name}"
    defined = {
        node.name
        for node in ast.parse(Path(__file__).read_text(encoding="utf-8")).body
        if isinstance(node, ast.FunctionDef)
    }
    assert name in defined
