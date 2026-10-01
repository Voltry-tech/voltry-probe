"""Every message voltry-mac prints around the report, as golden text (docs/VOLTRY_MAC_SPEC.md,
the copy policy under "Fixed notes": "every user-facing string ships as a golden fixture";
Test strategy, "Copy").

Each scenario runs the real command line on the fake M5 (tests/fake_mac.py) and records what
it prints: the command, stdout (with a typed answer as the terminal echoes it), stderr and
the exit code. stdout and stderr are kept apart, so a transcript does not show where a
warning falls among the stdout lines, and sudo's own prompt, which goes to the terminal
itself, is not in it. Each stream shows where it ends: the line break that ends its last
line is left out, so a blank line after it shows, and a stream that ends without one is
marked. The terminal summary is left out where it appears, since
tests/golden/terminal holds it; the usage block and --dry-run are in tests/golden/usage.txt
and dry_run.txt. A temporary file's random name prints as .voltry-mac-<random>.tmp, and
--version's three words about the machine as {python}, {architecture} and {rosetta}.
Every usage error is here too, in the tool's own words, the same on every Python it
supports: argparse's own lines, whose words were Python's and differed between versions,
never print (the GPT audit, pass 2, G2-01), and "--" and a word that starts with a dash and
a digit, which each Python read in its own way, are refused in the same words on every one
(the review of the audit fixes, round 3, m1). --help's refusals are here, since it takes the
preflight; its text is in tests/golden/help.txt and render_help.txt.

The words no scenario prints whole are in tests/golden/copy/strings.txt, read from the
source: every problem render can name (the validators' texts), every reason the output
writer gives, and the command line's help and its refusals. Each is spelled exactly as
the source spells it, one to a line as the body of a JSON string, so a doubled space shows
and a line break shows as \\n.

`uv run python tests/copy_golden.py` rewrites both files after a change to the words, and
the tests compare them.
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import copy
import dataclasses
import errno
import importlib.util
import io
import json
import os
import re
import signal
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Final

import pytest

import voltry_mac
from voltry_mac import (
    allowlist,
    assemble,
    canonical,
    cli,
    elevation,
    in_process,
    preflight,
    report_pdf,
    run,
    spawn,
    terminal,
    tracking,
    writer,
)

TESTS = Path(__file__).resolve().parent
GOLDEN = TESTS / "golden" / "copy" / "transcripts.txt"
STRINGS = TESTS / "golden" / "copy" / "strings.txt"
PACKAGE = TESTS.parent / "voltry_mac"
FIXTURES = TESTS / "fixtures" / "reports"
SUMMARY = "[the terminal summary, as tests/golden/terminal holds it]"
HEADING = "=== "
# What a transcript adds after a stream that ends without a line break.
NO_LINE_BREAK = "--- no line break at the end"


def _fake_mac():  # type: ignore[no-untyped-def]
    """tests/fake_mac.py, registered by conftest.py, or loaded here when run as a script."""
    name = "voltry_mac_test_fake_mac"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, TESTS / "fake_mac.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


fm = _fake_mac()

Setup = Callable[..., None]


@dataclasses.dataclass(frozen=True)
class Scenario:
    """A command line and what the fake M5 does differently for it. ``{home}`` in an argument
    is the fake home folder, shown as ``~`` in the golden. ``stdout`` makes the stream the
    run's stdout writes to."""

    name: str
    argv: tuple[str, ...]
    setup: Setup | None = None
    stdout: Callable[[], io.StringIO] = io.StringIO


# --- what each scenario changes -----------------------------------------------------------------


def _signal_at(command_id: str) -> Setup:
    def setup(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
        mac.before[command_id] = lambda: os.kill(os.getpid(), signal.SIGINT)
        if command_id.startswith("S"):
            mac.payloads[command_id] = fm.payload_run(
                command_id, cancelled=True, returncode=None, stdout=""
            )

    return setup


def _answer(value: str | None) -> Setup:
    def setup(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
        mac.answer = value

    return setup


def _preflight(**changes: object) -> Setup:
    def setup(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
        for name, value in changes.items():
            monkeypatch.setattr(preflight, name, lambda value=value, **_: value)

    return setup


def _cancelled_answer(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    def answer(cancelled):  # type: ignore[no-untyped-def]
        os.kill(os.getpid(), signal.SIGINT)
        return None

    monkeypatch.setattr(run, "_answer", answer)


def _no_service_account(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    def missing(name):  # type: ignore[no-untyped-def]
        raise KeyError(name)

    monkeypatch.setattr(elevation.pwd, "getpwnam", missing)


def _count_fails(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    mac.payloads["S3"] = fm.payload_run(
        "S3", returncode=1, stderr="Error: unable to open database file\n"
    )


def _clear_fails(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    mac.results["S5"] = fm.result("S5", 1)


def _survivor(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    survivor = tracking.Survivor(
        pid=4242, uid=0, name="powermetrics", started="Wed Sep 23 14:05:40 2026"
    )
    # sudo exits only after its command does, so a process outlives the sample only when
    # the tool stopped it, here at its runtime deadline (the copy pass's review, m1).
    mac.payloads["S4"] = fm.payload_run(
        "S4",
        forced="runtime_deadline",
        returncode=None,
        cleanup="survivor",
        survivors=(survivor,),
    )


def _unverified(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    mac.payloads["S3"] = fm.payload_run("S3", cleanup="listing_failed")


def _other_endings(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    # Every other way a command ends, in --debug's words (the copy pass's review, round 2,
    # M1): user reads that crash, cannot start or are stopped; a count that cannot start; a
    # power sample stopped at its deadline, leaving a process under a name the subtree
    # cannot hold; and a final clear that stalls and cannot be signalled.
    ended = spawn.Ending
    for command_id, changes in (
        ("C4", {"ending": ended.SIGNALED, "returncode": -6}),
        ("C8", {"ending": ended.NOT_STARTED, "returncode": None}),
        ("C9", {"ending": ended.DEADLINE, "returncode": -9}),
        ("C13", {"ending": ended.OUTPUT_CAP, "returncode": 0}),
        ("C14", {"ending": ended.DEADLINE, "returncode": None, "reaped": False}),
    ):
        mac.results[command_id] = fm.result(command_id, stdout="", **changes)
    mac.payloads["S3"] = fm.payload_run(
        "S3", started=False, returncode=None, stdout="", duration_ms=0
    )
    stranger = tracking.Survivor(
        pid=4243, uid=0, name="Jane's Helper", started="Wed Sep 23 14:05:40 2026"
    )
    mac.payloads["S4"] = fm.payload_run(
        "S4",
        forced="runtime_deadline",
        returncode=None,
        cleanup="survivor",
        survivors=(stranger,),
    )
    mac.results["S5"] = fm.result(
        "S5", ending=ended.DEADLINE, returncode=None, reaped=False, eperm=True
    )


def _cancelled_read(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    # The Ctrl-C comes while C5 runs, and the runner stops it.
    _signal_at("C5")(mac, monkeypatch, folder)
    mac.results["C5"] = fm.result("C5", -15, ending=spawn.Ending.CANCELLED, stdout="")


def _cancelled_payload_and_failed_clear(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    _signal_at("S3")(mac, monkeypatch, folder)
    _clear_fails(mac, monkeypatch, folder)


def _name_taken(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    (mac.desktop / fm.PDF_NAME).write_bytes(b"not ours")


def _desktop_refused(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    real = writer._open_folder

    def refusing(path):  # type: ignore[no-untyped-def]
        if path == str(mac.desktop):
            raise PermissionError(errno.EPERM, os.strerror(errno.EPERM))
        return real(path)

    monkeypatch.setattr(writer, "_open_folder", refusing)


def _reports_folder(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    (mac.home / "reports").mkdir()


def _disk_full(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    def full(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))

    monkeypatch.setattr(writer, "_write_all", full)


def _in(path: Path) -> Callable[[int], bool]:
    """Whether a folder descriptor is the folder at path."""
    found = os.stat(path)
    return lambda descriptor: (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino) == (
        found.st_dev,
        found.st_ino,
    )


def _stuck(monkeypatch, where: Callable[[int], bool], name_is: Callable[[str], bool]) -> None:  # type: ignore[no-untyped-def]
    """The writer's unlink fails, through its own seam, for the names chosen in the folders
    chosen: the real writer then decides what is left and what it says."""
    real = writer._unlink

    def unlink(folder_fd, name):  # type: ignore[no-untyped-def]
        if where(folder_fd) and name_is(name):
            raise OSError(errno.EIO, os.strerror(errno.EIO))
        return real(folder_fd, name)

    monkeypatch.setattr(writer, "_unlink", unlink)


def _temporary(name: str) -> bool:
    return name.startswith(".voltry-mac-")


def _left_after_failure(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    # The disk fills as the PDF is written, and its temporary will not go.
    _disk_full(mac, monkeypatch, folder)
    _stuck(monkeypatch, lambda descriptor: True, _temporary)


def _left_after_save(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    # The PDF is published, and its temporary, a second name for it, will not go: the report
    # is saved, and O1 does not open a file with two names.
    _stuck(monkeypatch, lambda descriptor: True, _temporary)


def _left_before_the_pdf(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    # With --json the JSON is published first, and its temporary will not go: the save stops
    # before the PDF's would be a second one, and the JSON goes again.
    _stuck(monkeypatch, lambda descriptor: True, _temporary)


def _no_hard_links(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    # A disk whose format has no hard links (FAT, exFAT) refuses the link that publishes.
    def refuse(folder_fd, temporary, final):  # type: ignore[no-untyped-def]
        raise OSError(errno.ENOTSUP, os.strerror(errno.ENOTSUP))

    monkeypatch.setattr(writer, "_publish", refuse)


def _left_in_two_places(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    # macOS refuses the Desktop once the JSON is there, and this run's JSON on the Desktop
    # will not go; at home the report is saved, and the PDF's temporary, the second one
    # made there, will not go.
    desktop = _in(mac.desktop)
    home_temporaries: list[str] = []
    real = writer._publish

    def publish(folder_fd, temporary, final):  # type: ignore[no-untyped-def]
        if desktop(folder_fd) and final.endswith(".pdf"):
            raise PermissionError(errno.EPERM, os.strerror(errno.EPERM))
        return real(folder_fd, temporary, final)

    monkeypatch.setattr(writer, "_publish", publish)
    real_unlink = writer._unlink

    def unlink(folder_fd, name):  # type: ignore[no-untyped-def]
        if desktop(folder_fd) and name.endswith(".json"):
            raise PermissionError(errno.EPERM, os.strerror(errno.EPERM))
        if not desktop(folder_fd) and _temporary(name):
            if name not in home_temporaries:
                home_temporaries.append(name)
            if home_temporaries.index(name) == 1:
                raise OSError(errno.EIO, os.strerror(errno.EIO))
        return real_unlink(folder_fd, name)

    monkeypatch.setattr(writer, "_unlink", unlink)


def _pdf_bug(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    def broken(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise RuntimeError("a bug")

    monkeypatch.setattr(report_pdf, "render", broken)


def _too_little(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    for command_id in allowlist.USER_COMMAND_IDS:
        if command_id not in ("C1", "C12"):
            mac.results[command_id] = fm.result(command_id, 1, stdout="")


def _nothing_answers(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    for command_id in allowlist.USER_COMMAND_IDS:
        mac.results[command_id] = fm.result(command_id, 1, stdout="")
    monkeypatch.setattr(
        in_process, "panic_count", lambda *args: in_process.Unavailable("tool_error")
    )


def _unexpected(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    def broken(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise ValueError("a bug")

    monkeypatch.setattr(assemble, "surfaces", broken)


def _home_refused_too(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    def open_folder(path):  # type: ignore[no-untyped-def]
        if path == str(mac.desktop):
            raise PermissionError(errno.EPERM, os.strerror(errno.EPERM))
        raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))

    monkeypatch.setattr(writer, "_open_folder", open_folder)


def _signal_in_save(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    real = writer._write_all

    def interrupted(*args, **kwargs):  # type: ignore[no-untyped-def]
        os.kill(os.getpid(), signal.SIGINT)
        return real(*args, **kwargs)

    monkeypatch.setattr(writer, "_write_all", interrupted)


def _signal_after_save(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    real = run._named

    def named(saved, local):  # type: ignore[no-untyped-def]
        real(saved, local)
        os.kill(os.getpid(), signal.SIGINT)

    monkeypatch.setattr(run, "_named", named)


def _signal_as_told(starts: str) -> Setup:
    # The signal comes as the run, or render, says why nothing was saved, before its last
    # read of the flag (the pre-audit of pass 3, 01).
    def setup(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
        real = run._tell

        def told(text: str) -> None:
            real(text)
            if text.startswith(starts):
                os.kill(os.getpid(), signal.SIGINT)

        monkeypatch.setattr(run, "_tell", told)

    return setup


def _signal_before_open(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    # The signal comes once the report is published for O1, just before it: nothing opens.
    real = spawn.Runner.published

    def published(runner, path):  # type: ignore[no-untyped-def]
        real(runner, path)
        os.kill(os.getpid(), signal.SIGINT)

    monkeypatch.setattr(spawn.Runner, "published", published)


def _open_stopped(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    # The chokepoint stopped O1 as it ran, or refused it for a signal after the run's last
    # look at the flag.
    mac.results["O1"] = fm.result("O1", None, ending=spawn.Ending.CANCELLED)


def _signal_after_open(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    # The open has run and said so; the signal comes before the run's last read of the flag
    # (the GPT audit, pass 2, G2-03).
    real = run._open

    def opened(*args, **kwargs):  # type: ignore[no-untyped-def]
        stopped = real(*args, **kwargs)
        os.kill(os.getpid(), signal.SIGINT)
        return stopped

    monkeypatch.setattr(run, "_open", opened)


def _later_argparse(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    # A later Python names an error by no argument the tool knows.
    def later(self, args=None, namespace=None):  # type: ignore[no-untyped-def]
        raise argparse.ArgumentError(None, "words of a Python still to come")

    monkeypatch.setattr(argparse.ArgumentParser, "parse_known_args", later)


def _broken(owner: object, name: str) -> Setup:
    def setup(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
        def broken(*args, **kwargs):  # type: ignore[no-untyped-def]
            raise RuntimeError("a bug")

        monkeypatch.setattr(owner, name, broken)

    return setup


def _interrupted_read(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    def read(path):  # type: ignore[no-untyped-def]
        raise KeyboardInterrupt

    monkeypatch.setattr(run, "_read_report", read)


def _all(*setups: Setup) -> Setup:
    def setup(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
        for each in setups:
            each(mac, monkeypatch, folder)

    return setup


def _root(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    monkeypatch.setattr(os, "geteuid", lambda: 0)


def _platform(**changes: object) -> Setup:
    def setup(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
        found = dataclasses.replace(fm.SUPPORTED, **changes)
        monkeypatch.setattr(preflight, "read", lambda **_: found)

    return setup


def _machine_words(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    # The Python, its architecture and Rosetta are the machine's: the golden holds a
    # placeholder for each (the copy pass's review, round 2, M1).
    monkeypatch.setattr(cli, "python_version", lambda: "{python}")
    monkeypatch.setattr(preflight, "architecture", lambda found: "{architecture}")
    monkeypatch.setattr(preflight, "rosetta", lambda found: "{rosetta}")


class _FullDisk(io.StringIO):
    """stdout sent to a file on a disk that fills as the terminal summary comes. The flush
    that meets the full disk fails with ENOSPC; from then on the stream keeps nothing, as
    /dev/null, where the run points stdout, keeps nothing."""

    ROOM: Final = 1000  # characters, fewer than the summary's

    def __init__(self) -> None:
        super().__init__()
        self.full = False
        self.gone = False

    def write(self, text: str) -> int:
        if not self.gone and self.tell() + len(text) > self.ROOM:
            self.full = True
        if self.full:
            return len(text)  # kept nowhere
        return super().write(text)

    def flush(self) -> None:
        if self.full and not self.gone:
            self.gone = True
            raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))


# A version no release of voltry-mac ever has, so the report is always another version's.
ANOTHER = "0.0.9"


def _report(**changes: object) -> bytes:
    """The m5-laptop report as saved, with top-level or tool fields changed and its ID made
    again, so it still validates."""
    document = copy.deepcopy(canonical.load((FIXTURES / "m5-laptop.json").read_bytes()))
    for name, value in changes.items():
        if name == "version":
            document["tool"]["version"] = value
        else:
            document[name] = value
    return canonical.canonical_json(canonical.with_report_id(document)).encode()


def _unknown_key(key: str) -> Callable[[], bytes]:
    """The m5-laptop report with a value key its first surface does not have, which render
    refuses by its field path."""

    def data() -> bytes:
        document = copy.deepcopy(canonical.load((FIXTURES / "m5-laptop.json").read_bytes()))
        document["surfaces"][0]["values"][key] = {"availability": "unavailable"}
        return canonical.canonical_json(canonical.with_report_id(document)).encode()

    return data


def _top_level_key(key: str) -> Callable[[], bytes]:
    """The m5-laptop report with one more top-level key, which the reader refuses before any
    validation, naming the top level as the field (the copy pass's review, round 3, m1)."""

    def data() -> bytes:
        document = copy.deepcopy(canonical.load((FIXTURES / "m5-laptop.json").read_bytes()))
        document[key] = 1
        return canonical.canonical_json(document).encode()

    return data


def _saved_report(data: bytes | Callable[[], bytes]) -> Setup:
    def setup(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
        (folder / "report.json").write_bytes(data() if callable(data) else data)

    return setup


def _report_folder(mac, monkeypatch, folder):  # type: ignore[no-untyped-def]
    (folder / "report.json").mkdir()


SCENARIOS: tuple[Scenario, ...] = (
    Scenario("the reads allowed, with --json", ("--json",)),
    Scenario("the reads declined", (), _answer("n\n")),
    Scenario("the question gets no answer", (), _answer(None)),
    Scenario("--no-root", ("--no-root",)),
    Scenario("not an administrator", (), _preflight(admin=False)),
    Scenario("no terminal", (), _preflight(terminal=False)),
    Scenario("--yes", ("--yes",)),
    Scenario("no memory-maintenance account", (), _no_service_account),
    Scenario("the memory error read fails", (), _count_fails),
    Scenario("the final clear fails", (), _clear_fails),
    Scenario("a process outlives the power sample", (), _survivor),
    Scenario("a stop that could not be verified", (), _unverified),
    Scenario("Ctrl-C during the user reads", (), _signal_at("C5")),
    Scenario("Ctrl-C at the question", (), _cancelled_answer),
    Scenario("Ctrl-C during the memory error read", (), _signal_at("S3")),
    Scenario(
        "Ctrl-C during the memory error read, and the clear fails",
        (),
        _cancelled_payload_and_failed_clear,
    ),
    Scenario("a report with the same name exists", ("--no-root",), _name_taken),
    Scenario("macOS refuses the Desktop", ("--no-root", "--json"), _desktop_refused),
    Scenario("--output a folder", ("--no-root", "--output", "{home}/reports"), _reports_folder),
    Scenario("--output a folder that does not exist", ("--no-root", "--output", "missing\x1b[2J")),
    Scenario(
        "--output a long folder that does not exist",
        ("--no-root", "--output", "{home}/" + "/".join(["a folder with a long name"] * 3)),
    ),
    Scenario("--output names no folder", ("--no-root", "--output", "")),
    Scenario("the disk is full", ("--no-root",), _disk_full),
    Scenario(
        "the JSON's temporary file will not go", ("--no-root", "--json"), _left_before_the_pdf
    ),
    Scenario("a disk with no hard links", ("--no-root",), _no_hard_links),
    Scenario(
        "macOS refuses the Desktop, and the home folder fails", ("--no-root",), _home_refused_too
    ),
    Scenario("a failed save leaves a file", ("--no-root",), _left_after_failure),
    Scenario("a saved report leaves its temporary file", ("--no-root",), _left_after_save),
    Scenario(
        "macOS refuses the Desktop midway, and files are left in two places",
        ("--no-root", "--json"),
        _left_in_two_places,
    ),
    Scenario("the PDF cannot be drawn", ("--no-root", "--json"), _pdf_bug),
    Scenario("too little answers to save a report", ("--no-root",), _too_little),
    Scenario("nothing answers", ("--no-root",), _nothing_answers),
    Scenario("--no-open", ("--no-root", "--no-open")),
    Scenario("the terminal report cannot be written in full", ("--no-root",), stdout=_FullDisk),
    Scenario("an unexpected error", ("--no-root",), _unexpected),
    Scenario("Ctrl-C during the save", ("--no-root",), _signal_in_save),
    Scenario(
        "Ctrl-C as the run says the report could not be saved",
        ("--no-root",),
        _all(_disk_full, _signal_as_told(run.NOT_SAVED.split(":")[0])),
    ),
    Scenario("Ctrl-C once the report is saved", ("--no-root",), _signal_after_save),
    Scenario("an unexpected error once the report is saved", ("--no-root",), _broken(run, "_open")),
    Scenario("Ctrl-C just before the report opens", ("--no-root",), _signal_before_open),
    Scenario("Ctrl-C as the report opens", ("--no-root",), _open_stopped),
    Scenario("Ctrl-C once the report has opened", ("--no-root",), _signal_after_open),
    Scenario("--debug", ("--debug",)),
    Scenario("--debug, when commands end in other ways", ("--debug",), _other_endings),
    Scenario("--debug, and Ctrl-C during the user reads", ("--debug",), _cancelled_read),
    Scenario("--version", ("--version",), _machine_words),
    Scenario("--yes with --no-root", ("--yes", "--no-root")),
    # Every other usage error, in the tool's own words (the GPT audit, pass 2, G2-01).
    Scenario("an argument voltry-mac does not take", ("--frobnicate",)),
    Scenario("a folder given without --output", ("{home}/reports",)),
    Scenario("an option spelled wrong, before its folder", ("--out", "{home}/reports")),
    Scenario("an argument with a terminal control in it", ("--bad\x1b[2J",)),
    Scenario("an argument that turns the line right to left", ("--x\u202etxt.exe",)),
    Scenario("--paper with another size", ("--paper", "tabloid")),
    Scenario("--paper with no size", ("--paper",)),
    Scenario("--output with no folder", ("--output",)),
    Scenario("an option given an argument it does not take", ("--json=yes",)),
    Scenario("render with no report", ("render",)),
    Scenario("render with a second file", ("render", "report.json", "other.json")),
    Scenario("render with a collecting option", ("--json", "render", "report.json")),
    Scenario("render's --output with no folder", ("render", "report.json", "--output")),
    Scenario(
        "a usage error argparse names in no way the tool knows", ("--frobnicate",), _later_argparse
    ),
    # A folder after = shows as a path, the home folder as ~ (the pre-audit of the GPT audit's
    # pass 3, control 02), and an empty argument is named in words (the review of the audit
    # fixes, round 3, n5).
    Scenario("an option spelled wrong, its folder after =", ("--ouput={home}/reports",)),
    Scenario("an option cut short, its folder after =", ("--out={home}/reports",)),
    Scenario("an empty argument", ("",)),
    Scenario("render with an empty argument for its report", ("render", "")),
    # "--" and a word that starts with a dash and a digit: one outcome, in the same words, on
    # every Python (the review of the audit fixes, round 3, m1; the pre-audits of pass 3).
    Scenario("-- before render", ("--", "render", "report.json")),
    Scenario("-- before an option", ("--", "--json")),
    Scenario("-- between an option and render", ("--no-root", "--", "render", "report.json")),
    Scenario("-- before -h", ("--", "-h")),
    Scenario("-- before an option voltry-mac does not have", ("--", "-x")),
    Scenario("-- between two options", ("--json", "--", "--json")),
    Scenario("--output with a folder that starts with a dash and a digit", ("--output", "-1.json")),
    Scenario("render with a file that starts with a dash and a digit", ("render", "-1.json")),
    Scenario("a word that starts with a dash and a digit, before -h", ("-1.json", "-h")),
    Scenario("started with sudo", (), _root),
    Scenario("an Intel Mac", (), _platform(arm64=False)),
    Scenario("macOS 14", (), _platform(release="23.6.0")),
    Scenario("a Darwin release older than macOS 11", (), _platform(release="19.6.0")),
    Scenario("not macOS", (), _platform(macos=False, arm64=None, translated=None, release=None)),
    Scenario("the processor type cannot be read", (), _platform(arm64=None)),
    # A release too old to support is named first when it is readable (change record 2; the
    # pre-audit of the GPT audit's pass 3, control 07).
    Scenario(
        "the processor type cannot be read, on macOS 14",
        (),
        _platform(arm64=None, release="23.1.0"),
    ),
    Scenario("whether Python runs under Rosetta cannot be read", (), _platform(translated=None)),
    Scenario("the macOS version cannot be read", (), _platform(release=None)),
    # --help takes the preflight: only --version and --dry-run skip it (change record 2; the
    # pre-audit of the GPT audit's pass 3, control 06).
    Scenario("--help, started with sudo", ("--help",), _root),
    Scenario("--help on an Intel Mac", ("--help",), _platform(arm64=False)),
    Scenario(
        "render a report another version made",
        ("render", "report.json"),
        _saved_report(lambda: _report(version=ANOTHER)),
    ),
    Scenario(
        "render a report this version made",
        ("render", "report.json"),
        _saved_report(lambda: _report(version=voltry_mac.__version__)),
    ),
    Scenario("render a file that is not JSON", ("render", "report.json"), _saved_report(b"{")),
    Scenario(
        "render a report that fails validation",
        ("render", "report.json"),
        # Refused for the "!" and named by its field alone, never its value.
        _saved_report(lambda: _report(time_zone="Secret/Value!")),
    ),
    Scenario(
        # The longest key the reader takes: its field path runs past 80 columns, whole.
        "render a report with an unknown key of 64 characters",
        ("render", "report.json"),
        _saved_report(_unknown_key("k" * canonical.MAX_KEY)),
    ),
    Scenario(
        "render a report with an unknown key that has spaces",
        ("render", "report.json"),
        _saved_report(_unknown_key("a key with spaces in it, as a report can hold")),
    ),
    Scenario(
        "render a report with a top-level key of 65 characters",
        ("render", "report.json"),
        _saved_report(_top_level_key("k" * (canonical.MAX_KEY + 1))),
    ),
    Scenario(
        "render a report with a top-level key that holds a control character",
        ("render", "report.json"),
        _saved_report(_top_level_key("a\u0007")),
    ),
    Scenario("render a folder", ("render", "report.json"), _report_folder),
    Scenario("render a missing file", ("render", "report.json")),
    Scenario(
        "render to a folder that does not exist",
        ("render", "report.json", "--output", "missing"),
        _saved_report(lambda: _report(version=ANOTHER)),
    ),
    Scenario(
        "render with --output naming no folder",
        ("render", "report.json", "--output", ""),
        _saved_report(lambda: _report(version=voltry_mac.__version__)),
    ),
    Scenario(
        "render when the disk is full",
        ("render", "report.json"),
        _all(_saved_report(lambda: _report(version=voltry_mac.__version__)), _disk_full),
    ),
    Scenario(
        "render when macOS refuses the Desktop",
        ("render", "report.json"),
        _all(_saved_report(lambda: _report(version=voltry_mac.__version__)), _desktop_refused),
    ),
    Scenario(
        "render when macOS refuses the Desktop, and the home folder fails",
        ("render", "report.json"),
        _all(_saved_report(lambda: _report(version=voltry_mac.__version__)), _home_refused_too),
    ),
    Scenario(
        "render when a PDF with the same name exists",
        ("render", "report.json"),
        _all(_saved_report(lambda: _report(version=voltry_mac.__version__)), _name_taken),
    ),
    Scenario(
        "render's failed save leaves a file",
        ("render", "report.json"),
        _all(_saved_report(lambda: _report(version=voltry_mac.__version__)), _left_after_failure),
    ),
    Scenario(
        "render's saved PDF leaves its temporary file",
        ("render", "report.json"),
        _all(_saved_report(lambda: _report(version=voltry_mac.__version__)), _left_after_save),
    ),
    Scenario(
        "render a PDF that cannot be drawn",
        ("render", "report.json"),
        _all(_saved_report(lambda: _report(version=voltry_mac.__version__)), _pdf_bug),
    ),
    Scenario("Ctrl-C while render reads the file", ("render", "report.json"), _interrupted_read),
    Scenario(
        "Ctrl-C as render says the PDF could not be saved",
        ("render", "report.json", "--output", "missing"),
        _all(
            _saved_report(lambda: _report(version=voltry_mac.__version__)),
            _signal_as_told(run.RENDER_NOT_SAVED_IN.split(":")[0]),
        ),
    ),
    Scenario(
        "Ctrl-C during render's save",
        ("render", "report.json"),
        _all(_saved_report(lambda: _report(version=voltry_mac.__version__)), _signal_in_save),
    ),
    Scenario(
        "Ctrl-C once render has saved the PDF",
        ("render", "report.json"),
        _all(_saved_report(lambda: _report(version=voltry_mac.__version__)), _signal_after_save),
    ),
    Scenario(
        "Ctrl-C just before render opens the PDF",
        ("render", "report.json"),
        _all(_saved_report(lambda: _report(version=voltry_mac.__version__)), _signal_before_open),
    ),
    Scenario(
        "Ctrl-C as render opens the PDF",
        ("render", "report.json"),
        _all(_saved_report(lambda: _report(version=voltry_mac.__version__)), _open_stopped),
    ),
    Scenario(
        "Ctrl-C once render has opened the PDF",
        ("render", "report.json"),
        _all(_saved_report(lambda: _report(version=voltry_mac.__version__)), _signal_after_open),
    ),
    Scenario(
        "an unexpected error in render's save",
        ("render", "report.json"),
        _all(
            _saved_report(lambda: _report(version=voltry_mac.__version__)),
            _broken(writer, "save"),
        ),
    ),
    Scenario(
        "an unexpected error once render has saved the PDF",
        ("render", "report.json"),
        _all(
            _saved_report(lambda: _report(version=voltry_mac.__version__)),
            _broken(run, "_open"),
        ),
    ),
)


# --- running them -----------------------------------------------------------------------------


def _shown(argv: tuple[str, ...], home: str) -> str:
    words = []
    for word in argv:
        word = word.replace(home, "~")
        word = word.encode("ascii", "backslashreplace").decode("ascii")
        word = "".join(ch if ch.isprintable() else f"\\x{ord(ch):02x}" for ch in word)
        words.append(word or "''")  # an empty argument, as a shell would quote it
    return " ".join(["$ voltry-mac", *words])


@contextlib.contextmanager
def _terminal_signals():  # type: ignore[no-untyped-def]
    """SIGINT, SIGTERM and SIGHUP as Python sets them when it starts from a terminal, and
    back after. The run keeps a signal that was ignored when it started, so a script started
    in the background, which inherits SIGINT ignored, would record Ctrl-C as ignored (the
    copy pass's review, round 1, m8); conftest does the same for every test."""
    signals = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    before = {signum: signal.getsignal(signum) for signum in signals}
    signal.signal(signal.SIGINT, signal.default_int_handler)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGHUP, signal.SIG_DFL)
    try:
        yield
    finally:
        for signum, handler in before.items():
            if handler is not None:  # None: set outside Python, which cannot take it back
                signal.signal(signum, handler)


_RANDOM: Final = re.compile(r"\.voltry-mac-[^/\s]+?\.tmp")


def _stream(text: str) -> str:
    """A stream as the golden shows it: less the line break that ends its last line, so a
    blank line after that shows, or marked when it ends without one (the copy pass's
    review, round 3, m1)."""
    return text.removesuffix("\n") if text.endswith("\n") else f"{text}\n{NO_LINE_BREAK}"


def transcript(scenario: Scenario) -> str:
    """What the command prints in one scenario, with the terminal summary left out."""
    summaries: list[str] = []
    real = terminal.summary

    def summary(document):  # type: ignore[no-untyped-def]
        summaries.append(real(document))
        return summaries[-1]

    with (
        _terminal_signals(),
        tempfile.TemporaryDirectory() as made,
        pytest.MonkeyPatch.context() as monkeypatch,
    ):
        folder = Path(made).resolve()
        mac = fm.build(monkeypatch, folder)
        monkeypatch.setattr(terminal, "summary", summary)
        if scenario.setup is not None:
            scenario.setup(mac, monkeypatch, folder)
        asked = run._answer

        def answer(cancelled):  # type: ignore[no-untyped-def]
            # A typed answer shows as the terminal echoes it, with the Enter that ends it.
            given = asked(cancelled)
            if given is not None:
                print(given.rstrip("\n"))
            return given

        monkeypatch.setattr(run, "_answer", answer)
        home = str(mac.home)
        argv = [word.replace("{home}", home) for word in scenario.argv]
        out, err = scenario.stdout(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(argv)
        shown = _shown(tuple(argv), home)
    printed = out.getvalue()
    for text in summaries:
        printed = printed.replace(text, f"{SUMMARY}\n")
    said = err.getvalue()
    # The running version changes at every release, and a temporary's name at every run; the
    # words around them do not.
    printed, said = (
        _RANDOM.sub(".voltry-mac-<random>.tmp", text.replace(voltry_mac.__version__, "{version}"))
        for text in (printed, said)
    )
    parts = [shown, _stream(printed)] if printed else [shown]
    if said:
        parts += ["--- stderr", _stream(said)]
    parts.append(f"--- exit {code}")
    return "\n".join(parts) + "\n"


def golden() -> str:
    return "\n".join(f"{HEADING}{s.name}\n{transcript(s)}" for s in SCENARIOS)


def sections(text: str) -> dict[str, str]:
    """The golden file's scenarios, by name."""
    found: dict[str, str] = {}
    for block in text.split(f"\n{HEADING}"):
        block = block.removeprefix(HEADING)
        name, _, body = block.partition("\n")
        found[name] = body
    return found


# --- the words no scenario prints whole ---------------------------------------------------------

# Where render's problems come from, and the calls that carry their words: canonical.Invalid
# itself, and the helpers that build one (a JSON form the reader rejects, a value with no
# canonical form, the grammar a text value must follow, and the check of a key's or a text's
# characters, whose field can fall back to the top level's label).
_PROBLEM_SOURCES: Final = (
    "canonical.py",
    "validate.py",
    "validate_elevation.py",
    "validate_relations.py",
)
_PROBLEM_CALLS: Final = frozenset({"Invalid", "NotCanonical", "_Rejected", "_text", "check_text"})


def _called(node: ast.Call) -> str:
    function = node.func
    if isinstance(function, ast.Name):
        return function.id
    return function.attr if isinstance(function, ast.Attribute) else ""


def _constants(tree: ast.Module) -> dict[str, ast.expr]:
    """A module's own names for a text, as it assigns them at its top level."""
    found: dict[str, ast.expr] = {}
    for node in tree.body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value:
            found[node.target.id] = node.value
        elif isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name):
                found[target.id] = node.value
    return found


def _text_of(node: ast.expr, constants: dict[str, ast.expr]) -> str | None:
    """A text as the source spells it, with {} for each part filled in when it prints; for a
    fallback, such as ``path or TOP_LEVEL``, the text it falls back to (the copy pass's
    review, round 3, m1)."""
    if isinstance(node, ast.BoolOp):
        found = (_text_of(value, constants) for value in node.values)
        return next((text for text in found if text is not None), None)
    if isinstance(node, ast.Name) and node.id in constants:
        return _text_of(constants[node.id], {})
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value if isinstance(v, ast.Constant) else "{}" for v in node.values)
    # A text whose {} parts are filled in when it prints.
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return _text_of(node.func.value, constants) if node.func.attr == "format" else None
    return None


def _words(name: str, calls: frozenset[str], keywords: frozenset[str] = frozenset()) -> set[str]:
    """Every text a module passes to the given calls, or names with the given keywords, with
    more than one word, spaces and line breaks as the source spells them: a key or a field
    path is one word, and is not copy."""
    tree = ast.parse((PACKAGE / name).read_text(encoding="utf-8"))
    constants = _constants(tree)
    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        given = node.args if _called(node) in calls else []
        given = [*given, *(k.value for k in node.keywords if k.arg in keywords)]
        for argument in given:
            text = _text_of(argument, constants)
            if text is not None and len(text.split()) > 1:
                found.add(text)
    return found


def _line(text: str) -> str:
    """A text on one line of the golden, as the body of a JSON string: every space as it
    is, and a line break as \\n (the copy pass's review, round 2, M1)."""
    return json.dumps(text)[1:-1]


def texts(section: str) -> list[str]:
    """The texts a section of the strings golden holds, spelled as the source spells them."""
    return [json.loads(f'"{line}"') for line in section.splitlines()]


def strings() -> str:
    """The golden of the words no scenario prints whole, by section, each sorted."""
    sections = {
        "render's problems": set().union(
            *(_words(name, _PROBLEM_CALLS) for name in _PROBLEM_SOURCES)
        ),
        # A reason is NotSaved's own, or an OSError's the writer raises with words of its own.
        "the output writer's reasons": _words(
            "writer.py", frozenset({"NotSaved", "_NoLinks", "OSError"})
        ),
        "the command line": _words(
            "cli.py",
            frozenset({"UsageError"}),
            frozenset({"help", "description", "usage", "epilog"}),
        ),
    }
    return "\n".join(
        f"{HEADING}{title}\n" + "".join(f"{_line(text)}\n" for text in sorted(found))
        for title, found in sections.items()
    )


def make() -> None:
    GOLDEN.parent.mkdir(parents=True, exist_ok=True)
    GOLDEN.write_text(golden(), encoding="utf-8")
    STRINGS.write_text(strings(), encoding="utf-8")


if __name__ == "__main__":
    make()
