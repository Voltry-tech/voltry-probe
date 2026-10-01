"""The collecting run (docs/VOLTRY_MAC_SPEC.md, "CLI transcripts" 1, 2, 4 and 5; Decision 2's
sequence and "What the owner sees before sudo asks"; Decision 5; Decision 7's validated
configurations; Failure modes and the exit codes; the Architecture's run order).

``voltry-mac`` with no subcommand, once the preflight has passed: the header and its promise;
the 27 user reads and the panic count, timed on one line; the explanation and the question
when the elevated path applies; a line for each payload; the final clear, and its warning
when it fails; the terminal summary; the PDF, and the JSON when asked for; the save with the
Desktop lines, the fallback and a taken name; the open, once, unless --no-open or over SSH;
and the exit code by the precedence 5, 3, 2, 130, 4, 6, 1, 0. A signal only sets the
cancellation flag. The report goes to stdout; a failure, a warning or a file to delete goes
to stderr, as the command line's refusals do. Every process goes through a real chokepoint
whose process calls answer from the M5's captured outputs, and the report is saved in a
home folder under tmp_path.
"""

from __future__ import annotations

import argparse
import builtins
import contextlib
import dataclasses
import errno
import fcntl
import io
import itertools
import json
import os
import pwd
import select
import signal
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from voltry_mac_test_fake_mac import (
    ELEVATED,
    JSON_NAME,
    M5,
    NOW,
    PDF_NAME,
    SPEC,
    SUPPORTED,
    Mac,
    build,
    command,
    go,
    payload_run,
    result,
)

import voltry_mac
from voltry_mac import (
    allowlist,
    canonical,
    cli,
    console,
    elevation,
    in_process,
    manifests,
    preflight,
    report_pdf,
    run,
    spawn,
    terminal,
    tracking,
    validate,
    writer,
)

UNVERIFIED = (
    "Voltry could not confirm that the administrator reads stopped: the process\n"
    "listing that checks them failed or did not run. Look with ps for sudo,\n"
    "sandbox-exec, sqlite3 or powermetrics processes started at the time of this run.\n"
)


@pytest.fixture
def mac(monkeypatch, tmp_path):  # type: ignore[no-untyped-def]
    yield build(monkeypatch, tmp_path)
    # Whatever a test did, every report the run saved is one render accepts (the run's
    # review, round 1).
    for saved in sorted(tmp_path.rglob("*.json")):
        validate.read(saved.read_bytes())


def _spec_block(heading: str) -> str:
    """The first text block under a heading of the spec."""
    text = SPEC.read_text(encoding="utf-8")
    start = text.index(f"### {heading}\n")
    start = text.index("```text\n", start) + len("```text\n")
    return text[start : text.index("```", start)]


# --- the words, from the spec ---------------------------------------------------------------


def test_the_explanation_and_the_question_are_decision_2s_words():
    block = _spec_block("What the owner sees before sudo asks")
    assert block == f"{run.EXPLANATION}\n\n{run.QUESTION.rstrip()}\n"


def test_the_fixed_lines_are_the_transcripts_words():
    transcript = _spec_block("1. First run, administrator reads allowed")
    for line in (
        run.BLURB,
        run.COUNTING + run.DONE,
        run.SAMPLING + run.DONE,
        run.CLEARED,
        run.FULL_REPORT,
        run.DESKTOP,
        run.OPENING,
    ):
        assert f"\n{line}\n" in transcript, line
    assert "\nReading this Mac... done (0.8 s).\n" in transcript
    assert run.READING == "Reading this Mac..."
    declined = _spec_block("2. Administrator reads declined")
    assert f"\n{run.SKIPPING}\n" in declined
    fallback = _spec_block("5. macOS refuses Desktop access")
    assert f"{run.FALLBACK_BEFORE}\n  ~/Voltry Mac Report" in fallback
    assert f"\n{run.FALLBACK_AFTER}\n" in fallback
    renamed = _spec_block("4. A PDF with the same name already exists")
    assert run.RENAMED.format(time="14:07") in renamed
    text = SPEC.read_text(encoding="utf-8")
    assert f"| {run.WARNING} |" in text
    assert "| Stopped. Nothing was saved |" in text and run.STOPPED == "Stopped. Nothing was saved."
    assert "| Could not create the PDF. Please report this with voltry-mac --debug |" in text
    assert run.PDF_BUG == "Could not create the PDF. Please report this with voltry-mac --debug"


def test_no_line_the_run_prints_has_a_dash():
    words = [
        value for name, value in vars(run).items() if name.isupper() and isinstance(value, str)
    ]
    assert words
    for text in words:
        assert chr(0x2013) not in text and chr(0x2014) not in text, text


# --- transcript 1: allowed ------------------------------------------------------------------


def _between(out: str, first: str, last: str) -> str:
    start = out.index(first)
    return out[start : out.index(last, start) + len(last)]


def test_a_run_with_the_reads_allowed_prints_transcript_1_and_saves_the_report(capsys, mac):
    code, out, err = go(capsys, "--json")
    assert (code, err) == (0, "")
    head = (
        f"{cli.HEADER}\n{run.BLURB}\n\n"
        f"{run.READING} done (0.0 s).\n\n"
        f"{run.EXPLANATION}\n\n{run.QUESTION}"
        f"{run.COUNTING}{run.DONE}\n{run.SAMPLING}{run.DONE}\n{run.CLEARED}\n\n"
    )
    assert out.startswith(head)
    document = validate.read((mac.desktop / JSON_NAME).read_bytes())
    summary = terminal.summary(document)
    home = str(mac.home)
    tail = (
        f"{summary}\n{run.FULL_REPORT}\n\n{run.DESKTOP}\n"
        f"Saved: {terminal.display_path(str(mac.desktop / JSON_NAME), home)}\n"
        f"Saved: {terminal.display_path(str(mac.desktop / PDF_NAME), home)}\n"
        f"{run.OPENING}\n"
    )
    assert out == head + tail
    assert "Saved: ~/Desktop/Voltry Mac Report 2026-09-23 14.05.pdf\n" in out
    assert mac.saved() == [JSON_NAME, PDF_NAME]
    assert mac.opened == [str(mac.desktop / PDF_NAME)]
    assert mac.asked == 1


def test_the_saved_report_is_the_runs_own(capsys, mac):
    go(capsys, "--json")
    data = (mac.desktop / JSON_NAME).read_bytes()
    document = validate.read(data)
    assert data == canonical.canonical_json(document).encode()
    assert document["tool"] == {
        "name": "voltry-mac",
        "version": voltry_mac.__version__,
        "renderer_version": report_pdf.RENDERER,
        "python": cli.python_version(),
        "architecture": "arm64",
        "rosetta": False,
    }
    assert (document["collected_at_local"], document["collected_at_utc"]) == (
        "2026-09-23T14:05:31-07:00",
        "2026-09-23T21:05:31Z",
    )
    assert (document["time_zone"], document["render"]) == (
        "America/Los_Angeles",
        {"paper": "letter"},
    )
    assert document["collection"]["status"] == "complete"
    assert (
        document["elevation"]["consent"] == "yes" and document["elevation"]["cleared"] == "cleared"
    )
    ids = [record["id"] for record in document["commands"]]
    assert ids == [*allowlist.USER_COMMAND_IDS, *ELEVATED]
    assert "O1" not in ids
    pdf = (mac.desktop / PDF_NAME).read_bytes()
    assert pdf == report_pdf.render(document, manifests.templates(voltry_mac.__version__))
    for path in (mac.desktop / JSON_NAME, mac.desktop / PDF_NAME):
        assert path.stat().st_mode & 0o777 == 0o600


def test_the_reads_run_first_then_the_elevated_path_then_the_open(capsys, mac):
    go(capsys)
    assert mac.ran == [*allowlist.USER_COMMAND_IDS, *ELEVATED, "O1"]


def test_the_reads_line_says_how_long_the_reads_took(capsys, mac, monkeypatch):
    clock = iter([100.0, 100.84])
    monkeypatch.setattr(run, "_monotonic", lambda: next(clock))
    _, out, _ = go(capsys, "--no-root")
    assert f"\n\n{run.READING} done (0.8 s).\n\n" in out


def test_the_panic_count_is_read_with_the_user_reads(capsys, mac, monkeypatch):
    order: list[str] = []
    monkeypatch.setattr(in_process, "panic_count", lambda *args: order.append("R1") or 3)
    mac.before["C28"] = lambda: order.append("C28")
    mac.before["X1"] = lambda: order.append("X1")
    go(capsys, "--json")
    assert order == ["C28", "R1", "X1"]
    document = json.loads((mac.desktop / JSON_NAME).read_text())
    panic = [s for s in document["surfaces"] if s["key"] == "panic_report_count"][0]
    assert panic["values"]["count"]["value"] == 3


# --- who is asked, and what a no gives --------------------------------------------------------


@pytest.mark.parametrize(
    "answer", ["n\n", "\n", None, "maybe\n"], ids=["n", "Enter", "end of input", "maybe"]
)
def test_a_no_skips_the_administrator_reads(capsys, mac, answer):
    mac.answer = answer
    code, out, err = go(capsys, "--json")
    assert (code, err) == (0, "")
    newline = "\n" if answer is None else ""
    assert f"{run.QUESTION}{newline}{run.SKIPPING}\n\n{terminal.summary(_saved(mac))}" in out
    assert not any(step.startswith("S") or step in ("X1", "P1") for step in mac.ran)
    assert run.CLEARED not in out
    assert _saved(mac)["elevation"]["consent"] == "no"


def _saved(mac: Mac) -> dict:
    return validate.read((mac.desktop / JSON_NAME).read_bytes())


@pytest.mark.parametrize(
    ("argv", "admin", "terminal_present", "consent", "skip_cause"),
    [
        (["--no-root"], True, True, "skipped", "no_root_flag"),
        ([], False, True, "skipped", "not_admin"),
        (["--yes"], False, True, "skipped", "not_admin"),
        ([], True, False, "skipped", "no_terminal"),
    ],
    ids=["--no-root", "not an administrator", "--yes, not an administrator", "no terminal"],
)
def test_a_run_that_skips_the_question_prints_no_explanation(
    capsys, mac, monkeypatch, argv, admin, terminal_present, consent, skip_cause
):
    monkeypatch.setattr(preflight, "admin", lambda: admin)
    monkeypatch.setattr(preflight, "terminal", lambda: terminal_present)
    code, out, err = go(capsys, "--json", *argv)
    assert (code, err) == (0, "")
    assert run.EXPLANATION.splitlines()[0] not in out and run.QUESTION not in out
    assert run.SKIPPING not in out
    assert f"{run.READING} done (0.0 s).\n\n{terminal.summary(_saved(mac))}" in out
    assert mac.asked == 0
    assert mac.ran == [*allowlist.USER_COMMAND_IDS, "O1"]
    elevation_record = _saved(mac)["elevation"]
    assert (elevation_record["consent"], elevation_record["skip_cause"]) == (consent, skip_cause)


def test_an_admin_check_that_cannot_answer_lets_sudo_decide(capsys, mac, monkeypatch):
    # preflight.admin() is None when the group check fails or does not answer in time: the
    # question is still asked, and sudo's own check decides (the #347 review).
    monkeypatch.setattr(preflight, "admin", lambda: None)
    go(capsys, "--json")
    assert mac.asked == 1
    assert _saved(mac)["elevation"]["consent"] == "yes"


@pytest.mark.parametrize("admin", [True, None], ids=["an administrator", "admin unknown"])
@pytest.mark.parametrize(
    "stdout_terminal", [True, False], ids=["stdout a terminal", "stdout a file"]
)
@pytest.mark.parametrize(
    "terminal_present", [True, False], ids=["stdin a terminal", "stdin not one"]
)
def test_yes_explains_without_asking(
    capsys, mac, monkeypatch, terminal_present, stdout_terminal, admin
):
    # With a terminal, sudo still prompts: the mode follows stdin's terminal whatever stdout
    # is, since stdout decides only whether Voltry's own question is asked, and --yes asks
    # none (the run's review, round 2, m11).
    monkeypatch.setattr(preflight, "terminal", lambda: terminal_present)
    monkeypatch.setattr(run, "_stdout_terminal", lambda: stdout_terminal)
    monkeypatch.setattr(preflight, "admin", lambda: admin)
    code, out, _ = go(capsys, "--yes", "--json")
    assert code == 0
    assert f"{run.EXPLANATION}\n\n{run.COUNTING}" in out
    assert run.QUESTION not in out and mac.asked == 0
    record = _saved(mac)["elevation"]
    assert record["consent"] == "flag"
    assert record["mode"] == ("interactive" if terminal_present else "noninteractive")
    suffix = "" if terminal_present else "n"
    assert mac.ran[27:] == [
        "X1",
        "P1",
        "S1",
        f"S2{suffix}",
        f"S3{suffix}",
        f"S4{suffix}",
        "S5",
        "O1",
    ]


# --- the payload lines, the clear and its warning ------------------------------------------------


def test_a_payload_that_fails_says_not_read(capsys, mac):
    mac.payloads["S3"] = payload_run(
        "S3", returncode=1, stderr="Error: unable to open database file\n"
    )
    code, out, _ = go(capsys)
    assert f"{run.COUNTING}{run.NOT_READ}\n{run.SAMPLING}{run.DONE}\n{run.CLEARED}\n" in out
    assert code == 1  # tool_error on the memory error records


def test_a_count_that_is_skipped_prints_no_line_for_it(capsys, mac, monkeypatch):
    def missing(name):  # type: ignore[no-untyped-def]
        raise KeyError(name)

    monkeypatch.setattr(elevation.pwd, "getpwnam", missing)
    code, out, _ = go(capsys)
    assert run.COUNTING not in out
    assert f"{run.QUESTION}{run.SAMPLING}{run.DONE}\n{run.CLEARED}\n" in out
    assert code == 0  # unsupported, service_account_missing: an expected omission


def test_a_failed_clear_warns_at_once_and_at_the_end_and_exits_6(capsys, mac):
    mac.results["S5"] = result("S5", 1)
    code, out, err = go(capsys)
    assert code == 6
    assert err == f"{run.WARNING}\n{run.WARNING}\n"
    assert run.CLEARED not in out
    assert out.endswith(f"{run.OPENING}\n")
    assert mac.saved() == [PDF_NAME]


def test_a_survivor_is_named_for_verification_and_the_run_exits_1(capsys, mac):
    survivor = tracking.Survivor(
        pid=4242, uid=0, name="powermetrics", started="Wed Sep 23 14:05:40 2026"
    )
    mac.payloads["S4"] = payload_run("S4", cleanup="survivor", survivors=(survivor,))
    code, _, err = go(capsys)
    assert code == 1
    # At 80 columns, with each command on a line of its own (the copy pass, MAC 3.11), and
    # the words before each one on a line of their own (its review, round 3, n4).
    assert (
        "A process from the administrator reads may still be running: process 4242,\n"
        "powermetrics, user ID 0, started Wed Sep 23 14:05:40 2026.\n"
        "Check it first with\n"
        "  ps -p 4242 -o pid,uid,lstart,comm\n"
        "and only if all four still match, stop it with\n"
        "  sudo /bin/kill -TERM 4242\n"
    ) in err


def test_a_stop_that_could_not_be_verified_says_so(capsys, mac):
    mac.payloads["S3"] = payload_run("S3", cleanup="listing_failed")
    code, _, err = go(capsys)
    assert code == 1
    assert UNVERIFIED in err


# --- cancellation ---------------------------------------------------------------------------------


def _signal(signum: int):  # type: ignore[no-untyped-def]
    return lambda: os.kill(os.getpid(), signum)


def _within(seconds: float):  # type: ignore[no-untyped-def]
    """A cancellation that comes after ``seconds``, so no test waits on a question for good."""
    ends = time.monotonic() + seconds
    return lambda: time.monotonic() > ends


def _late(monkeypatch):  # type: ignore[no-untyped-def]
    """A clock for the question's reader on which a second passes between any two
    readings, so every line comes long after the question (the run's review, round 2, m9)."""
    monkeypatch.setattr(run, "_monotonic", itertools.count(100.0).__next__)


@pytest.mark.parametrize("signum", [signal.SIGINT, signal.SIGTERM, signal.SIGHUP])
def test_a_signal_during_the_user_reads_stops_the_run_and_saves_nothing(capsys, mac, signum):
    mac.before["C5"] = _signal(signum)
    code, out, err = go(capsys)
    assert code == 130
    assert out.endswith(f"{run.READING}\n")
    assert err == f"{run.STOPPED}\n"
    assert "S1" not in mac.ran and "X1" not in mac.ran  # no sudo for a signal in the user reads
    assert mac.saved() == []


def test_a_cancellation_at_the_question_stops_the_run(capsys, mac, monkeypatch):
    def cancelled_answer(cancelled):  # type: ignore[no-untyped-def]
        os.kill(os.getpid(), signal.SIGINT)
        assert cancelled()
        return None

    monkeypatch.setattr(run, "_answer", cancelled_answer)
    code, out, err = go(capsys)
    assert code == 130
    assert out.endswith(f"{run.QUESTION}\n")
    assert err == f"{run.STOPPED}\n"
    assert not any(step.startswith("S") for step in mac.ran)
    assert mac.saved() == []


def test_a_cancellation_during_a_payload_clears_sudo_and_saves_nothing(capsys, mac):
    mac.before["S3"] = _signal(signal.SIGINT)
    mac.payloads["S3"] = payload_run("S3", cancelled=True, returncode=None, stdout="")
    code, out, err = go(capsys)
    assert code == 130
    assert mac.ran[-1] == "S5" and "S4" not in mac.ran
    assert out.endswith(f"{run.COUNTING}{run.NOT_READ}\n")
    assert err == f"{run.STOPPED}\n"
    assert mac.saved() == []


def test_a_cancellation_whose_clear_fails_still_exits_130_with_the_warning(capsys, mac):
    mac.before["S3"] = _signal(signal.SIGINT)
    mac.payloads["S3"] = payload_run("S3", cancelled=True, returncode=None, stdout="")
    mac.results["S5"] = result("S5", 1)
    code, _, err = go(capsys)
    assert code == 130
    # The warning where the clear failed, and again as the run's last line.
    assert err == f"{run.WARNING}\n{run.STOPPED}\n{run.WARNING}\n"


@pytest.mark.parametrize("signum", [signal.SIGINT, signal.SIGTERM, signal.SIGHUP])
def test_a_signal_during_the_save_removes_what_the_run_made(capsys, mac, monkeypatch, signum):
    # The run's handlers set the flag for the whole save, so the writer sees a real Ctrl-C
    # as a cancellation at its next check (the #354 review, round 2, m-1).
    real = writer._publish

    def publish(*args, **kwargs):  # type: ignore[no-untyped-def]
        published = real(*args, **kwargs)
        os.kill(os.getpid(), signum)  # after the JSON, before the PDF
        return published

    monkeypatch.setattr(writer, "_publish", publish)
    code, _, err = go(capsys, "--json")
    assert code == 130
    assert err == f"{run.STOPPED}\n"
    assert mac.saved() == []
    assert mac.opened == []


@pytest.mark.parametrize("stop", [False, True], ids=["saved", "stopped"])
def test_the_signals_are_ignored_once_the_run_ends(capsys, mac, stop):
    # The audit fixes' review, round 3, m2: the run put Python's handlers back after its last
    # read of the flag, so a Ctrl-C in the moments before the tool exited printed a traceback
    # naming the installed package's files, and SIGTERM or SIGHUP ended it by the signal. From
    # the command's last read to the process's end all three are ignored.
    if stop:
        mac.before["C3"] = _signal(signal.SIGHUP)
    code, _, _ = command(capsys, "--no-root")
    assert code == (130 if stop else 0)
    assert [signal.getsignal(signum) for signum in run.SIGNALS] == [signal.SIG_IGN] * 3
    for signum in run.SIGNALS:
        os.kill(os.getpid(), signum)  # ignored: nothing is raised, and the test goes on


@pytest.mark.parametrize("stop", [False, True], ids=["saved", "cancelled"])
def test_a_payload_left_running_is_collected_before_the_run_ends(capsys, mac, monkeypatch, stop):
    # A payload the tool could not signal is still its child: its exit status is collected
    # before the tool exits if it has ended by then (Decision 2, "Stopping a payload").
    calls: list[bool] = []
    monkeypatch.setattr(spawn, "collect_abandoned", lambda: calls.append(True) or 0)
    if stop:
        mac.before["C5"] = _signal(signal.SIGINT)
    code, _, _ = go(capsys, "--no-root")
    assert code == (130 if stop else 0)
    assert calls == [True]


def test_a_signal_just_after_the_panic_count_stops_the_run(capsys, mac, monkeypatch):
    def counted(*args):  # type: ignore[no-untyped-def]
        os.kill(os.getpid(), signal.SIGINT)
        return 0

    monkeypatch.setattr(in_process, "panic_count", counted)
    code, out, err = go(capsys, "--no-root")
    assert (code, err) == (130, f"{run.STOPPED}\n")
    assert out.endswith(f"{run.READING}\n")
    assert mac.saved() == []


def test_a_handler_python_did_not_set_is_taken_and_then_ignored(capsys, monkeypatch):
    # signal.getsignal gives None for a handler set outside Python, which it cannot take
    # back. The command takes each signal from its start, --dry-run's too, and ignores it at
    # its end, whatever it found.
    calls: list[tuple[int, object]] = []

    def installed(signum, handler):  # type: ignore[no-untyped-def]
        calls.append((signum, handler))

    monkeypatch.setattr(signal, "getsignal", lambda signum: None)
    monkeypatch.setattr(signal, "signal", installed)
    assert cli.main(["--dry-run"]) == 0
    assert [signum for signum, _ in calls] == [*run.SIGNALS, *run.SIGNALS]
    assert all(callable(handler) for _, handler in calls[:3])
    assert calls[3:] == [(signum, signal.SIG_IGN) for signum in run.SIGNALS]


def test_with_no_stdin_the_question_has_no_answer(monkeypatch):
    monkeypatch.setattr(run.sys, "stdin", None)
    assert run._answer(lambda: False) is None


def test_the_answer_wait_ends_on_a_cancellation(monkeypatch):
    # The question waits in short selects, so a signal that only sets the flag ends it.
    _late(monkeypatch)
    read_end, write_end = os.pipe()
    try:
        with os.fdopen(read_end, closefd=False) as stream:
            monkeypatch.setattr(run.sys, "stdin", stream)
            calls = iter([False, False, True])
            assert run._answer(lambda: next(calls)) is None
            os.write(write_end, b"y\n")
            assert run._answer(_within(2)) == "y\n"
            os.close(write_end)
            write_end = -1
            assert run._answer(_within(2)) is None  # end of input
    finally:
        os.close(read_end)
        if write_end >= 0:
            os.close(write_end)


# --- the save ----------------------------------------------------------------------------------


def test_a_taken_name_takes_the_next_and_says_so(capsys, mac):
    (mac.desktop / PDF_NAME).write_bytes(b"not ours")
    code, out, _ = go(capsys, "--no-root")
    assert code == 0
    assert (
        "Saved: ~/Desktop/Voltry Mac Report 2026-09-23 14.05 (2).pdf\n"
        f"{run.RENAMED.format(time='14:05')}\n{run.OPENING}\n"
    ) in out
    assert (mac.desktop / PDF_NAME).read_bytes() == b"not ours"


def test_a_refused_desktop_saves_at_the_top_of_the_home_folder(capsys, mac, monkeypatch):
    real = writer._open_folder

    def refusing(path):  # type: ignore[no-untyped-def]
        if path == str(mac.desktop):
            raise PermissionError(errno.EPERM, os.strerror(errno.EPERM))
        return real(path)

    monkeypatch.setattr(writer, "_open_folder", refusing)
    code, out, _ = go(capsys, "--no-root", "--json")
    assert code == 0
    assert out.endswith(
        f"{run.DESKTOP}\n{run.FALLBACK_BEFORE}\n"
        f"  ~/{JSON_NAME}\n  ~/{PDF_NAME}\n{run.FALLBACK_AFTER}\n{run.OPENING}\n"
    )
    assert sorted(path.name for path in mac.home.iterdir()) == ["Desktop", JSON_NAME, PDF_NAME]
    assert mac.opened == [str(mac.home / PDF_NAME)]


def test_an_explicit_folder_is_not_announced_and_saves_there(capsys, mac, tmp_path):
    folder = tmp_path / "reports"
    folder.mkdir()
    code, out, _ = go(capsys, "--no-root", "--output", str(folder))
    assert code == 0
    assert run.DESKTOP not in out
    assert f"Saved: {folder / PDF_NAME}\n{run.OPENING}\n" in out
    assert [path.name for path in folder.iterdir()] == [PDF_NAME]
    assert mac.saved() == []


def test_an_explicit_folder_that_fails_names_the_folder_and_exits_4(capsys, mac):
    code, _, err = go(capsys, "--no-root", "--output", "missing\x1b[2J")
    assert code == 4
    assert err == (
        "Your report is shown above but could not be saved in this folder: No such file\n"
        "or directory.\n"
        "  missing\\x1b[2J\n"
    )
    assert err.endswith("\n  missing\\x1b[2J\n")  # the folder on a line of its own
    assert mac.opened == []


def test_a_save_that_fails_leaves_the_report_on_screen_and_exits_4(capsys, mac, monkeypatch):
    def full(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))

    monkeypatch.setattr(writer, "_write_all", full)
    code, out, err = go(capsys, "--no-root")
    assert code == 4
    assert "MAC HARDWARE OBSERVATION REPORT\n" in out
    assert err == run.NOT_SAVED.format(reason=os.strerror(errno.ENOSPC)) + "\n"
    assert mac.saved() == []


def test_files_the_save_could_not_remove_are_named_as_safe_to_delete(capsys, mac, monkeypatch):
    stuck = str(mac.desktop / ".voltry-mac-abc.tmp")

    def save(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise writer.NotSaved("No space left on device", "~/Desktop", left=(stuck,))

    monkeypatch.setattr(writer, "save", save)
    code, _, err = go(capsys, "--no-root")
    assert code == 4
    assert err == (
        run.NOT_SAVED.format(reason="No space left on device")
        + f"\n{run.LEFT_ONE}\n  ~/Desktop/.voltry-mac-abc.tmp\n"
    )


def test_a_saved_report_with_a_temporary_left_says_so(capsys, mac, monkeypatch):
    stuck = (str(mac.desktop / ".voltry-mac-a.tmp"), str(mac.desktop / ".voltry-mac-b.tmp"))
    real = writer.save

    def save(*args, **kwargs):  # type: ignore[no-untyped-def]
        return dataclasses.replace(real(*args, **kwargs), left=stuck)

    monkeypatch.setattr(writer, "save", save)
    code, out, err = go(capsys, "--no-root")
    assert code == 0
    assert err == f"{run.LEFT_MANY}\n  ~/Desktop/.voltry-mac-a.tmp\n  ~/Desktop/.voltry-mac-b.tmp\n"
    assert out.endswith(f"Saved: ~/Desktop/{PDF_NAME}\n{run.OPENING}\n")


def test_a_pdf_that_cannot_be_drawn_saves_nothing_and_exits_4(capsys, mac, monkeypatch):
    def broken(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise RuntimeError("a bug")

    monkeypatch.setattr(report_pdf, "render", broken)
    code, out, err = go(capsys, "--no-root", "--json")
    assert code == 4
    assert "MAC HARDWARE OBSERVATION REPORT\n" in out
    assert err == f"{run.PDF_BUG}\n"
    assert "a bug" not in out + err
    assert mac.saved() == []


# --- the save gate --------------------------------------------------------------------------------


def test_too_little_read_saves_nothing_and_names_what_answered(capsys, mac):
    for command_id in allowlist.USER_COMMAND_IDS:
        if command_id not in ("C1", "C12"):
            mac.results[command_id] = result(command_id, 1, stdout="")
    code, out, err = go(capsys, "--no-root")
    assert code == 4
    # At 80 columns, as the terminal summary is set.
    answered = "These items did answer: macOS version, System Integrity Protection, Panic\nreports."
    not_enough = (
        "Could not read enough of this Mac to make a report, so no report file was\nwritten."
    )
    assert err == f"{not_enough}\n{answered}\n"
    assert "MAC HARDWARE OBSERVATION REPORT" not in out
    assert mac.saved() == [] and mac.opened == []


# --- the open ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "setup",
    [
        pytest.param(("--no-open",), id="--no-open"),
        pytest.param(("SSH_CONNECTION",), id="SSH_CONNECTION"),
        pytest.param(("SSH_TTY",), id="SSH_TTY"),
    ],
)
def test_no_open_with_no_open_or_over_ssh(capsys, mac, monkeypatch, setup):
    argv = ["--no-root"]
    if setup[0].startswith("--"):
        argv.append(setup[0])
    else:
        monkeypatch.setenv(setup[0], "10.0.0.2 50000 10.0.0.1 22")
    code, out, _ = go(capsys, *argv)
    assert code == 0
    assert mac.opened == [] and "O1" not in mac.ran
    assert out.endswith(f"Saved: ~/Desktop/{PDF_NAME}\n")


@pytest.mark.parametrize("when", ["as it is named", "before it opens"])
def test_an_open_the_chokepoint_refuses_leaves_the_saved_report(capsys, mac, monkeypatch, when):
    # The report is saved before the open is tried, so a refused open is a failed open: the
    # path is printed already, and the run never says nothing was saved.
    real = spawn.Runner.published

    def published(runner, path):  # type: ignore[no-untyped-def]
        if when == "as it is named":
            raise spawn.Refused("the published report cannot be read")
        real(runner, path)
        os.chmod(path, 0o644)  # changed after it was named, so O1 refuses it

    monkeypatch.setattr(spawn.Runner, "published", published)
    code, out, err = go(capsys, "--no-root")
    assert (code, err) == (0, "")
    assert out.endswith(f"Saved: ~/Desktop/{PDF_NAME}\n")
    assert mac.saved() == [PDF_NAME] and mac.opened == []


def test_an_open_that_fails_prints_nothing_more(capsys, mac):
    mac.results["O1"] = result("O1", 1)
    code, out, _ = go(capsys, "--no-root")
    assert code == 0
    assert mac.ran.count("O1") == 1
    assert out.endswith(f"Saved: ~/Desktop/{PDF_NAME}\n")


# --- exit codes ----------------------------------------------------------------------------------


def test_an_unexpected_read_failure_exits_1_after_saving(capsys, mac):
    mac.results["C9"] = result("C9", 1, stdout="")
    code, _, _ = go(capsys, "--no-root", "--json")
    assert code == 1
    assert _saved(mac)["collection"]["unexpected_reasons"] == ["tool_error"]


def test_gatekeeper_switched_off_is_read_and_the_run_exits_0(capsys, mac):
    # Change record 11 (MAC 4.1's review, M2): spctl --status prints "assessments disabled"
    # and exits 1 with Gatekeeper off. That reads the setting; it is not a failed read.
    mac.results["C13"] = result("C13", 1, stdout="assessments disabled\n")
    code, out, err = go(capsys, "--no-root", "--json")
    assert (code, err) == (0, "")
    assert "\n  Gatekeeper                   Off\n" in out
    document = _saved(mac)
    (record,) = [r for r in document["commands"] if r["id"] == "C13"]
    assert (record["runs"], record["failed_runs"]) == (1, 0)
    assert document["collection"]["unexpected_reasons"] == []


def test_a_failed_clear_outranks_a_partial_report(capsys, mac):
    mac.results["C9"] = result("C9", 1, stdout="")
    mac.results["S5"] = result("S5", 1)
    code, _, _ = go(capsys)
    assert code == 6


def test_a_report_not_saved_outranks_a_failed_clear(capsys, mac):
    mac.results["S5"] = result("S5", 1)
    code, _, err = go(capsys, "--output", "missing")
    assert code == 4
    refusal = (
        "Your report is shown above but could not be saved in this folder: No such file\n"
        "or directory.\n"
        "  missing"
    )
    assert err == f"{run.WARNING}\n{refusal}\n{run.WARNING}\n"


def test_an_unexpected_error_on_the_elevated_path_saves_nothing_and_exits_4(capsys, mac):
    def broken():  # type: ignore[no-untyped-def]
        raise RuntimeError("a bug")

    mac.before["S4"] = broken
    code, out, err = go(capsys)
    assert code == 4
    assert mac.ran[-1] == "S5"  # the final clear ran all the same
    # The power sample never had its final listing, so its stop is not verified.
    assert err == f"{UNVERIFIED}{run.UNEXPECTED}\n"
    assert "a bug" not in out + err
    assert mac.saved() == []


def test_an_unexpected_error_elsewhere_saves_nothing_and_exits_4(capsys, mac, monkeypatch):
    def broken(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise ValueError("a bug")

    monkeypatch.setattr(run.assemble, "surfaces", broken)
    code, out, err = go(capsys, "--no-root")
    assert code == 4
    assert err == f"{run.UNEXPECTED}\n"
    assert mac.saved() == []


# --- the report's inputs -------------------------------------------------------------------------


def test_the_validated_configuration_is_the_m5_on_macos_26_6_2(capsys, mac):
    assert frozenset({("Mac17,2", "26.6.2")}) == run.VALIDATED
    go(capsys, "--no-root", "--json")
    assert _saved(mac)["platform"] == {"validated": True}


def test_another_macos_release_is_not_validated(capsys, mac):
    text = (M5 / "C1.out").read_text().replace("26.6.2", "27.0")
    mac.results["C1"] = result("C1", stdout=text)
    _, out, _ = go(capsys, "--no-root", "--json")
    assert _saved(mac)["platform"] == {"validated": False}
    assert "Validated configuration: no." in out


@pytest.mark.parametrize(("argv", "paper"), [([], "letter"), (["--paper", "a4"], "a4")])
def test_the_paper_is_the_flags_or_the_regions(capsys, mac, monkeypatch, argv, paper):
    asked: list[str] = []
    monkeypatch.setattr(in_process, "paper", lambda home: asked.append(home) or "letter")
    go(capsys, "--no-root", "--json", *argv)
    assert _saved(mac)["render"] == {"paper": paper}
    assert asked == ([] if argv else [str(mac.home)])


def test_the_local_time_ignores_tz_so_it_matches_the_time_zone_read(monkeypatch):
    # R2 reads the zone from /etc/localtime, so the offset must come from the same place,
    # not from $TZ (the #355 review, N6).
    seen: list[str | None] = []
    monkeypatch.setenv("TZ", "Asia/Tokyo")
    monkeypatch.setattr(run, "_local", lambda: seen.append(os.environ.get("TZ")) or NOW)
    assert run._now() == NOW
    assert seen == [None]
    assert os.environ["TZ"] == "Asia/Tokyo"


def test_the_local_time_carries_its_offset(monkeypatch):
    monkeypatch.delenv("TZ", raising=False)
    now = run._now()
    assert now.utcoffset() is not None


def test_the_show_serial_flag_reaches_the_report(capsys, mac):
    go(capsys, "--no-root", "--json", "--show-serial")
    hardware = [s for s in _saved(mac)["surfaces"] if s["key"] == "hardware_overview"][0]
    assert "serial_number" in hardware["values"]


# --- --debug -------------------------------------------------------------------------------------


def test_debug_names_each_command_on_stderr_and_never_its_output(capsys, mac):
    code, out, err = go(capsys, "--debug")
    assert code == 0
    lines = err.splitlines()
    assert [line.split(" ", 1)[0] for line in lines] == [
        *allowlist.USER_COMMAND_IDS,
        *ELEVATED,
        "O1",
    ]
    first = f"C1 {allowlist.display(allowlist.BY_ID['C1'].template)}: exit 0, 20 ms"
    assert lines[0] == first
    assert (
        lines[31]
        == f"S3 {allowlist.display(allowlist.BY_ID['S3'].template)}: exit 0, 900 ms, verified"
    )
    # Nothing of the outputs: C2's model, the ledger's JSON, the power plist's keys.
    for output in ("Mac17,2", '"event_rows":0', "<key>", str(mac.home)):
        assert output not in err, output
    for path in mac.desktop.iterdir():
        path.unlink()
    _, plain, _ = go(capsys)
    assert out == plain


@pytest.mark.parametrize(
    ("changes", "how"),
    [
        ({"started": False, "returncode": None, "cleanup": "verified"}, "could not start"),
        # Each forced ending in words, a command's where the two share one, never its code
        # (the copy pass's review, round 3, n2).
        ({"forced": "runtime_deadline", "returncode": -9}, "ran past its deadline"),
        ({"forced": "output_cap", "returncode": None}, "went over the output cap"),
        ({"forced": "auth_failed", "returncode": None}, "was not authenticated in time"),
        ({"forced": "launch_deadline", "returncode": None}, "did not start in time"),
        (
            {"forced": "tracking_failed", "returncode": None},
            "was stopped because its processes could not be tracked",
        ),
        ({"cancelled": True, "returncode": None}, "cancelled"),
        ({"returncode": -15}, "ended on signal 15"),
        ({"returncode": 1}, "exit 1"),
    ],
    ids=[
        "could not start",
        "runtime deadline",
        "output cap",
        "authentication",
        "launch deadline",
        "tracking",
        "cancelled",
        "signal",
        "exit",
    ],
)
def test_a_payloads_debug_line_says_how_it_ended(changes, how):
    line = run._payload_line(payload_run("S4n", **changes))
    template = allowlist.display(allowlist.BY_ID["S4n"].template)
    assert line == f"S4n {template}: {how}, 900 ms, verified"


# --- no home folder, and nothing answered -----------------------------------------------------


def test_with_no_home_folder_paths_print_whole_and_the_paper_is_a4(
    capsys, mac, monkeypatch, tmp_path
):
    def no_home():  # type: ignore[no-untyped-def]
        raise writer.NotSaved("this account has no home folder", "~")

    monkeypatch.setattr(writer, "home", no_home)
    folder = tmp_path / "reports"
    folder.mkdir()
    code, out, _ = go(capsys, "--no-root", "--json", "--output", str(folder))
    assert code == 0
    assert f"Saved: {folder / JSON_NAME}\nSaved: {folder / PDF_NAME}\n" in out
    document = validate.read((folder / JSON_NAME).read_bytes())
    assert document["render"] == {"paper": "a4"}


def test_nothing_answered_says_so():
    assert run._answered([{"key": "os_version", "availability": "unavailable"}]) == (
        run.NONE_ANSWERED
    )


# --- the run's review, round 1 --------------------------------------------------------------


def test_what_was_typed_before_the_question_is_discarded_just_before_it(capsys, mac, monkeypatch):
    # An Enter pressed while the reads ran must not answer a question not yet asked (M1).
    order: list[str] = []
    monkeypatch.setattr(run, "_discard_typed", lambda: order.append("discarded"))
    asked = run._answer
    monkeypatch.setattr(run, "_answer", lambda cancelled: order.append("asked") or asked(cancelled))
    go(capsys)
    assert order == ["discarded", "asked"]


def test_discarding_drops_a_line_typed_ahead_on_a_real_terminal(monkeypatch):
    leader, follower = os.openpty()
    try:
        os.write(leader, b"\n")  # an Enter pressed during the reads
        with os.fdopen(follower, closefd=False) as stream:
            monkeypatch.setattr(run.sys, "stdin", stream)
            assert select.select([follower], [], [], 0.5)[0] == [follower]
            run._discard_typed()
            assert select.select([follower], [], [], 0.1)[0] == []
    finally:
        os.close(leader)
        os.close(follower)


def test_discarding_is_nothing_without_a_terminal(monkeypatch):
    _late(monkeypatch)
    read_end, write_end = os.pipe()
    try:
        os.write(write_end, b"y\n")
        with os.fdopen(read_end, closefd=False) as stream:
            monkeypatch.setattr(run.sys, "stdin", stream)
            run._discard_typed()
            assert run._answer(_within(2)) == "y\n"
    finally:
        os.close(read_end)
        os.close(write_end)


def test_an_answer_typed_then_ended_with_ctrl_d_is_read_at_once(monkeypatch):
    # "y" and Ctrl-D give the terminal's reader "y" with no newline; the answer is that, not
    # a wait for the rest of a line (n9).
    _late(monkeypatch)
    leader, follower = os.openpty()
    # Never closed here: a reader still waiting inside it would hold its lock.
    stream = os.fdopen(follower, closefd=False)
    monkeypatch.setattr(run.sys, "stdin", stream)
    answers: list[str | None] = []
    worker = threading.Thread(
        target=lambda: answers.append(run._answer(lambda: False)), daemon=True
    )
    try:
        os.write(leader, b"y\x04")
        worker.start()  # in a thread: a reader waiting for the rest of the line never returns
        worker.join(2)
        assert answers == ["y"]
    finally:
        os.close(leader)  # ends a read still waiting, so the thread can finish
        if worker.is_alive():
            worker.join(2)
        os.close(follower)


def test_the_question_wait_ends_soon_after_a_cancellation(monkeypatch):
    read_end, write_end = os.pipe()
    flag: list[bool] = []
    try:
        with os.fdopen(read_end, closefd=False) as stream:
            monkeypatch.setattr(run.sys, "stdin", stream)
            started = time.monotonic()
            assert run._answer(lambda: flag.append(True) or len(flag) > 1) is None
            assert time.monotonic() - started < 0.5
    finally:
        os.close(read_end)
        os.close(write_end)


def test_with_stdout_not_a_terminal_the_question_is_not_asked(capsys, mac, monkeypatch):
    # voltry-mac > summary.txt from a terminal: the question would go into the file, unseen
    # (m6), so the reads are skipped as with no terminal.
    monkeypatch.setattr(run, "_stdout_terminal", lambda: False)
    code, out, _ = go(capsys, "--json")
    assert code == 0 and run.QUESTION not in out and mac.asked == 0
    record = _saved(mac)["elevation"]
    assert (record["consent"], record["skip_cause"]) == ("skipped", "no_terminal")


def test_no_root_never_asks_whether_the_account_is_an_administrator(capsys, mac, monkeypatch):
    # The group check can take seconds when the directory service stalls (n11).
    asked: list[bool] = []
    monkeypatch.setattr(preflight, "admin", lambda: asked.append(True) or True)
    go(capsys, "--no-root")
    assert asked == []


def test_no_read_starts_after_a_ctrl_c(capsys, mac):
    mac.before["C5"] = _signal(signal.SIGINT)
    go(capsys)
    ids = list(allowlist.USER_COMMAND_IDS)
    assert mac.ran == ids[: ids.index("C5") + 1]


def test_a_cancelled_save_names_what_it_could_not_remove(capsys, mac, monkeypatch):
    stuck = str(mac.desktop / ".voltry-mac-abc.tmp")

    def save(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise writer.Cancelled(left=(stuck,))

    monkeypatch.setattr(writer, "save", save)
    code, _, err = go(capsys, "--no-root")
    assert code == 130
    assert err == f"{run.STOPPED}\n{run.LEFT_ONE}\n  ~/Desktop/.voltry-mac-abc.tmp\n"


def test_the_smart_child_is_judged_by_its_own_table(capsys, mac):
    # Exit 2 with a valid document, no controller read, is not a failed run of C28, whatever
    # the chokepoint's rule for other commands says.
    document = {
        "schema": "voltry-mac-smart/0",
        "controllers": [
            {
                "location": "Internal",
                "media": ["disk0"],
                "status": "error",
                "error": "smart_read_failed",
            }
        ],
    }
    mac.results["C28"] = result("C28", 2, stdout=json.dumps(document))
    go(capsys, "--no-root", "--json")
    (record,) = [r for r in _saved(mac)["commands"] if r["id"] == "C28"]
    assert (record["runs"], record["failed_runs"]) == (1, 0)


@pytest.mark.parametrize("where", ["the save gate", "a PDF that cannot be drawn", "a bug"])
def test_a_cancellation_that_meets_another_failure_still_exits_130(capsys, mac, monkeypatch, where):
    # The precedence puts 130 before 4, and the run says it stopped (m4).
    def broken(*args, **kwargs):  # type: ignore[no-untyped-def]
        os.kill(os.getpid(), signal.SIGINT)
        raise RuntimeError("a bug")

    if where == "the save gate":
        for command_id in allowlist.USER_COMMAND_IDS:
            if command_id not in ("C1", "C12"):
                mac.results[command_id] = result(command_id, 1, stdout="")
        monkeypatch.setattr(
            run.model, "save_gate", lambda surfaces: os.kill(os.getpid(), signal.SIGINT) or False
        )
    elif where == "a PDF that cannot be drawn":
        monkeypatch.setattr(report_pdf, "render", broken)
    else:
        monkeypatch.setattr(run.assemble, "surfaces", broken)
    code, _, err = go(capsys, "--no-root")
    assert code == 130
    assert run.STOPPED in err
    assert mac.saved() == []


def test_an_unexpected_error_after_the_save_says_the_report_was_saved(capsys, mac, monkeypatch):
    # The files are published and named before the open; a bug then is not "nothing was
    # saved" (m3).
    def broken(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise RuntimeError("a bug")

    monkeypatch.setattr(run, "_open", broken)
    code, out, err = go(capsys, "--no-root", "--json")
    assert code == 1
    assert f"Saved: ~/Desktop/{PDF_NAME}\n" in out
    assert err == f"{run.SAVED_THEN_UNEXPECTED}\n"
    assert "Nothing was saved" not in err
    assert mac.saved() == [JSON_NAME, PDF_NAME]


def test_a_signal_after_the_save_opens_nothing_and_says_the_report_is_saved(
    capsys, mac, monkeypatch
):
    # n7: the PDF is published and named; a Ctrl-C before the open stops the run there.
    real = run._named

    def named(saved, local):  # type: ignore[no-untyped-def]
        real(saved, local)
        os.kill(os.getpid(), signal.SIGINT)

    monkeypatch.setattr(run, "_named", named)
    code, out, err = go(capsys, "--no-root")
    assert code == 130
    assert f"Saved: ~/Desktop/{PDF_NAME}\n" in out and run.OPENING not in out
    assert err == f"{run.STOPPED_SAVED}\n"
    assert mac.opened == [] and mac.saved() == [PDF_NAME]


# Change record 10 (the GPT audit, pass 1, G1-09): a save is complete when the output
# writer's last read of the flag passes. A signal before it saves nothing; one after it keeps
# the report and opens nothing; one as the open runs or after it, until the run's last read
# of the flag, keeps the report and says it may not have opened (the GPT audit, pass 2,
# G2-03: the run once read the flag for the last time just before the open).
_BEFORE_COMPLETE = [
    "just before the PDF's link",
    "just after the PDF's link",
    "at the folder's flush",
]


def _signal_in_the_save(monkeypatch: pytest.MonkeyPatch, where: str, signum: int) -> None:
    """The signal at one step of the save before its last read of the flag."""
    if where == "at the folder's flush":
        real_sync = writer._sync

        def sync(descriptor):  # type: ignore[no-untyped-def]
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):  # the folder's, the last flush
                os.kill(os.getpid(), signum)
            return real_sync(descriptor)

        monkeypatch.setattr(writer, "_sync", sync)
        return
    real = writer._publish

    def publish(folder_fd, temporary, final):  # type: ignore[no-untyped-def]
        pdf = final.endswith(".pdf")
        if pdf and where == "just before the PDF's link":
            os.kill(os.getpid(), signum)
        published = real(folder_fd, temporary, final)
        if pdf and where == "just after the PDF's link":
            os.kill(os.getpid(), signum)
        return published

    monkeypatch.setattr(writer, "_publish", publish)


def _signal_once_saved(monkeypatch: pytest.MonkeyPatch, desktop: Path, signum: int) -> None:
    """The signal just after the save's last read of the flag: the writer names its folder
    again then, with the PDF published."""
    real = writer._named

    def named(folder_fd, path):  # type: ignore[no-untyped-def]
        if (desktop / PDF_NAME).exists():
            os.kill(os.getpid(), signum)
        return real(folder_fd, path)

    monkeypatch.setattr(writer, "_named", named)


@pytest.mark.parametrize("signum", run.SIGNALS)
@pytest.mark.parametrize("where", _BEFORE_COMPLETE)
def test_a_signal_before_the_save_is_complete_saves_nothing(
    capsys, mac, monkeypatch, where, signum
):
    _signal_in_the_save(monkeypatch, where, signum)
    code, out, err = go(capsys, "--no-root", "--json")
    assert (code, err) == (130, f"{run.STOPPED}\n")
    assert "Saved:" not in out and mac.saved() == [] and "O1" not in mac.ran


@pytest.mark.parametrize("signum", run.SIGNALS)
def test_a_signal_once_the_save_is_complete_keeps_the_report_and_opens_nothing(
    capsys, mac, monkeypatch, signum
):
    _signal_once_saved(monkeypatch, mac.desktop, signum)
    code, out, err = go(capsys, "--no-root", "--json")
    assert (code, err) == (130, f"{run.STOPPED_SAVED}\n")
    assert f"Saved: ~/Desktop/{PDF_NAME}\n" in out and run.OPENING not in out
    assert mac.saved() == [JSON_NAME, PDF_NAME] and "O1" not in mac.ran


def test_a_signal_as_the_open_returns_still_stops_the_run(capsys, mac, monkeypatch):
    real = spawn.Runner.run

    def ran(runner, command_id, **kwargs):  # type: ignore[no-untyped-def]
        found = real(runner, command_id, **kwargs)
        if command_id == "O1":
            os.kill(os.getpid(), signal.SIGINT)
        return found

    monkeypatch.setattr(spawn.Runner, "run", ran)
    code, out, err = go(capsys, "--no-root")
    assert (code, err) == (130, f"{run.STOPPED_OPENING}\n")
    assert out.endswith(f"Saved: ~/Desktop/{PDF_NAME}\n") and run.OPENING not in out
    assert mac.saved() == [PDF_NAME] and mac.opened == [str(mac.desktop / PDF_NAME)]


def _nothing_to_open(monkeypatch: pytest.MonkeyPatch, setup: str) -> list[str]:
    """The run's arguments with --no-open, or over SSH."""
    if setup.startswith("--"):
        return ["--no-root", setup]
    monkeypatch.setenv(setup, "10.0.0.2 50000 10.0.0.1 22")
    return ["--no-root"]


@pytest.mark.parametrize("setup", ["--no-open", "SSH_CONNECTION"])
def test_with_nothing_to_open_a_signal_as_the_saves_lines_print_stops_the_run(
    capsys, mac, monkeypatch, setup
):
    # The flag is read once more after the save's lines, where the open would be.
    real = run._named

    def named(saved, local):  # type: ignore[no-untyped-def]
        real(saved, local)
        os.kill(os.getpid(), signal.SIGINT)

    monkeypatch.setattr(run, "_named", named)
    code, out, err = go(capsys, *_nothing_to_open(monkeypatch, setup))
    assert (code, err) == (130, f"{run.STOPPED_SAVED}\n")
    assert out.endswith(f"Saved: ~/Desktop/{PDF_NAME}\n")
    assert mac.saved() == [PDF_NAME] and "O1" not in mac.ran


@pytest.mark.parametrize("setup", ["--no-open", "SSH_CONNECTION"])
def test_with_nothing_to_open_a_signal_after_that_read_still_stops_the_run(
    capsys, mac, monkeypatch, setup
):
    real = run._open

    def opened(*args, **kwargs):  # type: ignore[no-untyped-def]
        os.kill(os.getpid(), signal.SIGINT)  # after that read, before the run's last one
        return real(*args, **kwargs)

    monkeypatch.setattr(run, "_open", opened)
    code, out, err = go(capsys, *_nothing_to_open(monkeypatch, setup))
    assert (code, err) == (130, f"{run.STOPPED_SAVED}\n")
    assert out.endswith(f"Saved: ~/Desktop/{PDF_NAME}\n")
    assert mac.saved() == [PDF_NAME] and "O1" not in mac.ran


def test_an_ignored_signal_stays_ignored(capsys, mac, monkeypatch):
    # Under nohup, SIGHUP is ignored when the run starts, and stays so (n8).
    before = signal.signal(signal.SIGHUP, signal.SIG_IGN)
    try:
        mac.before["C5"] = _signal(signal.SIGHUP)
        code, _, _ = go(capsys, "--no-root")
        assert code == 0 and mac.saved() == [PDF_NAME]
        assert signal.getsignal(signal.SIGHUP) is signal.SIG_IGN
    finally:
        signal.signal(signal.SIGHUP, before)


def test_with_debug_the_reads_line_is_whole(mac, monkeypatch):
    # On a terminal stdout and stderr share the screen: the first --debug line never joins
    # "Reading this Mac..." (n14).
    screen = io.StringIO()
    monkeypatch.setattr(run.sys, "stdout", screen)
    monkeypatch.setattr(run.sys, "stderr", screen)
    assert cli.main(["--no-root", "--debug"]) == 0
    lines = screen.getvalue().splitlines()
    reads = lines.index(f"{run.READING} done (0.0 s).")
    assert all(
        line.split(" ", 1)[0] in allowlist.USER_COMMAND_IDS for line in lines[reads - 27 : reads]
    )
    assert sum(run.READING in line for line in lines) == 1


def test_an_empty_output_folder_is_named_as_such(capsys, mac):
    code, _, err = go(capsys, "--no-root", "--output", "")
    assert code == 4
    assert err == run.NOT_SAVED.format(reason=run.NO_FOLDER) + "\n"


def test_a_move_home_that_fails_too_names_the_home_folder(capsys, mac, monkeypatch):
    # n4: the Desktop refused, the home folder failed too; the line says where it tried last.
    def open_folder(path):  # type: ignore[no-untyped-def]
        if path == str(mac.desktop):
            raise PermissionError(errno.EPERM, os.strerror(errno.EPERM))
        raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))

    monkeypatch.setattr(writer, "_open_folder", open_folder)
    code, _, err = go(capsys, "--no-root")
    assert code == 4
    # The home folder was the fallback, so the message says the Desktop came first (the copy
    # pass's review, round 1, n4).
    assert err == (
        "macOS did not let your terminal app use your Desktop folder, and the report\n"
        "could not be saved at the top of your home folder either: No space left on\n"
        "device.\n"
    )


@pytest.mark.parametrize("code", [errno.EPIPE, errno.EIO, errno.ENXIO])
def test_a_terminal_that_went_away_does_not_end_the_run_with_a_traceback(monkeypatch, code):
    # m5: a closed terminal window makes every write fail with EIO. The rest has nowhere to
    # go, and nothing is said about it (the run's review, round 2, m13).
    class Gone(io.StringIO):
        def write(self, text):  # type: ignore[no-untyped-def]
            raise OSError(code, os.strerror(code))

        def flush(self):  # type: ignore[no-untyped-def]
            raise OSError(code, os.strerror(code))

        def fileno(self):  # type: ignore[no-untyped-def]
            raise io.UnsupportedOperation("no descriptor")

    gone, err = Gone(), io.StringIO()
    monkeypatch.setattr(sys, "stdout", gone)
    monkeypatch.setattr(sys, "stderr", err)
    console.write(gone, "a line\n")  # no exception
    assert err.getvalue() == ""


# --- the run's review, round 2 --------------------------------------------------------------


@pytest.mark.parametrize("early", [b"\n", b"\x04"], ids=["an Enter", "Ctrl-D"])
def test_what_comes_as_the_question_prints_is_dropped(monkeypatch, early):
    # m9: the flush drops only what has come. Keys still on their way, or the rest of a
    # paste the terminal held back, come just after it: what comes sooner than 0.2 s after
    # the question, a line or a Ctrl-D, was typed before anyone could read it, and the wait
    # goes on.
    leader, follower = os.openpty()
    try:
        with os.fdopen(follower, closefd=False) as stream:
            monkeypatch.setattr(run.sys, "stdin", stream)
            # The question prints at 100.0; the early key is read 0.15 s later, the "y" 0.25 s.
            clock = iter([100.0, 100.15, 100.25])
            monkeypatch.setattr(run, "_monotonic", lambda: next(clock))
            os.write(leader, early + b"y\n")
            assert run._answer(_within(2)) == "y\n"
    finally:
        os.close(leader)
        os.close(follower)


# The run on a real terminal (m10): a child whose stdin, stdout and stderr are a
# pseudo-terminal, against the fake M5 (tests/fake_mac.py), with the real question reader,
# flush and terminal checks and the real clock. C5 takes 1.5 s, a slow read to type during. Nothing
# real starts: the chokepoint answers from the M5's captures, no process can be spawned,
# and --no-open.
_ON_A_TERMINAL = (
    "import importlib.util, sys, time\n"
    "from pathlib import Path\n"
    "import pytest\n"
    "spec = importlib.util.spec_from_file_location('voltry_mac_test_fake_mac', sys.argv[1])\n"
    "tests = importlib.util.module_from_spec(spec)\n"
    "sys.modules[spec.name] = tests\n"
    "spec.loader.exec_module(tests)\n"
    "from voltry_mac import cli, preflight, run, spawn\n"
    "real = (run._answer, run._stdout_terminal, run._monotonic, run._discard_typed,\n"
    "        preflight.terminal)\n"
    "mac = tests.Mac(pytest.MonkeyPatch(), Path(sys.argv[2]))\n"
    "(run._answer, run._stdout_terminal, run._monotonic, run._discard_typed,\n"
    " preflight.terminal) = real\n"
    "def refused(*args, **kwargs):\n"
    "    raise AssertionError('a real process')\n"
    "spawn._popen = refused\n"
    "mac.before['C5'] = lambda: time.sleep(1.5)\n"
    "sys.exit(cli.main(['--json', '--no-open']))\n"
)


def _shown(
    leader: int,
    screen: bytearray,
    text: str | None,
    seconds: float,
    child: subprocess.Popen[bytes],
) -> bool:
    """Read the child's terminal for up to ``seconds``: True once ``text`` is on it; False
    when the time is up, or when the child has ended and shown everything."""
    wanted = None if text is None else text.encode()
    ends = time.monotonic() + seconds
    while time.monotonic() < ends:
        if not select.select([leader], [], [], 0.05)[0]:
            if child.poll() is not None:
                return False
            continue
        try:
            chunk = os.read(leader, 65536)
        except OSError:  # EIO, once every copy of the child's side is closed
            return False
        if not chunk:
            return False
        screen.extend(chunk)
        if wanted is not None and wanted in screen:
            return True
    return False


def test_on_a_terminal_only_an_answer_typed_after_the_question_decides(tmp_path):
    # m10: an Enter, then a "y" with no Enter, typed while a read is slow, answer nothing:
    # the question still waits a second after it prints, and the "y" typed then decides. A
    # flush moved before the reads would leave the "y" in the line, to join the answer.
    home = tmp_path / "home"
    (home / "Desktop").mkdir(parents=True)
    leader, follower = os.openpty()
    try:
        child = subprocess.Popen(  # noqa: S603 - a test-owned child
            [
                sys.executable,
                "-c",
                _ON_A_TERMINAL,
                str(Path(__file__).with_name("fake_mac.py")),
                str(home),
            ],
            stdin=follower,
            stdout=follower,
            stderr=follower,
            cwd=tmp_path,
            start_new_session=True,
        )
    finally:
        os.close(follower)
    screen = bytearray()
    try:
        assert _shown(leader, screen, run.READING, 60, child), bytes(screen)
        time.sleep(0.3)  # inside C5
        os.write(leader, b"\n")
        os.write(leader, b"y")
        assert _shown(leader, screen, run.QUESTION, 60, child), bytes(screen)
        _shown(leader, screen, run.COUNTING, 1.0, child)  # a second on the question
        assert child.poll() is None, bytes(screen)
        assert run.COUNTING.encode() not in screen and run.SKIPPING.encode() not in screen
        os.write(leader, b"y\n")  # the answer
        _shown(leader, screen, None, 60, child)  # to the end of the run
        assert child.wait(timeout=60) == 0, bytes(screen)
    finally:
        os.close(leader)
        if child.poll() is None:
            child.kill()
        child.wait(timeout=60)
    assert b"Traceback" not in screen
    document = validate.read((home / "Desktop" / JSON_NAME).read_bytes())
    assert document["elevation"]["consent"] == "yes"


def test_stdout_is_a_terminal_only_when_it_is_one(monkeypatch, tmp_path):
    # m10: the real check, which the run tests' fake Mac replaces.
    leader, follower = os.openpty()
    try:
        with os.fdopen(follower, "w", closefd=False) as screen:
            monkeypatch.setattr(run.sys, "stdout", screen)
            assert run._stdout_terminal() is True
    finally:
        os.close(leader)
        os.close(follower)
    with (tmp_path / "summary.txt").open("w") as file:
        monkeypatch.setattr(run.sys, "stdout", file)
        assert run._stdout_terminal() is False
    assert run._stdout_terminal() is False  # the file, closed
    monkeypatch.setattr(run.sys, "stdout", None)
    assert run._stdout_terminal() is False


def test_a_ctrl_c_then_a_folder_refused_stops_the_run(capsys, mac, monkeypatch, tmp_path):
    # m12: --output ~/Documents, and macOS asks whether the terminal app may use the folder;
    # the owner presses Ctrl-C, then Don't Allow. The stop outranks the refusal, 130 before 4.
    guarded = tmp_path / "Documents"
    guarded.mkdir()
    real = writer._open_folder

    def asked(path):  # type: ignore[no-untyped-def]
        if path == str(guarded):
            os.kill(os.getpid(), signal.SIGINT)
            raise PermissionError(errno.EPERM, os.strerror(errno.EPERM))
        return real(path)

    monkeypatch.setattr(writer, "_open_folder", asked)
    code, _, err = go(capsys, "--no-root", "--output", str(guarded))
    assert (code, err) == (130, f"{run.STOPPED}\n")
    assert list(guarded.iterdir()) == [] and mac.opened == []


def test_a_cancelled_save_that_failed_names_what_it_left(capsys, mac, monkeypatch):
    # m12: a save that fails after a Ctrl-C still names the files it could not remove.
    stuck = str(mac.desktop / ".voltry-mac-abc.tmp")

    def save(*args, **kwargs):  # type: ignore[no-untyped-def]
        os.kill(os.getpid(), signal.SIGINT)
        raise writer.NotSaved(os.strerror(errno.ENOSPC), str(mac.desktop), left=(stuck,))

    monkeypatch.setattr(writer, "save", save)
    code, _, err = go(capsys, "--no-root")
    assert code == 130
    assert err == f"{run.STOPPED}\n{run.LEFT_ONE}\n  ~/Desktop/.voltry-mac-abc.tmp\n"


class _FullDisk(io.FileIO):
    """A redirected stdout on a disk with room for ``room`` more bytes, then ENOSPC. Once
    pointed at /dev/null it takes everything, as /dev/null does."""

    def __init__(self, path: Path, room: int) -> None:
        super().__init__(path, "w")
        self.room = room

    def write(self, data):  # type: ignore[no-untyped-def]
        if os.path.samestat(os.fstat(self.fileno()), os.stat(os.devnull)):
            return super().write(data)
        if self.room == 0:
            raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))
        taken = super().write(bytes(data[: self.room]))
        self.room -= taken
        return taken


def test_a_full_disk_behind_stdout_is_said_once_and_keeps_the_exit_code(mac, monkeypatch, tmp_path):
    # m13: voltry-mac > summary.txt on a disk that fills. The terminal report stops where
    # the disk did; stderr says so once, in a fixed line; the run saves and exits as it
    # would have.
    summary = tmp_path / "summary.txt"
    disk = io.BufferedWriter(_FullDisk(summary, 2500))
    err = io.StringIO()
    # The patch is undone before the file closes.
    with io.TextIOWrapper(disk, encoding="utf-8") as out, monkeypatch.context() as patch:
        patch.setattr(run.sys, "stdout", out)
        patch.setattr(run.sys, "stderr", err)
        code = cli.main(["--no-root"])
    assert code == 0 and mac.saved() == [PDF_NAME]
    assert len(err.getvalue().splitlines()) == 1
    assert err.getvalue() == f"{console.INCOMPLETE}\n"
    assert summary.stat().st_size == 2500
    assert summary.read_text(encoding="utf-8").startswith(f"{cli.HEADER}\n")


def test_a_terminal_left_non_blocking_still_shows_the_whole_report(mac, monkeypatch):
    # m13: another program in the same terminal can leave it non-blocking, and a write it
    # cannot take yet then fails (EAGAIN) while the terminal is slow to read. The run waits
    # until it takes more, and nothing is lost, the Saved line included.
    leader, follower = os.openpty()
    screen = bytearray()
    last = f"{run.OPENING}\r\n".encode()

    def slow_terminal() -> None:
        try:
            time.sleep(0.3)  # the terminal fills before it reads
            ends = time.monotonic() + 10
            while last not in screen and time.monotonic() < ends:
                if select.select([leader], [], [], 0.1)[0]:
                    chunk = os.read(leader, 65536)
                    if not chunk:
                        break
                    screen.extend(chunk)
        except OSError:  # EIO: the run's side of the terminal is gone
            pass
        finally:
            os.close(leader)  # a run still waiting on the terminal then ends with EIO

    reader = threading.Thread(target=slow_terminal, daemon=True)
    err = io.StringIO()
    try:
        flags = fcntl.fcntl(follower, fcntl.F_GETFL)
        fcntl.fcntl(follower, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        # As Python opens a terminal for stdout: line-buffered, with the device's block size.
        with (
            open(follower, "w", encoding="utf-8", closefd=False) as tty,
            monkeypatch.context() as patch,
        ):
            patch.setattr(run.sys, "stdout", tty)
            patch.setattr(run.sys, "stderr", err)
            reader.start()
            code = cli.main(["--no-root"])
            reader.join(15)
    finally:
        if reader.ident is None:  # once started, the reader closes the leader itself
            os.close(leader)
        os.close(follower)
    shown = bytes(screen).replace(b"\r\n", b"\n").decode()
    assert (code, err.getvalue()) == (0, "")
    assert shown.startswith(f"{cli.HEADER}\n")
    assert shown.endswith(f"Saved: ~/Desktop/{PDF_NAME}\n{run.OPENING}\n")


def test_a_stream_that_would_block_with_nothing_to_wait_on_says_so(monkeypatch):
    # m13: with no descriptor to wait on, the rest cannot be written.
    class Stuck(io.StringIO):
        def flush(self):  # type: ignore[no-untyped-def]
            raise BlockingIOError(errno.EAGAIN, os.strerror(errno.EAGAIN))

        def fileno(self):  # type: ignore[no-untyped-def]
            raise io.UnsupportedOperation("no descriptor")

    stuck, err = Stuck(), io.StringIO()
    monkeypatch.setattr(sys, "stdout", stuck)
    monkeypatch.setattr(sys, "stderr", err)
    console.write(stuck, "a line\n")
    assert len(err.getvalue().splitlines()) == 1
    assert err.getvalue() == f"{console.INCOMPLETE}\n"


@pytest.mark.parametrize(("answer", "then"), [("y", run.COUNTING), ("n", run.SKIPPING)])
def test_an_answer_ended_with_ctrl_d_ends_its_line(capsys, mac, answer, then):
    # n15: Ctrl-D hands the answer over without echoing a newline, so the run gives one, and
    # the next line, or sudo's prompt, never joins the question's.
    mac.answer = answer
    code, out, _ = go(capsys)
    assert code == 0
    assert f"{run.QUESTION}\n{then}" in out


def test_the_cancellation_flag_is_set_without_a_lock(capsys, mac):
    # n18: CPython runs a signal handler inside another. A threading.Event's set() holds a
    # lock, and a second signal handled inside the first would wait on it for good: no
    # Stopped line, and no final sudo -k. The handler sets a plain attribute, calling nothing,
    # and the run stops.
    calls: list[object] = []
    handlers: list[object] = []

    def trace(frame, event, arg):  # type: ignore[no-untyped-def]
        if event == "call":
            calls.append(frame.f_code)

    def handled() -> None:
        handler = signal.getsignal(signal.SIGINT)
        assert callable(handler)
        handlers.append(handler)
        before = sys.gettrace()
        sys.settrace(trace)
        try:
            handler(signal.SIGINT, None)
        finally:
            sys.settrace(before)

    mac.before["C5"] = handled
    code, _, err = go(capsys, "--no-root")
    assert (code, err) == (130, f"{run.STOPPED}\n")
    assert calls == [handlers[0].__code__]  # type: ignore[attr-defined]


def test_a_ctrl_c_while_the_admin_check_waits_explains_nothing(capsys, mac, monkeypatch):
    # n19: the group check can wait 5 s on a directory service that stalls; a Ctrl-C then
    # stops the run before the explanation.
    def stalled():  # type: ignore[no-untyped-def]
        os.kill(os.getpid(), signal.SIGINT)  # the owner gives up while macOS looks
        return None  # no answer in time

    monkeypatch.setattr(preflight, "admin", stalled)
    code, out, err = go(capsys)
    assert (code, err) == (130, f"{run.STOPPED}\n")
    assert run.EXPLANATION.splitlines()[0] not in out and run.QUESTION not in out
    assert mac.ran == list(allowlist.USER_COMMAND_IDS) and mac.saved() == []


def test_a_ctrl_c_while_the_report_is_built_prints_no_summary(capsys, mac, monkeypatch):
    # n19: a run that knows it was stopped prints no summary before it says so.
    monkeypatch.setattr(run, "_now", lambda: os.kill(os.getpid(), signal.SIGINT) or NOW)
    code, out, err = go(capsys, "--no-root", "--json")
    assert (code, err) == (130, f"{run.STOPPED}\n")
    assert "MAC HARDWARE OBSERVATION REPORT" not in out and run.FULL_REPORT not in out
    assert mac.saved() == []


def test_a_ctrl_c_while_the_summary_prints_outranks_a_pdf_that_cannot_be_drawn(
    capsys, mac, monkeypatch
):
    # A signal that comes as the summary prints, after the flag was last read, still comes
    # before the PDF writer's bug: 130, and the stop line (m4, with n19's read before).
    def broken(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise RuntimeError("a bug")

    real = terminal.summary

    def summary(document):  # type: ignore[no-untyped-def]
        os.kill(os.getpid(), signal.SIGINT)
        return real(document)

    monkeypatch.setattr(report_pdf, "render", broken)
    monkeypatch.setattr(run.terminal, "summary", summary)
    code, out, err = go(capsys, "--no-root")
    assert (code, err) == (130, f"{run.STOPPED}\n")
    assert "MAC HARDWARE OBSERVATION REPORT\n" in out
    assert mac.saved() == []


# --- the GPT audit, pass 1 ---------------------------------------------------------------------


def test_a_status_line_given_twice_is_read_as_neither(capsys, mac):
    # G1-02: csrutil's line twice, enabled and disabled, is not csrutil's shape. The report
    # keeps neither, the collection is no longer complete, and the unexpected reason exits 1.
    lines = (
        "System Integrity Protection status: enabled.\n"
        "System Integrity Protection status: disabled.\n"
    )
    mac.results["C12"] = result("C12", stdout=lines)
    code, out, _ = go(capsys, "--no-root", "--json")
    assert code == 1
    document = _saved(mac)
    sip = next(s for s in document["surfaces"] if s["key"] == "sip_status")
    assert (sip["availability"], sip.get("reason"), sip["values"]) == (
        "unavailable",
        "source_changed",
        {},
    )
    assert document["collection"]["status"] != "complete"
    assert "SIP, " not in out and "SIP on" not in out


def test_an_open_a_stop_came_before_or_cut_short_says_it_may_not_have_opened(capsys, mac):
    # G1-01: O1 does not start once its last check finds the flag set, and one running when
    # it is set is stopped. Either way the report is saved and the open may not have happened.
    mac.results["O1"] = result("O1", None, ending=spawn.Ending.CANCELLED)
    code, out, err = go(capsys, "--no-root")
    assert code == 130
    assert f"Saved: ~/Desktop/{PDF_NAME}\n" in out and run.OPENING not in out
    assert err == f"{run.STOPPED_OPENING}\n"
    assert mac.saved() == [PDF_NAME]


# --- the review of #326, round 1 -----------------------------------------------------------------


def test_a_payload_the_flag_kept_from_starting_says_so_on_its_debug_line():
    # M6: it said "could not start" and "verified", though nothing failed to start and no
    # listing looked.
    line = run._payload_line(
        payload_run("S3", started=False, cancelled=True, returncode=None, duration_ms=0)
    )
    assert line == f"S3 {allowlist.display(allowlist.BY_ID['S3'].template)}: cancelled, 0 ms"


@pytest.mark.parametrize("command_id", ["S3", "S4n"])
def test_a_payload_the_flag_keeps_from_starting_gets_no_line(capsys, monkeypatch, command_id):
    # N3: "Reading memory error records..." then " not read" printed for a payload the run
    # was never going to start. The real runner and tracking; no process starts.
    def no_start(argv):  # type: ignore[no-untyped-def]
        raise AssertionError("a process was started")

    monkeypatch.setattr(spawn, "_popen", no_start)
    stopped = run._Run(argparse.Namespace(debug=True), SUPPORTED, lambda: True)
    runner = spawn.Runner(cancelled=lambda: True)
    found = stopped.payloads(runner)(command_id, 0)
    out, err = capsys.readouterr()
    assert out == ""
    template = allowlist.display(allowlist.BY_ID[command_id].template)
    assert err == f"{command_id} {template}: cancelled, 0 ms\n"
    assert (found.started, found.cancelled, found.cleanup) == (False, True, "verified")
    # M6: no listing ran, so P1 has no record of none.
    assert runner.records() == []


def _signal_once_published(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """The signal comes once the report is published for O1, just before it."""
    real = spawn.Runner.published

    def published(runner, path):  # type: ignore[no-untyped-def]
        real(runner, path)
        os.kill(os.getpid(), signal.SIGINT)

    monkeypatch.setattr(spawn.Runner, "published", published)


def test_a_stop_just_before_the_open_says_the_report_was_not_opened(capsys, mac, monkeypatch):
    # N3: the flag read just before O1 is a stop that came first: nothing opened, so the run
    # says so, rather than that it may not have opened.
    _signal_once_published(monkeypatch)
    code, out, err = go(capsys, "--no-root")
    assert code == 130 and "O1" not in mac.ran
    assert f"Saved: ~/Desktop/{PDF_NAME}\n" in out and run.OPENING not in out
    assert err == f"{run.STOPPED_SAVED}\n"
    assert mac.saved() == [PDF_NAME]


# --- the review of #326, round 2 -----------------------------------------------------------------
#
# m1 and n8: the home folder in a path the run prints is what the file system says it is, the
# longest leading part with the home folder's device and inode number, whatever the path's
# case, form or spelling. Made-up account names, in folders under tmp_path.


def _one_folder(one: str, other: str) -> bool:
    try:
        return os.path.samestat(os.stat(one), os.stat(other))
    except OSError:
        return False


def _home_through_a_link(monkeypatch, tmp_path) -> tuple[Mac, Path]:  # type: ignore[no-untyped-def]
    """A fake M5 whose home folder, as the account database names it, is a symlink,
    tmp_path/Users/jane, to the folder itself, tmp_path/Data/jane; the working folder is
    tmp_path."""
    itself = tmp_path / "Data" / "jane"
    (itself / "Desktop").mkdir(parents=True)
    home = tmp_path / "Users" / "jane"
    home.parent.mkdir()
    home.symlink_to(itself)
    monkeypatch.chdir(tmp_path)
    return Mac(monkeypatch, home), itself


def test_output_dot_in_a_home_folder_reached_through_a_symlink_prints_with_a_tilde(
    capsys, monkeypatch, tmp_path
):
    # n8: the working folder is the folder itself, never the link the account database
    # names, so no name of the home folder's matched the paths the run printed.
    mac, itself = _home_through_a_link(monkeypatch, tmp_path)
    monkeypatch.chdir(mac.home)
    code, out, err = go(capsys, "--no-root", "--json", "--output", ".")
    assert (code, err) == (0, "")
    assert out.endswith(f"Saved: ~/{JSON_NAME}\nSaved: ~/{PDF_NAME}\n{run.OPENING}\n")
    assert sorted(path.name for path in itself.iterdir()) == ["Desktop", JSON_NAME, PDF_NAME]


def test_a_file_left_in_a_home_folder_reached_through_a_symlink_prints_with_a_tilde(
    capsys, monkeypatch, tmp_path
):
    mac, itself = _home_through_a_link(monkeypatch, tmp_path)
    monkeypatch.chdir(mac.home)
    real = writer._unlink

    def unlink(folder_fd, name):  # type: ignore[no-untyped-def]
        if name.startswith(".voltry-mac-"):
            raise OSError(errno.EBUSY, os.strerror(errno.EBUSY))
        real(folder_fd, name)

    monkeypatch.setattr(writer, "_unlink", unlink)
    code, out, err = go(capsys, "--no-root", "--output", ".")
    (left,) = [path.name for path in itself.iterdir() if path.name.startswith(".voltry-mac-")]
    # The temporary is a second name for the PDF, so it was not opened (change record 21).
    assert (code, err) == (0, f"{run.LEFT_ONE}\n  ~/{left}\n{run.SECOND_NAME}\n")
    assert out.endswith(f"Saved: ~/{PDF_NAME}\n")


def test_a_missing_folder_in_a_home_folder_reached_through_a_symlink_prints_with_a_tilde(
    capsys, monkeypatch, tmp_path
):
    _, itself = _home_through_a_link(monkeypatch, tmp_path)
    code, _, err = go(capsys, "--no-root", "--output", str(itself / "Gone"))
    assert code == 4
    assert err.endswith("\n  ~/Gone\n") and str(itself) not in err


def test_a_refused_folder_that_is_the_home_folder_itself_prints_as_a_tilde(
    capsys, monkeypatch, tmp_path
):
    # m1: the folder a report could not be saved in may be the home folder itself, so the
    # run looks up that folder's own path too, not only the folders above it.
    _, itself = _home_through_a_link(monkeypatch, tmp_path)

    def full(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))

    monkeypatch.setattr(writer, "_write_all", full)
    code, _, err = go(capsys, "--no-root", "--output", str(itself))
    assert code == 4
    assert err.endswith("\n  ~\n") and str(itself) not in err


@pytest.mark.parametrize(
    "spelling", ["{parent}//{name}", "{home}/."], ids=["with //", "with a trailing /."]
)
def test_a_home_folder_the_account_database_spells_another_way_prints_as_a_tilde(
    capsys, mac, monkeypatch, spelling
):
    # n8: every path the writer names is in normal form, and the home folder's, as the
    # account database gives it, need not be.
    home = spelling.format(parent=mac.home.parent, name=mac.home.name, home=mac.home)
    monkeypatch.setattr(writer, "home", lambda: home)
    code, out, _ = go(capsys, "--no-root", "--json")
    assert code == 0
    assert out.endswith(
        f"Saved: ~/Desktop/{JSON_NAME}\nSaved: ~/Desktop/{PDF_NAME}\n{run.OPENING}\n"
    )


@pytest.mark.parametrize(
    "made", [True, False], ids=["a folder by that name", "no folder by that name"]
)
def test_the_volume_decides_whether_a_name_in_another_case_is_the_home_folder(
    capsys, monkeypatch, tmp_path, made
):
    # m1: where the volume ignores case, Alice is the home folder alice itself, and prints as
    # ~. On a case-sensitive volume it is a folder of its own, or nothing, and prints in
    # full, though the character table folds its name to the home folder's.
    home = tmp_path / "Users" / "alice"
    (home / "Documents").mkdir(parents=True)
    other = tmp_path / "Users" / "Alice" / "Documents"
    if made:
        other.mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(tmp_path)
    Mac(monkeypatch, home)
    same = _one_folder(str(other), str(home / "Documents"))
    code, out, err = go(capsys, "--no-root", "--output", str(other))
    if same:
        assert (code, err) == (0, "")
        assert f"Saved: ~/Documents/{PDF_NAME}\n" in out
    elif made:
        assert code == 0
        assert f"Saved: {terminal.display_path(str(other / PDF_NAME), '')}\n" in out
    else:
        assert code == 4
        assert err.endswith(f"\n  {terminal.display_path(str(other), '')}\n")


def test_a_home_folder_the_volume_matches_by_a_later_unicode_prints_with_a_tilde(
    capsys, monkeypatch, tmp_path
):
    # m1: APFS on macOS 26 matches names by Unicode 16.0 and 17.0, and the character table
    # is 15.0.0, which leaves Cyrillic capital TJE (U+1C89, Unicode 16.0) unassigned. The
    # home folder is in a folder named with it, and the path names that folder with the small
    # letter (U+1C8A): where the volume finds one folder, the path is the home folder's.
    home = tmp_path / "Vol\u1c89" / "jane"
    try:
        (home / "Documents").mkdir(parents=True)
    except OSError as error:
        if error.errno != errno.EILSEQ:
            raise
        pytest.skip("this volume refuses a name from Unicode 16.0")
    typed = tmp_path / "Vol\u1c8a" / "jane" / "Documents"
    typed.mkdir(parents=True, exist_ok=True)
    same = _one_folder(str(typed), str(home / "Documents"))
    monkeypatch.chdir(tmp_path)
    Mac(monkeypatch, home)
    code, out, _ = go(capsys, "--no-root", "--output", str(typed))
    shown = f"~/Documents/{PDF_NAME}" if same else terminal.display_path(str(typed / PDF_NAME), "")
    assert code == 0
    assert f"Saved: {shown}\n" in out


@pytest.mark.parametrize(
    "home_first", [True, False], ids=["the home folder under /private", "the path under it"]
)
def test_a_path_and_a_home_folder_one_of_them_under_private_print_with_a_tilde(
    capsys, mac, monkeypatch, home_first
):
    # n8: /var and /tmp lead to /private/var and /private/tmp on macOS, so one folder has
    # both paths, and no name matched one to the other.
    resolved = str(mac.home)
    unresolved = resolved.removeprefix("/private")
    if unresolved == resolved or not _one_folder(unresolved, resolved):
        pytest.skip("the temporary folder has no path outside /private")
    (mac.home / "Documents").mkdir()
    home, typed = (resolved, unresolved) if home_first else (unresolved, resolved)
    monkeypatch.setattr(writer, "home", lambda: home)
    code, out, _ = go(capsys, "--no-root", "--output", f"{typed}/Documents")
    assert code == 0
    assert f"Saved: ~/Documents/{PDF_NAME}\n" in out


def test_a_path_through_the_data_volumes_own_folder_prints_with_a_tilde(capsys, mac):
    # n8: macOS shows the data volume at /System/Volumes/Data as well, so the home folder
    # /Users/jane is also /System/Volumes/Data/Users/jane.
    data = f"/System/Volumes/Data{mac.home}"
    if not _one_folder(data, str(mac.home)):
        pytest.skip("no /System/Volumes/Data path to the temporary folder")
    (mac.home / "Documents").mkdir()
    code, out, _ = go(capsys, "--no-root", "--output", f"{data}/Documents")
    assert code == 0
    assert f"Saved: ~/Documents/{PDF_NAME}\n" in out


def test_finding_the_home_folder_looks_at_it_and_the_folders_of_the_path_and_nothing_else(
    monkeypatch, tmp_path
):
    # m1, within the product contract: a stat of the home folder, then one of each folder
    # along the path, the longest first, until one is the home folder. Never a file's
    # contents or a listing, and never the printed file itself; the path's own last part
    # only when the path may be a folder.
    itself = tmp_path / "Data" / "jane"
    (itself / "Documents").mkdir(parents=True)
    home = tmp_path / "Users" / "jane"
    home.parent.mkdir()
    home.symlink_to(itself)
    monkeypatch.setattr(writer, "home", lambda: str(home))
    looked: list[str] = []
    stat = os.stat

    def looking(path, *args, **kwargs):  # type: ignore[no-untyped-def]
        looked.append(os.fspath(path))
        return stat(path, *args, **kwargs)

    def refused(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError("a file was read or a folder listed")

    with monkeypatch.context() as patched:
        patched.setattr(os, "stat", looking)
        for name in ("lstat", "open", "listdir", "scandir", "readlink"):
            patched.setattr(os, name, refused)
        patched.setattr(builtins, "open", refused)
        file = run._shown(str(itself / "Documents" / "r.pdf"))
        folder = run._shown(str(itself), whole=True)
    assert (file, folder) == ("~/Documents/r.pdf", "~")
    assert looked == [str(home), str(itself / "Documents"), str(itself), str(home), str(itself)]


def test_the_run_looks_up_the_home_folder_and_never_a_file_it_prints(capsys, mac, monkeypatch):
    # m1, within the product contract: a saved file is no folder, so never the home folder,
    # and the run does not look it up to print it; the home folder it does look up.
    looked: list[str] = []
    stat = os.stat

    def looking(path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if isinstance(path, str | os.PathLike):
            looked.append(os.fspath(path))
        return stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", looking)
    code, _, _ = go(capsys, "--no-root", "--json")
    assert code == 0
    assert str(mac.home) in looked
    assert {str(mac.desktop / JSON_NAME), str(mac.desktop / PDF_NAME)}.isdisjoint(looked)


@pytest.mark.parametrize(
    ("name", "typed"),
    [
        ("jane", "JANE"),
        ("jane", "Jane"),
        ("jos\u00e9", "jose\u0301"),
        ("jose\u0301", "jos\u00e9"),
        ("jane", "jane\u0301"),
    ],
    ids=["capitals", "one capital", "decomposed", "composed", "a mark added"],
)
def test_a_home_folder_that_cannot_be_looked_at_is_taken_only_as_spelled(
    monkeypatch, tmp_path, name, typed
):
    # The GPT audit, pass 2, G2-05, replacing m1's match by the character table: when the
    # home folder's own stat fails, only its own spelling, name for name and character for
    # character, is the home folder. A name that differs, in case or in its Unicode form,
    # can be another folder on a case-sensitive volume, and prints in full. Neither folder
    # is made.
    home = tmp_path / "Users" / name
    monkeypatch.setattr(writer, "home", lambda: str(home))
    other = str(tmp_path / "Users" / typed / "r.pdf")
    assert run._shown(other) == terminal.display_path(other, "")
    assert run._shown(str(home / "r.pdf")) == "~/r.pdf"
    assert run._shown(f"{home}/", whole=True) == "~/"
    assert run._shown(str(home), whole=True) == "~"
    assert run._shown(str(home)) == terminal.display_path(str(home), "")  # a file, not ~


def test_a_folder_the_volume_does_not_find_is_not_the_home_folder_whatever_its_name(
    monkeypatch, tmp_path
):
    # m1: on a case-sensitive volume nothing is at Users/ALICE, though the character table
    # folds the name to the home folder's, so a refusal that names the folder names it in
    # full. The stat here answers as that volume would.
    home = tmp_path / "Users" / "alice"
    home.mkdir(parents=True)
    other = str(tmp_path / "Users" / "ALICE")
    typed = f"{other}/Documents"
    stat = os.stat

    def case_sensitive(path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if os.fspath(path).startswith(other):
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT))
        return stat(path, *args, **kwargs)

    monkeypatch.setattr(writer, "home", lambda: str(home))
    with monkeypatch.context() as patched:
        patched.setattr(os, "stat", case_sensitive)
        shown = run._shown(typed, whole=True)
    assert shown == terminal.display_path(typed, "")
    assert terminal.display_path(typed, str(home)) == "~/Documents"  # the table's own answer


# --- the GPT audit, pass 2 -----------------------------------------------------------------------
#
# G2-03: the run read the flag for the last time just before the open, so a signal after that
# read, on any path of the open, ended with exit 0 and no stop line; and a Ctrl-C at the
# terminal while the report opened always did, since it ends open(1) too and a failed open was
# never read as a stop. The flag is read again as O1 returns, whatever its ending, and as the
# run's last step. The lines are change record 10's: "was not opened" unless O1 may have
# started, "may not have opened" once it may have.

# The real chokepoint, before the fake M5 stands in for it: a test-owned /bin/sleep stands in
# for O1, never /usr/bin/open.
_REAL_EXECUTE = spawn._execute
_REAL_POPEN = spawn._popen
OPEN_PATHS = {
    "--no-open": run.STOPPED_SAVED,
    "over SSH": run.STOPPED_SAVED,
    "a refused open": run.STOPPED_SAVED,
    "an open refused for a changed file": run.STOPPED_SAVED,
    "an open that could not start": run.STOPPED_SAVED,
    "an open that failed": run.STOPPED_OPENING,
    "an open that finished": run.STOPPED_OPENING,
    "after the open": run.STOPPED_OPENING,
}


def _stop_on_the_open_path(
    mac: Mac, monkeypatch: pytest.MonkeyPatch, path: str, signum: int
) -> list[str]:
    """The run's arguments, with the signal sent on one path of the open, once the run's
    read of the flag just after the save's lines has passed."""
    send = _signal(signum)
    argv = ["--no-root"]
    if path in ("--no-open", "after the open"):
        real = run._open

        def opened(*args, **kwargs):  # type: ignore[no-untyped-def]
            stopped = real(*args, **kwargs)
            send()  # as _open returns, --no-open's or the finished open's
            return stopped

        monkeypatch.setattr(run, "_open", opened)
        if path == "--no-open":
            argv.append("--no-open")
    elif path == "over SSH":
        monkeypatch.setenv("SSH_CONNECTION", "10.0.0.2 50000 10.0.0.1 22")
        monkeypatch.setattr(run, "_ssh", lambda: send() or True)
    elif path == "a refused open":

        def refused(runner, pdf):  # type: ignore[no-untyped-def]
            send()
            raise spawn.Refused("the published report cannot be read")

        monkeypatch.setattr(spawn.Runner, "published", refused)
    elif path == "an open refused for a changed file":
        real_published, real_run = spawn.Runner.published, spawn.Runner.run

        def published(runner, pdf):  # type: ignore[no-untyped-def]
            real_published(runner, pdf)
            os.chmod(pdf, 0o644)  # so the chokepoint refuses O1

        def ran(runner, command_id, **kwargs):  # type: ignore[no-untyped-def]
            if command_id == "O1":
                send()
            return real_run(runner, command_id, **kwargs)

        monkeypatch.setattr(spawn.Runner, "published", published)
        monkeypatch.setattr(spawn.Runner, "run", ran)
    else:
        ending = {
            "an open that could not start": result("O1", None, ending=spawn.Ending.NOT_STARTED),
            "an open that failed": result("O1", 1),
            "an open that finished": result("O1", 0),
        }
        mac.results["O1"] = ending[path]
        mac.before["O1"] = send  # while O1 runs, in the pass that collects its end
    return argv


@pytest.mark.parametrize("signum", run.SIGNALS)
@pytest.mark.parametrize("path", list(OPEN_PATHS))
def test_a_signal_on_every_path_of_the_open_stops_the_run(capsys, mac, monkeypatch, path, signum):
    argv = _stop_on_the_open_path(mac, monkeypatch, path, signum)
    code, out, err = go(capsys, *argv)
    assert (code, err) == (130, f"{OPEN_PATHS[path]}\n")
    assert mac.saved() == [PDF_NAME]
    opened = path == "after the open"
    assert out.endswith(
        f"Saved: ~/Desktop/{PDF_NAME}\n{run.OPENING}\n" if opened else f"{PDF_NAME}\n"
    )
    started = path.startswith("an open that") or opened
    assert ("O1" in mac.ran) == started


def _o1_stand_in(
    monkeypatch: pytest.MonkeyPatch, signum: int, *, both: bool
) -> list[subprocess.Popen[bytes]]:
    """O1 as a real child under the real chokepoint: /bin/sleep 5, which the signal ends
    when it reaches both, as a terminal's Ctrl-C or hang-up reaches its foreground process
    group, or leaves to the chokepoint's stop when it reaches the tool alone, as a script's
    kill does. The children it started."""
    children: list[subprocess.Popen[bytes]] = []
    fake = spawn._execute

    def popen(argv):  # type: ignore[no-untyped-def]
        assert argv == ["/bin/sleep", "5"], "never /usr/bin/open"
        child = _REAL_POPEN(argv)
        children.append(child)
        if both:
            child.send_signal(signum)
            child.wait(5)  # ended before the loop's first pass looks
        os.kill(os.getpid(), signum)
        return child

    def execute(argv, **kwargs):  # type: ignore[no-untyped-def]
        if kwargs["command_id"] != "O1":
            return fake(argv, **kwargs)
        return _REAL_EXECUTE(["/bin/sleep", "5"], **kwargs)

    monkeypatch.setattr(spawn, "_popen", popen)
    monkeypatch.setattr(spawn, "_execute", execute)
    return children


@pytest.mark.parametrize("signum", run.SIGNALS)
@pytest.mark.parametrize("both", [True, False], ids=["the open and the tool", "the tool alone"])
def test_a_signal_while_a_real_open_runs_stops_the_run(capsys, mac, monkeypatch, signum, both):
    children = _o1_stand_in(monkeypatch, signum, both=both)
    started = time.monotonic()
    code, out, err = go(capsys, "--no-root")
    assert (code, err) == (130, f"{run.STOPPED_OPENING}\n")
    assert run.OPENING not in out and mac.saved() == [PDF_NAME]
    (child,) = children
    assert child.returncode == -(signum if both else signal.SIGTERM)
    assert time.monotonic() - started < 4, "stopped at once, never at its 5 s"


def test_a_signal_as_the_run_repeats_its_warning_stops_it(capsys, mac, monkeypatch):
    # The last read comes after the warning the run repeats and after everything else the
    # run does, so a signal while that warning prints stops the run: 130 comes before 6
    # (change record 10; the GPT audit, pass 3, G3-02).
    mac.results["S5"] = result("S5", 1)
    real = run._tell
    warnings: list[str] = []

    def told(text: str) -> None:
        real(text)
        if text == run.WARNING:
            warnings.append(text)
            if len(warnings) == 2:
                os.kill(os.getpid(), signal.SIGINT)

    monkeypatch.setattr(run, "_tell", told)
    code, out, err = go(capsys)
    assert (code, err) == (130, f"{run.WARNING}\n{run.WARNING}\n{run.STOPPED_OPENING}\n")
    assert out.endswith(f"{run.OPENING}\n")


def test_a_stop_after_the_save_is_said_after_the_repeated_warning(capsys, mac, monkeypatch):
    # The run's last read is its last step, so the stop line it prints comes last.
    mac.results["S5"] = result("S5", 1)
    _stop_on_the_open_path(mac, monkeypatch, "after the open", signal.SIGINT)
    code, _, err = go(capsys)
    assert (code, err) == (130, f"{run.WARNING}\n{run.WARNING}\n{run.STOPPED_OPENING}\n")


# G2-04: R5 took any whole number for the service account's user ID, 0 included, so the
# count would run sqlite3 as root under the service account's name.


def test_a_service_account_that_is_root_never_runs_the_count(capsys, mac, monkeypatch):
    account = pwd.struct_passwd(("_mmaintenanced", "*", 0, 0, "", "/var/db/mmaintenanced", ""))
    monkeypatch.setattr(elevation.pwd, "getpwnam", lambda name: account)
    code, out, _ = go(capsys, "--json")
    assert code == 1  # tool_error, service_account_error: not expected
    assert "S3" not in mac.ran and "S4" in mac.ran
    assert run.COUNTING not in out and f"{run.SAMPLING}{run.DONE}\n" in out
    document = _saved(mac)
    assert document["elevation"]["checks"]["service_account"] == "error"
    assert document["elevation"]["count"] == {"ending": "not_run", "cleanup": "not_applicable"}
    surfaces = {surface["key"]: surface for surface in document["surfaces"]}
    ledger = surfaces["memory_error_ledger"]
    assert (ledger["availability"], ledger["reason"], ledger["detail"]) == (
        "unavailable",
        "tool_error",
        "service_account_error",
    )
    assert surfaces["power_and_thermal_samples"]["availability"] == "available"


# G2-05: when the home folder cannot be looked up, a name that folds to its own printed as ~.


def test_a_folder_saved_in_beside_a_home_folder_not_there_prints_in_full(
    capsys, monkeypatch, tmp_path
):
    # The verification's case on a case-sensitive volume, where Users/ALICE is a folder of
    # its own and the account database's Users/alice is not there. This volume may join the
    # two names, so the stat answers for the home folder as that volume would.
    home = tmp_path / "Users" / "alice"
    folder = tmp_path / "Users" / "ALICE" / "Reports"
    folder.mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    Mac(monkeypatch, home)
    stat = os.stat

    def case_sensitive(path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if os.fspath(path) == str(home):
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT))
        return stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", case_sensitive)
    code, out, _ = go(capsys, "--no-root", "--output", str(folder))
    assert code == 0 and (folder / PDF_NAME).exists()
    assert f"Saved: {terminal.display_path(str(folder / PDF_NAME), '')}\n" in out
    assert "Saved: ~" not in out


# G2-06: console.write swallowed an OSError from the write itself and trusted the flush, so a
# stdout made write-through (python -u, PYTHONUNBUFFERED) that failed as it was written cut
# the report short with no warning, and a short count, or none from a stream that would
# block, went unseen too. Real streams where a test can have them: pipes; the full disk is a
# disk image, replayed by hand. Files that take less than they are given where not.

LINE = "one complete line\n"


class _Takes(io.FileIO):
    """A file on a disk with ``room`` bytes left, then ENOSPC (or ``fails``), that takes at
    most ``each`` bytes a write and answers the first ``blocked`` writes with None, as a
    full non-blocking file does. Pointed at /dev/null, it takes everything, as /dev/null
    does."""

    def __init__(
        self,
        path: Path,
        *,
        room: int | None = None,
        each: int | None = None,
        blocked: int = 0,
        fails: int = errno.ENOSPC,
    ) -> None:
        super().__init__(path, "w")
        self.room, self.each, self.blocked, self.fails = room, each, blocked, fails

    def write(self, data):  # type: ignore[no-untyped-def]
        if os.path.samestat(os.fstat(self.fileno()), os.stat(os.devnull)):
            return super().write(data)
        if self.blocked:
            self.blocked -= 1
            return None
        if self.room == 0:
            raise OSError(self.fails, os.strerror(self.fails))
        size = len(data) if self.each is None else min(len(data), self.each)
        taken = super().write(bytes(data[: size if self.room is None else min(size, self.room)]))
        if self.room is not None:
            self.room -= taken
        return taken


@contextlib.contextmanager
def _write_through(raw: io.FileIO) -> Iterator[tuple[io.TextIOWrapper, io.StringIO]]:
    """stdout as Python makes it with python -u, over ``raw``, and stderr to read; both are
    put back before the file closes."""
    err = io.StringIO()
    with (
        io.TextIOWrapper(raw, encoding="utf-8", write_through=True) as stdout,
        pytest.MonkeyPatch.context() as patch,
    ):
        patch.setattr(sys, "stdout", stdout)
        patch.setattr(sys, "stderr", err)
        yield stdout, err


@pytest.mark.parametrize(
    ("given", "kept", "warned"),
    [
        ({"room": 4}, LINE[:4], True),
        ({"each": 5}, LINE * 2, False),
        ({"blocked": 3}, LINE * 2, False),
        ({"room": 0, "fails": errno.EIO}, "", False),
        ({"room": 0, "fails": errno.ENXIO}, "", False),
        ({"room": 0, "fails": errno.EPIPE}, "", False),
    ],
    ids=[
        "4 bytes, then a full disk",
        "a short count each time",
        "none while it would block",
        "a closed terminal window",
        "a device that is gone",
        "a reader that went away",
    ],
)
def test_a_write_through_stdout_is_checked_by_count(tmp_path, given, kept, warned):
    raw = _Takes(tmp_path / "summary.txt", **given)
    with _write_through(raw) as (stdout, err):
        console.write(stdout, LINE)
        console.write(stdout, LINE)  # said once, whatever follows
        gone = os.path.samestat(os.fstat(raw.fileno()), os.stat(os.devnull))
    assert (tmp_path / "summary.txt").read_text(encoding="utf-8") == kept
    assert err.getvalue() == (f"{console.INCOMPLETE}\n" if warned else "")
    assert gone == (kept != LINE * 2), "a failed stdout is pointed at /dev/null"


def test_a_write_through_stdout_on_a_disk_that_fills_is_said_once(mac, tmp_path):
    # PYTHONUNBUFFERED=1 voltry-mac > summary.txt on a disk that fills, as the full-disk case
    # above with a buffered stdout: the report is saved, and the run exits as it would.
    summary = tmp_path / "summary.txt"
    with _write_through(_Takes(summary, room=2500)) as (_, err):
        code = cli.main(["--no-root"])
    assert code == 0 and mac.saved() == [PDF_NAME]
    assert err.getvalue() == f"{console.INCOMPLETE}\n"
    assert summary.stat().st_size == 2500


@contextlib.contextmanager
def _pipe(*, buffered: bool) -> Iterator[tuple[int, int, io.TextIOWrapper, io.StringIO]]:
    """A real pipe, its write end non-blocking, as stdout: buffered, as Python makes stdout
    for a pipe, or write-through, as it does with python -u. The test closes both ends."""
    read_end, write_end = os.pipe()
    os.set_blocking(write_end, False)
    raw = io.FileIO(write_end, "w", closefd=False)
    layer: io.RawIOBase | io.BufferedWriter = io.BufferedWriter(raw) if buffered else raw
    err = io.StringIO()
    with (
        io.TextIOWrapper(layer, encoding="utf-8", write_through=not buffered) as stdout,
        pytest.MonkeyPatch.context() as patch,
    ):
        patch.setattr(sys, "stdout", stdout)
        patch.setattr(sys, "stderr", err)
        yield read_end, write_end, stdout, err


def _fill(write_end: int) -> int:
    """Fill a non-blocking pipe until it would block; how much it took."""
    filled = 0
    while True:
        try:
            filled += os.write(write_end, b"f" * 4096)
        except BlockingIOError:
            return filled


@pytest.mark.parametrize("buffered", [False, True], ids=["write-through", "buffered"])
def test_a_pipe_that_is_full_is_waited_on_and_takes_it_all(buffered):
    # A write larger than the pipe, to a pipe already full: the write-through layer took one
    # part and dropped the rest, and the buffered one kept only what fitted in its buffer.
    text = "".join(f"line {n:06d} of the terminal report\n" for n in range(8000))
    got = bytearray()
    with _pipe(buffered=buffered) as (read_end, write_end, stdout, err):

        def reader() -> None:
            time.sleep(0.2)  # full before anything reads it
            while chunk := os.read(read_end, 65536):
                got.extend(chunk)

        thread = threading.Thread(target=reader, daemon=True)
        try:
            filled = _fill(write_end)
            thread.start()
            console.write(stdout, text)
        finally:
            os.close(write_end)  # the reader then reads to the end
            thread.join(10)
            os.close(read_end)
    assert not thread.is_alive()
    assert bytes(got) == b"f" * filled + text.encode()
    assert err.getvalue() == ""


def test_a_pipe_whose_reader_went_away_is_said_nowhere():
    with _pipe(buffered=False) as (read_end, write_end, stdout, err):
        os.close(read_end)
        try:
            console.write(stdout, LINE)  # EPIPE as it writes: no exception and no warning
            gone = os.path.samestat(os.fstat(write_end), os.stat(os.devnull))
        finally:
            os.close(write_end)
    assert gone and err.getvalue() == ""


# Change record 21 (the GPT audit, pass 2, G2-02): a file the file system will not let the run
# remove never stops a report that can still be saved, and is named as safe to delete. The
# PDF's temporary is a second name for the PDF, so while it is there the open is refused, and
# the run says why.


def _removals_refused(monkeypatch: pytest.MonkeyPatch, *, only_temporaries: bool) -> None:
    real = writer._unlink

    def unlink(folder_fd, name):  # type: ignore[no-untyped-def]
        if name.startswith(".voltry-mac-") or not only_temporaries:
            raise PermissionError(errno.EPERM, os.strerror(errno.EPERM))
        real(folder_fd, name)

    monkeypatch.setattr(writer, "_unlink", unlink)


def test_a_pdf_whose_temporary_stays_is_saved_and_the_run_says_why_it_did_not_open(
    capsys, mac, monkeypatch
):
    _removals_refused(monkeypatch, only_temporaries=True)
    code, out, err = go(capsys, "--no-root")
    (left,) = [name for name in mac.saved() if name.startswith(".voltry-mac-")]
    assert (code, err) == (0, f"{run.LEFT_ONE}\n  ~/Desktop/{left}\n{run.SECOND_NAME}\n")
    assert out.endswith(f"Saved: ~/Desktop/{PDF_NAME}\n") and "O1" not in mac.ran


def test_with_no_open_a_temporary_that_stays_is_only_named(capsys, mac, monkeypatch):
    _removals_refused(monkeypatch, only_temporaries=True)
    code, _, err = go(capsys, "--no-root", "--no-open")
    (left,) = [name for name in mac.saved() if name.startswith(".voltry-mac-")]
    assert (code, err) == (0, f"{run.LEFT_ONE}\n  ~/Desktop/{left}\n")


def _append_only(tmp_path: Path, name: str) -> Path:
    folder = tmp_path / name
    folder.mkdir()
    return folder


def test_where_nothing_can_be_removed_the_pdf_alone_saves_with_its_temporary(
    capsys, mac, monkeypatch, tmp_path
):
    # An append-only folder takes a create and a link and refuses every removal: the PDF saves,
    # its temporary stays beside it, and the run names that file and says why it did not open.
    folder = _append_only(tmp_path, "append-only")
    _removals_refused(monkeypatch, only_temporaries=False)
    code, out, err = go(capsys, "--no-root", "--output", str(folder))
    (left,) = [path for path in folder.iterdir() if path.name.startswith(".voltry-mac-")]
    shown = terminal.display_path(str(left), "")
    assert (code, err) == (0, f"{run.LEFT_ONE}\n  {shown}\n{run.SECOND_NAME}\n")
    assert (folder / PDF_NAME).exists() and "O1" not in mac.ran


def test_where_nothing_can_be_removed_json_is_never_saved_and_both_files_are_named(
    capsys, mac, monkeypatch, tmp_path
):
    # With --json the JSON's temporary stays, no second temporary is made while it is there,
    # and the JSON already published cannot go either: exit 4, both named.
    folder = _append_only(tmp_path, "append-only")
    _removals_refused(monkeypatch, only_temporaries=False)
    code, out, err = go(capsys, "--no-root", "--json", "--output", str(folder))
    assert code == 4 and "Saved:" not in out
    assert writer._STUCK in " ".join(err.split())
    (temporary,) = [path for path in folder.iterdir() if path.name.startswith(".voltry-mac-")]
    assert sorted(path.name for path in folder.iterdir()) == sorted([temporary.name, JSON_NAME])
    named = [terminal.display_path(str(path), "") for path in (temporary, folder / JSON_NAME)]
    assert err.endswith(f"{run.LEFT_MANY}\n" + "".join(f"  {each}\n" for each in named))


# --- the audit fixes' review, round 3, and the pre-audit of pass 3 ----------------------------
#
# m2 and the pre-audit's 05: outside the run's handlers a Ctrl-C printed a Python traceback
# naming the installed package's files, and SIGTERM or SIGHUP ended the process by the
# signal: as the command line was read, during the preflight, as a refusal, --help, --version
# or --dry-run printed, and once the run had put Python's handlers back. From the start of
# the command a signal only sets the flag, read at each exit: a stop line and 130 where 130
# comes first, the refusal's own code and words where 5, 3 or 2 do. After the command's last
# read all three are ignored until the process ends. command() runs the command line where a
# signal that would end the process fails the test instead.


@pytest.mark.parametrize("signum", run.SIGNALS)
def test_a_signal_as_the_command_line_is_read_stops_it_before_the_run(
    capsys, mac, monkeypatch, signum
):
    real = argparse.ArgumentParser.parse_known_args

    def parsed(parser, *args, **kwargs):  # type: ignore[no-untyped-def]
        os.kill(os.getpid(), signum)
        return real(parser, *args, **kwargs)

    monkeypatch.setattr(argparse.ArgumentParser, "parse_known_args", parsed)
    code, out, err = command(capsys, "--no-root")
    assert (code, out, err) == (130, "", f"{run.STOPPED}\n")
    assert mac.ran == [] and mac.saved() == []


@pytest.mark.parametrize("signum", run.SIGNALS)
@pytest.mark.parametrize("argv", [["--no-root"], ["render", "report.json"]], ids=["run", "render"])
def test_a_signal_during_the_preflight_stops_the_command_before_anything_starts(
    capsys, mac, monkeypatch, argv, signum
):
    def read(**_: object) -> preflight.Platform:
        os.kill(os.getpid(), signum)  # while the platform is read
        return SUPPORTED

    monkeypatch.setattr(preflight, "read", read)
    code, out, err = command(capsys, *argv)
    assert (code, out, err) == (130, "", f"{run.STOPPED}\n")
    assert mac.ran == [] and mac.saved() == []


REFUSALS = {
    "started with sudo": (),
    "an Intel Mac": (),
    "--yes with --no-root": ("--yes", "--no-root"),
    "an argument voltry-mac does not take": ("--frobnicate",),
}


@pytest.mark.parametrize("signum", run.SIGNALS)
@pytest.mark.parametrize("when", ["during the preflight", "as it prints"])
@pytest.mark.parametrize("refusal", list(REFUSALS))
def test_a_signal_before_or_as_a_refusal_prints_leaves_its_code_and_its_words(
    capsys, mac, monkeypatch, refusal, when, signum
):
    # 5, 3 and 2 come before 130 (Failure modes, the exit codes), so the refusal stands and
    # no stop line follows it, whether the signal came as the preflight began or as the
    # refusal printed.
    user = 0 if refusal == "started with sudo" else 501
    monkeypatch.setattr(os, "geteuid", lambda: user)
    if refusal == "an Intel Mac":
        intel = dataclasses.replace(SUPPORTED, arm64=False)
        monkeypatch.setattr(preflight, "read", lambda **_: intel)
    argv = REFUSALS[refusal]
    expected = command(capsys, *argv)
    if when == "during the preflight":

        def euid() -> int:
            os.kill(os.getpid(), signum)  # as the preflight asks who runs it, its first step
            return user

        monkeypatch.setattr(os, "geteuid", euid)
    else:
        real = console.write

        def write(stream, text):  # type: ignore[no-untyped-def]
            if stream is sys.stderr:
                os.kill(os.getpid(), signum)  # as the refusal prints
            real(stream, text)

        monkeypatch.setattr(console, "write", write)
    assert command(capsys, *argv) == expected
    assert expected[0] in (5, 3, 2) and "Stopped" not in expected[2]


@pytest.mark.parametrize("signum", run.SIGNALS)
def test_a_signal_as_version_answers_stops_it_after_the_answer(capsys, mac, monkeypatch, signum):
    def read(**_: object) -> preflight.Platform:
        os.kill(os.getpid(), signum)  # as --version reads R4's two flags
        return SUPPORTED

    monkeypatch.setattr(preflight, "read", read)
    code, out, err = command(capsys, "--version")
    assert (code, err) == (130, f"{run.STOPPED}\n")
    assert out.startswith(f"voltry-mac {voltry_mac.__version__}\n") and len(out.splitlines()) == 4


@pytest.mark.parametrize("signum", run.SIGNALS)
def test_a_signal_as_dry_run_answers_stops_it_after_the_answer(capsys, monkeypatch, signum):
    real = cli.dry_run_text

    def text() -> str:
        os.kill(os.getpid(), signum)
        return real()

    monkeypatch.setattr(cli, "dry_run_text", text)
    assert command(capsys, "--dry-run") == (130, real(), f"{run.STOPPED}\n")


@pytest.mark.parametrize("signum", run.SIGNALS)
def test_a_signal_as_help_answers_stops_it_after_the_answer(capsys, mac, monkeypatch, signum):
    real = cli._emit

    def printed(text: str) -> int:  # --help's text comes back as cli.Help; _emit prints it
        code = real(text)
        os.kill(os.getpid(), signum)
        return code

    monkeypatch.setattr(cli, "_emit", printed)
    code, out, err = command(capsys, "--help")
    assert (code, err) == (130, f"{run.STOPPED}\n")
    assert out.startswith("usage: voltry-mac") and mac.ran == []


@pytest.mark.parametrize("signum", run.SIGNALS)
def test_a_signal_as_the_run_collects_its_abandoned_children_stops_it(
    capsys, mac, monkeypatch, signum
):
    # Collecting the payloads the tool could not signal is part of the run, before its last
    # read of the flag, so a signal then stops the run (the GPT audit, pass 3, G3-02).
    real = spawn.collect_abandoned

    def collected() -> int:
        os.kill(os.getpid(), signum)
        return real()

    monkeypatch.setattr(spawn, "collect_abandoned", collected)
    code, out, err = command(capsys, "--no-root")
    assert (code, err) == (130, f"{run.STOPPED_OPENING}\n")
    assert out.endswith(f"{run.OPENING}\n") and mac.saved() == [PDF_NAME]


@pytest.mark.parametrize("argv", [["--no-root"], ["--dry-run"], ["--frobnicate"]], ids=str)
def test_the_signals_are_ignored_once_the_command_ends(capsys, mac, argv):
    command(capsys, *argv)
    assert [signal.getsignal(signum) for signum in run.SIGNALS] == [signal.SIG_IGN] * 3
    for signum in run.SIGNALS:
        os.kill(os.getpid(), signum)  # ignored until the process ends


# The same through the console script's own shape, sys.exit(cli.main(...)), in a child: with
# a command line that does not parse, a signal as the refusal prints; with --dry-run, one in
# the process's last moments, as Python shuts down, where it once put back the handler that
# prints a traceback or ends the process. HOME and TMPDIR are the test's.
_CHILD = (
    "import atexit, os, signal, sys\n"
    "from voltry_mac import cli, console\n"
    "signum = getattr(signal, sys.argv[1])\n"
    "if sys.argv[2] == '--dry-run':\n"
    "    atexit.register(lambda: os.kill(os.getpid(), signum))\n"
    "else:\n"
    "    real = console.write\n"
    "    def write(stream, text):\n"
    "        if stream is sys.stderr:\n"
    "            os.kill(os.getpid(), signum)\n"
    "        real(stream, text)\n"
    "    console.write = write\n"
    "sys.exit(cli.main(sys.argv[2:]))\n"
)


@pytest.mark.parametrize("name", ["SIGINT", "SIGTERM", "SIGHUP"])
@pytest.mark.parametrize("argv", [["--frobnicate"], ["--dry-run"]], ids=str)
def test_the_console_script_ends_with_its_own_code_whatever_signal_comes(tmp_path, argv, name):
    env = {**os.environ, "HOME": str(tmp_path), "TMPDIR": str(tmp_path)}
    child = subprocess.run(  # noqa: S603 - a test-owned child, never a collection
        [sys.executable, "-c", _CHILD, name, *argv],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=tmp_path,
        env=env,
    )
    assert "Traceback" not in child.stderr and "Exception ignored" not in child.stderr
    if argv == ["--dry-run"]:
        assert (child.returncode, child.stderr) == (0, "")
    else:  # this Mac's preflight comes first: 5, 3 or 2 (Failure modes, the exit codes)
        assert child.returncode in (5, 3, 2) and "Stopped" not in child.stderr


# The pre-audit of pass 3, 01: an exit that saves nothing read the flag once, before it said
# why, and never again, so a signal as the reason printed exited 4 with no stop line, though
# 130 comes before 4. The run's last read comes after the reason on these exits too (change
# record 10).
# How each reason starts, on its first line whatever its wrapping.
NOT_SAVED = {
    "below the save gate": run.NOT_ENOUGH.split(",")[0],
    "a PDF that cannot be drawn": run.PDF_BUG.split(".")[0],
    "a folder that is not there": run.NOT_SAVED_IN.split(":")[0],
    "a full disk": run.NOT_SAVED.split(":")[0] + ":",
    "an unexpected error before the save": run.UNEXPECTED.split(".")[0],
}


def _broken(*args: object, **kwargs: object) -> object:
    raise RuntimeError("a bug")


def _full(*args: object, **kwargs: object) -> object:
    raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))


def _saving_nothing(mac: Mac, monkeypatch: pytest.MonkeyPatch, path: str) -> list[str]:
    """The run's arguments, with the run set to save nothing on one path."""
    argv = ["--no-root"]
    if path == "below the save gate":
        for command_id in allowlist.USER_COMMAND_IDS:
            if command_id not in ("C1", "C12"):
                mac.results[command_id] = result(command_id, 1, stdout="")
    elif path == "a PDF that cannot be drawn":
        monkeypatch.setattr(report_pdf, "render", _broken)
    elif path == "a folder that is not there":
        argv += ["--output", "missing"]
    elif path == "a full disk":
        monkeypatch.setattr(writer, "_write_all", _full)
    else:
        monkeypatch.setattr(run._Run, "document", _broken)
    return argv


@pytest.mark.parametrize("signum", run.SIGNALS)
@pytest.mark.parametrize("path", list(NOT_SAVED))
def test_a_signal_as_the_run_says_why_nothing_was_saved_stops_it(
    capsys, mac, monkeypatch, path, signum
):
    argv = _saving_nothing(mac, monkeypatch, path)
    real = run._tell

    def told(text: str) -> None:
        if text.startswith(NOT_SAVED[path]):
            os.kill(os.getpid(), signum)  # as the reason prints
        real(text)

    monkeypatch.setattr(run, "_tell", told)
    code, _, err = command(capsys, *argv)
    assert code == 130 and err.startswith(NOT_SAVED[path])
    assert err.endswith(f"\n{run.STOPPED}\n") and err.count("Stopped.") == 1
    assert mac.saved() == [] and "O1" not in mac.ran


@pytest.mark.parametrize("path", list(NOT_SAVED))
def test_with_no_signal_the_run_that_saves_nothing_exits_4(capsys, mac, monkeypatch, path):
    code, _, err = command(capsys, *_saving_nothing(mac, monkeypatch, path))
    assert code == 4 and err.startswith(NOT_SAVED[path]) and "Stopped" not in err


def test_a_stop_as_the_saves_lines_print_is_said_alone_when_the_pdfs_temporary_stays(
    capsys, mac, monkeypatch
):
    # The review of the audit fixes, round 3, n7 (mutant S4): the flag is read right after
    # the save's lines, before the chokepoint takes the file. So with the PDF's temporary
    # left, a second name for the PDF, a stop there says only that the report is saved and
    # was not opened; the refusal for the second name never comes.
    _removals_refused(monkeypatch, only_temporaries=True)
    real = run._named

    def named(saved, local):  # type: ignore[no-untyped-def]
        real(saved, local)
        os.kill(os.getpid(), signal.SIGINT)

    monkeypatch.setattr(run, "_named", named)
    code, out, err = go(capsys, "--no-root")
    (left,) = [name for name in mac.saved() if name.startswith(".voltry-mac-")]
    assert (code, err) == (130, f"{run.LEFT_ONE}\n  ~/Desktop/{left}\n{run.STOPPED_SAVED}\n")
    assert out.endswith(f"Saved: ~/Desktop/{PDF_NAME}\n") and "O1" not in mac.ran


def test_a_long_argument_is_shown_in_time_in_proportion_to_its_length(tmp_path, monkeypatch):
    # The review of the audit fixes, round 3, n6: finding the home folder in an argument took
    # time in the square of its slashes while the home folder was there, 6.2 s to refuse
    # 100 KB of "/a". A leading part too long for macOS to look up, 1,024 bytes or more
    # (PATH_MAX), is never looked up.
    home = tmp_path / "Users" / "jane"
    home.mkdir(parents=True)
    monkeypatch.setattr(writer, "home", lambda: str(home))
    looked_up: list[str] = []
    real = os.stat

    def stat(path, *args, **kwargs):  # type: ignore[no-untyped-def]
        looked_up.append(os.fspath(path))
        return real(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", stat)
    typed = "/a" * 50_000
    started = time.monotonic()
    assert run.display_argument(typed) == typed
    assert time.monotonic() - started < 1.5
    assert max(len(path) for path in looked_up) < 1024
    inside = f"{home}/{'x/' * 5_000}report.json"  # 10 KB, the home folder at its start
    assert run.display_argument(inside) == f"~/{'x/' * 5_000}report.json"
