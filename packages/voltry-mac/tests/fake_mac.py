"""A fake M5 for the run's tests and the copy goldens (docs/VOLTRY_MAC_SPEC.md, Test strategy
parts 3 and "Copy"): the real chokepoint, whose process calls answer from the M5's captured
outputs, the in-process reads, the question, the clock and the home folder set by the test;
and the command line run where a signal that would end the process fails the test instead.
Registered once by conftest.py as ``voltry_mac_test_fake_mac``.
"""

from __future__ import annotations

import dataclasses
import json
import os
import pwd
import signal
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from voltry_mac import allowlist, cli, elevation, in_process, preflight, run, spawn, writer

TESTS = Path(__file__).resolve().parent
SPEC = TESTS.parents[2] / "docs" / "VOLTRY_MAC_SPEC.md"
M5 = TESTS / "fixtures" / "commands" / "m5-laptop"
SAMPLE_E = (TESTS / "fixtures" / "payloads" / "m5-sample-e3.powermetrics").read_text()
LOG_HEX = (TESTS / "fixtures" / "smart" / "m5-laptop-2026-09-26.hex").read_text().strip()
LEDGER_E = (
    '[{"class":"correctable","event_rows":0,"reported_count":0},'
    '{"class":"uncorrectable","event_rows":0,"reported_count":0}]\n'
)
LISTING = (
    "  PID  PPID   UID STARTED                      COMM\n"
    "    1     0     0 Fri Aug 28 08:00:54 2026     /sbin/launchd\n"
)
SERVICE_UID = 283  # _mmaintenanced on the M5
NOW = datetime(2026, 9, 23, 14, 5, 31, tzinfo=timezone(timedelta(hours=-7)))
SUPPORTED = preflight.Platform(macos=True, arm64=True, translated=False, release="25.6.0")
PDF_NAME = "Voltry Mac Report 2026-09-23 14.05.pdf"
JSON_NAME = "Voltry Mac Report 2026-09-23 14.05.json"
ELEVATED = ("X1", "P1", "S1", "S2", "S3", "S4", "S5")


def _stdout(command_id: str) -> str:
    if command_id == "C28":
        controller = {"location": "Internal", "media": ["disk0"], "status": "ok"}
        controller["smart_hex"] = LOG_HEX
        return json.dumps({"schema": "voltry-mac-smart/0", "controllers": [controller]})
    if command_id == "P1":
        return LISTING
    if command_id in allowlist.USER_COMMAND_IDS:
        return (M5 / f"{command_id}.out").read_text()
    return ""


def result(command_id: str, code: int | None = 0, **changes: object) -> spawn.Result:
    found = spawn.Result(
        command_id, spawn.Ending.EXITED, code, _stdout(command_id), "", 20, False, True
    )
    return dataclasses.replace(found, **changes)


def payload_run(command_id: str, **changes: object) -> spawn.PayloadRun:
    stdout = LEDGER_E if command_id.startswith("S3") else SAMPLE_E
    found = spawn.PayloadRun(command_id, True, None, 0, stdout, "", "verified", 900)
    return dataclasses.replace(found, **changes)


class Mac:
    """The M5 under a real chokepoint: each process call answers from its captures, and a
    command given the cancellation flag once it is set starts nothing, as the chokepoint's
    own check refuses it.

    ``results`` replaces a command's answer, ``payloads`` a payload's run, and ``before``
    runs a hook as a command starts (to send a signal, say). ``ran`` lists every command
    the chokepoint started, payloads included, in order; ``opened`` the paths O1 opened.
    """

    def __init__(self, monkeypatch: pytest.MonkeyPatch, home: Path) -> None:
        self.home = home
        self.answer: str | None = "y\n"  # as the terminal hands it over, with its Enter
        self.asked = 0
        self.results: dict[str, spawn.Result] = {}
        self.payloads: dict[str, spawn.PayloadRun] = {}
        self.before: dict[str, object] = {}
        self.ran: list[str] = []
        self.opened: list[str] = []
        mac = self

        def execute(argv, **kwargs):  # type: ignore[no-untyped-def]
            command_id = kwargs["command_id"]
            # As spawn._execute does: once the run is cancelled, a command given the flag
            # starts nothing (the review of #326, round 2, n4).
            cancelled = kwargs.get("cancelled")
            if cancelled is not None and cancelled():
                return spawn.Result(
                    command_id, spawn.Ending.CANCELLED, None, "", "", 0, False, True
                )
            mac.ran.append(command_id)
            hook = mac.before.get(command_id)
            if callable(hook):
                hook()
            if command_id == "O1":
                mac.opened.append(argv[-1])
            found = mac.results.get(command_id) or result(command_id)
            return dataclasses.replace(found, command_id=command_id)

        def payload(runner, command_id, *, uid):  # type: ignore[no-untyped-def]
            mac.ran.append(command_id)
            hook = mac.before.get(command_id)
            if callable(hook):
                hook()
            found = mac.payloads.get(command_id.rstrip("n")) or payload_run(command_id)
            # The listing after the payload goes into P1's record, failed when the cleanup
            # says it failed, as the real runner's _listed puts it.
            counts = runner._counts.setdefault("P1", [0, 0, 0])
            counts[0] += 1
            counts[1] += int(found.cleanup == "listing_failed")
            counts[2] += 20
            return dataclasses.replace(found, command_id=command_id)

        def answer(cancelled):  # type: ignore[no-untyped-def]
            mac.asked += 1
            return mac.answer

        account = pwd.struct_passwd(
            ("_mmaintenanced", "*", SERVICE_UID, SERVICE_UID, "", "/var/db/mmaintenanced", "")
        )
        monkeypatch.setattr(spawn, "_execute", execute)
        monkeypatch.setattr(spawn.Runner, "payload", payload)
        monkeypatch.setattr(elevation.pwd, "getpwnam", lambda name: account)
        monkeypatch.setattr(os, "geteuid", lambda: 501)
        monkeypatch.setattr(preflight, "read", lambda **_: SUPPORTED)
        monkeypatch.setattr(preflight, "admin", lambda: True)
        monkeypatch.setattr(preflight, "terminal", lambda: True)
        monkeypatch.setattr(run, "_stdout_terminal", lambda: True)
        monkeypatch.setattr(in_process, "panic_count", lambda *args: 0)
        monkeypatch.setattr(in_process, "time_zone", lambda *args: "America/Los_Angeles")
        monkeypatch.setattr(in_process, "paper", lambda *args: "letter")
        monkeypatch.setattr(writer, "home", lambda: str(home))
        monkeypatch.setattr(run, "_answer", answer)
        # The real flush would drop what is typed in the terminal a test runs from (the copy
        # pass's review, round 1, n2); the run's tests pin that it is called.
        monkeypatch.setattr(run, "_discard_typed", lambda: None)
        monkeypatch.setattr(run, "_now", lambda: NOW)
        monkeypatch.setattr(run, "_monotonic", lambda: 100.0)
        monkeypatch.delenv("SSH_CONNECTION", raising=False)
        monkeypatch.delenv("SSH_TTY", raising=False)

    @property
    def desktop(self) -> Path:
        return self.home / "Desktop"

    def saved(self) -> list[str]:
        return sorted(path.name for path in self.desktop.iterdir())


def build(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Mac:
    """A fake M5 with an empty Desktop in a home folder under ``tmp_path``, which is also
    the working folder."""
    home = tmp_path / "home"
    (home / "Desktop").mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    return Mac(monkeypatch, home)


def go(capsys, *argv: str) -> tuple[int, str, str]:
    code = cli.main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


class Ended(BaseException):
    """A signal that would end the process: SIGTERM's and SIGHUP's default action, which in
    a test would end the test run too."""


def ending_signals() -> None:
    """SIGTERM and SIGHUP raise Ended in this process, where their default action would end
    it, so a test sees a window the tool leaves them in; conftest puts them back after the
    test. SIGINT stays Python's, whose KeyboardInterrupt the console script would print as a
    traceback naming the installed package's files."""

    def ended(signum: int, frame: object) -> None:
        raise Ended(signum)

    signal.signal(signal.SIGINT, signal.default_int_handler)
    signal.signal(signal.SIGTERM, ended)
    signal.signal(signal.SIGHUP, ended)


def command(capsys, *argv: str) -> tuple[int, str, str]:
    """The command line, from signals as ending_signals sets them, which must end with an
    exit code whatever signal comes: never a traceback, never ended by the signal (the audit
    fixes' review, round 3, m2, and the pre-audit of pass 3, 05)."""
    ending_signals()
    try:
        code = cli.main(list(argv))
    except KeyboardInterrupt:
        pytest.fail("a signal left the command line as a traceback")
    except Ended:
        pytest.fail("a signal ended the process")
    out, err = capsys.readouterr()
    return code, out, err
