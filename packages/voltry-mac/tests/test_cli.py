"""The command-line shell (docs/VOLTRY_MAC_SPEC.md, "CLI transcripts" and Decision 7).

What this package's CLI does at this stage of the build: it parses every flag the spec
names, answers ``--version`` and ``--dry-run`` on any platform without collecting, prints
``--help`` once the preflight has passed, refuses ``--yes`` with ``--no-root`` (exit 2)
after the preflight's refusals, and hands a collecting run to run.collect (test_run.py) and
render to run.rebuild (test_render_command.py). The preflight's own tests are in
test_preflight.py. No test here starts a bare run: on a supported Mac it would collect for
real, and every usage error below runs with run.collect and run.rebuild refusing.
"""

from __future__ import annotations

import argparse
import contextlib
import itertools
import os
import pwd
import re
import select
import signal
import subprocess
import sys
import sysconfig
import tomllib
import unicodedata
from pathlib import Path

import pytest

import voltry_mac
from voltry_mac import allowlist, cli, preflight, run, writer

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
GOLDEN = Path(__file__).resolve().parent / "golden"


def _run(capsys, *argv: str) -> tuple[int, str, str]:
    code = cli.main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


SUPPORTED = preflight.Platform(macos=True, arm64=True, translated=False, release="25.6.0")


@pytest.fixture
def supported(monkeypatch, tmp_path):
    """A user on a supported Mac, from an empty folder: the preflight lets the run go on,
    so argument errors are reached on any machine the suite runs on."""
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    monkeypatch.setattr(preflight, "read", lambda **_: SUPPORTED)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _preflight_code(passed: int = 2) -> int:
    """What this machine's preflight gives a run that is not --version or --dry-run: 5 as
    root, 3 on a platform the spec does not cover, and otherwise ``passed``: 2 by default,
    since most command lines below are refused, an argument error or a render of a file
    that is not there, and 0 for --help. Asked of a child, so it answers for the same
    interpreter and platform the children below run on."""
    probe = subprocess.run(  # noqa: S603 - a test-owned child
        [
            sys.executable,
            "-c",
            "import sys\nfrom voltry_mac import preflight as p\n"
            f"sys.exit(5 if p.is_root() else 3 if p.refusal(p.read()) else {passed})",
        ],
        timeout=60,
        check=False,
    )
    return probe.returncode


# --- --version ------------------------------------------------------------------------------


def test_version_names_the_tool_and_the_python_it_runs_on(capsys):
    code, out, err = _run(capsys, "--version")
    info = sys.version_info
    python = f"{info.major}.{info.minor}.{info.micro}"
    assert (code, err) == (0, "")
    assert out.splitlines()[0] == f"voltry-mac {voltry_mac.__version__}"
    assert out.splitlines()[1].startswith(f"Python {python}")
    assert len(out.splitlines()) == 4, "then the architecture and Rosetta (MAC 3.1b)"


def test_the_package_and_the_distribution_agree_on_the_version():
    project = tomllib.loads((PACKAGE_ROOT / "pyproject.toml").read_text())["project"]
    assert project["version"] == voltry_mac.__version__


# --- --dry-run ------------------------------------------------------------------------------


def test_dry_run_prints_the_frozen_list_exactly(capsys):
    code, out, err = _run(capsys, "--dry-run")
    expected = (GOLDEN / "dry_run.txt").read_text(encoding="utf-8")
    assert (code, err) == (0, "")
    assert out == expected.replace("{version}", voltry_mac.__version__)


def test_dry_run_prints_every_id_once_in_list_order(capsys):
    _, out, _ = _run(capsys, "--dry-run")
    # An ID line starts with two spaces and the ID; a wrapped description continues further in.
    printed_ids = [
        line.split()[0] for line in out.splitlines() if line.startswith("  ") and line[2] != " "
    ]
    assert printed_ids == [c.id for c in allowlist.COMMANDS] + ["R1", "R2", "R3", "R4", "R5"]


def test_dry_run_starts_no_process(capsys, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("--dry-run started a process")

    monkeypatch.setattr(subprocess, "Popen", refuse)
    for name in ("system", "popen", "posix_spawn", "posix_spawnp", "execv", "execve", "fork"):
        monkeypatch.setattr(os, name, refuse)
    code, _, _ = _run(capsys, "--dry-run")
    assert code == 0


@pytest.mark.parametrize("platform_name", ["linux", "win32", "darwin"])
def test_version_and_dry_run_answer_on_any_platform(capsys, monkeypatch, platform_name):
    # --version and --dry-run skip the platform preflight (Decision 7).
    monkeypatch.setattr(sys, "platform", platform_name)
    assert _run(capsys, "--version")[0] == 0
    assert _run(capsys, "--dry-run")[0] == 0


def test_dry_run_answers_beside_flags_it_does_not_use(capsys):
    code, out, _ = _run(capsys, "--dry-run", "--json", "--no-open")
    assert code == 0 and out.startswith("voltry-mac ")


@pytest.mark.parametrize("answer", ["--dry-run", "--version"])
def test_the_contradiction_is_refused_even_beside_dry_run_or_version(capsys, answer):
    # Refused at argument parsing (spec, Failure modes), which --version and --dry-run do
    # not skip: they skip only the platform preflight (Decision 7).
    code, out, err = _run(capsys, answer, "--yes", "--no-root")
    assert (code, out, err) == (2, "", "--yes and --no-root cannot be used together\n")


def test_help_shows_the_spec_usage_block(capsys, supported, monkeypatch):
    # The usage block is the spec's ("CLI transcripts"), pinned by a golden, as the whole
    # help is below; this names what the help must hold.
    monkeypatch.setenv("COLUMNS", "200")
    monkeypatch.setenv("NO_COLOR", "1")
    code, out, err = _run(capsys, "--help")
    assert (code, err) == (0, "")
    assert out.startswith((GOLDEN / "usage.txt").read_text(encoding="utf-8") + "\n")
    for option in (
        "--no-root",
        "--yes",
        "--output DIR",
        "--json",
        "--no-open",
        "--show-serial",
        "--paper {letter,a4}",
        "--debug",
        "--dry-run",
        "--version",
    ):
        assert option in out, option
    assert "{render}" not in out, "render is listed once, in the usage block"
    # Change record 26: sudo can ask only where there is a terminal to ask on.
    assert (
        "--yes skips Voltry's own question only. With a terminal, sudo may still ask for\n"
        "your password; without one, sudo cannot ask." in out
    )
    assert "still asks for your password" not in out
    assert "--yes and --no-root contradict each other and are refused (exit 2)." in out
    assert "\u2014" not in out and "\u2013" not in out


def test_render_usage_is_its_own_line(capsys, supported):
    code, _, err = _run(capsys, "render")
    assert code == 2
    # render's own usage line, not the whole usage block, then the tool's own words (the GPT
    # audit, pass 2, G2-01): argparse named the subcommand differently on 3.11 and 3.12.
    assert err == (
        "usage: voltry-mac render REPORT.json [--output DIR] [--no-open]\n"
        "render needs REPORT.json\n"
    )


# --help prints the same bytes on every Python the tool supports, with color asked for and
# on a terminal too: Python 3.14 colors argparse's help there unless told not to, and the
# tool prints plain text (spec, Failure modes; the review of the audit fixes, round 3, n4,
# and the pre-audit of the GPT audit's pass 3, output 08).
HELP = {
    "--help": (GOLDEN / "help.txt").read_text(encoding="utf-8"),
    "render --help": (GOLDEN / "render_help.txt").read_text(encoding="utf-8"),
}
COLOR = ("NO_COLOR", "FORCE_COLOR", "PYTHON_COLORS", "TERM")


@pytest.mark.parametrize(
    "asked",
    [{}, {"FORCE_COLOR": "1"}, {"PYTHON_COLORS": "1"}, {"FORCE_COLOR": "1", "TERM": "xterm"}],
    ids=["plain", "FORCE_COLOR", "PYTHON_COLORS", "FORCE_COLOR and TERM"],
)
@pytest.mark.parametrize("line", list(HELP))
def test_help_is_the_same_bytes_with_color_asked_for(capsys, supported, monkeypatch, line, asked):
    for name in COLOR:
        monkeypatch.delenv(name, raising=False)
    for name, value in asked.items():
        monkeypatch.setenv(name, value)
    assert _run(capsys, *line.split()) == (0, HELP[line], "")


def _on_a_terminal(tmp_path: Path, *argv: str) -> tuple[int, bytes]:
    """The tool's stdout on a pseudo-terminal, as a terminal window shows it, with the
    carriage returns the terminal adds taken back out; stderr goes nowhere. The read ends
    when the terminal's other end closes, or after a minute with nothing to read."""
    reader, output = os.openpty()
    try:
        child = subprocess.Popen(  # noqa: S603 - a test-owned child, the tool with --help
            [sys.executable, "-m", "voltry_mac", *argv],
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.DEVNULL,
            cwd=tmp_path,
            env={
                "PATH": "/usr/bin:/bin",
                "LC_ALL": "en_US.UTF-8",
                "HOME": str(tmp_path),
                "TMPDIR": str(tmp_path),
                "TERM": "xterm-256color",
            },
        )
        os.close(output)
        output = -1
        chunks = []
        while select.select([reader], [], [], 60)[0]:
            try:
                chunk = os.read(reader, 65536)
            except OSError:  # the other end closed, as Linux says it
                break
            if not chunk:
                break
            chunks.append(chunk)
        code = child.wait(timeout=60)
    finally:
        os.close(reader)
        if output >= 0:
            os.close(output)
    return code, b"".join(chunks).replace(b"\r\n", b"\n")


@pytest.mark.parametrize("line", list(HELP))
def test_help_is_the_same_bytes_on_a_terminal(tmp_path, line):
    code, out = _on_a_terminal(tmp_path, *line.split())
    assert code == _preflight_code(passed=0)
    assert b"\x1b" not in out
    if code == 0:  # this machine's preflight passed
        assert out == HELP[line].encode()


@pytest.mark.parametrize("flag", ["--dry-run", "--version", "--help"])
def test_a_closed_pipe_ends_the_output_quietly(flag):
    reader = subprocess.Popen(  # noqa: S603 - a test-owned child
        [sys.executable, "-m", "voltry_mac", flag],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert reader.stdout is not None and reader.stderr is not None
    reader.stdout.close()  # the reader goes away before the tool writes
    with reader.stderr:
        err = reader.stderr.read().decode()
    # --help answers once the preflight has passed (change record 2).
    assert reader.wait(timeout=60) == (_preflight_code(passed=0) if flag == "--help" else 0)
    assert "Traceback" not in err and "Exception ignored" not in err


REFUSED_RUNS = [["--frobnicate"], ["--yes", "--no-root"], ["render", "report.json"]]


@pytest.mark.parametrize("argv", REFUSED_RUNS, ids=str)
def test_a_closed_stderr_pipe_keeps_the_exit_code(argv, tmp_path):
    # A refusal written to a reader that went away still exits with its own code, not
    # Python's 120 for an output it could not flush.
    child = subprocess.Popen(  # noqa: S603 - a test-owned child
        [sys.executable, "-m", "voltry_mac", *argv],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=tmp_path,
    )
    assert child.stdout is not None and child.stderr is not None
    child.stderr.close()
    with child.stdout:
        out = child.stdout.read()
    assert child.wait(timeout=60) == _preflight_code()
    assert out == b""
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("argv", REFUSED_RUNS, ids=str)
def test_stderr_closed_at_launch_keeps_stdout_clean(argv, tmp_path):
    # With stderr closed before Python starts, sys.stderr is None, and print(file=None)
    # would write the refusal to stdout.
    child = subprocess.run(  # noqa: S603 - a test-owned child
        ["/bin/sh", "-c", 'exec "$0" -m voltry_mac "$@" 2>&-', sys.executable, *argv],
        capture_output=True,
        timeout=60,
        check=False,
        cwd=tmp_path,
    )
    assert child.returncode == _preflight_code()
    assert child.stdout == b""
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("flag", ["--dry-run", "--version", "--help"])
def test_stdout_closed_at_launch_ends_quietly(flag):
    # With stdout closed before Python starts, sys.stdout is None (the round-3 review).
    child = subprocess.run(  # noqa: S603 - a test-owned child
        ["/bin/sh", "-c", 'exec "$0" -m voltry_mac "$1" >&-', sys.executable, flag],
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert child.returncode == (_preflight_code(passed=0) if flag == "--help" else 0)
    assert b"Traceback" not in child.stderr


class _GoneReader:
    """A stream whose reader went away: every write and flush raises BrokenPipeError."""

    def __init__(self, fd: int) -> None:
        self.fd = fd

    def write(self, text: str) -> int:
        raise BrokenPipeError

    def flush(self) -> None:
        raise BrokenPipeError

    def fileno(self) -> int:
        return self.fd


@pytest.mark.parametrize("argv", [["--yes", "--no-root"], ["--frobnicate"]], ids=str)
def test_a_refusal_to_a_reader_that_went_away_keeps_its_exit_code(supported, monkeypatch, argv):
    # In-process, beside the children above: the stream is pointed at /dev/null, so the
    # interpreter's own flush at exit cannot fail either.
    read_end, write_end = os.pipe()
    try:
        monkeypatch.setattr(sys, "stderr", _GoneReader(write_end))
        assert cli.main(argv) == 2
        assert os.path.samestat(os.fstat(write_end), os.stat(os.devnull))
    finally:
        os.close(read_end)
        os.close(write_end)


@pytest.mark.parametrize("argv", [["--yes", "--no-root"], ["--frobnicate"]], ids=str)
def test_with_no_stderr_a_refusal_goes_nowhere(capsys, supported, monkeypatch, argv):
    monkeypatch.setattr(sys, "stderr", None)
    assert cli.main(argv) == 2
    assert capsys.readouterr().out == ""


def test_with_no_stdout_help_still_answers(capsys, supported, monkeypatch):
    monkeypatch.setattr(sys, "stdout", None)
    assert cli.main(["--help"]) == 0


# --- flags ----------------------------------------------------------------------------------


def test_yes_with_no_root_is_refused_with_exit_2(capsys, supported):
    code, out, err = _run(capsys, "--yes", "--no-root")
    assert (code, out) == (2, "")
    assert err == "--yes and --no-root cannot be used together\n"
    assert list(supported.iterdir()) == []


@pytest.mark.parametrize(
    "argv",
    [
        ["--frobnicate"],
        ["--paper", "tabloid"],
        ["--paper"],
        ["--output"],
        ["render"],
        ["render", "a.json", "b.json"],
        ["render", "a.json", "--yes"],
        ["--json", "render", "a.json"],
        ["--output", "/Users/owner/Reports", "render", "a.json"],
    ],
)
def test_bad_arguments_exit_2_without_a_traceback(capsys, supported, argv):
    code, out, err = _run(capsys, *argv)
    assert code == 2 and out == ""
    assert "Traceback" not in err and err.strip()


def test_every_spec_flag_parses():
    args = cli.parse(
        [
            "--no-root",
            "--output",
            "/Users/owner/Reports",
            "--json",
            "--no-open",
            "--show-serial",
            "--paper",
            "a4",
            "--debug",
        ]
    )
    assert args.no_root and args.json and args.no_open and args.show_serial and args.debug
    assert (args.output, args.paper, args.yes, args.command) == (
        "/Users/owner/Reports",
        "a4",
        False,
        None,
    )
    render = cli.parse(["render", "report.json", "--output", "/Users/owner/Reports", "--no-open"])
    assert (render.command, render.report, render.output, render.no_open) == (
        "render",
        "report.json",
        "/Users/owner/Reports",
        True,
    )
    assert cli.parse(["--paper", "letter", "--yes"]).paper == "letter"


# --- render ------------------------------------------------------------------------------------


def test_a_render_of_a_file_that_is_not_there_exits_2(capsys, supported):
    code, out, err = _run(capsys, "render", "r.json")
    assert (code, out) == (2, "")
    assert err == "Could not read this file: No such file or directory.\n  r.json\n"
    assert list(supported.iterdir()) == []


# --- a Ctrl-C before the run takes the signals ----------------------------------------------


@pytest.mark.parametrize(
    "argv", [[], ["render", "report.json"], ["--help"]], ids=["run", "render", "--help"]
)
def test_a_ctrl_c_during_the_preflight_stops_with_nothing_saved(
    capsys, supported, monkeypatch, argv
):
    # The run's review, round 2, n17: a Ctrl-C while the preflight runs stops the command
    # with the stop line and 130, never a traceback naming the installed package's paths.
    # run.collect and run.rebuild refuse, so nothing can start whatever the command line
    # does. --help takes the preflight too (change record 2), so it stops the same way.
    # test_run.py sends SIGTERM and SIGHUP there too.
    def interrupted(**_: object) -> preflight.Platform:
        os.kill(os.getpid(), signal.SIGINT)  # a Ctrl-C while the platform is read
        return SUPPORTED

    def refused(*args: object) -> int:
        raise AssertionError("nothing may start after a Ctrl-C")

    monkeypatch.setattr(preflight, "read", interrupted)
    monkeypatch.setattr(run, "collect", refused)
    monkeypatch.setattr(run, "rebuild", refused)
    try:
        code, out, err = _run(capsys, *argv)
    except KeyboardInterrupt:  # escaping, it would stop the whole test run
        pytest.fail("the Ctrl-C left the command line as it was")
    assert (code, out, err) == (130, "", "Stopped. Nothing was saved.\n")
    assert list(supported.iterdir()) == []


# --- entry points ---------------------------------------------------------------------------


def test_the_console_script_is_voltry_mac():
    project = tomllib.loads((PACKAGE_ROOT / "pyproject.toml").read_text())["project"]
    assert project["scripts"] == {"voltry-mac": "voltry_mac.cli:main"}


def test_python_dash_m_runs_the_cli():
    result = subprocess.run(
        [sys.executable, "-m", "voltry_mac", "--version"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0
    assert result.stdout.splitlines()[0] == f"voltry-mac {voltry_mac.__version__}"


def test_render_refuses_a_collecting_option_in_its_own_words(capsys, supported):
    # The copy pass's review, round 1, M1: Voltry's own words, not Python's, so pinned whole.
    # A collecting option before render; after it, render does not take it (below).
    code = cli.main(["--json", "render", "report.json"])
    _, err = capsys.readouterr()
    assert code == 2
    assert err == (
        "usage: voltry-mac render REPORT.json [--output DIR] [--no-open]\n"
        "render takes only REPORT.json, --output DIR and --no-open\n"
    )


# --- the GPT audit, pass 2, G2-01: every usage error in the tool's own words --------------------
#
# argparse's own lines echoed what was typed as it is, a path with the account's name in it or
# a terminal's control sequence, in words that differed between Python 3.11, 3.12 and 3.14.
# Every usage error is the tool's own now, the same on every Python, after the usage it
# belongs to, and names an argument only through the display path. The home folder is a
# made-up one under tmp_path, as the account database would give it.

TOP = f"usage: {cli._USAGE}\n"
RENDER = "usage: voltry-mac render REPORT.json [--output DIR] [--no-open]\n"
ONE = "voltry-mac does not take this argument here:\n"
MANY = "voltry-mac does not take these arguments here:\n"


def _no_run(*args: object) -> int:
    raise AssertionError("a command line that does not parse reached the run")


@pytest.fixture
def home(supported, monkeypatch):  # type: ignore[no-untyped-def]
    # A usage error never reaches the run, so run.collect and run.rebuild refuse: a command
    # line that one Python took for a run, as 3.14 took --output -1.json, fails here and
    # never collects.
    folder = supported / "Users" / "cnryaccount"
    (folder / "Reports").mkdir(parents=True)
    monkeypatch.setattr(writer, "home", lambda: str(folder))
    monkeypatch.setattr(run, "collect", _no_run)
    monkeypatch.setattr(run, "rebuild", _no_run)
    return folder


USAGE_ERRORS = [
    (["--frobnicate"], f"{TOP}{ONE}  --frobnicate\n"),
    (["report.json"], f"{TOP}{ONE}  report.json\n"),
    (["{home}/Reports"], f"{TOP}{ONE}  ~/Reports\n"),
    (["--no-root", "--no-open", "{home}"], f"{TOP}{ONE}  ~\n"),
    (["--out", "{home}/Reports"], f"{TOP}{MANY}  --out\n  ~/Reports\n"),
    (["--no"], f"{TOP}{ONE}  --no\n"),
    (["--no-r"], f"{TOP}{ONE}  --no-r\n"),
    (["--output", "x", "x"], f"{TOP}{ONE}  x\n"),
    (["-o", "x", "--json"], f"{TOP}{MANY}  -o\n  x\n"),
    (["--paper", "tabloid"], f"{TOP}--paper takes letter or a4\n"),
    (["--paper"], f"{TOP}--paper takes letter or a4\n"),
    (["--output"], f"{TOP}--output needs a folder\n"),
    (["--output", "--json"], f"{TOP}--output needs a folder\n"),
    (["--json=yes"], f"{TOP}--json takes no argument\n"),
    (["--no-root="], f"{TOP}--no-root takes no argument\n"),
    (["--help=yes"], f"{TOP}--help takes no argument\n"),
    (["-h=yes"], f"{TOP}--help takes no argument\n"),
    (["render"], f"{RENDER}render needs REPORT.json\n"),
    (["render", "--no-open"], f"{RENDER}render needs REPORT.json\n"),
    (["--version", "render"], f"{RENDER}render needs REPORT.json\n"),
    (["render", "a.json", "b.json"], f"{RENDER}{ONE}  b.json\n"),
    (["render", "a.json", "--yes", "--json"], f"{RENDER}{MANY}  --yes\n  --json\n"),
    (["render", "a.json", "--output"], f"{RENDER}--output needs a folder\n"),
    (["render", "a.json", "--no-open=yes"], f"{RENDER}--no-open takes no argument\n"),
    (["--json", "render", "a.json"], f"{RENDER}{cli.RENDER_ONLY}\n"),
    (["--frobnicate", "render", "a.json"], f"{RENDER}{ONE}  --frobnicate\n"),
    # An option spelled wrong keeps its folder after =: the parts on either side of each =
    # are shown as paths, so the home folder there prints as ~ too, and a ~ that was typed
    # as \x7e (the pre-audit of the GPT audit's pass 3, control 02).
    (["--ouput={home}/Reports"], f"{TOP}{ONE}  --ouput=~/Reports\n"),
    (["--out={home}/Reports"], f"{TOP}{ONE}  --out=~/Reports\n"),
    (["render", "a.json", "--outptu={home}/Reports"], f"{RENDER}{ONE}  --outptu=~/Reports\n"),
    (["--x={home}/Reports={home}"], f"{TOP}{ONE}  --x=~/Reports=~\n"),
    (["REPORTS={home}/Reports"], f"{TOP}{ONE}  REPORTS=~/Reports\n"),
    (["--x=~/Reports"], f"{TOP}{ONE}  --x=\\x7e/Reports\n"),
    # An empty argument is named in words, and names no report (the review of the audit
    # fixes, round 3, n5).
    ([""], f"{TOP}{ONE}  (an empty argument)\n"),
    (["--x", "", "y"], f"{TOP}{MANY}  --x\n  (an empty argument)\n"),
    (["render", "a.json", ""], f"{RENDER}{ONE}  (an empty argument)\n"),
    (["render", ""], f"{RENDER}render needs REPORT.json\n"),
    # "--" and a word that starts with a dash and a digit, which each Python reads in its own
    # way, are refused first wherever they stand, each named, under render's usage when the
    # rest is a render (the review of the audit fixes, round 3, m1; the pre-audits of the
    # GPT audit's pass 3, control 03 and output 03).
    (["--"], f"{TOP}{ONE}  --\n"),
    (["--", "render", "r.json"], f"{RENDER}{ONE}  --\n"),
    (["--", "--json"], f"{TOP}{ONE}  --\n"),
    (["--no-root", "--", "render", "r.json"], f"{RENDER}{ONE}  --\n"),
    (["--", "-h"], f"{TOP}{ONE}  --\n"),
    (["--", "-x"], f"{TOP}{ONE}  --\n"),
    (["--json", "--", "--json"], f"{TOP}{ONE}  --\n"),
    (["--", "{home}/Reports"], f"{TOP}{ONE}  --\n"),
    (["render", "--", "r.json"], f"{RENDER}{ONE}  --\n"),
    (["render", "r.json", "--"], f"{RENDER}{ONE}  --\n"),
    (["--", "--"], f"{TOP}{MANY}  --\n  --\n"),
    (["--output", "-1.json"], f"{TOP}{ONE}  -1.json\n"),
    (["--output", "-1x"], f"{TOP}{ONE}  -1x\n"),
    (["--output", "-1.json", "-h"], f"{TOP}{ONE}  -1.json\n"),
    (["--paper", "-1"], f"{TOP}{ONE}  -1\n"),
    (["render", "-1.json"], f"{RENDER}{ONE}  -1.json\n"),
    (["render", "-1e5.json"], f"{RENDER}{ONE}  -1e5.json\n"),
    (["render", "-.5.json"], f"{RENDER}{ONE}  -.5.json\n"),
    (["render", "a.json", "--output", "-1"], f"{RENDER}{ONE}  -1\n"),
    (["-1.json", "-h"], f"{TOP}{ONE}  -1.json\n"),
    (["-5"], f"{TOP}{ONE}  -5\n"),
    (["-\u0665"], f"{TOP}{ONE}  -\u0665\n"),
    (["-1", "--", "render"], f"{RENDER}{MANY}  -1\n  --\n"),
]


@pytest.mark.parametrize(("argv", "said"), USAGE_ERRORS, ids=lambda each: str(each)[:40])
def test_each_usage_error_is_the_tools_own(capsys, home, argv, said):
    argv = [each.replace("{home}", str(home)) for each in argv]
    assert _run(capsys, *argv) == (2, "", said)


# What a terminal would act on, each with how the refusal shows it.
CONTROLS = [
    ("--bad\x1b[2J", "--bad\\x1b[2J"),  # clears the screen
    ("\x1b]0;owned\x07", "\\x1b]0;owned\\x07"),  # sets the window's title
    ("--x\u202etxt.exe", "--x\\u202etxt.exe"),  # shows the rest right to left
    ("--no=\x1b[2J", "--no=\\x1b[2J"),  # was argparse's ambiguous option
    ("a\x7fb\nc\u200bd", "a\\x7fb\\nc\\u200bd"),  # DEL, a new line, a hidden space
]


@pytest.mark.parametrize(("typed", "shown"), CONTROLS, ids=["ESC", "OSC", "RLO", "=ESC", "DEL"])
def test_an_argument_with_a_terminal_control_is_named_escaped(capsys, home, typed, shown):
    code, out, err = _run(capsys, typed)
    assert (code, out, err) == (2, "", f"{TOP}{ONE}  {shown}\n")


def _plain(text: str) -> bool:
    """Whether a terminal shows the text as it is: no control, format or line separator
    character but the new line."""
    return all(
        each == "\n" or unicodedata.category(each) not in ("Cc", "Cf", "Zl", "Zp") for each in text
    )


# Command lines that do not parse, the canaries above among them.
REFUSED = (
    [argv for argv, _ in USAGE_ERRORS]
    + [[typed] for typed, _ in CONTROLS]
    + [
        ["render", "r.json", "\x1b]0;owned\x07"],
        ["--paper", "x\x1b[2J"],
        ["--json=\x1b[2J"],
        ["-v"],
        ["-x y"],
        ["Render", "a.json"],
        ["--x", "--y", "z"],
        ["--no-open", "render", "a.json", "--output", "a", "b"],
    ]
)
ARGPARSE = (
    "error:",
    "invalid choice",
    "unrecognized argument",
    "expected one argument",
    "ambiguous option",
    "ignored explicit argument",
    "arguments are required",
    "choose from",
)


@pytest.mark.parametrize("argv", REFUSED, ids=lambda each: str(each)[:40])
def test_no_argparse_sentence_or_control_reaches_the_terminal(capsys, home, argv):
    argv = [each.replace("{home}", str(home)) for each in argv]
    code, out, err = _run(capsys, *argv)
    assert (code, out) == (2, "")
    assert _plain(err) and not any(said in err for said in ARGPARSE)
    usage = RENDER if err.startswith(RENDER) else TOP
    assert err.startswith(usage)
    words, *named = err.removeprefix(usage).removesuffix("\n").split("\n")
    known = (cli.NOT_TAKEN_ONE, cli.NOT_TAKEN_MANY, cli.PAPER_SIZES, cli.NEEDS_FOLDER)
    known += (cli.NEEDS_REPORT, cli.RENDER_ONLY, cli.UNREAD)
    flags = {cli.NO_ARGUMENT.format(option=option) for option in cli._FLAGS}
    assert words in known or words in flags, words
    assert all(line.startswith("  ") for line in named)
    assert str(home) not in err


def test_the_words_know_every_option_that_takes_no_argument():
    parser = cli._parser()
    (commands,) = [each for each in parser._actions if isinstance(each, argparse._SubParsersAction)]
    flags = {
        option
        for each in (parser, commands._name_parser_map["render"])
        for action in each._actions
        if action.nargs == 0
        for option in action.option_strings
        if option.startswith("--")
    }
    assert flags == cli._FLAGS


def test_an_error_argparse_names_no_way_the_tool_knows_is_still_the_tools_own(
    capsys, supported, monkeypatch
):
    # A later Python may name an error by no argument, or by one the tool never gave it.
    def later(self, args=None, namespace=None):  # type: ignore[no-untyped-def]
        raise argparse.ArgumentError(None, "words of a Python still to come")

    monkeypatch.setattr(argparse.ArgumentParser, "parse_known_args", later)
    assert _run(capsys, "--frobnicate") == (
        2,
        "",
        f"{TOP}voltry-mac could not read this command line\n",
    )


def test_argparses_own_error_line_never_prints(capsys, supported):
    with pytest.raises(cli.UsageError) as held:
        cli._parser().error("argparse's own words")
    assert (held.value.words, held.value.named) == (cli.UNREAD, ())
    assert capsys.readouterr() == ("", "")


# The words argparse reads in its own way on some Python the tool supports: "--", and a word
# that starts with a dash and a digit, by 3.14's pattern for a number, which covers the one
# 3.11 to 3.13 use. With words around them, some of which argparse must still read.
DASH_DIGIT = re.compile(r"-\.?\d")
WORDS = ["render", "r.json", "--", "-1", "-1.json", "-.5", "-\u0665", "--output", "a4", "--x=-1"]


def test_argparse_never_reads_a_double_dash_or_a_dash_and_a_digit(monkeypatch):
    # So the outcome of a command line cannot depend on the Python it runs on (the review of
    # the audit fixes, round 3, m1): parse() decides each such word before argparse reads
    # the command line, render's arguments included.
    read: list[list[str]] = []
    real = argparse.ArgumentParser.parse_known_args

    def spy(self, args=None, namespace=None):  # type: ignore[no-untyped-def]
        read.append(list(args))
        return real(self, args, namespace)

    monkeypatch.setattr(argparse.ArgumentParser, "parse_known_args", spy)
    for count in (1, 2, 3):
        for argv in itertools.product(WORDS, repeat=count):
            with contextlib.suppress(cli.UsageError):
                cli.parse(list(argv))
    odd = [args for args in read if any(w == "--" or DASH_DIGIT.match(w) for w in args)]
    assert odd == []
    assert ["--x=-1"] in read and ["r.json"] in read, "the rest is still argparse's"


def test_a_usage_error_looks_up_nothing_before_the_preflight(capsys, supported, monkeypatch):
    # MAC 3.1b: the preflight comes first, so a run as root looks nothing up for a path.
    looked: list[str] = []
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(run, "_home_in", lambda path, home, **_: looked.append(path) or "")
    assert _run(capsys, "/Users/cnryaccount/Reports") == (5, "", preflight.ROOT + "\n")
    assert looked == []


# The real console script, as an owner runs it, with a made-up folder in the home folder the
# account database gives: the real preflight, the real lookup of the home folder, the real
# stderr. --yes and --no-root come first, so nothing could collect even if the rest parsed.
# The home folder is read here only to build the argument, and no assertion prints it.


def _script(tmp_path: Path, *argv: str) -> subprocess.CompletedProcess[bytes]:
    script = Path(sysconfig.get_path("scripts")) / "voltry-mac"
    if not script.exists():
        pytest.skip("no voltry-mac console script beside this Python")
    (tmp_path / "home").mkdir()
    (tmp_path / "tmp").mkdir()
    return subprocess.run(  # noqa: S603 - the tool itself, with arguments that do not parse
        [str(script), "--yes", "--no-root", *argv],
        capture_output=True,
        timeout=60,
        check=False,
        cwd=tmp_path,
        env={
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "en_US.UTF-8",
            "HOME": str(tmp_path / "home"),
            "TMPDIR": str(tmp_path / "tmp"),
        },
    )


@pytest.mark.parametrize(
    "form", ["{home}/CNRYPRIVATE", "--ouput={home}/CNRYPRIVATE", "--out={home}/CNRYPRIVATE"]
)
def test_a_path_canary_in_the_home_folder_prints_as_a_tilde(tmp_path, form):
    # Alone, or after = in an option spelled wrong or cut short, where the home folder does
    # not start the argument (the pre-audit of the GPT audit's pass 3, control 02).
    home = pwd.getpwuid(os.getuid()).pw_dir
    child = _script(tmp_path, form.format(home=home))
    leaked = os.fsencode(home) in child.stderr
    assert not leaked, "the home folder's path reached the terminal"
    assert child.stdout == b""
    assert child.returncode == _preflight_code()
    if child.returncode == 2:  # this Mac's preflight passed
        assert child.stderr == f"{TOP}{ONE}  {form.format(home='~')}\n".encode()


def test_a_control_canary_reaches_the_terminal_escaped(tmp_path):
    child = _script(tmp_path, "--bad\x1b[2J", "--x\u202etxt.exe", "\x1b]0;owned\x07\x7f")
    raw = [each for each in (b"\x1b", b"\x07", b"\x7f", "\u202e".encode()) if each in child.stderr]
    assert raw == []
    assert child.stdout == b""
    assert child.returncode == _preflight_code()
    if child.returncode == 2:
        assert (
            child.stderr
            == (
                f"{TOP}{MANY}  --bad\\x1b[2J\n  --x\\u202etxt.exe\n  \\x1b]0;owned\\x07\\x7f\n"
            ).encode()
        )


READ_APART = [
    (["--", "render", "r.json"], f"{RENDER}{ONE}  --\n"),
    (["--output", "-1.json"], f"{TOP}{ONE}  -1.json\n"),
    (["render", "-1.json"], f"{RENDER}{ONE}  -1.json\n"),
]


@pytest.mark.parametrize(
    ("argv", "said"), READ_APART, ids=[" ".join(argv) for argv, _ in READ_APART]
)
def test_a_word_each_python_reads_its_own_way_is_refused_in_the_same_bytes(tmp_path, argv, said):
    # The real console script, after --yes --no-root: 3.11 named "--" where 3.12 and later
    # ran render, and 3.14 took -1.json for a folder or a report where 3.11 to 3.13 refused
    # it (the review of the audit fixes, round 3, m1). Now each Python refuses the word.
    child = _script(tmp_path, *argv)
    assert child.stdout == b""
    assert child.returncode == _preflight_code()
    if child.returncode == 2:
        assert child.stderr == said.encode()
