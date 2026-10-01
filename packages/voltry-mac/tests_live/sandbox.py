"""The sandbox job (docs/VOLTRY_MAC_SPEC.md, Test strategy part 5, "Live macOS CI", its third
bullet and its Python bullet as change record 14 reads it, and the Acceptance lines on the
sandboxed run; board item MAC 4.2, issue #324).

A release prerequisite. The CLI runs with --no-root under /usr/bin/sandbox-exec with a
profile of the job's own that denies the network, allows process execution only for the
programs of the allow-listed commands a --no-root run starts and the interpreter, and denies
file writes outside a temporary output folder, so the job never mixes its own sandbox with
sudo. The report must still come out. sandbox-exec is deprecated but present on macOS 26;
where an image drops it, this fails rather than skips, and the release waits for a
replacement the owner approves. The job runs it on the package's floor and on uv's default
Python, since the interpreter's own paths are part of the profile.

First a probe under the same profile shows this image enforces it: a write in the folder
and to /dev/null go through, and a write outside it, a program off the list and a
connection are refused. Then the CLI runs as `voltry-mac --no-root --json --no-open
--output <folder>` with no terminal, and the report must come out: a PDF and a JSON of the
runner's own with mode 0600; a JSON the package's own validator takes, the one `render`
reads with; the exit the report implies, by the package's own rule; the elevation record of
a --no-root run; one record for each user command and none for anything else; and nothing
left in the working folder. The profile must break no command: the CLI runs once more
without it, and the same commands must fail both ways. And the PDF must be the report's
whole: `voltry-mac render`, under the same profile with a folder of its own, rebuilds it
from the JSON byte for byte.

.github/workflows/voltry-mac.yml's sandbox job runs this as the runner user, never as root
and never with sudo; it refuses to run anywhere else (tests_live/gate.py). It prints counts,
states and command IDs, never a report's values, and removes what it made. It imports the
package it runs: tests/test_live_scripts.py imports it on every platform, for the profile,
the checks and the refusal.
"""

from __future__ import annotations

import ctypes
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Final

from voltry_mac import model, validate

HERE: Final = Path(__file__).resolve().parent


def _load(name: str, file: str) -> ModuleType:
    """A sibling module by its path, as conftest.py loads it: tests_live is not a package."""
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, HERE / file)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


gate = _load("voltry_mac_live_gate", "gate.py")

SANDBOX_EXEC: Final = "/usr/bin/sandbox-exec"
# The programs a --no-root run starts: every user command's, as the spec's allow-list gives
# them ("Run as the user"), C28's being the interpreter, which the profile adds. X1's
# sandbox-exec, P1's ps and sudo run only after consent, and open only without --no-open, so
# the profile refuses them.
PROGRAMS: Final = (
    "/usr/bin/sw_vers",
    "/usr/sbin/system_profiler",
    "/usr/sbin/ioreg",
    "/usr/bin/pmset",
    "/usr/bin/memory_pressure",
    "/usr/sbin/diskutil",
    "/usr/bin/csrutil",
    "/usr/sbin/spctl",
    "/usr/bin/fdesetup",
    "/usr/sbin/sysctl",
)
# The 27 user commands, in allow-list order: C1 to C9, then C11 to C28.
USER_COMMANDS: Final = tuple(f"C{n}" for n in (*range(1, 10), *range(11, 29)))
# Decision 2's record when --no-root skips the question: nothing elevated is attempted.
SKIPPED: Final = {
    "consent": "skipped",
    "skip_cause": "no_root_flag",
    "mode": "none",
    "checks": {"service_account": "not_run", "sandbox_probe": "not_run", "listing": "not_run"},
    "prepare": "not_run",
    "authenticate": "not_run",
    "count": {"ending": "not_run", "cleanup": "not_applicable"},
    "power": {"ending": "not_run", "cleanup": "not_applicable"},
    "cleared": "not_attempted",
    "clear_error": None,
}
# The options of both runs of the collecting CLI (the spec's sandbox bullet): --no-root,
# never --yes, so the job never mixes its own sandbox with sudo.
NO_ROOT: Final = ("--no-root", "--json", "--no-open", "--output")
# Each run's bound: far past a --no-root run, and three of them, with the probe, well short
# of the job's timeout.
RUN_S: Final = 240.0
STDERR_LINES: Final = 5  # of sandbox-exec's own stderr, when the probe reports nothing

# What the probe tries under the profile, and what the profile must make of each.
PROBE: Final = r"""
import json, os, socket, subprocess, sys
folder, outside = sys.argv[1], sys.argv[2]
found = {}
def attempt(name, action):
    try:
        action()
    except PermissionError:
        found[name] = "refused"
    except OSError as error:
        found[name] = f"failed with errno {error.errno}"
    else:
        found[name] = "done"
def write(path):
    with open(path, "w") as handle:
        handle.write("probe")
attempt("a write in the folder", lambda: write(os.path.join(folder, "probe")))
attempt("a write outside the folder", lambda: write(os.path.join(outside, "probe")))
def null():
    descriptor = os.open(os.devnull, os.O_RDWR)  # as subprocess opens it for a child's stdin
    try:
        os.write(descriptor, b"probe")
    finally:
        os.close(descriptor)
attempt("/dev/null opened read-write", null)
touched = os.path.join(folder, "touched")
attempt("starting /usr/bin/touch", lambda: subprocess.run(["/usr/bin/touch", touched], check=False))
local = ("127.0.0.1", 9)
attempt("a connection to 127.0.0.1", lambda: socket.create_connection(local, timeout=5).close())
print(json.dumps(found))
"""
ENFORCED: Final = {
    "a write in the folder": "done",
    "a write outside the folder": "refused",
    "/dev/null opened read-write": "done",
    "starting /usr/bin/touch": "refused",
    "a connection to 127.0.0.1": "refused",
}


def _string(path: str) -> str:
    """A path as a profile string. Only an absolute path with no quote, backslash or control
    character is taken, so the profile cannot read it as anything else."""
    unsafe = any(char in '"\\' or ord(char) < 0x20 or ord(char) == 0x7F for char in path)
    if not path.startswith("/") or unsafe:
        raise ValueError(
            "the profile takes only an absolute path with no quote, backslash or control "
            "character"
        )
    return f'"{path}"'


def profile(folder: str, interpreters: Sequence[str]) -> str:
    """The job's profile. Everything the default allows, but no network; no program but
    PROGRAMS and the interpreter, by each path it may be started by; and no file write
    outside ``folder``, but data written to /dev/null, which stores nothing and which
    subprocess opens read-write for every child's standard input. The later rule wins in a
    profile, so each allowance follows the denial it narrows."""
    programs = " ".join(f"(literal {_string(path)})" for path in (*PROGRAMS, *interpreters))
    rules = (
        "(version 1)",
        "(allow default)",
        "(deny network*)",
        "(deny process-exec*)",
        f"(allow process-exec* {programs})",
        "(deny file-write*)",
        f"(allow file-write* (subpath {_string(folder)}))",
        '(allow file-write-data (literal "/dev/null"))',
    )
    return "\n".join(rules) + "\n"


def interpreters() -> tuple[str, ...]:
    """The interpreter by each path it may be started by: as this venv names it, which C28
    uses, the file that is, and the file this process runs where that is another.
    python.org's builds for macOS start as a small launcher that becomes the framework's
    Resources/Python.app/Contents/MacOS/Python, which the profile must allow too (the first
    live run, 2026-09-29: the job's 3.11 legs could not start it)."""
    named = sys.executable
    paths = [named, os.path.realpath(named)]
    running = _running_image()
    if running is not None:
        paths.append(running)
    return tuple(dict.fromkeys(paths))


def _running_image() -> str | None:
    """The file this process runs, as the kernel names it (libproc's proc_pidpath), or None
    where there is no such call, as on Linux, where the job never runs."""
    try:
        library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    except OSError:
        return None
    buffer = ctypes.create_string_buffer(4096)  # PROC_PIDPATHINFO_MAXSIZE
    size = library.proc_pidpath(os.getpid(), buffer, ctypes.sizeof(buffer))
    return os.fsdecode(buffer.raw[:size]) if size > 0 else None


def sandbox_exec_problem(path: str = SANDBOX_EXEC) -> str | None:
    """Why this image cannot run the job, or None: sandbox-exec is not a program here. The
    job then fails, never skips."""
    if os.path.isfile(path) and os.access(path, os.X_OK):
        return None
    return (
        f"{path} is not on this image, so the sandbox job fails rather than skips: the "
        "release waits for a replacement the owner approves, which would also replace the "
        "payload sandbox (docs/VOLTRY_MAC_SPEC.md, Test strategy part 5)."
    )


# --- the checks ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Check:
    """One check: whether it holds, what it claims, and what was seen, which the log prints
    beside a failure: a state, a count, a mode or command IDs, never a report's value."""

    holds: bool
    what: str
    seen: object = None


class Checks:
    """Each check's line, what was seen beside each that failed, and the ones that failed."""

    def __init__(self) -> None:
        self.failed: list[str] = []

    def that(self, holds: bool, what: str, seen: object = None) -> None:
        print(f"  {'ok  ' if holds else 'FAIL'}  {what}")
        if not holds:
            self.failed.append(what)
            if seen is not None:
                print(f"        seen: {seen}")

    def every(self, checks: Sequence[Check]) -> None:
        for check in checks:
            self.that(check.holds, check.what, check.seen)


def probe_check(enforced: Mapping[str, str] | None) -> Check:
    return Check(
        enforced == ENFORCED,
        "the profile holds: a write in the folder and /dev/null opened read-write go "
        "through; a write outside it, /usr/bin/touch and a connection are refused",
        dict(enforced) if enforced is not None else "the probe reported nothing",
    )


@dataclass(frozen=True)
class Entry:
    """One file in the output folder: its suffix, its base name, and what lstat says."""

    suffix: str
    stem: str
    mode: int
    uid: int
    links: int


def file_checks(entries: Sequence[Entry], uid: int) -> list[Check]:
    """Decision 5: a PDF and a JSON sharing one base name, each a regular file of the
    runner's own, mode 0600, one name."""
    kinds = sorted(entry.suffix for entry in entries)
    return [
        Check(
            kinds == [".json", ".pdf"] and len({entry.stem for entry in entries}) == 1,
            "a PDF and a JSON sharing one base name, and nothing else",
            kinds,
        ),
        Check(
            all(stat.S_ISREG(entry.mode) and entry.uid == uid for entry in entries),
            "each a regular file the runner user owns",
            [(stat.S_IFMT(entry.mode), entry.uid == uid) for entry in entries],
        ),
        Check(
            all(stat.S_IMODE(entry.mode) == 0o600 and entry.links == 1 for entry in entries),
            "each with mode 0600 and one name",
            [(oct(stat.S_IMODE(entry.mode)), entry.links) for entry in entries],
        ),
    ]


def failed_commands(report: Mapping[str, Any]) -> list[str]:
    """The commands with a failed run, in the report's order."""
    return [record["id"] for record in report["commands"] if record["failed_runs"]]


def report_checks(
    report: Mapping[str, Any], *, returncode: int, plain: Mapping[str, Any] | None
) -> list[Check]:
    """What the report must hold, beside what the package's validator checks: the exit the
    package's own rule gives it, the elevation record of a --no-root run, one run of each
    user command and nothing else, and the same commands failed as in the run without the
    profile, ``plain``, so the profile broke none."""
    expected = model.exit_code(
        clear_failed=report["elevation"]["cleared"] == "failed",
        unexpected=model.unexpected(report),
    )
    records = report["commands"]
    failed = failed_commands(report)
    return [
        Check(returncode == expected, f"exit {expected}, the code the report implies", returncode),
        Check(
            report["elevation"] == SKIPPED,
            "the elevation record of a --no-root run",
            report["elevation"],
        ),
        Check(
            [record["id"] for record in records] == list(USER_COMMANDS)
            and all(record["runs"] == 1 for record in records),
            "one run of each user command, and nothing else run",
            [(record["id"], record["runs"]) for record in records],
        ),
        Check(
            plain is not None and failed == failed_commands(plain),
            "the same commands failed with the profile as without it, so it broke none",
            f"with it {failed}, without it "
            + (str(failed_commands(plain)) if plain is not None else "no report"),
        ),
    ]


def pdf_checks(pdf: bytes, rendered: bytes | None, *, render_code: int | None) -> list[Check]:
    """The PDF is one whole file, and render, from the JSON under the same profile, rebuilds
    it byte for byte, as it must on the same package version."""
    return [
        Check(
            pdf.startswith(b"%PDF-") and pdf.rstrip().endswith(b"%%EOF"),
            "the PDF begins with %PDF- and ends with %%EOF",
            f"{len(pdf)} bytes",
        ),
        Check(
            render_code == 0 and rendered == pdf,
            "render, under the profile, rebuilt the PDF from the JSON byte for byte",
            f"render exit {render_code}, "
            + (f"{len(rendered)} bytes against {len(pdf)}" if rendered is not None else "no PDF"),
        ),
    ]


# --- the run ------------------------------------------------------------------------------


def probe_report(stdout: str, stderr: str, returncode: int) -> dict[str, str] | None:
    """What the profile made of each attempt, or None if the probe did not report; then
    sandbox-exec's own first lines are printed, since they name a profile the image
    rejects."""
    try:
        reported: dict[str, str] = json.loads(stdout)
    except ValueError:
        print(f"  the probe exited {returncode} and reported nothing; sandbox-exec's stderr:")
        for line in stderr.strip().split("\n")[:STDERR_LINES]:
            print(f"    {line[:200]}")
        return None
    return reported


def _probe(profile_path: Path, folder: Path, outside: Path) -> dict[str, str] | None:
    found = subprocess.run(
        [SANDBOX_EXEC, "-f", str(profile_path), sys.executable, "-I", "-c", PROBE]
        + [str(folder), str(outside)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=60,
    )
    return probe_report(found.stdout, found.stderr, found.returncode)


def cli(python: str, profile_path: Path | None, *arguments: str) -> list[str]:
    """The CLI as the job runs it, ``python -m voltry_mac``: under ``profile_path`` through
    sandbox-exec, or, to compare, with no profile."""
    argv = [python, "-m", "voltry_mac", *arguments]
    return [SANDBOX_EXEC, "-f", str(profile_path), *argv] if profile_path is not None else argv


def _count(folder: Path) -> int:
    return len(list(folder.iterdir()))


def leftover_checks(work: Path, outside: Path) -> list[Check]:
    """Nothing left in the working folder the runs started in, or outside the output
    folder."""
    return [
        Check(not any(work.iterdir()), "nothing left in the working folder", _count(work)),
        Check(
            not any(outside.iterdir()),
            "nothing left outside the output folder",
            _count(outside),
        ),
    ]


def _cli(argv: Sequence[str], work: Path) -> int:
    """The CLI as the runner user with no terminal, both streams on pipes: under the profile
    a write to a file outside the folder fails, an inherited one included, and a pipe is no
    file. Its exit status."""
    ran = subprocess.run(
        list(argv), cwd=work, stdin=subprocess.DEVNULL, capture_output=True, timeout=RUN_S
    )
    return ran.returncode


def _one(folder: Path, suffix: str) -> Path | None:
    found = sorted(folder.glob(f"*{suffix}"))
    return found[0] if len(found) == 1 else None


def _valid(saved: Path | None) -> dict[str, Any] | None:
    """A saved JSON the package's validator takes, read; None for none, or one it refuses."""
    if saved is None:
        return None
    data = saved.read_bytes()
    try:
        validate.read(data)
    except ValueError:
        return None
    report: dict[str, Any] = json.loads(data)
    return report


def run(root: Path) -> list[str]:
    """The job, in a fresh folder of its own; returns the checks that failed."""
    checks = Checks()
    folder, plain, rendered = root / "report", root / "plain", root / "render"
    outside, work = root / "outside", root / "cwd"
    for path in (folder, plain, rendered, outside, work):
        path.mkdir()
    paths = interpreters()
    profile_path, render_profile = root / "profile.sb", root / "render.sb"
    profile_path.write_text(profile(str(folder), paths), encoding="utf-8")
    render_profile.write_text(profile(str(rendered), paths), encoding="utf-8")

    print("The job's profile, as this image enforces it")
    enforced = _probe(profile_path, folder, outside)
    for attempt, outcome in (enforced or {}).items():
        print(f"  {attempt}: {outcome}")
    checks.every([probe_check(enforced)])
    for leftover in folder.iterdir():
        leftover.unlink()

    print("The CLI with --no-root under the profile, no terminal")
    code = _cli(cli(sys.executable, profile_path, *NO_ROOT, str(folder)), work)
    saved = _one(folder, ".json")
    print(f"  exit {code}; a JSON report {'came out' if saved else 'did not come out'}")
    checks.that(
        saved is not None, "the report came out", sorted(path.suffix for path in folder.iterdir())
    )
    print("The CLI with --no-root without the profile, to compare")
    plain_code = _cli(cli(sys.executable, None, *NO_ROOT, str(plain)), work)
    plain_saved = _one(plain, ".json")
    print(f"  exit {plain_code}; a JSON report {'came out' if plain_saved else 'did not come out'}")
    if saved is not None:
        entries = []
        for path in sorted(folder.iterdir()):
            info = path.lstat()
            entries.append(Entry(path.suffix, path.stem, info.st_mode, info.st_uid, info.st_nlink))
        kinds = sorted(entry.suffix for entry in entries)
        print(f"  the output folder holds {len(entries)} files {kinds}")
        checks.every(file_checks(entries, os.getuid()))
        data = saved.read_bytes()
        try:
            validate.read(data)
        except ValueError as refused:  # canonical.Invalid names a field's path, never a value
            checks.that(False, "the package's validator takes the JSON", str(refused))
        else:
            checks.that(True, "the package's validator takes the JSON")
            report = json.loads(data)
            plain_report = _valid(plain_saved)
            print(
                f"  {len(report['commands'])} command records; failed runs under the profile: "
                f"{failed_commands(report)}"
            )
            checks.every(report_checks(report, returncode=code, plain=plain_report))
        print("render, under the same profile with a folder of its own")
        render_code = _cli(
            cli(
                sys.executable,
                render_profile,
                *("render", str(saved), "--output", str(rendered), "--no-open"),
            ),
            work,
        )
        pdf, again = _one(folder, ".pdf"), _one(rendered, ".pdf")
        checks.every(
            pdf_checks(
                pdf.read_bytes() if pdf is not None else b"",
                again.read_bytes() if again is not None else None,
                render_code=render_code,
            )
        )
    checks.every(leftover_checks(work, outside))
    return checks.failed


def within(root: Path, work: Callable[[Path], list[str]]) -> list[str]:
    """``work`` in the folder ``root``, which goes afterwards whatever happened: the reports
    carry the virtual machine's identifiers, and nothing of them stays."""
    try:
        return work(root)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def main() -> int:
    refused = gate.refusal(os.environ, gate.SANDBOX_REFUSAL)
    if refused is not None:
        print(refused, file=sys.stderr)
        return 2
    missing = sandbox_exec_problem()
    if missing is not None:
        print(missing, file=sys.stderr)
        return 1
    failed = within(Path(tempfile.mkdtemp(prefix="voltry-mac-sandbox-")).resolve(), run)
    print(f"{len(failed)} checks failed" if failed else "Every check passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
