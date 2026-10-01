"""What the live tests share (docs/VOLTRY_MAC_SPEC.md, Test strategy part 5, "Live macOS
CI"; board item MAC 4.1, issue #323): the installed command, the process listings that
watch it run, the kernel's answer on whether a payload runs sandboxed, sudo's version, the
folders checked for a file a payload could have made, and the spec's expectations. The
expectations are written out here from the spec, not read from the package, so a check
compares the running tool with the spec rather than with itself. Registered once by
conftest.py as ``voltry_mac_live``, after the gate.

Nothing here prints a report's values or a process's arguments: a failure names what it
expected and the state it found. A count that did not parse adds sqlite3's and
sandbox-exec's own error lines, which may name S3's fixed store, and never a line of
sudo's, which can name the account and the host.
"""

from __future__ import annotations

import ctypes
import functools
import json
import os
import pty
import re
import signal
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Protocol

# The command under test: the one installed beside the interpreter running these tests, in
# the live job's own venv (.github/workflows/voltry-mac.yml).
CLI: Final = Path(sys.executable).with_name("voltry-mac")
# --dry-run's text, which the package's own tests hold to the spec's allow-list.
DRY_RUN: Final = Path(__file__).resolve().parents[1] / "tests" / "golden" / "dry_run.txt"
# The tests' own commands run in the environment the tool gives every child ("Environment
# for every child"), so ps prints its columns and sudo its words as this file parses them,
# whatever the runner's locale. The tool itself runs in the job's own environment.
ENVIRONMENT: Final = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "en_US.UTF-8"}

# "Command allow-list": the 27 user commands, then the records a run with --yes and no
# terminal adds. Decision 8 keeps the records in allow-list ID order, where the -n forms
# come last.
USER_COMMANDS: Final = tuple(f"C{n}" for n in (*range(1, 10), *range(11, 29)))
NONINTERACTIVE: Final = (*USER_COMMANDS, "X1", "P1", "S1", "S5", "S2n", "S3n", "S4n")
# C24 and C25 read the second performance level; on a Mac with one they fail as expected,
# binding to nothing (the C15 to C25 row, and Decision 8's command records).
SECOND_LEVEL: Final = ("C24", "C25")

PROFILE: Final = "(version 1) (allow default) (deny file-write*) (deny network*)"
POWERMETRICS: Final = (
    "/usr/bin/powermetrics",
    "-n",
    "5",
    "-i",
    "1000",
    "--samplers",
    "cpu_power,gpu_power,thermal",
    "--format",
    "plist",
)
S4N: Final = (
    "/usr/bin/sudo",
    "-H",
    "-n",
    "--",
    "/usr/bin/sandbox-exec",
    "-p",
    PROFILE,
    *POWERMETRICS,
)
SERVICE_ACCOUNT: Final = "_mmaintenanced"
STORE_FOLDER: Final = "/private/var/db/mmaintenanced"
# S3's sqlite3 with its flags, and its aggregate query ("Command allow-list"); the ledger
# fixtures run them against stores of their own.
SQLITE3: Final = (
    "/usr/bin/sqlite3",
    "-init",
    "/dev/null",
    "-safe",
    "-nofollow",
    "-readonly",
    "-json",
    "-bail",
)
LEDGER_QUERY: Final = (
    "PRAGMA query_only=ON; PRAGMA temp_store=MEMORY; WITH classes(correctable,label) AS "
    "(VALUES(1,'correctable'),(0,'uncorrectable')) SELECT c.label AS class, COUNT(e.ID) AS "
    "event_rows, COALESCE(SUM(e.count),0) AS reported_count FROM classes c LEFT JOIN "
    "ecc_errors_v2 e ON e.correctable=c.correctable GROUP BY c.correctable,c.label ORDER BY "
    "c.correctable DESC;"
)
# The only processes the subtree under sudo can hold ("Stopping a payload").
SUBTREE: Final = ("sudo", "sandbox-exec", "sqlite3", "powermetrics")
# sudo's version, the first line of `sudo -V`. sudo made use_pty its default in 1.9.14, so
# on a terminal sudo 1.9.14 and later run the payload behind a monitor process, and an
# older sudo, 1.9.13p2 on macOS 15.0 to 15.6 and 26.0, runs it as its own child (Decision
# 2, "Stopping a payload"; change record 12).
SUDO_VERSION: Final = re.compile(r"Sudo version ([0-9]+)\.([0-9]+)\.([0-9]+)(?:p([0-9]+))?")
MONITOR_SINCE: Final = (1, 9, 14)
LEDGER_VALUES: Final = frozenset(
    f"{kind}_{column}"
    for kind in ("correctable", "uncorrectable")
    for column in ("event_rows", "reported_count")
)
SERIES: Final = (
    "sample_elapsed_ns",
    "sample_thermal_pressure",
    *(f"sample_{kind}_power_mw" for kind in ("cpu", "gpu", "ane", "combined")),
)

# The run's own words: Decision 7's line for a virtual machine, first in At a glance, and
# the Failure modes row for a signal; and its --debug lines for the final clear and for a
# payload it stopped.
GLANCE: Final = (
    "AT A GLANCE Machine This is a virtual machine. Hardware readings describe the virtual "
    "machine, not a physical Mac."
)
STOPPED: Final = "Stopped. Nothing was saved."
CLEAR_LINE: Final = re.compile(r"S5 /usr/bin/sudo -k: .*")
CANCELLED_LINE: Final = re.compile(r"S4n? /usr/bin/sudo .*: cancelled, [0-9]+ ms, ([a-z_]+)")
PROMPT: Final = "Your Mac password, for the two steps above:"
# --debug's lines print S2's, S3's and S4's templates, which carry the prompt quoted after
# -p; sudo prints it bare.
_QUOTED_PROMPT: Final = f'-p "{PROMPT} "'
_CHIP: Final = re.compile(r" +(measured|reported|derived)$")

# Five samples one second apart take five seconds, so a power sample gone well before then
# was stopped; and for the tool, which runs as the user, only sudo's relay can stop a
# process running as root.
SAMPLES_S: Final = 5.0
EARLY_S: Final = SAMPLES_S - 0.5
POLL_S: Final = 0.1
RUN_S: Final = 480.0  # far past a run on a runner, well short of the job's timeout
ZOMBIE: Final = "<defunct>"  # how ps names a process that ended and was not collected yet


class Child(Protocol):
    """The started tool, as subprocess.Popen and Terminal both give it."""

    @property
    def pid(self) -> int: ...
    def poll(self) -> int | None: ...
    def kill(self) -> None: ...


# --- the process listings ------------------------------------------------------------------


@dataclass(frozen=True)
class Process:
    """One process as ps shows it: its IDs, its effective user ID, when it started, and the
    basename of its command."""

    pid: int
    ppid: int
    uid: int
    started: str
    name: str

    @property
    def key(self) -> tuple[int, str]:
        """The process ID and start time, which tell a process from a later one with its ID."""
        return self.pid, self.started


def _listed(selection: Sequence[str], *, check: bool) -> dict[int, Process]:
    """The processes ps selects, by ID, from the columns P1 reads (Decision 2), as the runner
    user and in the fixed locale, where lstart is always five words."""
    listed = subprocess.run(
        ["/bin/ps", *selection, "-o", "pid=,ppid=,uid=,lstart=,comm="],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        errors="replace",
        env=ENVIRONMENT,
        timeout=10,
        check=check,
    )
    found = {}
    for line in listed.stdout.split("\n"):
        words = line.split(maxsplit=8)
        if len(words) == 9 and all(word.lstrip("-").isdigit() for word in words[:3]):
            pid, ppid, uid = (int(word) for word in words[:3])
            name = words[8].rstrip().rsplit("/", 1)[-1]
            found[pid] = Process(pid, ppid, uid, " ".join(words[3:8]), name)
    return found


def processes() -> dict[int, Process]:
    """Every process now, by ID."""
    return _listed(["-ax"], check=True)


def running(rows: Mapping[int, Process], key: tuple[int, str]) -> Process | None:
    """That very process, if the listing shows it still running."""
    row = rows.get(key[0])
    return row if row is not None and row.key == key and row.name != ZOMBIE else None


def elevated(rows: Mapping[int, Process], top: int) -> list[tuple[int, Process, int]]:
    """Every process under ``top``'s sudo, with its level and the level-0 process's ID.

    The sudo the tool spawns is level 0, as the spec numbers it; where sudo executes a
    payload directly, that same process shows as sandbox-exec or the payload, so any of the
    four subtree names at level 0 counts.
    """
    children: dict[int, list[Process]] = {}
    for row in rows.values():
        children.setdefault(row.ppid, []).append(row)
    found = []
    for spawned in children.get(top, []):
        if spawned.name not in SUBTREE:
            continue
        level, current = 0, [spawned]
        while current and level <= 8:  # a listing is never a cycle; this bounds it anyway
            found.extend((level, row, spawned.pid) for row in current)
            current = [child for row in current for child in children.get(row.pid, [])]
            level += 1
    return found


def arguments(pid: int) -> str | None:
    """A process's arguments as ps prints them, joined by single spaces; None once it ended."""
    listed = subprocess.run(
        ["/bin/ps", "-ww", "-o", "command=", "-p", str(pid)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        errors="replace",
        env=ENVIRONMENT,
        timeout=10,
    )
    return listed.stdout.rstrip("\n") or None


def parsed_in_place(argv: Sequence[str]) -> str:
    """``argv`` as ps prints it once powermetrics has read its options. powermetrics cuts
    its --samplers list at each comma in its own argument memory, and ps prints as many
    strings as the process started with, so it shows each sampler as an argument of its own
    and drops as many from the end as the cuts added (the first live run, 2026-09-29: every
    image showed it)."""
    cut = [part for argument in argv for part in argument.split(",")]
    return " ".join(cut[: len(argv)])


@functools.cache
def _sandbox_check() -> Callable[[int, bytes | None, int], int]:
    library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    check = library.sandbox_check
    check.restype = ctypes.c_int
    check.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
    return check


def sandboxed(process: Process) -> bool | None:
    """Whether the kernel says ``process`` runs in a sandbox: libSystem's sandbox_check with no
    operation, which the runner user may ask of any process, root's included. It answers 1
    for a sandboxed process and 0 for one that is not, but 1 too for a process that has
    ended, a zombie included. So an answer counts only when a listing right after it still
    shows that very process running; otherwise, or for any other answer, this is None."""
    answer = _sandbox_check()(process.pid, None, 0)
    still = running(_listed(["-p", str(process.pid)], check=False), process.key)
    return answer == 1 if answer in (0, 1) and still is not None else None


def sudo_version() -> tuple[int, int, int, int]:
    """sudo's version, from the first line `/usr/bin/sudo -V` prints, which needs no
    authorization. Another exit code, or a first line in any other shape, fails the check
    that asked, and the failure gives the exit code and that line."""
    shown = subprocess.run(
        ["/usr/bin/sudo", "-V"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        errors="replace",
        env=ENVIRONMENT,
        timeout=30,
    )
    first = shown.stdout.split("\n", 1)[0]
    found = SUDO_VERSION.fullmatch(first)
    assert shown.returncode == 0 and found is not None, (
        "expected `sudo -V` to exit 0 and print its version first, as in 'Sudo version "
        f"1.9.13p2'; it exited {shown.returncode}, and its first line was {first!r}"
    )
    major, minor, patch, level = found.groups()
    return int(major), int(minor), int(patch), int(level or 0)


def spelled(version: tuple[int, int, int, int]) -> str:
    """A sudo version as sudo prints it, such as 1.9.13p2."""
    major, minor, patch, level = version
    return f"{major}.{minor}.{patch}" + (f"p{level}" if level else "")


@dataclass
class Watch:
    """What the listings saw of the administrator reads while one run lasted.

    ``seen`` holds every process under a sudo the tool spawned, by ID and start time, with
    each (level, user ID, basename) a listing showed it with. ``power`` is the power
    sample's payload as first seen, ``chain`` the processes from level 0 down to it, and
    ``absent_since`` the start of the last listing that did not show it, so it started
    later. ``gone_at`` is the end of the first listing that no longer showed it, and
    ``left`` what was still running once the tool had exited.

    In a run that is not stopped, the kernel is asked whether each payload it shows runs
    sandboxed, at its first sighting: ``power_sandboxed`` for the power sample,
    ``sudo_sandboxed`` for its level-0 sudo at that moment, which runs outside the profile
    and so shows the answer tells the two apart, and ``count_sandboxed`` for each sqlite3
    caught. None is an answer that could not count (see ``sandboxed``).
    """

    seen: dict[tuple[int, str], set[tuple[int, int, str]]] = field(default_factory=dict)
    power: Process | None = None
    chain: tuple[Process, ...] = ()
    sudo_arguments: str | None = None
    power_arguments: str | None = None
    power_sandboxed: bool | None = None
    sudo_sandboxed: bool | None = None
    count_sandboxed: dict[tuple[int, str], bool | None] = field(default_factory=dict)
    absent_since: float | None = None
    gone_at: float | None = None
    left: tuple[Process, ...] = ()

    def shapes(self) -> list[tuple[int, str]]:
        """Each (level, basename) the listings showed, once, for the log."""
        return sorted({(level, name) for found in self.seen.values() for level, _, name in found})

    def note_gone(self, rows: Mapping[int, Process]) -> None:
        """The first listing that no longer shows the power sample's payload marks its end."""
        if (
            self.power is not None
            and self.gone_at is None
            and running(rows, self.power.key) is None
        ):
            self.gone_at = time.monotonic()


def _chain(rows: Mapping[int, Process], process: Process, top: int) -> tuple[Process, ...]:
    found = [process]
    while found[-1].pid != top and found[-1].ppid in rows and len(found) <= 8:
        found.append(rows[found[-1].ppid])
    return tuple(reversed(found))


def watch(
    child: Child, *, started: float, stop: bool, pump: Callable[[], object] = lambda: None
) -> Watch:
    """List the processes every POLL_S until ``child`` ends, keeping what ran under its sudo.

    The first time the power sample's payload shows, the tool gets SIGTERM at once with
    ``stop``; without, the kernel is asked whether it and its sudo run sandboxed, and their
    arguments are read, and so is the answer for each sqlite3 caught. ``pump`` runs
    between listings (a terminal's output is read there). A tool still running after RUN_S
    is killed, and the watch fails.
    """
    found = Watch()
    before = started  # the payload cannot have started before the tool did
    while child.poll() is None:
        begin = time.monotonic()
        rows = processes()
        for level, process, top in elevated(rows, child.pid):
            if process.name == ZOMBIE:
                continue
            found.seen.setdefault(process.key, set()).add((level, process.uid, process.name))
            if process.name == "sqlite3" and not stop and process.key not in found.count_sandboxed:
                found.count_sandboxed[process.key] = sandboxed(process)
            if process.name == "powermetrics" and found.power is None:
                found.power, found.absent_since = process, before
                found.chain = _chain(rows, process, top)
                if stop:
                    os.kill(child.pid, signal.SIGTERM)
                else:
                    found.power_sandboxed = sandboxed(process)
                    sudo = rows[top] if rows[top].name == "sudo" else None
                    found.sudo_sandboxed = None if sudo is None else sandboxed(sudo)
                    found.sudo_arguments = arguments(top)
                    found.power_arguments = arguments(process.pid)
        found.note_gone(rows)
        before = begin
        pump()
        if time.monotonic() - started > RUN_S:
            child.kill()
            raise AssertionError(f"expected voltry-mac to end within {RUN_S:.0f} s; it was killed")
        time.sleep(POLL_S)
    rows = processes()
    found.note_gone(rows)
    found.left = tuple(row for key in found.seen if (row := running(rows, key)) is not None)
    return found


# --- the folders a payload could write in --------------------------------------------------


@dataclass(frozen=True)
class Listing:
    """A folder's names, or the state that kept them from being read: ``absent`` or
    ``unlisted``."""

    state: str
    names: frozenset[str] = frozenset()


def store_listing() -> Listing:
    """The ledger store's folder, listed as its service account through sudo, since the
    runner user cannot list it ("What discovery added": drwxr-x---, owned by that account)."""
    listed = subprocess.run(
        ["/usr/bin/sudo", "-n", "-u", SERVICE_ACCOUNT, "/bin/ls", "-1A", STORE_FOLDER],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        errors="replace",
        env=ENVIRONMENT,
        timeout=60,
    )
    if listed.returncode == 0:
        return Listing("listed", frozenset(name for name in listed.stdout.split("\n") if name))
    if "No such file or directory" in listed.stderr:
        return Listing("absent")
    return Listing("unlisted")


def names(path: Path) -> tuple[str, ...]:
    """The names in a folder of the runner's own, sorted."""
    return tuple(sorted(entry.name for entry in path.iterdir()))


# --- why a count did not parse ---------------------------------------------------------------

# S3's store, as its template names it ("Command allow-list").
LEDGER_URI: Final = f"file:{STORE_FOLDER}/memory_errors.db?readonly_shm=1"
_AS_ACCOUNT: Final = ("/usr/bin/sudo", "-u", SERVICE_ACCOUNT, "-H", "-n", "--")
_AS_ROOT: Final = ("/usr/bin/sudo", "-H", "-n", "--")
_IN_PROFILE: Final = ("/usr/bin/sandbox-exec", "-p", PROFILE)
_TABLES: Final = "SELECT type, name FROM sqlite_master ORDER BY name;"
# How sqlite3's and sandbox-exec's own error lines start.
_OWN_WORDS: Final = ("Error: ", "Parse error", "Runtime error", "sandbox-exec: ")


def _said(line: str) -> str:
    """A stderr line for the diagnosis: sqlite3's and sandbox-exec's own error lines as they
    are, and any other line as its length, since sudo's lines can name the account and the
    host."""
    if line.startswith(_OWN_WORDS):
        return line[:300]
    return f"a line of {len(line)} characters"


def _tried(label: str, argv: Sequence[str], *, shown: bool = False) -> str:
    """One try for the diagnosis: its exit and the first lines of its stderr, and its
    stdout only where ``shown``."""
    ran = subprocess.run(
        list(argv),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        errors="replace",
        env=ENVIRONMENT,
        timeout=60,
    )
    said = [_said(line) for line in ran.stderr.splitlines()[:6]]
    printed = f"; stdout {ran.stdout.strip()[:600]!r}" if shown else ""
    return f"{label}: exit {ran.returncode}; stderr {said}{printed}"


def count_diagnosis() -> list[str]:
    """Why S3n did not parse, for a failed check's log: S3n's own argv run once more, then
    without the profile, then as root in it, then the profile alone as the service account,
    each with its exit and the first lines of its stderr; then the store's tables by type
    and name, sqlite3's version and the store's folder. stderr holds the words of sudo,
    sandbox-exec or sqlite3, never a ledger value, and the tables' names are the store's
    shape, not its contents, so this prints nothing a report would."""
    query = (*SQLITE3, LEDGER_URI, LEDGER_QUERY)
    tables = (*_AS_ACCOUNT, "/usr/bin/sqlite3", "-readonly", "-json", LEDGER_URI, _TABLES)
    return [
        _tried("S3n as the tool runs it", (*_AS_ACCOUNT, *_IN_PROFILE, *query)),
        _tried("S3n without the profile", (*_AS_ACCOUNT, *query)),
        _tried("S3n as root, in the profile", (*_AS_ROOT, *_IN_PROFILE, *query)),
        _tried("the profile alone, as the account", (*_AS_ACCOUNT, *_IN_PROFILE, "/usr/bin/true")),
        _tried("the store's tables", tables, shown=True),
        _tried("sqlite3's version", ("/usr/bin/sqlite3", "-version"), shown=True),
        f"the store's folder, listed as the account: {store_listing()}",
    ]


# --- the runs ------------------------------------------------------------------------------


@dataclass(frozen=True)
class Run:
    """One run of the tool: its exit code, what it printed, its output folder and the names
    in it, its report, what the listings saw, and the names left in its working folder.
    The shared run also lists the store's folder before and after it."""

    code: int
    stdout: str
    stderr: str
    output: Path
    files: tuple[str, ...]
    report: dict[str, Any] | None
    watched: Watch
    work: tuple[str, ...]
    store_before: Listing | None = None
    store_after: Listing | None = None


def _folders(root: Path) -> tuple[Path, Path]:
    """A working folder any account could write in, so a payload writing by a relative path
    would have left its file there, and an empty output folder."""
    work, output = root / "cwd", root / "report"
    work.mkdir()
    work.chmod(0o777)
    output.mkdir()
    return work, output


def _report(output: Path) -> dict[str, Any] | None:
    saved = sorted(output.glob("*.json"))
    return json.loads(saved[0].read_text(encoding="utf-8")) if len(saved) == 1 else None


def collect(root: Path) -> Run:
    """The run the checks share: ``voltry-mac --yes --json --no-open --output <folder>``,
    with no terminal, so the elevated path takes S2n to S4n (Decision 2)."""
    work, output = _folders(root)
    before = store_listing()
    started = time.monotonic()
    out, err = root / "stdout.txt", root / "stderr.txt"
    with (
        out.open("wb") as stdout,
        err.open("wb") as stderr,
        subprocess.Popen(
            [str(CLI), "--yes", "--json", "--no-open", "--output", str(output)],
            cwd=work,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
        ) as child,
    ):
        watched = watch(child, started=started, stop=False)
    return Run(
        code=child.returncode,
        stdout=out.read_text(encoding="utf-8", errors="replace"),
        stderr=err.read_text(encoding="utf-8", errors="replace"),
        output=output,
        files=names(output),
        report=_report(output),
        watched=watched,
        work=names(work),
        store_before=before,
        store_after=store_listing(),
    )


class Terminal:
    """The tool on a pseudo-terminal that is its controlling terminal, as a Terminal window
    starts it. With a terminal, sudo 1.9.14 and later run each payload behind a monitor
    process; an older sudo, 1.9.13p2 on macOS 15.0 to 15.6 and 26.0, runs it as its own
    child (Decision 2, "Stopping a payload"; change record 12). What the tool prints is read
    as it comes, so it never blocks on a full terminal."""

    def __init__(self, argv: Sequence[str], cwd: Path) -> None:
        pid, descriptor = pty.fork()
        if pid == 0:  # the child becomes the tool, or ends at once
            try:
                os.chdir(cwd)
                os.execv(argv[0], list(argv))  # noqa: S606 - the installed tool's own argv
            finally:
                os._exit(127)
        self._pid, self._descriptor = pid, descriptor
        self._read = bytearray()
        self.returncode: int | None = None
        os.set_blocking(descriptor, False)

    @property
    def pid(self) -> int:
        return self._pid

    def pump(self) -> bool:
        """Read what the tool has printed so far; False once the other side is closed."""
        while True:
            try:
                chunk = os.read(self._descriptor, 65536)
            except BlockingIOError:
                return True
            except OSError:  # EIO: every process holding the terminal has ended
                return False
            if not chunk:
                return False
            self._read.extend(chunk)

    def poll(self) -> int | None:
        if self.returncode is None:
            pid, status = os.waitpid(self._pid, os.WNOHANG)
            if pid:
                self.returncode = os.waitstatus_to_exitcode(status)
        return self.returncode

    def kill(self) -> None:
        if self.poll() is None:
            os.kill(self._pid, signal.SIGKILL)

    def close(self) -> str:
        """Wait for the tool, read the rest and let the terminal go; what it printed."""
        deadline = time.monotonic() + 30
        while self.poll() is None and time.monotonic() < deadline:
            self.pump()
            time.sleep(POLL_S)
        self.kill()
        while self.poll() is None:
            time.sleep(POLL_S)
        deadline = time.monotonic() + 5
        while self.pump() and time.monotonic() < deadline:  # what it wrote as it ended
            time.sleep(POLL_S)
        os.close(self._descriptor)
        return self._read.decode("utf-8", errors="replace").replace("\r\n", "\n")


def stop_power_sample(root: Path, *, terminal: bool) -> Run:
    """A run sent SIGTERM as soon as its power sample shows, with --debug so its lines name
    the final clear. With ``terminal`` it runs on a pseudo-terminal of its own (S2 to S4,
    behind sudo's monitor where sudo runs one, from 1.9.14); without, as in CI (S2n to
    S4n)."""
    work, output = _folders(root)
    argv = [str(CLI), "--yes", "--json", "--no-open", "--debug", "--output", str(output)]
    started = time.monotonic()
    if terminal:
        tool = Terminal(argv, work)
        try:
            watched = watch(tool, started=started, stop=True, pump=tool.pump)
        finally:
            printed = tool.close()
        code, stdout, stderr = tool.returncode, printed, printed
    else:
        err = root / "stderr.txt"
        with (
            err.open("wb") as stderr_file,
            subprocess.Popen(
                argv,
                cwd=work,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=stderr_file,
            ) as child,
        ):
            watched = watch(child, started=started, stop=True)
        code, stdout = child.returncode, ""
        stderr = err.read_text(encoding="utf-8", errors="replace")
    assert code is not None  # both ways above wait for the tool to end
    return Run(code, stdout, stderr, output, names(output), _report(output), watched, names(work))


# --- reading a report ----------------------------------------------------------------------


def surface(report: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    (found,) = [item for item in report["surfaces"] if item["key"] == key]
    return found


def unexpected(report: Mapping[str, Any]) -> list[str]:
    """The unexpected reasons (Decision 6) on any surface or value, counted afresh."""
    codes = set()
    for item in report["surfaces"]:
        if item["availability"] == "unavailable":
            codes.add(item["reason"])
        for entry in item["values"].values():
            if entry["availability"] == "unavailable":
                codes.add(entry["reason"])
    return sorted(codes & {"source_absent", "source_changed", "timeout", "tool_error"})


def expected_exit(report: Mapping[str, Any]) -> int:
    """The exit code the spec gives a saved report ("Exit codes, in one place"): 6 when the
    final clear failed, else 1 for an unexpected reason anywhere or a stop no listing
    verified, else 0."""
    elevation = report["elevation"]
    if elevation["cleared"] == "failed":
        return 6
    unverified = any(
        elevation[step]["cleanup"] in ("survivor", "listing_failed") for step in ("count", "power")
    )
    return 1 if unexpected(report) or unverified else 0


def smart_reasons(report: Mapping[str, Any]) -> frozenset[str]:
    """The reasons the two SMART surfaces may carry for what the report shows: Decision 8's
    storage dependency table, then C28's outcome table. A C28 that ran cleanly narrows
    that table to rows 8 to 11: no controller lists the startup disk (source_absent), a
    controller the tool cannot use (unsupported), or its read failing (tool_error)."""
    startup = surface(report, "startup_disk")
    if startup["availability"] == "unavailable":
        return frozenset({startup["reason"]})
    whole = startup["values"]["whole_disk"]
    if whole["availability"] == "unavailable":
        return frozenset({whole["reason"]})
    (c28,) = [record for record in report["commands"] if record["id"] == "C28"]
    if c28["failed_runs"]:
        return frozenset({"tool_error", "source_changed", "timeout"})
    return frozenset({"source_absent", "unsupported", "tool_error"})


def flat(text: str) -> str:
    """Printed text as one line of words, each label chip at a line's end set aside, so a
    sentence reads whole however the terminal summary wrapped it."""
    return " ".join(" ".join(_CHIP.sub("", line) for line in text.split("\n")).split())


def lines(text: str) -> list[str]:
    return [line.rstrip() for line in text.split("\n")]


def prompted(printed: str) -> bool:
    """Whether sudo's prompt shows in what the tool printed on its terminal, apart from
    --debug's lines, which print the templates that carry it."""
    return PROMPT in printed.replace(_QUOTED_PROMPT, "")
