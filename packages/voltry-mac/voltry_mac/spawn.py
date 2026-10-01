"""The spawn chokepoint: the only module in voltry-mac that starts a process.

docs/VOLTRY_MAC_SPEC.md, "Architecture": the allow-list check before spawn, absolute
paths, no shell, a fixed minimal environment, stdout and stderr drained as they arrive,
the child stopped the moment either stream passes 4 MiB, per-command deadlines with one
of three stop sequences, a deadline that passes in the same check that collects the exit
ignored while the output cap still applies, and undecodable bytes replaced. Output goes
back to the caller in a ``Result`` and nowhere else: nothing here logs or prints.

The three stop sequences ("Time bounds"):

- user commands, X1, S1, S5, O1 and C28: SIGTERM, a 2 s grace, SIGKILL, a reap within 1 s;
- P1, one process listing: SIGKILL at its deadline and a reap within 1 s;
- S2 to S4, through the elevation broker: SIGTERM, a 3 s grace, SIGKILL, a reap within
  1 s, and when the spawned process can no longer be signalled (``EPERM``, because sudo
  executed the payload directly under another identity) the pipes close and the tool
  stops waiting, with no stop or reap promised.

A process not reaped within its sequence is abandoned rather than waited for, and its
duration ends there.
"""

from __future__ import annotations

import os
import posixpath
import selectors
import signal
import stat
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum, StrEnum
from types import MappingProxyType
from typing import Final, Literal

from voltry_mac import allowlist, tracking

ENVIRONMENT: Final[Mapping[str, str]] = MappingProxyType(
    {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "en_US.UTF-8"}
)
OUTPUT_CAP: Final = 4 * 1024 * 1024
USER_GRACE_S = 2
PAYLOAD_GRACE_S = 3
REAP_S = 1

_POLL_S: Final = 0.05
_READ_CHUNK: Final = 65536
# The sudo commands other than sudo -k (S2 to S4 and their -n forms) run only through the
# elevation broker, which keeps its own clocks and listings (board items MAC 3.7 and 3.8).
_BROKER_ONLY: Final = frozenset(
    command.id
    for command in allowlist.COMMANDS
    if command.template[0] == "/usr/bin/sudo" and command.template[1:] != ("-k",)
)
# The broker's one plain-wait sudo step: the authentication (S2, or S2n with --yes).
_AUTHENTICATE: Final = frozenset({"S2", "S2n"})
# The two payloads, whose records the broker keeps once it has judged their endings.
_PAYLOADS: Final = frozenset({"S3", "S3n", "S4", "S4n"})
# Processes whose stop sequence ended without a reap: kept, so they are not waited for and
# not dropped, and collected without waiting by collect_abandoned().
_ABANDONED: list[subprocess.Popen[bytes]] = []


class Ending(StrEnum):
    """How a command ended."""

    EXITED = "exited"
    SIGNALED = "signaled"
    DEADLINE = "deadline"
    OUTPUT_CAP = "output_cap"
    NOT_STARTED = "not_started"
    CANCELLED = "cancelled"


class Stop(Enum):
    """Which stop sequence a command gets."""

    TERM_THEN_KILL = "term_then_kill"
    KILL = "kill"
    PAYLOAD = "payload"


class Refused(Exception):
    """An argv that is not on the allow-list. Nothing was started."""


@dataclass(frozen=True)
class Result:
    """One run of one allow-listed command.

    ``returncode`` is the exit status, or minus the signal number, and ``None`` when the
    command never started or was abandoned unreaped. ``missing_executable`` separates a
    program that does not exist (``source_absent``) from one that could not start for
    another reason (``tool_error``). ``eperm`` marks a process the tool could not signal,
    as when sudo executed a payload directly under another identity. The output is kept
    out of the repr, so no log or traceback shows it.
    """

    command_id: str
    ending: Ending
    returncode: int | None
    stdout: str = field(repr=False)
    stderr: str = field(repr=False)
    duration_ms: int
    missing_executable: bool
    reaped: bool
    eperm: bool = False

    @property
    def ok(self) -> bool:
        """Exited on its own with status 0."""
        return self.ending is Ending.EXITED and self.returncode == 0


@dataclass(frozen=True)
class Stopped:
    """What a stop sequence achieved."""

    reaped: bool
    eperm: bool


@dataclass(frozen=True)
class CommandRecord:
    """The aggregate the report keeps per command ID (spec, Decision 8)."""

    id: str
    runs: int
    failed_runs: int
    duration_ms: int


# The forced endings (Decision 2): the output cap, a tracking failure, and the expiry of
# whichever clock was armed. After one latches, sudo's stderr is never read.
FORCED_ENDINGS: Final = frozenset(
    {"output_cap", "tracking_failed", "auth_failed", "launch_deadline", "runtime_deadline"}
)
CLEANUPS: Final = frozenset({"verified", "survivor", "listing_failed"})


@dataclass(frozen=True)
class PayloadRun:
    """One tracked run of a payload command (S3, S4 or an -n form), as the broker's loop
    (MAC 3.8) ends it.

    ``started`` is false when sudo could not be started at all, the ending
    ``spawn_failed``, which has no exit status and never a survivor. ``forced`` is the
    forced ending that latched, if one did; otherwise ``returncode`` is sudo's exit status,
    or minus the signal number, and decides the ending with stderr. ``cleanup`` is what the
    listing after the payload found, and ``survivors`` what it named. ``cancelled`` marks a
    run the tool stopped before its end, for the cancellation or an error, which may have
    no exit status and is never saved. The output and the survivors' process names are
    kept out of the repr, like a Result's output.
    """

    command_id: str
    started: bool
    forced: str | None
    returncode: int | None
    stdout: str = field(repr=False)
    stderr: str = field(repr=False)
    cleanup: str
    duration_ms: int
    survivors: tuple[tracking.Survivor, ...] = field(default=(), repr=False)
    cancelled: bool = False

    def __post_init__(self) -> None:
        if self.command_id not in _PAYLOADS:
            raise ValueError(f"{self.command_id} is not a payload")
        if self.cleanup not in CLEANUPS:
            raise ValueError("a payload's cleanup is verified, survivor or listing_failed")
        if type(self.duration_ms) is not int or self.duration_ms < 0:
            raise ValueError("a duration is a whole number of milliseconds, never negative")
        if type(self.started) is not bool:
            raise ValueError("started is true or false")
        if (self.cleanup == "survivor") != bool(self.survivors):
            raise ValueError("survivors are named exactly when the cleanup is survivor")
        if not self.started:
            if self.forced is not None or self.returncode is not None:
                raise ValueError("a payload that never started has no status and no ending")
            if self.cleanup == "survivor":
                raise ValueError("a payload that never started leaves no survivor")
        elif self.forced is None:
            if self.returncode is None and not self.cancelled:
                raise ValueError("a payload that ended on its own has its exit status")
        elif self.forced not in FORCED_ENDINGS:
            raise ValueError(f"{self.forced} is not a forced ending")


def _ms(seconds: float) -> int:
    return max(0, round(seconds * 1000))


def _judge(
    cap_hit: bool, exited: bool, deadline_passed: bool, cancelled: bool = False
) -> Ending | Literal["exit"] | None:
    """One pass's verdict, in the spec's order: the cap, then the exit, then a stop.

    A deadline, or a cancellation, seen in the same pass that collects the exit is
    ignored; the output cap is not.
    """
    if cap_hit:
        return Ending.OUTPUT_CAP
    if exited:
        return "exit"
    if cancelled:
        return Ending.CANCELLED
    if deadline_passed:
        return Ending.DEADLINE
    return None


def _signal(proc: subprocess.Popen[bytes], signum: int) -> bool:
    """Send one signal; ``False`` when the process may not be signalled (EPERM)."""
    try:
        proc.send_signal(signum)
    except PermissionError:
        return False
    return True


def _wait(proc: subprocess.Popen[bytes], seconds: float) -> bool:
    try:
        proc.wait(timeout=seconds)
    except subprocess.TimeoutExpired:
        return False
    return True


def _close(proc: subprocess.Popen[bytes]) -> None:
    for stream in (proc.stdout, proc.stderr):
        if stream is not None and not stream.closed:
            stream.close()


def _stop(proc: subprocess.Popen[bytes], stop: Stop, grace_s: float | None = None) -> Stopped:
    """Run one stop sequence on a started process."""
    if stop is Stop.KILL:
        if not _signal(proc, signal.SIGKILL):
            _close(proc)
            return Stopped(reaped=False, eperm=True)
        return Stopped(reaped=_wait(proc, REAP_S), eperm=False)
    if grace_s is None:
        grace_s = USER_GRACE_S if stop is Stop.TERM_THEN_KILL else PAYLOAD_GRACE_S
    if not _signal(proc, signal.SIGTERM):
        _close(proc)
        return Stopped(reaped=False, eperm=True)
    if _wait(proc, grace_s):
        return Stopped(reaped=True, eperm=False)
    if not _signal(proc, signal.SIGKILL):
        _close(proc)
        return Stopped(reaped=False, eperm=True)
    return Stopped(reaped=_wait(proc, REAP_S), eperm=False)


def _read_ready(key: selectors.SelectorKey, selector: selectors.BaseSelector, cap: int) -> bool:
    """Read what one pipe holds now; ``True`` when its stream has passed the cap."""
    buffer: bytearray = key.data
    while True:
        try:
            chunk = os.read(key.fd, _READ_CHUNK)
        except BlockingIOError:
            return False
        if not chunk:
            selector.unregister(key.fileobj)
            return False
        buffer.extend(chunk)
        if len(buffer) > cap:
            del buffer[cap:]
            return True


def _drain(selector: selectors.BaseSelector, timeout: float, cap: int) -> bool:
    """Wait up to ``timeout`` for output and read it; ``True`` when a stream passed the cap."""
    if not selector.get_map():
        if timeout > 0:
            time.sleep(timeout)
        return False
    hit = False
    for key, _ in selector.select(timeout):
        hit = _read_ready(key, selector, cap) or hit
    return hit


def _popen(argv: Sequence[str]) -> subprocess.Popen[bytes]:
    """The one way a child starts: no shell, the fixed environment, no stdin, both output
    streams on pipes, and no file of this process passed on."""
    return subprocess.Popen(  # noqa: S603 - argv comes from the allow-list, checked first
        list(argv),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=dict(ENVIRONMENT),
        close_fds=True,
        shell=False,
    )


def _execute(
    argv: Sequence[str],
    *,
    command_id: str,
    deadline_s: float,
    stop: Stop,
    cap: int = OUTPUT_CAP,
    grace_s: float | None = None,
    cancelled: Callable[[], bool] | None = None,
) -> Result:
    """Start ``argv`` and see it to its end. Private: callers go through ``Runner.run``.

    A command given ``cancelled`` starts only when its last check finds the flag false, and
    is stopped when it turns true; the one cleanup the runner starts after a cancellation,
    the final sudo -k, is given none (the GPT audit, pass 1, G1-01: a flag set just before a
    command started let it run unwatched to its end, a password prompt for its whole 180 s
    clock). A flag set in the instant between that check and the start, under about a
    millisecond, still lets the command start, and the loop's first pass stops it. The
    signals are not masked across that instant: a mask would only hold the handler back
    until the child exists, which starts all the same, and the child would keep the
    blocked mask through exec.
    Tracking's listings, which can start after the flag too (Runner), go through its own
    engine. If anything raises while the command runs (an interrupt, a bug), the child is
    killed and given its 1 s reap before the exception leaves, so no command outlives a
    run.
    """
    started = time.monotonic()
    # Before the child exists, so a run already cancelled starts nothing; a flag that turns
    # true after this check stops the child at the loop's first pass.
    if cancelled is not None and cancelled():
        return Result(command_id, Ending.CANCELLED, None, "", "", 0, False, True)
    selector = selectors.DefaultSelector()
    try:
        proc = _popen(argv)
    except OSError as problem:
        selector.close()
        elapsed = _ms(time.monotonic() - started)
        missing = isinstance(problem, FileNotFoundError)
        return Result(command_id, Ending.NOT_STARTED, None, "", "", elapsed, missing, True)

    out, err = bytearray(), bytearray()
    reaped, eperm, settled = True, False, False
    try:
        for stream, buffer in ((proc.stdout, out), (proc.stderr, err)):
            assert stream is not None  # noqa: S101 - both are pipes by construction
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, buffer)
        deadline = started + deadline_s
        while True:
            cap_hit = _drain(selector, max(0.0, min(_POLL_S, deadline - time.monotonic())), cap)
            exited = proc.poll() is not None
            if exited:
                cap_hit = _drain(selector, 0.0, cap) or cap_hit
            stop_now = cancelled is not None and cancelled()
            verdict = _judge(cap_hit, exited, time.monotonic() >= deadline, stop_now)
            if verdict is None:
                continue
            if verdict == "exit":
                ending = Ending.SIGNALED if (proc.returncode or 0) < 0 else Ending.EXITED
            else:
                ending = verdict
                if not exited:
                    stopped = _stop(proc, stop, grace_s)
                    reaped, eperm = stopped.reaped, stopped.eperm
            settled = True
            break
    finally:
        try:
            if not settled and proc.poll() is None:
                reaped = False  # until the stop proves otherwise, even if it is interrupted
                stopped = _stop(proc, Stop.KILL)
                reaped, eperm = stopped.reaped, stopped.eperm
        finally:
            selector.close()
            _close(proc)
            if not reaped:
                _ABANDONED.append(proc)
    return Result(
        command_id,
        ending,
        proc.returncode if reaped else None,
        out.decode("utf-8", errors="replace"),
        err.decode("utf-8", errors="replace"),
        _ms(time.monotonic() - started),
        False,
        reaped,
        eperm,
    )


class _Child:
    """A started payload command or listing, its two pipes read into buffers up to the cap."""

    def __init__(
        self, proc: subprocess.Popen[bytes], selector: selectors.BaseSelector, cap: int
    ) -> None:
        self.proc = proc
        self._selector = selector
        self._cap = cap
        self._out, self._err = bytearray(), bytearray()
        self.capped = False
        self.closed = False
        for stream, buffer in ((proc.stdout, self._out), (proc.stderr, self._err)):
            assert stream is not None  # noqa: S101 - both are pipes by construction
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, (self, buffer))

    @property
    def pid(self) -> int:
        return self.proc.pid

    @property
    def stdout(self) -> str:
        return self._out.decode("utf-8", errors="replace")

    @property
    def stderr(self) -> str:
        return self._err.decode("utf-8", errors="replace")

    def poll(self) -> int | None:
        return self.proc.poll()

    def signal(self, signum: int) -> bool:
        return _signal(self.proc, signum)

    def read(self, key: selectors.SelectorKey, buffer: bytearray) -> None:
        """What one pipe holds now, up to the cap; past it the pipe is still drained, and
        truncated, so the child never blocks on a full pipe."""
        while True:
            try:
                chunk = os.read(key.fd, _READ_CHUNK)
            except BlockingIOError:
                return
            if not chunk:
                self._selector.unregister(key.fileobj)
                return
            buffer.extend(chunk)
            if len(buffer) > self._cap:
                del buffer[self._cap :]
                self.capped = True
                return

    def close(self) -> None:
        self.closed = True
        for stream in (self.proc.stdout, self.proc.stderr):
            if stream is not None and not stream.closed:
                if stream in self._selector.get_map():
                    self._selector.unregister(stream)
                stream.close()


class _Engine:
    """The real processes behind tracking.track(): sudo's argv and P1's, their pipes
    drained on one selector, and the monotonic clock."""

    def __init__(self, payload: Sequence[str], listing: Sequence[str], cap: int) -> None:
        self._payload, self._listing, self._cap = list(payload), list(listing), cap
        self._selector = selectors.DefaultSelector()
        self._children: list[_Child] = []
        self._payload_child: _Child | None = None

    def now(self) -> float:
        return time.monotonic()

    def start_payload(self) -> _Child | None:
        self._payload_child = self._start(self._payload)
        return self._payload_child

    def start_listing(self) -> _Child | None:
        # A listing that is closed and reaped holds nothing more: let it go, output too.
        # The payload is never polled here: after EPERM its exit stays uncollected until
        # the final listing has run, so no other process can take its ID first.
        self._children = [
            child
            for child in self._children
            if child is self._payload_child or not child.closed or child.poll() is None
        ]
        return self._start(self._listing)

    def _start(self, argv: list[str]) -> _Child | None:
        try:
            proc = _popen(argv)
        except OSError:
            return None
        child = _Child(proc, self._selector, self._cap)
        self._children.append(child)
        return child

    def wait(
        self, *, drain: Sequence[tracking.Child], watch: tracking.Child | None, until: float
    ) -> None:
        """Read every pipe until ``watch`` has ended, what it wrote read, or ``until``."""
        while True:
            if watch is not None and watch.poll() is not None:
                self._read(0.0)
                return
            now = time.monotonic()
            if now >= until:
                return
            self._read(min(until - now, _POLL_S))

    def _read(self, timeout: float) -> None:
        if not self._selector.get_map():
            if timeout > 0:
                time.sleep(timeout)
            return
        for key, _ in self._selector.select(timeout):
            child, buffer = key.data
            child.read(key, buffer)

    def close(self) -> None:
        """Close every pipe; hold any child still running so its exit is collected later."""
        for child in self._children:
            child.close()
            if child.poll() is None and child.proc not in _ABANDONED:
                _ABANDONED.append(child.proc)
        self._selector.close()


class PayloadInterrupted(Exception):
    """An error stopped a payload command's tracking. The payload was stopped and the final
    listing taken all the same; ``run`` says what it found, and the error is the cause."""

    def __init__(self, run: PayloadRun) -> None:
        super().__init__("a payload command's tracking stopped on an unexpected error")
        self.run = run


def _payload_run(command_id: str, tracked: tracking.Tracked) -> PayloadRun:
    return PayloadRun(
        command_id,
        tracked.started,
        tracked.forced,
        tracked.returncode,
        tracked.stdout,
        tracked.stderr,
        tracked.cleanup,
        _ms(tracked.duration_s),
        tracked.survivors,
        tracked.cancelled,
    )


def collect_abandoned() -> int:
    """Collect every abandoned child that has ended, without waiting; return how many run.

    The spec's direct-execution branch: a payload the tool could not signal is still its
    child, so its exit status is collected before the tool exits if it has ended by then,
    and otherwise launchd inherits it.
    """
    for proc in list(_ABANDONED):
        if proc.poll() is not None:
            _ABANDONED.remove(proc)
    return len(_ABANDONED)


# How a forced ending reads in a --debug line; never "passed", which the copy rules keep for
# verdicts (the copy pass's review, round 2, M1).
_FORCED: Final = MappingProxyType(
    {
        Ending.DEADLINE: "ran past its deadline",
        Ending.OUTPUT_CAP: "went over the output cap",
        Ending.CANCELLED: "cancelled",
    }
)
# How a payload's forced ending reads in its --debug line: in a command's words where the two
# share one, and never as its code (the copy pass's review, round 3, n2).
PAYLOAD_FORCED: Final = MappingProxyType(
    {
        "runtime_deadline": _FORCED[Ending.DEADLINE],
        "output_cap": _FORCED[Ending.OUTPUT_CAP],
        "auth_failed": "was not authenticated in time",
        "launch_deadline": "did not start in time",
        "tracking_failed": "was stopped because its processes could not be tracked",
    }
)


def debug_line(result: Result) -> str:
    """One ``--debug`` line: the ID, its fixed template, how it ended and how long it took.

    Never the command's output, and never the interpreter path or the report's path: the
    template shows both as placeholders.
    """
    template = allowlist.display(allowlist.BY_ID[result.command_id].template)
    code = result.returncode
    if result.ending is Ending.EXITED:
        how = f"exit {code}"
    elif result.ending is Ending.SIGNALED:
        how = f"ended on signal {-(code or 0)}"
    elif result.ending is Ending.NOT_STARTED:
        how = "could not start"
    else:
        how = _FORCED[result.ending]
        if result.eperm:
            how += ", could not be signalled"
        elif not result.reaped:
            how += ", not reaped"
        elif code is not None:
            how += f", then exit {code}" if code >= 0 else f", then signal {-code}"
    return f"{result.command_id} {template}: {how}, {result.duration_ms} ms"


class _NoInterpreter(Exception):
    """C28 has no usable interpreter: the child cannot be started (its table's row 1)."""


def _publication_problem(path: object) -> tuple[str | None, os.stat_result | None]:
    """Why ``path`` cannot be the report O1 opens, or ``None``, with what lstat found.

    The output writer publishes the report with mode 0600 under one name, so a file
    readable by others or with a second name (a hard link to another file) is refused.
    """
    if not isinstance(path, str) or not path.startswith("/"):
        return "the published report must be named by an absolute path", None
    try:
        path.encode("utf-8")
    except UnicodeEncodeError:
        return "the published report's path is not valid text", None
    if "\x00" in path or path.startswith("//") or posixpath.normpath(path) != path:
        return "the published report's path is not in normal form", None
    if not path.endswith(".pdf"):
        return "only the PDF report is opened", None
    try:
        info = os.lstat(path)
    except OSError:
        return "nothing is at the published report's path", None
    if not stat.S_ISREG(info.st_mode):
        return "the published report is not a regular file", None
    if info.st_uid != os.getuid():
        return "the published report belongs to another account", None
    if stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
        return "the published report is not as the writer leaves it (mode 0600, one name)", None
    return None, info


class Runner:
    """Runs allow-listed commands one at a time and keeps their records.

    Every argv is resolved from the frozen allow-list, matched against it exactly and
    scanned for forbidden shapes before anything starts; a command that fails any of the
    three raises ``Refused`` and starts nothing. The one exception is C28 with no usable
    interpreter, which its outcome table makes a failed run: it starts nothing and is
    recorded. O1, the open, takes no path from its caller: it opens the one file
    ``published`` was given, once, only while that name still leads to the same file,
    and like the spec it leaves no command record. ``published`` holds the file open
    until O1 runs, so its inode stays in use and no new file can take its identity;
    ``close`` lets go of a report that is never opened, and so does leaving a ``with``
    block. O1 needs that hold: its first attempt, refused or not, uses it up, and after
    ``close`` it refuses. Once ``cancelled`` is true no command starts but the cleanup: S5,
    the final sudo -k, which it never stops, and the listings tracking takes, through its
    own engine, to stop a payload the flag cut short: the one a pass already had due when
    the flag turned true, and the last one, after the stop (the review of #326, round 2,
    n5). The one exception is a command whose last check of the flag came in the instant,
    under about a millisecond, before it turned true: that command starts, and its loop's
    first pass stops it, as it stops any command running when the flag turns true.
    """

    def __init__(
        self,
        *,
        on_result: Callable[[Result], None] | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> None:
        self._on_result = on_result
        self._cancelled = cancelled
        self._counts: dict[str, list[int]] = {}
        self._published: str | None = None
        self._identity: tuple[int, int] | None = None
        self._pin: int | None = None
        self._opened = False

    def published(self, path: str) -> None:
        """Name the report file the output writer just published; only O1 uses it."""
        if self._published is not None:
            raise Refused("a report was already published in this run")
        problem, info = _publication_problem(path)
        if problem is not None or info is None:
            raise Refused(problem or "the published report cannot be read")
        try:
            pin = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            raise Refused("the published report cannot be read") from None
        held = os.fstat(pin)
        if (held.st_dev, held.st_ino) != (info.st_dev, info.st_ino):
            os.close(pin)
            raise Refused("the published report changed while it was checked")
        self._published, self._identity, self._pin = path, (held.st_dev, held.st_ino), pin

    def close(self) -> None:
        """Let go of the published report; O1 does this itself once it has run."""
        pin, self._pin = self._pin, None
        if pin is not None:
            os.close(pin)

    def __enter__(self) -> Runner:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def run(self, command_id: str, *, failed: Callable[[Result], bool] | None = None) -> Result:
        """Run one command; ``failed`` overrides the default rule (not ``Result.ok``)."""
        if command_id == "O1":
            if self._published is None:
                raise Refused("O1 opens only the report just published, and none was")
            if self._opened:
                raise Refused("O1 opens the report once")
            self._opened = True
            if self._pin is None:
                raise Refused("the published report was let go before O1")
        try:
            if command_id == "O1":
                problem, info = _publication_problem(self._published)
                if (
                    problem is not None
                    or info is None
                    or ((info.st_dev, info.st_ino) != self._identity)
                ):
                    raise Refused("the published report changed after it was published")
            try:
                argv = self._checked_argv(command_id)
            except _NoInterpreter:
                result = Result(command_id, Ending.NOT_STARTED, None, "", "", 0, False, True)
            else:
                command = allowlist.BY_ID[command_id]
                result = _execute(
                    argv,
                    command_id=command_id,
                    deadline_s=command.timeout_s,
                    stop=Stop.KILL if command_id == "P1" else Stop.TERM_THEN_KILL,
                    # The final clear is cleanup: a Ctrl-C while it runs must not stop it.
                    cancelled=None if command_id == "S5" else self._cancelled,
                )
        finally:
            if command_id == "O1":
                self.close()
        if command_id != "O1":
            self._record(result, failed)
        if self._on_result is not None:
            self._on_result(result)
        return result

    def authenticate(
        self, command_id: str, *, failed: Callable[[Result], bool] | None = None
    ) -> Result:
        """S2 or S2n, sudo -v: the one password prompt, for the elevation broker only.

        A plain wait under the 180 s authentication clock (Decision 2), stopped by the
        payload sequence when the clock runs out or the run is cancelled at the prompt;
        the broker classifies what it returns. ``failed`` is the broker's own judgment.
        """
        if command_id not in _AUTHENTICATE:
            raise Refused(f"{command_id} is not the authentication step")
        argv = self._checked_argv(command_id, broker=True)
        result = _execute(
            argv,
            command_id=command_id,
            deadline_s=allowlist.BY_ID[command_id].timeout_s,
            stop=Stop.PAYLOAD,
            cancelled=self._cancelled,
        )
        self._record(result, failed)
        if self._on_result is not None:
            self._on_result(result)
        return result

    def note_payload(self, command_id: str, *, failed: bool, duration_ms: int) -> None:
        """Record S3 or S4 (or an -n form) once the broker has judged its ending.

        The payload's run is tracked by the broker's loop (MAC 3.8); whether it failed
        depends on its output, which only the broker reads, so its record comes after.
        """
        if command_id not in _PAYLOADS:
            raise Refused(f"{command_id} is not a payload")
        if type(duration_ms) is not int or duration_ms < 0:
            raise ValueError("a duration is a whole number of milliseconds, never negative")
        counts = self._counts.setdefault(command_id, [0, 0, 0])
        counts[0] += 1
        counts[1] += int(failed)
        counts[2] += duration_ms

    def payload(self, command_id: str, *, uid: int) -> PayloadRun:
        """S3 or S4 (or an -n form) under tracking.track(): the listings, the three clocks,
        the latch, the stop sequence and the final listing, which decides the cleanup.

        ``uid`` is the account the payload runs as (the service account's for the count,
        0 for the power sample), which with its name identifies it. Every listing goes into
        P1's record; the payload's own record waits for the broker's judgment
        (``note_payload``). A child still running at the end is held, so its exit is
        collected without blocking later.
        """
        if command_id not in _PAYLOADS:
            raise Refused(f"{command_id} is not a payload")
        argv = self._checked_argv(command_id, broker=True)
        engine = _Engine(argv, self._checked_argv("P1"), OUTPUT_CAP)
        try:
            tracked = tracking.track(
                engine,
                payload=tracking.Payload(uid=uid, name=tracking.PAYLOAD_NAMES[command_id]),
                runtime_s=tracking.RUNTIME_S[command_id],
                cancelled=self._cancelled or (lambda: False),
            )
        except tracking.Unfinished as unfinished:
            self._listed(unfinished.tracked)
            run = _payload_run(command_id, unfinished.tracked)
            raise PayloadInterrupted(run) from unfinished.__cause__
        finally:
            engine.close()
        self._listed(tracked)
        return _payload_run(command_id, tracked)

    def _listed(self, tracked: tracking.Tracked) -> None:
        """Every listing of one payload command into P1's record; a payload the flag kept
        from starting took none, and leaves no record (the review of #326, round 1, M6)."""
        if not tracked.listings:
            return
        counts = self._counts.setdefault("P1", [0, 0, 0])
        for took, failed in tracked.listings:
            counts[0] += 1
            counts[1] += int(failed)
            counts[2] += _ms(took)

    def _record(self, result: Result, failed: Callable[[Result], bool] | None) -> None:
        # Judged first, so a rule that raises leaves no half-counted record.
        was_failed = bool(failed(result)) if failed is not None else not result.ok
        counts = self._counts.setdefault(result.command_id, [0, 0, 0])
        counts[0] += 1
        counts[1] += int(was_failed)
        counts[2] += result.duration_ms

    def records(self) -> list[CommandRecord]:
        """One record per command that ran, in allow-list order; O1 never has one."""
        order = {command.id: index for index, command in enumerate(allowlist.COMMANDS)}
        return [
            CommandRecord(command_id, runs, failed_runs, duration_ms)
            for command_id, (runs, failed_runs, duration_ms) in sorted(
                self._counts.items(), key=lambda item: order[item[0]]
            )
        ]

    def _checked_argv(self, command_id: str, *, broker: bool = False) -> list[str]:
        if command_id in _BROKER_ONLY and not broker:
            raise Refused(f"{command_id} runs only through the elevation broker")
        try:
            argv = allowlist.resolve(command_id, published_path=self._published)
        except KeyError:
            raise Refused(f"{command_id} is not on the allow-list") from None
        except ValueError as problem:
            if command_id == "C28":
                raise _NoInterpreter from None
            raise Refused(str(problem)) from None
        if allowlist.match(argv, published_path=self._published) is None:
            raise Refused(f"{command_id} does not match the allow-list")
        if allowlist.forbidden_shape(argv, published_path=self._published) is not None:
            raise Refused(f"{command_id} has a forbidden shape")
        return list(argv)
