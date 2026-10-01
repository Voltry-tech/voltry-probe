"""Tracking a payload command: what the listings saw, the clocks, the latch and the notes.

docs/VOLTRY_MAC_SPEC.md, Decision 2, "Stopping a payload". While S3 or S4 runs, P1 lists the
processes. The spawned process is recorded at level 0 with every identity it takes (its
numeric user ID and basename), and so is each descendant down to three levels, whatever
its user or name; a process first seen deeper is not recorded, and one there that takes
the payload's identity is a tracking failure. ps shows the setuid sudo as user 0 from its
first listing, so a user ID never marks a phase on its own. Three clocks run one after
another, each armed when a pass observes the start of its phase: authentication from the
spawn until the first sign that sudo authenticated, launch from that sign until the
payload is identified, and runtime from then until the spawned process exits. Everything
here is pure: the loop that runs the listings, the pipes and the stops is apart.
"""

from __future__ import annotations

import contextlib
import signal
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Final, Protocol

from voltry_mac import listing, phrases
from voltry_mac.listing import Process

AUTH_S: Final = 180.0
LAUNCH_S: Final = 5.0
RUNTIME_S: Final = MappingProxyType({"S3": 10.0, "S3n": 10.0, "S4": 20.0, "S4n": 20.0})
# The basename that identifies each payload command's payload.
PAYLOAD_NAMES: Final = MappingProxyType(
    {"S3": "sqlite3", "S3n": "sqlite3", "S4": "powermetrics", "S4n": "powermetrics"}
)
POLL_S: Final = 0.2  # a listing starts every 200 ms, or when the last one returns if later
LISTING_S: Final = 2.0  # a listing's own deadline; one that misses it is a failed listing
REAP_S: Final = 1.0
TERM_WAIT_S: Final = 3.0  # after SIGTERM, before SIGKILL
LEVELS: Final = 3
# The only processes the subtree can legitimately hold, and so the only names a note prints.
SUBTREE_NAMES: Final = ("sudo", "sandbox-exec", "sqlite3", "powermetrics")
# How macOS's ps names a process that has ended and whose exit is not collected yet.
ZOMBIE: Final = "<defunct>"
_ENDINGS: Final = MappingProxyType(
    {"auth": "auth_failed", "launch": "launch_deadline", "runtime": "runtime_deadline"}
)


@dataclass(frozen=True)
class Payload:
    """The identity that identifies the payload: the account it runs as and its basename."""

    uid: int
    name: str


@dataclass(frozen=True)
class Record:
    """A process the listings saw in the subtree: its ID, its start time, and every user ID
    and basename it was seen with. The start time tells a reused ID from the same process."""

    pid: int
    started: str
    identities: frozenset[tuple[int, str]]


class Tracker:
    """What the listings have shown of one payload command, and its armed clock."""

    def __init__(self, *, spawned: int, payload: Payload, runtime_s: float, now: float) -> None:
        self._spawned = spawned
        self._payload = payload
        self._runtime_s = runtime_s
        self._started: str | None = None
        self._seen: dict[tuple[int, str], set[tuple[int, str]]] = {}
        self._seen_as_sudo = False
        self.clock = "auth"
        self.deadline = now + AUTH_S
        self.failed = False

    @property
    def ending(self) -> str:
        """The forced ending the armed clock gives when it expires."""
        return _ENDINGS[self.clock]

    def expired(self, now: float) -> bool:
        return now >= self.deadline

    @property
    def records(self) -> tuple[Record, ...]:
        return tuple(
            Record(pid, started, frozenset(identities))
            for (pid, started), identities in self._seen.items()
        )

    def apply(self, rows: Sequence[Process] | None, now: float) -> None:
        """Apply one listing at the pass's time ``now``; ``None`` is a failed listing."""
        if rows is None:
            self.failed = True
            return
        root = next((row for row in rows if row.pid == self._spawned), None)
        if root is None or (self._started is not None and root.started != self._started):
            return  # the spawned process is gone, its exit collected apart, or its ID reused
        self._started = root.started
        children: dict[int, list[Process]] = {}
        for row in rows:
            children.setdefault(row.ppid, []).append(row)
        sign = identified = False
        level, current, walked = 0, [root], set()
        while current:
            below: list[Process] = []
            for row in current:
                if row.pid in walked:
                    continue  # a listing is never a cycle, but this walk ends regardless
                walked.add(row.pid)
                below.extend(children.get(row.pid, ()))
                if row.name == ZOMBIE:
                    continue  # it has ended: no identity, and no sign of anything
                identity = (row.uid, row.name)
                matching = identity == (self._payload.uid, self._payload.name)
                key = (row.pid, row.started)
                if level > LEVELS:
                    if key in self._seen:  # seen at a shallower level first
                        self._seen[key].add(identity)
                    self.failed |= matching
                    continue
                self._seen.setdefault(key, set()).add(identity)
                identified |= matching
                sign |= self._level_0_sign(row.name) if level == 0 else self._sign(row.name)
            current, level = below, level + 1
        if identified and self.clock != "runtime":
            self.clock, self.deadline = "runtime", now + self._runtime_s
        elif sign and self.clock == "auth":
            self.clock, self.deadline = "launch", now + LAUNCH_S

    def _sign(self, name: str) -> bool:
        """A descendant under one of these names: sudo forks only once it has authenticated."""
        return name in ("sudo", "sandbox-exec", self._payload.name)

    def _level_0_sign(self, name: str) -> bool:
        # The spawned process's name counts only once it has been seen as sudo: a listing can
        # catch it between the tool's fork and sudo's start, under the tool's own name.
        if name in ("sandbox-exec", self._payload.name):
            return True
        if name == "sudo":
            self._seen_as_sudo = True
            return False
        return self._seen_as_sudo


def latch(*, cap: bool, tracking: bool, expired: str | None, exited: bool) -> str | None:
    """The forced ending a pass latches: the output cap, then a tracking failure, then the
    armed clock's expiry, which does not latch in the pass that collects the exit."""
    if cap:
        return "output_cap"
    if tracking:
        return "tracking_failed"
    if expired is not None and not exited:
        return expired
    return None


@dataclass(frozen=True)
class Survivor:
    """A recorded process the listing after the payload still shows, by its process ID
    and start time, with the user ID and basename that listing gives it now."""

    pid: int
    uid: int
    started: str
    name: str


def survivors(
    records: Iterable[Record],
    rows: Sequence[Process],
    *,
    unsignalled: int | None = None,
) -> tuple[Survivor, ...]:
    """The recorded processes still alive: a row with a recorded process ID and its start
    time, whatever user ID and basename it has now (change record 5: an exec after the last
    poll keeps the first two and changes the others, and the start time still tells a
    reused process ID apart).

    ``unsignalled`` is the spawned process's ID when a signal to it failed with EPERM: its
    exit has not been collected (the engine collects it only after the final listing), so
    no other process can have that ID, and it survives while any listing row carries it,
    under any identity and whether or not a listing ever showed it before. A zombie (ps's
    ``<defunct>``) has ended and survives nothing."""
    running = [row for row in rows if row.name != ZOMBIE]
    alive = {(row.pid, row.started): row for row in running}
    found: list[Survivor] = []
    for record in records:
        row = alive.get((record.pid, record.started))
        if row is not None:
            found.append(Survivor(row.pid, row.uid, row.started, row.name))
    if unsignalled is not None and all(survivor.pid != unsignalled for survivor in found):
        found += [
            Survivor(row.pid, row.uid, row.started, row.name)
            for row in running
            if row.pid == unsignalled
        ]
    return tuple(found)


def survivor_note(survivor: Survivor) -> str:
    """The verification-first note: the four fields, the check, and only then the stop,
    each command on a line of its own so it can be copied whole. The words before each
    command start a line too, so wrapping never leaves one of them alone above it (the copy
    pass's review, round 3, n4)."""
    name = survivor.name if survivor.name in SUBTREE_NAMES else "an unexpected process"
    pid = survivor.pid
    return (
        f"A process from the administrator reads may still be running: process {pid}, "
        f"{name}, user ID {survivor.uid}, started {survivor.started}.\n"
        "Check it first with\n"
        f"  ps -p {pid} -o pid,uid,lstart,comm\n"
        "and only if all four still match, stop it with\n"
        f"  sudo /bin/kill -TERM {pid}"
    )


UNVERIFIED_NOTE: Final = (
    "Voltry could not confirm that the administrator reads stopped: the process listing "
    "that checks them failed or did not run. Look with ps for sudo, sandbox-exec, sqlite3 "
    "or powermetrics processes started at the time of this run."
)


# The guarantee's words live with the other words a report prints (phrases.guarantee).
guarantee = phrases.guarantee


# --- the loop --------------------------------------------------------------------------------


class Child(Protocol):
    """A started process, the payload command or one listing, as the engine runs it."""

    @property
    def pid(self) -> int: ...
    @property
    def stdout(self) -> str: ...
    @property
    def stderr(self) -> str: ...
    @property
    def capped(self) -> bool: ...
    def poll(self) -> int | None: ...
    def signal(self, signum: int) -> bool: ...
    def close(self) -> None: ...


class Engine(Protocol):
    """What the loop needs from the processes and the clock: the chokepoint runs the real
    ones, and the tests a fake sudo and a fake ps on a virtual clock."""

    def now(self) -> float: ...
    def start_payload(self) -> Child | None: ...
    def start_listing(self) -> Child | None: ...
    def wait(self, *, drain: Sequence[Child], watch: Child | None, until: float) -> None:
        """Keep at least ``drain``'s pipes read until ``watch`` has ended and what it wrote
        is read, or until ``until``; a watched child that has already ended is read once."""


@dataclass(frozen=True)
class Tracked:
    """How one payload command ended, and what the listing after it found.

    ``stop`` says how the stop sequence ended, when one ran: ``terminated`` by SIGTERM,
    ``killed``, ``abandoned`` when not reaped within it, or ``eperm`` when the spawned
    process could not be signalled. ``listings`` holds each listing's duration and
    whether it failed, for P1's command record.
    """

    started: bool
    forced: str | None
    returncode: int | None
    stdout: str = field(repr=False)
    stderr: str = field(repr=False)
    cleanup: str
    survivors: tuple[Survivor, ...] = field(repr=False)
    records: tuple[Record, ...] = field(repr=False)
    cancelled: bool
    stop: str | None
    duration_s: float
    listings: tuple[tuple[float, bool], ...]


def _listing(engine: Engine, drain: Sequence[Child]) -> tuple[list[Process] | None, float]:
    """One listing under its 2 s deadline, killed and given 1 s to be reaped if it misses
    it; its rows, or None for a failed listing, and how long it took. Its pipes are closed
    as soon as it is read, on every path: a listing a second held open until the payload
    ended would exhaust the open-file limit during a long prompt. One an error interrupted
    is killed before it is closed."""
    begin = engine.now()
    child = engine.start_listing()
    if child is None:
        return None, 0.0
    try:
        engine.wait(drain=[*drain, child], watch=child, until=begin + LISTING_S)
        code = child.poll()
        if code is None:
            child.signal(signal.SIGKILL)
            engine.wait(drain=[*drain, child], watch=child, until=engine.now() + REAP_S)
            return None, engine.now() - begin
        took = engine.now() - begin
        if code != 0 or child.capped:
            return None, took
        try:
            return listing.processes(child.stdout), took
        except listing.Unreadable:
            return None, took
    finally:
        if child.poll() is None:
            child.signal(signal.SIGKILL)
        child.close()


def _stop(engine: Engine, child: Child) -> str:
    """SIGTERM, up to 3 s, SIGKILL and a 1 s reap; a signal refused with EPERM closes the
    pipes and stops waiting, since the tool can do nothing more to that process."""
    for signum, allowance, outcome in (
        (signal.SIGTERM, TERM_WAIT_S, "terminated"),
        (signal.SIGKILL, REAP_S, "killed"),
    ):
        if not child.signal(signum):
            child.close()
            return "eperm"
        engine.wait(drain=[child], watch=child, until=engine.now() + allowance)
        if child.poll() is not None:
            return outcome
    child.close()
    return "abandoned"


def _kill(engine: Engine, child: Child) -> str:
    """The end of a stop an error broke off: SIGKILL while the payload runs, then a 1 s
    reap and the pipes closed. A third error, in that reap, adds nothing the first two do
    not say, and the final listing still runs."""
    try:
        if child.poll() is not None:
            return "terminated"
        if not child.signal(signal.SIGKILL):
            return "eperm"
        with contextlib.suppress(BaseException):  # see above
            engine.wait(drain=[child], watch=child, until=engine.now() + REAP_S)
        return "killed" if child.poll() is not None else "abandoned"
    finally:
        child.close()


_NONE: Final = object()  # a pass that applies no listing: the armed deadline arrived first


class Unfinished(Exception):
    """An error stopped the loop. The payload was stopped and the final listing taken all
    the same; ``tracked`` says what that listing found, and the error is the cause."""

    def __init__(self, tracked: Tracked) -> None:
        super().__init__("the tracking stopped on an unexpected error")
        self.tracked = tracked


@dataclass
class _Loop:
    """Where the loop stands: the latched ending, whether the exit is collected, and
    whether the run is being stopped (the cancellation, a Ctrl-C, or an error)."""

    forced: str | None = None
    exited: bool = False
    stopping: bool = False


def _passes(
    engine: Engine,
    child: Child,
    tracker: Tracker,
    listings: list[tuple[float, bool]],
    cancelled: Callable[[], bool],
    loop: _Loop,
) -> None:
    """The passes, until something latched, the payload exited or the run is cancelled. The
    flag is read at the end of a pass, after its listing, so a listing already due when the
    flag turns true still runs: it records what appeared since the last one, for the final
    listing to check (the review of #326, round 2, n5)."""
    due = engine.now()
    while True:
        applied: object = _NONE
        if engine.now() >= due:
            started = engine.now()
            found, took = _listing(engine, (child,))
            listings.append((took, found is None))
            applied = found
            due = max(started + POLL_S, engine.now())
        else:
            engine.wait(drain=[child], watch=None, until=min(due, tracker.deadline))
            if engine.now() < tracker.deadline:
                continue
        # A pass: the pipes are drained; collect the exit, apply the listing, then the clock.
        now = engine.now()
        loop.exited = child.poll() is not None
        if loop.exited:
            # What it wrote as it exited, read once more, so a last burst past the cap is
            # the output cap and not a truncated output.
            engine.wait(drain=[child], watch=child, until=now)
        if applied is not _NONE:
            tracker.apply(applied if isinstance(applied, list) else None, now)
        expired = tracker.ending if tracker.expired(now) else None
        loop.forced = latch(
            cap=child.capped, tracking=tracker.failed, expired=expired, exited=loop.exited
        )
        loop.stopping = cancelled()
        if loop.forced is not None or loop.exited or loop.stopping:
            return


def track(
    engine: Engine, *, payload: Payload, runtime_s: float, cancelled: Callable[[], bool]
) -> Tracked:
    """Run one payload command to its end under the listings, the clocks and the latch,
    stop it if anything latched or the run was cancelled, and take the final listing.

    Whatever stops the loop, or breaks into the stop or the final listing, the payload is
    stopped and the final listing taken before anything leaves: a Ctrl-C no handler turned
    into the flag is the cancellation it is, and any other error raises Unfinished with
    what the listing found, the first error as its cause and a later one as its context."""
    if cancelled():
        # A run already cancelled here starts no payload (the GPT audit, pass 1, G1-01), so
        # there is nothing to stop and nothing to list. A flag set just after this check,
        # in the instant before the start, lets the payload start, and the loop's first
        # pass stops it.
        return Tracked(
            started=False,
            forced=None,
            returncode=None,
            stdout="",
            stderr="",
            cleanup="verified",
            survivors=(),
            records=(),
            cancelled=True,
            stop=None,
            duration_s=0.0,
            listings=(),
        )
    begin = engine.now()
    child = engine.start_payload()
    listings: list[tuple[float, bool]] = []
    if child is None:
        rows, took = _listing(engine, ())
        listings.append((took, rows is None))
        return Tracked(
            started=False,
            forced=None,
            returncode=None,
            stdout="",
            stderr="",
            cleanup="listing_failed" if rows is None else "verified",
            survivors=(),
            records=(),
            cancelled=False,
            stop=None,
            duration_s=0.0,
            listings=tuple(listings),
        )
    tracker = Tracker(spawned=child.pid, payload=payload, runtime_s=runtime_s, now=begin)
    loop = _Loop()
    error: BaseException | None = None
    try:
        _passes(engine, child, tracker, listings, cancelled, loop)
    except KeyboardInterrupt:
        loop.stopping = True
    except BaseException as problem:  # noqa: BLE001 - raised again once the payload is stopped
        error, loop.stopping = problem, True
    if error is not None or loop.stopping:
        loop.exited = child.poll() is not None
    late: BaseException | None = None
    stop: str | None = None
    if not loop.exited:
        try:
            stop = _stop(engine, child)
        except BaseException as problem:  # noqa: BLE001 - the payload is killed, then it leaves
            late = problem
            stop = _kill(engine, child)
    duration = engine.now() - begin
    started = engine.now()
    try:
        rows, took = _listing(engine, () if stop == "eperm" else (child,))
    except BaseException as problem:  # noqa: BLE001 - the listing is killed and counted failed
        late = late or problem
        rows, took = None, engine.now() - started
    listings.append((took, rows is None))
    found_survivors: tuple[Survivor, ...] = ()
    if rows is None:
        cleanup = "listing_failed"
    else:
        # After EPERM the exit is not collected, so the spawned process keeps its ID.
        unsignalled = child.pid if stop == "eperm" else None
        found_survivors = survivors(tracker.records, rows, unsignalled=unsignalled)
        cleanup = "survivor" if found_survivors else "verified"
    tracked = Tracked(
        started=True,
        forced=loop.forced,
        returncode=child.poll(),  # collected without blocking, even after EPERM
        stdout=child.stdout,
        stderr=child.stderr,
        cleanup=cleanup,
        survivors=found_survivors,
        records=tracker.records,
        cancelled=loop.stopping or isinstance(late, KeyboardInterrupt),
        stop=stop,
        duration_s=duration,
        listings=tuple(listings),
    )
    # A Ctrl-C is the cancellation it is; any other error, SystemExit included, leaves as
    # Unfinished, so what the final listing found still reaches the survivor note.
    first = error if error is not None else late
    if isinstance(late, KeyboardInterrupt) and error is None:
        first = None
    if first is None:
        return tracked
    unfinished = Unfinished(tracked)
    if late is not None and late is not first:
        unfinished.__context__ = late
    raise unfinished from first
