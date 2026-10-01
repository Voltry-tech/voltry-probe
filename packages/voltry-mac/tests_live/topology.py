"""The capture's in-process probes (docs/VOLTRY_MAC_SPEC.md, Test strategy part 5, "Live macOS
CI", its second bullet, and Decision 2, "Stopping a payload"; board item MAC 4.2, issue
#324).

capture.py runs each probe in a child process of its own that has become the runner user
or a test account, since the tool runs as the owner and never as root. A probe drives the
package's own payload runner or broker, watched from inside: the tracker is the package's,
subclassed to note each clock it arms and when, each process of the subtree with its level,
user ID and what ps printed for comm, and each descendant seen before any sign that sudo
authenticated; the listing parser and the stop sequence are wrapped to keep what they read
and did. None of their logic changes. The broker's runs patch what the bullet names and
nothing more: the runtime clock to 1 s, and for the first run the count's payload, with
the allow-list's S3n to match, to a sandboxed /bin/sleep 8 as the service account. A broker
run also returns what the tool's final listing showed of each payload, and the note the
owner reads for each survivor, as the tool renders it. A probe returns plain data for
capture.py to judge and print; nothing here prints. capture.py loads this module only once
the gate has passed.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from types import MappingProxyType
from typing import Any, Final

from voltry_mac import allowlist, elevation, listing, spawn, tracking

SERVICE_ACCOUNT: Final = "_mmaintenanced"
# The count's stand-in ("Stopping a payload"): the real count finishes in milliseconds, too
# soon for a 1 s runtime clock, so the first broker run replaces it, for that run alone,
# with a sandboxed sleep as the same account, in S3n's own shape.
STAND_IN: Final = (
    "/usr/bin/sudo",
    "-u",
    SERVICE_ACCOUNT,
    "-H",
    "-n",
    "--",
    "/usr/bin/sandbox-exec",
    "-p",
    allowlist.PROFILE,
    "/bin/sleep",
    "8",
)
STAND_IN_NAME: Final = "sleep"
RUNTIME_S: Final = 1.0  # the broker runs' runtime clock, patched
# S3n ends in milliseconds and a listing starts every 200 ms, so one run can end before any
# listing shows its payload; it runs again until one does, for at most this long.
S3N_S: Final = 90.0
WAIT_S: Final = 15.0  # how long a probe waits for a process it could not stop to end

Summary = dict[str, Any]


# --- watching the package's own code ------------------------------------------------------


class _Tap:
    """The text of the last listing the parser read, so a tracker can see what ps printed
    for comm; the parser keeps the basename alone."""

    text = ""


_PARSE: Final = listing.processes
_STOP: Final = tracking._stop
_TRACKERS: list[Watched] = []
_STOPS: list[str] = []


def _processes(stdout: str) -> list[listing.Process]:
    rows = _PARSE(stdout)  # a listing the parser refuses is never kept
    _Tap.text = stdout
    return rows


def _stop(engine: tracking.Engine, child: tracking.Child) -> str:
    outcome = _STOP(engine, child)
    _STOPS.append(outcome)
    return outcome


def _rows(text: str) -> list[tuple[int, int, int, str]]:
    """Each row of a listing the parser read, as its process ID, parent, user ID and what
    ps printed for comm, sometimes a full path."""
    rows = []
    for line in text.split("\n")[1:]:
        words = line.split(maxsplit=8)
        if len(words) == 9:
            rows.append((int(words[0]), int(words[1]), int(words[2]), words[8].rstrip()))
    return rows


def final_state(text: str, pid: int) -> str:
    """What a listing showed of one process: alive; ps's <defunct> once it has ended and its
    exit is not collected yet; or gone."""
    for row_pid, _, _, comm in _rows(text):
        if row_pid == pid:
            return tracking.ZOMBIE if comm == tracking.ZOMBIE else "alive"
    return "gone"


def _subtree(text: str, spawned: int) -> set[tuple[int, int, str]]:
    """Each process at levels 0 to 3 under the spawned one in a listing the parser read,
    as its level, its user ID and what ps printed for comm, sometimes a full path."""
    rows: dict[int, tuple[int, str]] = {}
    children: dict[int, list[int]] = {}
    for pid, ppid, uid, comm in _rows(text):
        rows[pid] = (uid, comm)
        children.setdefault(ppid, []).append(pid)
    found: set[tuple[int, int, str]] = set()
    level, current = 0, [spawned] if spawned in rows else []
    while current and level <= tracking.LEVELS:
        found.update((level, *rows[pid]) for pid in current)
        current = [child for pid in current for child in children.get(pid, [])]
        level += 1
    return found


class Watched(tracking.Tracker):
    """The package's tracker, noting what it saw: each clock it arms after the first and
    when, each process of the subtree, and each descendant seen in a listing that showed no
    sign that sudo had authenticated (before the monitor, on the password path)."""

    def __init__(
        self, *, spawned: int, payload: tracking.Payload, runtime_s: float, now: float
    ) -> None:
        super().__init__(spawned=spawned, payload=payload, runtime_s=runtime_s, now=now)
        self.spawned = spawned
        self.payload = payload
        self.armed: list[tuple[float, str]] = []
        self.subtree: set[tuple[int, int, str]] = set()
        self.early: set[tuple[int, int, str]] = set()
        _TRACKERS.append(self)

    def apply(self, rows: Sequence[listing.Process] | None, now: float) -> None:
        before = self.clock
        super().apply(rows, now)
        if rows is None:
            return
        found = _subtree(_Tap.text, self.spawned)
        self.subtree |= found
        if self.clock == before == "auth":
            self.early |= {process for process in found if process[0] > 0}
        if self.clock != before:
            self.armed.append((now, self.clock))

    @property
    def identified_at_0(self) -> bool:
        """Whether the spawned process itself took the payload's identity: sudo executed
        the payload directly, and the tracker identified it at level 0."""
        identity = (self.payload.uid, self.payload.name)
        return any(
            record.pid == self.spawned and identity in record.identities for record in self.records
        )

    @property
    def comm(self) -> list[list[object]]:
        return sorted([level, uid, comm] for level, uid, comm in self.subtree)


def watch() -> None:
    """Watch the tracker, the listing parser and the stop sequence in this process."""
    tracking.Tracker = Watched
    listing.processes = _processes
    tracking._stop = _stop


def _next() -> Watched:
    """The one tracker the last payload command made."""
    (tracker,) = _TRACKERS
    _TRACKERS.clear()
    return tracker


def _ending(run: spawn.PayloadRun) -> str:
    """The ending the broker records for this run (Decision 2's outcome tables)."""
    ending = elevation._ending(run)
    return ending if ending is not None else elevation._read(run.command_id[:2], run.stdout)[0]


def _summary(run: spawn.PayloadRun, tracker: Watched) -> Summary:
    """One payload command: how it ended, and what its tracker saw."""
    return {
        "command": run.command_id,
        "ending": _ending(run),
        "cleanup": run.cleanup,
        "identified": any(clock == "runtime" for _, clock in tracker.armed),
        "identified_at_0": tracker.identified_at_0,
        "descendants": sum(1 for record in tracker.records if record.pid != tracker.spawned),
        "armed": [[at, clock] for at, clock in tracker.armed],
        "subtree": tracker.comm,
        "early": sorted([level, uid, comm] for level, uid, comm in tracker.early),
    }


# --- the probes -----------------------------------------------------------------------------


def direct(service_uid: int) -> Summary:
    """S3n, then S4n, through the payload runner with no terminal, while the drop-in makes
    sudo execute each payload directly. S3n runs again until a listing identifies its
    payload, for at most S3N_S, with its listings back to back rather than 200 ms apart:
    the count ends in milliseconds, and ps shows it under the service account only while
    it runs, so 200 ms apart the listings missed it in all of 442 runs on macOS 26 (the
    first live run, 2026-09-29). The probe asks where sudo runs the payload, not how often
    the tool lists; each listing is still the package's own, parsed and applied by its
    tracker."""
    watch()
    runs: list[Summary] = []
    deadline = time.monotonic() + S3N_S
    every = tracking.POLL_S
    tracking.POLL_S = 0.0
    try:
        while not (runs and runs[-1]["identified"]) and time.monotonic() < deadline:
            runs.append(_summary(spawn.Runner().payload("S3n", uid=service_uid), _next()))
    finally:
        tracking.POLL_S = every
    return {"S3n": runs, "S4n": _summary(spawn.Runner().payload("S4n", uid=0), _next())}


def slow(service_uid: int) -> Summary:
    """S3, then S4, through the payload runner on the terminal capture.py drives, which
    answers each prompt only after 10 s."""
    watch()
    return {
        command_id: _summary(spawn.Runner().payload(command_id, uid=uid), _next())
        for command_id, uid in (("S3", service_uid), ("S4", 0))
    }


def _runtime(seconds: float) -> None:
    tracking.RUNTIME_S = MappingProxyType(dict.fromkeys(tracking.RUNTIME_S, seconds))


def _stand_in() -> None:
    """The count's payload for this run only, a sandboxed /bin/sleep 8 as the service
    account: the allow-list's S3n becomes that argv, so the chokepoint still checks what it
    runs against the list; the forbidden-shape scan takes that one argv; and the tracker
    identifies the payload by its own basename."""
    commands = tuple(
        allowlist.Command("S3n", STAND_IN, "service", 10) if command.id == "S3n" else command
        for command in allowlist.COMMANDS
    )
    allowlist.COMMANDS = commands
    allowlist.BY_ID = MappingProxyType({command.id: command for command in commands})
    scan = allowlist.forbidden_shape

    def forbidden_shape(argv: Sequence[str], *, published_path: str | None = None) -> str | None:
        if tuple(argv) == STAND_IN:
            return None
        return scan(argv, published_path=published_path)

    allowlist.forbidden_shape = forbidden_shape
    tracking.PAYLOAD_NAMES = MappingProxyType({**tracking.PAYLOAD_NAMES, "S3n": STAND_IN_NAME})


def _no_service_account(name: str) -> int:
    raise KeyError(name)  # the broker then skips the count, and S4n runs alone


def _plain(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    return value


def _broker(found: elevation.Elevation, runner: spawn.Runner) -> Summary:
    """What one broker run left: its record and outcomes, the survivors it named and the
    note the owner reads for each, each stop and payload, what the tool's final listing
    showed of each payload, the command records, and whether the nonblocking wait
    collected each process the tool could not stop once that process ended on its own."""
    # The last listing the tool read: the final listing after the last payload that ran,
    # since nothing after it lists (S5 is sudo -k).
    final = _Tap.text
    held = spawn.collect_abandoned()
    deadline = time.monotonic() + WAIT_S
    left = held
    while left and time.monotonic() < deadline:
        time.sleep(0.2)
        left = spawn.collect_abandoned()
    alive = {(row.pid, row.started) for row in listing.processes(spawn.Runner().run("P1").stdout)}
    return {
        "record": _plain(found.record),
        "ledger": [found.ledger.reason, found.ledger.detail],
        "power": [found.power.reason, found.power.detail],
        "survivors": [[one.pid, one.uid, one.started, one.name] for one in found.survivors],
        "notes": [tracking.survivor_note(one) for one in found.survivors],
        "stops": list(_STOPS),
        "payloads": [
            {
                "spawned": tracker.spawned,
                "identity": [tracker.payload.uid, tracker.payload.name],
                "identified_at_0": tracker.identified_at_0,
                "subtree": tracker.comm,
                "final": final_state(final, tracker.spawned),
            }
            for tracker in _TRACKERS
        ],
        "commands": [record.id for record in runner.records()],
        "held": held,
        "left": left,
        "gone": all((one.pid, one.started) not in alive for one in found.survivors),
    }


def _broker_run(
    lookup: Callable[[str], object] = elevation._lookup,
) -> tuple[elevation.Elevation, spawn.Runner]:
    """The broker in-process as with --yes and no terminal: consent by the flag, the -n
    forms, and sudo executing each payload directly. ``lookup`` is the broker's own
    service-account lookup unless a probe names another."""
    runner = spawn.Runner()
    found = elevation.run(
        yes=True,
        no_root=False,
        admin=True,
        terminal=False,
        ask=lambda: None,
        runner=runner,
        cancelled=lambda: False,
        lookup=lookup,
    )
    return found, runner


def stand_in() -> Summary:
    """The broker with the runtime clock at 1 s and the count's payload the stand-in."""
    watch()
    _runtime(RUNTIME_S)
    _stand_in()
    return _broker(*_broker_run())


def power_alone() -> Summary:
    """The broker with the runtime clock at 1 s and the real S4n alone: the count is
    skipped through the broker's own service-account lookup."""
    watch()
    _runtime(RUNTIME_S)
    return _broker(*_broker_run(_no_service_account))
