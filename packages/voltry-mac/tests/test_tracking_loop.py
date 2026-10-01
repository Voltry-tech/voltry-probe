"""The broker's loop around one payload command (docs/VOLTRY_MAC_SPEC.md, Decision 2,
"Stopping a payload", the latch, the cleanup table and the time bounds; Test strategy
part 3, "Process behavior" and "Bounds").

The loop runs against a fake engine on a virtual clock: a fake sudo whose process table
changes over time, listings that each take a snapshot and some time to finish, and the
stop signals. Nothing waits in real time, so every timing the spec names is exact here.
"""

from __future__ import annotations

import math
import signal
from collections.abc import Callable
from dataclasses import dataclass, field

import pytest

from voltry_mac import listing, tracking

AT = "Sat Sep 26 12:00:00 2026"
LATER = "Sat Sep 26 12:03:30 2026"
TOOL = 501
SERVICE = 283
S4 = tracking.Payload(uid=0, name="powermetrics")
S3 = tracking.Payload(uid=SERVICE, name="sqlite3")
HEADER = "  PID  PPID   UID STARTED                      COMM\n"
BASE = [listing.Process(1, 0, 0, AT, "launchd"), listing.Process(50, 1, TOOL, AT, "python3.12")]


def row(pid: int, ppid: int, uid: int, name: str, started: str = AT) -> listing.Process:
    return listing.Process(pid, ppid, uid, started, name)


def render(rows: list[listing.Process]) -> str:
    lines = [f"{r.pid:5} {r.ppid:5} {r.uid:5} {r.started}     /usr/bin/{r.name}" for r in rows]
    return HEADER + "".join(line + "\n" for line in lines)


@dataclass
class Child:
    """A fake process: it ends at ``end`` with ``code``, and answers the stop signals."""

    engine: FakeEngine
    pid: int
    end: float = math.inf
    code: int = 0
    stdout: str = ""
    stderr: str = ""
    capped: bool = False
    term_after: float | None = 0.05  # None: it ignores SIGTERM
    kill_after: float | None = 0.0  # None: it cannot be reaped in time
    eperm_from: float = math.inf  # from then on, a signal fails with EPERM
    burst_at_exit: bool = False  # a last burst past the cap, read only by a drain after exit
    closed: bool = False
    signals: list[tuple[float, int]] = field(default_factory=list)

    def poll(self) -> int | None:
        return self.code if self.engine.t >= self.end else None

    def signal(self, signum: int) -> bool:
        if self.engine.t >= self.eperm_from:
            return False
        self.signals.append((self.engine.t, signum))
        if self.poll() is None:
            delay = self.term_after if signum == signal.SIGTERM else self.kill_after
            if delay is not None and self.engine.t + delay < self.end:
                self.end, self.code = self.engine.t + delay, -signum
        return True

    def close(self) -> None:
        self.closed = True


class FakeEngine:
    """A fake sudo and a fake ps on a virtual clock.

    ``world(t)`` is the subtree ps shows at time ``t``; ``timing(start)`` gives a listing
    started then its snapshot's delay and how long it takes (math.inf: it hangs).
    """

    def __init__(
        self,
        world: Callable[[float], list[listing.Process]],
        *,
        payload: Child | None = None,
        spawn_fails: bool = False,
        timing: Callable[[float], tuple[float, float]] = lambda _start: (0.0, 0.05),
        listing_fails: Callable[[float], bool] = lambda _start: False,
        listing_missing: Callable[[float], bool] = lambda _start: False,
        listing_garbled: Callable[[float], bool] = lambda _start: False,
        listing_capped: Callable[[float], bool] = lambda _start: False,
    ) -> None:
        self.t = 0.0
        self.world = world
        self.payload = None if spawn_fails else (payload or Child(self, 100))
        if self.payload is not None:
            self.payload.engine = self
        self.timing = timing
        self.listing_fails = listing_fails
        self.listing_missing = listing_missing
        self.listing_garbled = listing_garbled
        self.listing_capped = listing_capped
        self.listings: list[tuple[float, float]] = []  # start, snapshot
        self.children: list[Child] = []  # every listing started, to check each is closed
        self.raises: list[tuple[float, BaseException]] = []  # each raised once, in order
        self._pid = 900

    def now(self) -> float:
        return self.t

    def start_payload(self) -> Child | None:
        return self.payload

    def start_listing(self) -> Child | None:
        if self.listing_missing(self.t):
            return None  # ps could not be started
        delay, took = self.timing(self.t)
        snapshot = self.t + delay
        self.listings.append((self.t, snapshot))
        self._pid += 1
        text = (
            "not the listing\n"
            if self.listing_garbled(self.t)
            else render(BASE + self.world(snapshot))
        )
        fails = self.listing_fails(self.t)
        capped = self.listing_capped(self.t)
        code = 1 if fails else 0
        child = Child(self, self._pid, end=self.t + took, code=code, stdout=text, capped=capped)
        self.children.append(child)
        return child

    def wait(self, *, drain: list[Child], watch: Child | None, until: float) -> None:
        ends = watch.end if watch is not None else math.inf
        target = max(self.t, min(until, ends))
        if self.raises and target >= self.raises[0][0]:
            at, error = self.raises.pop(0)
            self.t = max(self.t, at)
            raise error
        self.t = target
        # A burst the payload wrote as it exited is read only by a drain that waits on it.
        if watch is not None and watch.burst_at_exit and watch.poll() is not None:
            watch.capped = True


def phases(*steps: tuple[float, list[listing.Process]]) -> Callable[[float], list[listing.Process]]:
    """A world whose table is each step's rows from its time on."""

    def world(t: float) -> list[listing.Process]:
        current: list[listing.Process] = []
        for since, rows in steps:
            if t >= since:
                current = rows
        return current

    return world


SUDO = [row(100, 50, 0, "sudo")]
MONITOR = [*SUDO, row(101, 100, 0, "sudo")]
SANDBOX = [*MONITOR, row(102, 101, 0, "sandbox-exec")]
POWER = [*MONITOR, row(102, 101, 0, "powermetrics")]
ORPHAN = [row(102, 1, 0, "powermetrics")]  # the payload alone, sudo and its monitor gone


def run(
    engine: FakeEngine,
    payload: tracking.Payload = S4,
    runtime_s: float = 20.0,
    cancelled: Callable[[], bool] = lambda: False,
) -> tracking.Tracked:
    return tracking.track(engine, payload=payload, runtime_s=runtime_s, cancelled=cancelled)


def normal_world(auth: float = 2.0, launch: float = 0.3, work: float = 1.0) -> tuple:
    """sudo asks, then its monitor, sandbox-exec and the payload; all gone once it ends."""
    end = auth + launch + work
    world = phases(
        (0.0, SUDO), (auth, MONITOR), (auth + 0.1, SANDBOX), (auth + launch, POWER), (end, [])
    )
    return world, end


# --- a run that ends on its own --------------------------------------------------------------


def test_a_payload_that_ends_on_its_own_is_classified_by_its_exit():
    world, end = normal_world()
    engine = FakeEngine(world)
    engine.payload.end, engine.payload.stdout = end, "five samples"
    found = run(engine)
    assert (found.started, found.forced, found.returncode) == (True, None, 0)
    assert (found.cleanup, found.survivors, found.cancelled) == ("verified", (), False)
    assert found.stdout == "five samples"
    assert engine.payload.signals == [], "nothing is stopped that ended by itself"


def test_the_poller_records_the_monitor_the_sandbox_and_the_payload_with_start_times():
    world, end = normal_world(auth=4.0)
    engine = FakeEngine(world)
    engine.payload.end = end
    found = run(engine)
    records = {r.pid: r.identities for r in found.records}
    assert records[100] == {(0, "sudo")}
    assert records[101] == {(0, "sudo")}
    assert records[102] == {(0, "sandbox-exec"), (0, "powermetrics")}
    assert all(r.started == AT for r in found.records)


def test_a_listing_starts_every_200_ms_or_when_the_last_returns():
    world, end = normal_world()
    engine = FakeEngine(world, timing=lambda start: (0.0, 0.05))
    engine.payload.end = end
    run(engine)
    starts = [start for start, _ in engine.listings[:-1]]  # the last is the final listing
    gaps = {round(b - a, 6) for a, b in zip(starts, starts[1:], strict=False)}
    assert gaps == {0.2}
    slow = FakeEngine(world, timing=lambda start: (0.0, 0.5))
    slow.payload.end = end
    run(slow)
    starts = [start for start, _ in slow.listings[:-1]]
    assert {round(b - a, 6) for a, b in zip(starts, starts[1:], strict=False)} == {0.5}


def test_a_payload_that_ends_before_it_is_identified_simply_finished():
    engine = FakeEngine(phases((0.0, SUDO), (1.0, [])))
    engine.payload.end, engine.payload.code = 1.0, 1
    found = run(engine)
    assert (found.forced, found.returncode, found.cleanup) == (None, 1, "verified")


def test_a_slow_prompt_never_times_a_payload_out():
    world, end = normal_world(auth=170.0, work=15.0)
    engine = FakeEngine(world)
    engine.payload.end = end
    found = run(engine, runtime_s=20.0)
    assert (found.forced, found.returncode) == (None, 0)


# --- the clocks -------------------------------------------------------------------------------


def test_no_first_sign_in_180_s_is_the_authentication_clock():
    engine = FakeEngine(phases((0.0, SUDO)))
    found = run(engine)
    assert found.forced == "auth_failed"
    (when, signum), *_ = engine.payload.signals
    assert signum == signal.SIGTERM and 180.0 <= when <= 183.0


def test_a_stand_in_that_never_execs_the_payload_trips_the_launch_deadline():
    engine = FakeEngine(phases((0.0, SUDO), (3.0, SANDBOX)))
    found = run(engine)
    assert found.forced == "launch_deadline"
    first_sign = next(start for start, snap in engine.listings if snap >= 3.0)
    when = engine.payload.signals[0][0]
    assert first_sign + 5.0 <= when <= first_sign + 0.05 + 5.0 + 3.0


def test_a_sudo_that_lingers_after_its_payload_ends_is_the_runtime_deadline():
    # The runtime clock runs from the identification until the spawned process exits.
    world = phases((0.0, SUDO), (2.0, MONITOR), (2.1, POWER), (4.0, SUDO))
    engine = FakeEngine(world)
    engine.payload.end = 34.0  # sudo lingers 30 s after its payload ended
    found = run(engine, runtime_s=20.0)
    assert found.forced == "runtime_deadline"
    assert 22.1 <= engine.payload.signals[0][0] <= 25.1


def test_a_clock_that_expires_in_the_pass_that_collects_the_exit_does_not_latch():
    # A listing runs from 179.1 to 181.0; sudo exits at 180.5, past the clock's deadline.
    engine = FakeEngine(phases((0.0, SUDO), (180.5, [])), timing=lambda start: (0.0, 1.9))
    engine.payload.end, engine.payload.code = 180.5, 1
    found = run(engine)
    assert (found.forced, found.returncode) == (None, 1)
    assert engine.payload.signals == []


def test_a_deadline_between_listings_is_acted_on_at_once():
    # Listings every 200 ms that take no time: the deadline falls between two of them.
    engine = FakeEngine(phases((0.0, SUDO)), timing=lambda start: (0.0, 0.0))
    found = run(engine)
    assert found.forced == "auth_failed"
    assert engine.payload.signals[0][0] == 180.0


def test_a_change_2_s_before_a_deadline_is_seen_in_time_even_with_slow_listings():
    # Each listing snapshots at once and returns 1.9 s later; the first sign comes 2 s
    # before the authentication clock would expire and lasts.
    engine = FakeEngine(
        phases((0.0, SUDO), (178.0, SANDBOX), (179.0, POWER), (190.0, [])),
        timing=lambda start: (0.0, 1.9),
    )
    engine.payload.end = 190.0
    found = run(engine)
    assert (found.forced, found.returncode) == (None, 0)


def test_a_snapshot_just_before_a_change_delays_its_observation_by_about_3_8_s():
    def timing(start: float) -> tuple[float, float]:
        return (0.0, 1.9) if start < 10.0 else (1.9, 1.95)

    engine = FakeEngine(
        phases((0.0, SUDO), (10.0, SANDBOX), (11.0, POWER), (25.0, [])), timing=timing
    )
    engine.payload.end = 25.0
    found = run(engine)
    assert found.forced is None
    seen = next(start + 1.9 for start, snap in engine.listings if snap >= 10.0)
    assert 10.0 < seen <= 10.0 + 3.8 + 0.2


def test_a_state_between_two_snapshots_is_never_seen():
    world = phases((0.0, SUDO), (1.05, [*SUDO, row(150, 100, 0, "helper")]), (1.15, SUDO))
    world_then = phases((0.0, SUDO), (2.0, MONITOR), (2.1, POWER), (5.0, []))

    def both(t: float) -> list[listing.Process]:
        return world(t) if t < 2.0 else world_then(t)

    engine = FakeEngine(both, timing=lambda start: (0.0, 0.1))
    engine.payload.end = 5.0
    found = run(engine)
    assert 150 not in {r.pid for r in found.records}
    assert (found.forced, found.cleanup) == (None, "verified")


# --- listings that fail ------------------------------------------------------------------------


def test_a_ps_that_hangs_is_killed_at_2_s_reaped_within_1_s_and_is_a_failed_listing():
    def timing(start: float) -> tuple[float, float]:
        return (0.0, math.inf) if start >= 2.0 else (0.0, 0.05)

    engine = FakeEngine(phases((0.0, SUDO), (2.0, MONITOR)), timing=timing)
    found = run(engine)
    assert found.forced == "tracking_failed"
    hung = next((took, failed) for took, failed in found.listings if took >= 2.0)
    assert hung == (2.0, True)
    # Round 2: the hung listing itself is killed at its 2 s deadline.
    index = next(i for i, child in enumerate(engine.children) if child.signals)
    start = engine.listings[index][0]
    assert engine.children[index].signals == [(start + 2.0, signal.SIGKILL)]
    assert engine.payload.signals[0][0] <= 2.2 + 3.0, "no clock overshot by more than 3 s"


def test_a_listing_that_fails_in_the_pass_that_collects_the_exit_still_latches():
    world, end = normal_world()
    engine = FakeEngine(world, listing_fails=lambda start: start >= end)
    engine.payload.end = end
    assert run(engine).forced == "tracking_failed"


@pytest.mark.parametrize(
    "failure",
    [
        {"listing_fails": lambda start: start >= 1.0},
        {"listing_garbled": lambda start: start >= 1.0},
        {"listing_missing": lambda start: start >= 1.0},
        {"listing_capped": lambda start: start >= 1.0},
    ],
    ids=["exit 1", "not ps's listing", "ps could not start", "past its output cap"],
)
def test_a_listing_that_fails_in_any_way_is_a_tracking_failure(failure):
    engine = FakeEngine(phases((0.0, SUDO)), **failure)
    found = run(engine)
    assert found.forced == "tracking_failed"
    assert found.listings[-2][1], "the failed listing is counted as one"


def test_a_payload_deeper_than_three_levels_is_a_tracking_failure():
    deep = [
        *SUDO,
        row(101, 100, 0, "sudo"),
        row(102, 101, 0, "helper"),
        row(103, 102, 0, "helper"),
        row(104, 103, 0, "powermetrics"),
    ]
    engine = FakeEngine(phases((0.0, SUDO), (2.0, deep)))
    assert run(engine).forced == "tracking_failed"


# --- the output cap -----------------------------------------------------------------------------


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_oversized_output_on_either_stream_stops_the_child(stream):
    world, _ = normal_world()
    engine = FakeEngine(world)
    engine.payload.capped = True
    setattr(engine.payload, stream, "x")
    found = run(engine)
    assert found.forced == "output_cap"
    assert engine.payload.signals[0][1] == signal.SIGTERM


def test_the_output_cap_outranks_a_tracking_failure_in_one_pass():
    engine = FakeEngine(phases((0.0, SUDO)), listing_fails=lambda start: True)
    engine.payload.capped = True
    assert run(engine).forced == "output_cap"


# --- the stop sequence ------------------------------------------------------------------------


def test_the_stop_is_sigterm_then_3_s_then_sigkill_then_a_1_s_reap():
    engine = FakeEngine(phases((0.0, SUDO)))
    engine.payload.term_after = None  # ignores SIGTERM
    found = run(engine)
    (t_term, first), (t_kill, second) = engine.payload.signals
    assert (first, second) == (signal.SIGTERM, signal.SIGKILL)
    assert t_kill - t_term == pytest.approx(3.0)
    assert (found.stop, found.returncode) == ("killed", -signal.SIGKILL)


def test_a_process_not_reaped_within_its_stop_is_abandoned():
    engine = FakeEngine(phases((0.0, SUDO)))
    engine.payload.term_after = engine.payload.kill_after = None
    found = run(engine)
    assert (found.stop, found.returncode) == ("abandoned", None)
    assert engine.payload.closed
    assert found.duration_s == pytest.approx(engine.payload.signals[0][0] + 4.0)


def test_a_payload_that_ignores_sigterm_behind_the_monitor_is_verified_gone_or_named():
    # sudo is killed within the stop; the payload is either gone by the listing or a survivor.
    def world_survives(t: float) -> list[listing.Process]:
        return POWER if t < 22.0 else [row(102, 1, 0, "powermetrics")]

    engine = FakeEngine(world_survives)
    engine.payload.term_after = None
    found = run(engine)
    assert found.forced == "runtime_deadline" and found.stop == "killed"
    assert found.cleanup == "survivor"
    assert [s.pid for s in found.survivors] == [102]


@pytest.mark.parametrize(
    ("world", "cancelled"),
    [
        (
            phases((0.0, SUDO), (2.0, MONITOR), (2.1, SANDBOX), (2.3, POWER), (5.0, ORPHAN)),
            lambda t: t >= 2.15,
        ),
        (
            phases((0.0, SUDO), (2.0, MONITOR), (2.1, SANDBOX), (8.0, POWER), (10.0, ORPHAN)),
            lambda t: False,
        ),
    ],
    ids=["cancelled", "the launch deadline"],
)
def test_a_process_that_execs_after_the_last_poll_is_still_a_survivor(world, cancelled):
    # Change record 5 (the GPT audit, pass 1, S1-01): the last poll records PID 102 as
    # sandbox-exec; it then execs powermetrics, keeping its ID and start time, ignores the
    # stop and outlives sudo. The final listing shows it under a name no poll saw: alive,
    # so a survivor, never verified gone.
    engine = FakeEngine(world)
    engine.payload.term_after = None
    found = run(engine, cancelled=lambda: cancelled(engine.t))
    assert {r.pid: r.identities for r in found.records}[102] == {(0, "sandbox-exec")}
    assert (found.stop, found.cleanup) == ("killed", "survivor")
    assert found.survivors == (tracking.Survivor(pid=102, uid=0, started=AT, name="powermetrics"),)


def test_eperm_closes_the_pipes_stops_waiting_and_records_a_survivor():
    # sudo executed the payload directly: level 0 now runs as the service account.
    world = phases((0.0, SUDO), (2.0, [row(100, 50, SERVICE, "sqlite3")]))
    engine = FakeEngine(world)
    engine.payload.eperm_from = 2.0
    found = run(engine, payload=S3, runtime_s=10.0)
    assert found.forced == "runtime_deadline"
    assert (found.stop, found.cleanup) == ("eperm", "survivor")
    assert engine.payload.closed and engine.payload.signals == []
    assert found.returncode is None


def test_after_eperm_the_spawned_process_survives_under_an_identity_never_recorded():
    # sudo executes the payload directly after the snapshot of a slow listing that spans
    # the authentication deadline, so no poll ever sees it under its new identity.
    world = phases((0.0, SUDO), (179.95, [row(100, 50, SERVICE, "sqlite3")]))

    def timing(start: float) -> tuple[float, float]:
        return (0.0, 1.5) if 179.0 <= start < 180.0 else (0.0, 0.05)

    engine = FakeEngine(world, timing=timing)
    engine.payload.eperm_from = 179.95
    found = run(engine, payload=S3, runtime_s=10.0)
    assert (found.forced, found.stop) == ("auth_failed", "eperm")
    assert [(s.pid, s.uid, s.name) for s in found.survivors] == [(100, SERVICE, "sqlite3")]


def test_after_eperm_an_exit_before_the_end_is_collected_without_blocking():
    world = phases((0.0, SUDO), (2.0, [row(100, 50, SERVICE, "sqlite3")]))
    engine = FakeEngine(world)
    # The final listing, after the pipes are closed, takes 1 s; the payload ends in it.
    engine.timing = lambda start: (0.0, 1.0) if engine.payload.closed else (0.0, 0.05)
    engine.payload.eperm_from = 2.0
    engine.payload.end = 12.9
    found = run(engine, payload=S3, runtime_s=10.0)
    assert found.stop == "eperm" and found.returncode == 0


# --- cancellation, and a sudo that could not start ---------------------------------------------


def test_a_cancellation_runs_the_stop_and_the_final_listing():
    world = phases((0.0, SUDO), (2.0, MONITOR), (2.3, POWER), (3.02, []))
    engine = FakeEngine(world)
    found = run(engine, cancelled=lambda: engine.t >= 3.0)
    assert found.cancelled and found.forced is None
    assert engine.payload.signals[0][1] == signal.SIGTERM
    assert found.cleanup == "verified"


def test_a_sudo_that_could_not_start_still_gets_its_listing():
    engine = FakeEngine(phases(), spawn_fails=True)
    found = run(engine)
    assert (found.started, found.returncode, found.cleanup) == (False, None, "verified")
    assert len(found.listings) == 1 and found.duration_s == 0.0
    failing = FakeEngine(phases(), spawn_fails=True, listing_fails=lambda start: True)
    assert run(failing).cleanup == "listing_failed"
    missing = FakeEngine(phases(), spawn_fails=True, listing_missing=lambda start: True)
    assert run(missing).cleanup == "listing_failed"
    assert run(missing).listings == ((0.0, True),), "a listing that could not start took 0 s"


def test_a_failed_final_listing_is_listing_failed():
    # The listing at 3.4 s collects the exit at 3.3 s; only the final one, at 3.45 s, fails.
    world, end = normal_world()
    engine = FakeEngine(world, listing_fails=lambda start: start >= end + 0.12)
    engine.payload.end = end
    found = run(engine)
    assert (found.forced, found.cleanup) == (None, "listing_failed")
    assert found.listings[-1][1]


def test_a_short_lived_helper_between_polls_is_never_recorded_and_the_run_completes():
    world = phases(
        (0.0, SUDO),
        (0.25, [*SUDO, row(160, 100, 0, "helper")]),
        (0.35, SUDO),
        (2.0, MONITOR),
        (2.1, POWER),
        (4.0, []),
    )
    engine = FakeEngine(world, timing=lambda start: (0.0, 0.0))
    engine.payload.end = 4.0
    found = run(engine)
    assert 160 not in {r.pid for r in found.records}
    assert (found.forced, found.cleanup) == (None, "verified")


# --- the time bounds ---------------------------------------------------------------------------


def _slowest(
    payload: tracking.Payload, runtime_s: float, hang: bool, took: float = 1.99
) -> tracking.Tracked:
    """Each phase uses its whole allowance: the first sign at 178 s and the payload 3 s
    later, the latest each is sure to be seen in time, then a sudo that never ends and
    ignores SIGTERM. Every listing takes 1.99 s, so each change is observed as late as a
    successful listing allows; with ``hang``, the listing running at the runtime
    deadline hangs instead, and the loop acts only once it is killed and reaped."""
    world = phases(
        (0.0, SUDO),
        (178.0, MONITOR),
        (181.0, [*MONITOR, row(102, 101, payload.uid, payload.name)]),
    )
    state = {"identified_by": math.inf}

    def timing(start: float) -> tuple[float, float]:
        if hang and start + took >= state["identified_by"] + runtime_s:
            return (0.0, math.inf)
        if start >= 181.0:
            state["identified_by"] = min(state["identified_by"], start + took)
        return (0.0, took)

    engine = FakeEngine(world, timing=timing)
    engine.payload.term_after = None
    return run(engine, payload=payload, runtime_s=runtime_s)


@pytest.mark.parametrize("hang", [False, True], ids=["slow listings", "a listing hangs"])
@pytest.mark.parametrize(
    ("payload", "runtime_s", "bound"), [(S3, 10.0, 208.0), (S4, 20.0, 218.0)], ids=["S3", "S4"]
)
def test_a_payload_command_stays_within_its_time_bound(payload, runtime_s, bound, hang):
    found = _slowest(payload, runtime_s, hang)
    assert found.forced == ("tracking_failed" if hang else "runtime_deadline")
    assert found.stop == "killed"
    assert found.duration_s <= bound


def test_the_listings_stay_within_five_a_second():
    found = run(FakeEngine(phases((0.0, SUDO)), timing=lambda start: (0.0, 0.0)))
    assert found.forced == "auth_failed"
    assert len(found.listings) <= 5 * 184 + 2


# --- the review of #348: listings closed, exceptions, EPERM, zombies, bounds ------------------


def test_every_listing_is_closed_once_it_is_read():
    # A listing holds two pipes; left open until the payload ends, 120 of them exhaust
    # macOS's default limit of 256 open files in about 24 s at the prompt.
    world, end = normal_world(auth=30.0)
    engine = FakeEngine(world, listing_fails=lambda start: 40.0 < start < 40.3)
    engine.payload.end = end
    run(engine)
    assert len(engine.children) > 100
    assert all(child.closed for child in engine.children)


def test_a_listing_that_hangs_or_fails_is_closed_too():
    engine = FakeEngine(phases((0.0, SUDO)), timing=lambda start: (0.0, math.inf))
    run(engine)
    assert engine.children and all(child.closed for child in engine.children)


STOPPED_AT_3 = phases((0.0, SUDO), (2.0, MONITOR), (2.3, POWER), (3.02, []))


def test_a_ctrl_c_inside_the_loop_is_a_cancellation_with_its_stop_and_listing():
    engine = FakeEngine(STOPPED_AT_3)
    engine.raises = [(3.0, KeyboardInterrupt())]
    try:
        found = run(engine)
    except KeyboardInterrupt:  # left alone, it would stop the whole test session
        pytest.fail("the Ctrl-C left the loop without its stop and listing")
    assert found.cancelled and found.stop == "terminated"
    assert engine.payload.signals[0][1] == signal.SIGTERM
    assert found.cleanup == "verified"
    assert engine.listings[-1][0] >= 3.0, "the final listing ran after the stop"


def test_an_error_inside_the_loop_stops_the_payload_and_lists_before_it_leaves():
    engine = FakeEngine(STOPPED_AT_3)
    problem = RuntimeError("a bug in the loop")
    engine.raises = [(3.0, problem)]
    with pytest.raises(tracking.Unfinished) as stopped:
        run(engine)
    assert stopped.value.__cause__ is problem
    found = stopped.value.tracked
    assert found.cancelled and found.stop == "terminated" and found.cleanup == "verified"
    assert engine.payload.signals[0][1] == signal.SIGTERM
    assert all(child.closed for child in engine.children)


def test_a_system_exit_inside_the_loop_is_unfinished_with_its_survivors_kept():
    # Round 2: it leaves as Unfinished, so what the final listing found reaches the note.
    engine = FakeEngine(phases((0.0, SUDO), (2.0, MONITOR), (2.3, POWER)))
    leave = SystemExit(3)
    engine.raises = [(3.0, leave)]
    with pytest.raises(tracking.Unfinished) as stopped:
        run(engine)
    assert stopped.value.__cause__ is leave
    found = stopped.value.tracked
    assert found.cleanup == "survivor" and found.survivors
    assert engine.payload.signals[0][1] == signal.SIGTERM
    assert engine.listings[-1][0] >= 3.0, "the final listing ran before it left"


LINGERS = phases((0.0, SUDO), (2.0, MONITOR), (2.3, POWER))


def test_an_error_in_the_stop_after_one_in_the_loop_still_kills_lists_and_keeps_both():
    engine = FakeEngine(LINGERS)
    engine.payload.term_after = None  # it ignores SIGTERM, so the stop waits its 3 s
    first, second = RuntimeError("a bug in the loop"), RuntimeError("a bug in the stop")
    engine.raises = [(3.0, first), (4.0, second)]
    with pytest.raises(tracking.Unfinished) as stopped:
        run(engine)
    assert stopped.value.__cause__ is first, "the first error is the cause"
    assert stopped.value.__context__ is second, "the second is kept"
    assert [signum for _, signum in engine.payload.signals] == [signal.SIGTERM, signal.SIGKILL]
    assert stopped.value.tracked.stop == "killed"
    assert engine.listings[-1][0] >= 4.0, "the final listing ran after the kill"


def test_a_second_ctrl_c_in_the_stop_is_still_a_cancellation_with_the_kill_and_listing():
    engine = FakeEngine(phases((0.0, SUDO), (2.0, MONITOR), (2.3, POWER), (6.0, [])))
    engine.payload.term_after = None
    engine.raises = [(3.0, KeyboardInterrupt()), (4.0, KeyboardInterrupt())]
    try:
        found = run(engine)
    except KeyboardInterrupt:
        pytest.fail("a Ctrl-C in the stop escaped the tracking")
    assert found.cancelled and found.stop == "killed"
    assert [signum for _, signum in engine.payload.signals] == [signal.SIGTERM, signal.SIGKILL]
    assert engine.listings[-1][0] >= 4.0


def test_an_error_in_the_stop_alone_still_kills_lists_and_is_unfinished():
    engine = FakeEngine(LINGERS)
    engine.payload.term_after = None
    problem = RuntimeError("a bug in the stop")
    engine.raises = [(3.0, KeyboardInterrupt()), (4.0, problem)]
    with pytest.raises(tracking.Unfinished) as stopped:
        run(engine)
    assert stopped.value.__cause__ is problem
    assert [signum for _, signum in engine.payload.signals] == [signal.SIGTERM, signal.SIGKILL]
    assert engine.listings[-1][0] >= 4.0


def test_an_error_as_the_payload_ends_under_sigterm_needs_no_kill():
    engine = FakeEngine(LINGERS)  # the payload ends 0.05 s after SIGTERM
    first, second = RuntimeError("a bug in the loop"), RuntimeError("a bug in the stop")
    engine.raises = [(3.0, first), (3.05, second)]
    with pytest.raises(tracking.Unfinished) as stopped:
        run(engine)
    assert stopped.value.tracked.stop == "terminated"
    assert [signum for _, signum in engine.payload.signals] == [signal.SIGTERM]


def test_an_error_in_the_stop_then_eperm_on_the_kill_still_lists_by_id():
    engine = FakeEngine(
        phases((0.0, SUDO), (2.0, MONITOR), (2.3, [row(100, 50, SERVICE, "sqlite3")]))
    )
    engine.payload.term_after = None
    engine.payload.eperm_from = 3.5
    engine.raises = [(3.0, RuntimeError("a bug")), (4.0, RuntimeError("another"))]
    with pytest.raises(tracking.Unfinished) as stopped:
        run(engine, payload=S3, runtime_s=10.0)
    found = stopped.value.tracked
    assert found.stop == "eperm"
    assert [(s.pid, s.name) for s in found.survivors] == [(100, "sqlite3")]


def test_a_third_error_in_the_kills_reap_is_passed_over_and_the_listing_runs():
    engine = FakeEngine(LINGERS)
    engine.payload.term_after, engine.payload.kill_after = None, None
    first = RuntimeError("one")
    engine.raises = [(3.0, first), (4.0, RuntimeError("two")), (4.5, RuntimeError("three"))]
    with pytest.raises(tracking.Unfinished) as stopped:
        run(engine)
    assert stopped.value.__cause__ is first
    assert stopped.value.tracked.stop == "abandoned"
    assert engine.listings[-1][0] >= 4.5


def test_an_error_in_the_final_listing_kills_that_listing_and_counts_it_failed():
    world, end = normal_world()
    engine = FakeEngine(world, timing=lambda start: (0.0, 1.5) if start >= end else (0.0, 0.05))
    engine.payload.end = end
    problem = RuntimeError("a bug while listing")
    # The listing at 3.4 s collects the exit; the final one starts at 4.9 s and takes 1.5 s.
    engine.raises = [(end + 2.2, problem)]
    with pytest.raises(tracking.Unfinished) as stopped:
        run(engine)
    assert stopped.value.__cause__ is problem
    found = stopped.value.tracked
    assert found.cleanup == "listing_failed"
    assert found.listings[-1][1], "P1's record counts it as a failed listing"
    last = engine.children[-1]
    assert [signum for _, signum in last.signals] == [signal.SIGKILL] and last.closed


def test_an_error_inside_the_loop_after_the_payload_ended_needs_no_stop():
    world, end = normal_world()
    engine = FakeEngine(world)
    engine.payload.end = 2.5
    engine.raises = [(2.55, RuntimeError("a bug"))]
    with pytest.raises(tracking.Unfinished) as stopped:
        run(engine)
    assert stopped.value.tracked.stop is None and engine.payload.signals == []
    assert stopped.value.tracked.returncode == 0


def test_after_eperm_a_spawned_process_no_listing_showed_is_still_found():
    # The first listing fails, so no listing ever showed the spawned process's start time;
    # after EPERM the final listing shows it running the payload directly.
    world = phases((0.0, [row(100, 50, SERVICE, "sqlite3")]))
    engine = FakeEngine(world, listing_fails=lambda start: start == 0.0)
    engine.payload.eperm_from = 0.0
    found = run(engine, payload=S3, runtime_s=10.0)
    assert (found.forced, found.stop) == ("tracking_failed", "eperm")
    assert found.cleanup == "survivor"
    assert [(s.pid, s.uid, s.name) for s in found.survivors] == [(100, SERVICE, "sqlite3")]


def test_after_eperm_a_spawned_process_gone_by_the_final_listing_is_verified():
    world = phases((0.0, SUDO), (2.0, [row(100, 50, SERVICE, "sqlite3")]), (13.0, []))
    engine = FakeEngine(world)
    engine.timing = lambda start: (1.5, 2.0) if engine.payload.closed else (0.0, 0.05)
    engine.payload.eperm_from = 2.0
    found = run(engine, payload=S3, runtime_s=10.0)
    assert (found.stop, found.cleanup, found.survivors) == ("eperm", "verified", ())


def test_after_eperm_a_zombie_is_not_a_survivor():
    # The spawned process ended before the final listing but is not reaped yet: ps shows it
    # with its ID and start time and the command <defunct>.
    world = phases(
        (0.0, SUDO),
        (2.0, [row(100, 50, SERVICE, "sqlite3")]),
        (13.0, [row(100, 50, SERVICE, "<defunct>")]),
    )
    engine = FakeEngine(world)
    engine.timing = lambda start: (1.5, 2.0) if engine.payload.closed else (0.0, 0.05)
    engine.payload.eperm_from = 2.0
    found = run(engine, payload=S3, runtime_s=10.0)
    assert (found.stop, found.cleanup, found.survivors) == ("eperm", "verified", ())


def test_a_zombie_is_never_recorded_as_an_identity():
    world = phases(
        (0.0, SUDO), (2.0, MONITOR), (2.3, POWER), (3.0, [*MONITOR, row(102, 101, 0, "<defunct>")])
    )
    engine = FakeEngine(world)
    engine.payload.end = 3.5
    found = run(engine)
    assert all("<defunct>" not in {name for _, name in r.identities} for r in found.records)


def test_a_burst_past_the_cap_read_after_the_exit_is_the_output_cap():
    world, end = normal_world()
    engine = FakeEngine(world)
    engine.payload.end, engine.payload.burst_at_exit = end, True
    found = run(engine)
    assert found.forced == "output_cap"


def test_a_sudo_that_could_not_start_is_never_a_cancellation():
    # The flag turns true once the start was tried: the start's own failure decides.
    engine = FakeEngine(phases((0.0, [])), spawn_fails=True)
    checks = iter([False])
    found = run(engine, cancelled=lambda: next(checks, True))
    assert (found.started, found.cancelled) == (False, False)


def test_no_payload_starts_once_the_run_is_cancelled():
    # The GPT audit, pass 1, G1-01: a payload started after the flag ran until the first
    # pass saw it, then took the whole stop sequence. Nothing starts, so nothing is listed.
    # Every field is pinned (the review of #326, round 1, M6): a cleanup of listing_failed
    # here would print the unverified-stop note for a run stopped before its first payload.
    engine = FakeEngine(phases((0.0, [])))
    tried: list[bool] = []
    engine.start_payload = lambda: tried.append(True)  # type: ignore[method-assign]
    found = run(engine, cancelled=lambda: True)
    assert tried == [] and engine.listings == []
    assert found == tracking.Tracked(
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


def test_the_duration_is_measured_from_the_payloads_own_start():
    world, end = normal_world()
    engine = FakeEngine(world)
    engine.t = 1000.0
    engine.world = lambda t: world(t - 1000.0)
    engine.payload.end = 1000.0 + end
    found = run(engine)
    assert found.duration_s == pytest.approx(end, abs=0.25)


def test_the_whole_elevated_path_makes_at_most_2135_listings_and_takes_at_most_642_s():
    # Decision 2's bounds: P1 once as the check, at most five a second while S3 or S4
    # runs, and once after each; S1 13 s, S2 184 s, S3 208 s, a listing 3 s, S4 218 s, a
    # listing 3 s and S5 13 s. The payloads' figures are measured here on the fake clock.
    count = _slowest(S3, 10.0, hang=False)
    power = _slowest(S4, 20.0, hang=False)
    listings = 1 + len(count.listings) + len(power.listings)
    assert listings <= 2135
    assert 13 + 184 + count.duration_s + 3 + power.duration_s + 3 + 13 <= 642


def test_instant_listings_over_the_longest_phases_still_keep_to_2135():
    # Round 2: slow listings are few; instant ones are the most the 200 ms spacing allows.
    count = _slowest(S3, 10.0, hang=False, took=0.0)
    power = _slowest(S4, 20.0, hang=False, took=0.0)
    listings = 1 + len(count.listings) + len(power.listings)
    assert 1900 <= listings <= 2135, listings


# --- the review of #326, round 2 -----------------------------------------------------------------


def test_the_listing_a_pass_has_due_as_the_flag_turns_true_still_runs_and_records():
    # n5: the loop reads the flag after its pass's listing, so a listing already due when
    # the flag turns true still starts. It records what appeared since the last one, here a
    # sandbox-exec, and the final listing after the stop names it when it survives. Read
    # first, the flag would start the stop one listing sooner and leave that process
    # unrecorded. So two listings start after the flag: the pass's and the final one.
    world = phases(
        (0.0, SUDO),
        (2.0, MONITOR),
        (2.3, POWER),
        (2.9, [*POWER, row(103, 101, 0, "sandbox-exec")]),
        (3.08, [row(103, 1, 0, "sandbox-exec")]),
    )
    engine = FakeEngine(world)
    found = run(engine, cancelled=lambda: engine.t >= 2.95)
    after = [start for start, _ in engine.listings if start >= 2.95]
    assert after == pytest.approx([3.0, 3.1])
    assert found.cancelled and found.cleanup == "survivor"
    assert [survivor.pid for survivor in found.survivors] == [103]
