"""The payload runner through the chokepoint's real engine (docs/VOLTRY_MAC_SPEC.md,
Decision 2, "Stopping a payload"; Test strategy part 3, "Process behavior").

The loop itself is tested on a virtual clock in test_tracking_loop.py. Here it runs real
processes: the allow-listed P1 lists this Mac's processes, and a stand-in script takes
the place of sudo, since no test ever runs sudo. The clocks are shortened so each test
takes a second or two; the pipes, the output cap, the signals, the reaping and P1's
command record are the real ones.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import textwrap
import threading
import time

import pytest

from voltry_mac import allowlist, spawn, tracking

PY = sys.executable
LIVE = pytest.mark.skipif(sys.platform != "darwin", reason="P1 is macOS's ps")


def program(code: str) -> list[str]:
    return [PY, "-c", textwrap.dedent(code)]


@pytest.fixture
def stand_in(monkeypatch):
    """Replace one command's argv; everything else keeps its allow-listed template."""
    real = spawn.Runner._checked_argv
    chosen: dict[str, list[str]] = {}

    def checked(self, command_id, *, broker=False):
        if command_id in chosen:
            return list(chosen[command_id])
        return real(self, command_id, broker=broker)

    monkeypatch.setattr(spawn.Runner, "_checked_argv", checked)
    return chosen.__setitem__


@pytest.fixture
def quick(monkeypatch):
    monkeypatch.setattr(tracking, "AUTH_S", 0.6)
    monkeypatch.setattr(tracking, "TERM_WAIT_S", 0.5)


class RefusingPopen:
    def __init__(self, *args, **kwargs):
        raise AssertionError("a process was started")


@pytest.mark.parametrize("command_id", ["S1", "S2", "S2n", "S5", "C1", "P1", "O1", "X1"])
def test_only_a_payload_goes_through_the_payload_runner(monkeypatch, command_id):
    monkeypatch.setattr(subprocess, "Popen", RefusingPopen)
    with pytest.raises(spawn.Refused):
        spawn.Runner().payload(command_id, uid=0)


def test_each_payload_is_identified_by_its_own_name():
    assert tracking.PAYLOAD_NAMES == {
        "S3": "sqlite3",
        "S3n": "sqlite3",
        "S4": "powermetrics",
        "S4n": "powermetrics",
    }


@LIVE
def test_a_payload_that_ends_on_its_own(stand_in):
    stand_in("S4", program("print('five samples')"))
    runner = spawn.Runner()
    run = runner.payload("S4", uid=0)
    assert (run.command_id, run.started, run.forced, run.returncode) == ("S4", True, None, 0)
    assert run.stdout == "five samples\n"
    assert (run.cleanup, run.survivors, run.cancelled) == ("verified", (), False)
    (p1,) = runner.records()
    assert (p1.id, p1.failed_runs) == ("P1", 0) and p1.runs >= 2, "polls and the final one"
    assert not [r for r in runner.records() if r.id == "S4"], "the broker notes the payload"


@LIVE
def test_the_clock_stops_a_payload_with_sigterm_and_the_listing_verifies_it(stand_in, quick):
    stand_in("S4", program("import time; time.sleep(30)"))
    started = time.monotonic()
    run = spawn.Runner().payload("S4", uid=0)
    assert (run.forced, run.returncode, run.cleanup) == (
        "auth_failed",
        -signal.SIGTERM,
        "verified",
    )
    assert time.monotonic() - started < 10


@LIVE
def test_a_payload_that_closes_its_pipes_and_keeps_running_is_still_stopped(stand_in, quick):
    stand_in("S4", program("import os, time; os.close(1); os.close(2); time.sleep(30)"))
    run = spawn.Runner().payload("S4", uid=0)
    assert (run.forced, run.returncode, run.cleanup) == (
        "auth_failed",
        -signal.SIGTERM,
        "verified",
    )


@LIVE
def test_a_payload_that_ignores_sigterm_is_killed(stand_in, quick):
    code = "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)"
    stand_in("S4", program(code))
    run = spawn.Runner().payload("S4", uid=0)
    assert (run.forced, run.returncode, run.cleanup) == (
        "auth_failed",
        -signal.SIGKILL,
        "verified",
    )


@LIVE
@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_output_past_the_cap_on_either_stream_stops_the_payload(stand_in, stream):
    size = spawn.OUTPUT_CAP + 10
    code = (
        f"import sys, time; sys.{stream}.write('x' * {size}); sys.{stream}.flush(); time.sleep(30)"
    )
    stand_in("S4", program(code))
    run = spawn.Runner().payload("S4", uid=0)
    assert run.forced == "output_cap"
    assert len(getattr(run, stream)) == spawn.OUTPUT_CAP


@LIVE
def test_eperm_closes_the_pipes_and_leaves_a_named_survivor(stand_in, quick, monkeypatch):
    stand_in("S4", program("import time; time.sleep(30)"))
    real = spawn._signal

    def refusing(proc, signum):
        # The stand-in payload plays sudo that executed the payload as another user.
        return False if list(proc.args[:2]) == [PY, "-c"] else real(proc, signum)

    monkeypatch.setattr(spawn, "_signal", refusing)
    run = spawn.Runner().payload("S4", uid=0)
    try:
        assert (run.forced, run.cleanup, run.returncode) == ("auth_failed", "survivor", None)
        (survivor,) = run.survivors
        assert survivor.uid == os.getuid()
        assert spawn.collect_abandoned() >= 1, "held so its exit is collected later"
    finally:
        os.kill(run.survivors[0].pid, signal.SIGKILL)
    deadline = time.monotonic() + 5
    while spawn.collect_abandoned() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert spawn.collect_abandoned() == 0, "collected without blocking once it ended"


@LIVE
def test_a_payload_that_could_not_start_still_gets_its_listing(stand_in):
    stand_in("S4", ["/nonexistent/voltry-test-sudo"])
    runner = spawn.Runner()
    run = runner.payload("S4", uid=0)
    assert (run.started, run.returncode, run.cleanup) == (False, None, "verified")
    (p1,) = runner.records()
    assert (p1.id, p1.runs, p1.failed_runs) == ("P1", 1, 0)


@LIVE
def test_a_cancellation_stops_the_payload(stand_in):
    stand_in("S4", program("import time; time.sleep(30)"))
    flag = threading.Event()
    timer = threading.Timer(0.5, flag.set)
    timer.start()
    try:
        run = spawn.Runner(cancelled=flag.is_set).payload("S4", uid=0)
    finally:
        timer.cancel()
    assert run.cancelled and run.returncode == -signal.SIGTERM
    assert run.cleanup == "verified"


def test_every_listing_is_in_p1s_record_and_a_failed_one_counts(stand_in):
    stand_in("S4", program("import time; time.sleep(30)"))
    stand_in("P1", program("import sys; sys.exit(1)"))
    runner = spawn.Runner()
    run = runner.payload("S4", uid=0)
    assert (run.forced, run.cleanup, run.returncode) == (
        "tracking_failed",
        "listing_failed",
        -signal.SIGTERM,
    )
    (p1,) = runner.records()
    assert (p1.runs, p1.failed_runs) == (2, 2), "the poll and the final listing"


def test_a_ps_that_hangs_is_killed_at_its_deadline(stand_in, monkeypatch):
    monkeypatch.setattr(tracking, "LISTING_S", 0.4)
    stand_in("S4", program("import time; time.sleep(30)"))
    stand_in("P1", program("import time; time.sleep(30)"))
    started = time.monotonic()
    run = spawn.Runner().payload("S4", uid=0)
    assert (run.forced, run.cleanup) == ("tracking_failed", "listing_failed")
    assert time.monotonic() - started < 6


# --- PayloadRun, as the runner now fills it ----------------------------------------------------


def payload_run(**changes: object) -> spawn.PayloadRun:
    fields: dict[str, object] = {
        "command_id": "S4",
        "started": True,
        "forced": None,
        "returncode": 0,
        "stdout": "",
        "stderr": "",
        "cleanup": "verified",
        "duration_ms": 1,
    }
    fields.update(changes)
    return spawn.PayloadRun(**fields)  # type: ignore[arg-type]


SURVIVOR = tracking.Survivor(pid=101, uid=0, started="Sat Sep 26 12:00:00 2026", name="sudo")


def test_survivors_are_named_exactly_when_the_cleanup_is_survivor():
    payload_run(forced="runtime_deadline", cleanup="survivor", survivors=(SURVIVOR,))
    with pytest.raises(ValueError):
        payload_run(forced="runtime_deadline", cleanup="survivor")
    with pytest.raises(ValueError):
        payload_run(survivors=(SURVIVOR,))


def test_a_cancelled_payload_may_have_no_exit_status():
    payload_run(returncode=None, cancelled=True)
    with pytest.raises(ValueError):
        payload_run(returncode=None)


# --- the review of #348 ------------------------------------------------------------------------


def _open_files() -> int:
    return len(os.listdir("/dev/fd"))


@LIVE
def test_each_listing_closes_its_pipes_once_read(stand_in, monkeypatch):
    # Before the fix every listing kept its two pipes until the payload ended: 120 of them
    # exhaust macOS's default limit of 256 open files in about 24 s at the prompt.
    stand_in("S4", program("import time; time.sleep(3)"))
    at_close: list[int] = []
    real_close = spawn._Engine.close

    def close(self: spawn._Engine) -> None:
        at_close.append(_open_files())
        real_close(self)

    monkeypatch.setattr(spawn._Engine, "close", close)
    before = _open_files()
    runner = spawn.Runner()
    run = runner.payload("S4", uid=0)
    (p1,) = runner.records()
    assert run.returncode == 0 and p1.runs >= 10
    assert at_close[0] <= before + 3, "the selector and the payload's two pipes, no more"
    assert _open_files() <= before


@LIVE
def test_a_payload_that_writes_as_it_runs_is_read_as_it_goes(stand_in):
    code = """
    import time
    for i in range(30):
        print(f"sample {i}", flush=True)
        time.sleep(0.05)
    """
    stand_in("S4", program(code))
    runner = spawn.Runner()
    run = runner.payload("S4", uid=0)
    assert (run.forced, run.returncode) == (None, 0)
    assert run.stdout.splitlines() == [f"sample {i}" for i in range(30)]
    (p1,) = runner.records()
    assert p1.runs >= 5 and p1.failed_runs == 0


@LIVE
def test_the_payload_gets_the_fixed_environment_no_stdin_and_no_inherited_file(
    stand_in, monkeypatch
):
    monkeypatch.setenv("VOLTRY_MAC_PARENT_ONLY", "1")  # would reach a child that inherits
    read_end, write_end = os.pipe()
    os.set_inheritable(write_end, True)  # a file this process would pass on without close_fds
    try:
        code = f"""
        import json, os, stat
        null, fd0 = os.stat(os.devnull), os.fstat(0)
        try:
            os.fstat({write_end})
            inherited = True
        except OSError:
            inherited = False
        print(json.dumps({{
            "env": sorted(os.environ),
            "stdin": stat.S_ISCHR(fd0.st_mode) and fd0.st_rdev == null.st_rdev,
            "inherited": inherited,
        }}))
        """
        stand_in("S4", program(code))
        found = json.loads(spawn.Runner().payload("S4", uid=0).stdout)
    finally:
        os.close(read_end)
        os.close(write_end)
    # macOS's CoreFoundation adds its text-encoding variable inside the child itself.
    names = set(found["env"]) - {"__CF_USER_TEXT_ENCODING"}
    assert names == set(spawn.ENVIRONMENT) and "VOLTRY_MAC_PARENT_ONLY" not in names
    assert (found["stdin"], found["inherited"]) == (True, False)


@pytest.mark.parametrize("command_id", ["S3", "S3n", "S4", "S4n"])
def test_the_payload_runner_starts_the_allow_listed_argvs(monkeypatch, command_id):
    seen: dict[str, list[str]] = {}

    class Engine(spawn._Engine):
        def __init__(self, payload, listing, cap) -> None:
            seen["payload"], seen["listing"] = list(payload), list(listing)
            super().__init__(payload, listing, cap)

        def start_payload(self):
            return None

        def start_listing(self):
            return None

    monkeypatch.setattr(spawn, "_Engine", Engine)
    monkeypatch.setattr(subprocess, "Popen", RefusingPopen)
    run = spawn.Runner().payload(command_id, uid=0)
    assert (run.started, run.cleanup) == (False, "listing_failed")
    assert seen == {
        "payload": list(allowlist.resolve(command_id)),
        "listing": list(allowlist.resolve("P1")),
    }


def _breaks_on_the_third_listing(monkeypatch, error: BaseException) -> None:
    real = tracking.Tracker.apply
    calls: list[int] = []

    def apply(self, rows, now):
        calls.append(1)
        if len(calls) == 3:
            raise error
        return real(self, rows, now)

    monkeypatch.setattr(tracking.Tracker, "apply", apply)


def _pid_writer(tmp_path) -> tuple[list[str], object]:
    pidfile = tmp_path / "pid"
    code = f"import os, time; open({str(pidfile)!r}, 'w').write(str(os.getpid())); time.sleep(30)"
    return program(code), pidfile


def _gone(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False


@LIVE
def test_an_error_inside_the_tracking_stops_the_payload_and_says_what_it_found(
    stand_in, monkeypatch, tmp_path
):
    argv, pidfile = _pid_writer(tmp_path)
    stand_in("S4", argv)
    _breaks_on_the_third_listing(monkeypatch, RuntimeError("a bug in the tracking"))
    runner = spawn.Runner()
    with pytest.raises(spawn.PayloadInterrupted) as stopped:
        runner.payload("S4", uid=0)
    assert isinstance(stopped.value.__cause__, RuntimeError)
    run = stopped.value.run
    assert run.cancelled and run.cleanup == "verified"
    assert _gone(int(pidfile.read_text()))
    (p1,) = runner.records()
    assert p1.runs >= 4, "the polls and the final listing are in P1's record"


@LIVE
def test_a_ctrl_c_inside_the_tracking_is_a_cancellation_that_stops_the_payload(
    stand_in, monkeypatch, tmp_path
):
    argv, pidfile = _pid_writer(tmp_path)
    stand_in("S4", argv)
    _breaks_on_the_third_listing(monkeypatch, KeyboardInterrupt())
    try:
        run = spawn.Runner().payload("S4", uid=0)
    except KeyboardInterrupt:
        pytest.fail("the Ctrl-C left the payload runner without its stop and listing")
    assert run.cancelled and run.cleanup == "verified"
    assert _gone(int(pidfile.read_text()))


def test_a_payload_runs_repr_names_no_process():
    survivor = tracking.Survivor(101, 0, "Sat Sep 26 12:00:00 2026", "Jane's Helper")
    run = spawn.PayloadRun("S4", True, None, 0, "", "", "survivor", 10, (survivor,))
    assert "Jane" not in repr(run)


@LIVE
@pytest.mark.parametrize("extra", [0, 1], ids=["exactly the cap", "one byte past it"])
def test_the_output_cap_starts_one_byte_past_it(stand_in, extra):
    size = spawn.OUTPUT_CAP + extra
    stand_in("S4", program(f"import sys; sys.stdout.write('x' * {size})"))
    run = spawn.Runner().payload("S4", uid=0)
    assert (run.forced == "output_cap") is bool(extra)
    assert len(run.stdout) == spawn.OUTPUT_CAP


@LIVE
def test_bytes_that_are_not_utf_8_are_replaced(stand_in):
    stand_in("S4", program("import sys; sys.stdout.buffer.write(b'a\\xffb')"))
    assert spawn.Runner().payload("S4", uid=0).stdout == "a" + chr(0xFFFD) + "b"


# --- the review of #348, round 2: what the engine holds ------------------------------------------


def test_the_engine_lets_go_of_the_listings_it_has_closed_and_reaped():
    engine = spawn._Engine(["/bin/sleep", "5"], ["/usr/bin/true"], 1024)
    try:
        for _ in range(20):
            child = engine.start_listing()
            assert child is not None
            child.proc.wait()
            child.close()
            assert child.closed
        assert len(engine._children) <= 2, "each closed and reaped listing is let go"
    finally:
        engine.close()


def test_the_prune_never_collects_the_payloads_exit():
    # After EPERM the payload's exit must stay uncollected until the final listing has run,
    # so no other process can take its ID first.
    engine = spawn._Engine(["/usr/bin/true"], ["/usr/bin/true"], 1024)
    try:
        payload = engine.start_payload()
        assert payload is not None
        time.sleep(0.3)
        payload.close()
        listing = engine.start_listing()
        assert listing is not None
        assert payload.proc.returncode is None, "the prune collected the payload's exit"
    finally:
        engine.close()
        spawn.collect_abandoned()


@LIVE
def test_a_closed_pipe_is_not_read_again(stand_in, monkeypatch):
    # After EOF a pipe leaves the selector; left on it, every select returns at once and
    # the loop spins for the whole run.
    stand_in("S4", program("import os, time; os.close(1); os.close(2); time.sleep(1)"))
    reads: list[int] = []
    real = spawn._Child.read

    def read(self, key, buffer):
        reads.append(1)
        return real(self, key, buffer)

    monkeypatch.setattr(spawn._Child, "read", read)
    run = spawn.Runner().payload("S4", uid=0)
    assert run.returncode == 0
    assert len(reads) < 200


def test_the_engine_closes_its_selector(monkeypatch):
    engines: list[spawn._Engine] = []

    class Engine(spawn._Engine):
        def __init__(self, payload, listing, cap) -> None:
            super().__init__(payload, listing, cap)
            engines.append(self)

        def start_payload(self):
            return None

        def start_listing(self):
            return None

    monkeypatch.setattr(spawn, "_Engine", Engine)
    spawn.Runner().payload("S4", uid=0)
    assert engines[0]._selector.get_map() is None
