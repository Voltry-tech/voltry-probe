"""The spawn chokepoint (docs/VOLTRY_MAC_SPEC.md, "Architecture", "Environment for every
child", "Stopping a payload" and "Time bounds").

The engine is exercised with small Python programs standing in for Apple's tools, run
through the private ``_execute`` with short deadlines; ``run`` is exercised for what it
refuses and for how it calls the engine. Timing assertions keep wide margins so a slow
CI runner does not flake.
"""

from __future__ import annotations

import contextlib
import errno
import inspect
import json
import os
import signal
import subprocess
import sys
import textwrap
import time

import pytest

from voltry_mac import allowlist, spawn, tracking

PY = sys.executable


def program(code: str) -> list[str]:
    return [PY, "-c", textwrap.dedent(code)]


@contextlib.contextmanager
def sigterm_ignored_by_children():
    """Children started inside ignore SIGTERM from their first instruction: an ignored
    disposition survives exec, so no test races the child's interpreter startup."""
    previous = signal.signal(signal.SIGTERM, signal.SIG_IGN)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


def execute(argv, **kwargs):
    kwargs.setdefault("command_id", "C1")
    kwargs.setdefault("deadline_s", 5.0)
    kwargs.setdefault("stop", spawn.Stop.TERM_THEN_KILL)
    return spawn._execute(argv, **kwargs)


# --- the fixed environment and the child's plumbing ---------------------------------------


def test_the_environment_is_exactly_the_spec_pair():
    assert dict(spawn.ENVIRONMENT) == {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LC_ALL": "en_US.UTF-8",
    }
    with pytest.raises(TypeError):
        spawn.ENVIRONMENT["HOME"] = "/"  # type: ignore[index]


def test_a_child_sees_the_fixed_environment_and_nothing_inherited(monkeypatch):
    monkeypatch.setenv("VOLTRY_CANARY", "leaked")
    monkeypatch.setenv("HOME", "/Users/canary")
    result = execute(program("import json, os; print(json.dumps(dict(os.environ)))"))
    env = json.loads(result.stdout)
    assert env["PATH"] == "/usr/bin:/bin:/usr/sbin:/sbin"
    assert env["LC_ALL"] == "en_US.UTF-8"
    assert "VOLTRY_CANARY" not in env and "HOME" not in env
    # The OS or the interpreter may add its own bookkeeping; nothing of the caller's.
    assert set(env) - {"PATH", "LC_ALL"} <= {"__CF_USER_TEXT_ENCODING", "LC_CTYPE"}


def test_a_child_reads_end_of_input_immediately():
    result = execute(program("import sys; print(repr(sys.stdin.read()))"), deadline_s=5.0)
    assert (result.ending, result.stdout) == (spawn.Ending.EXITED, "''\n")


def test_undecodable_bytes_are_replaced_not_raised():
    result = execute(program("import sys; sys.stdout.buffer.write(b'ok\\xff\\xfe')"))
    assert result.stdout == "ok��"


def test_stdout_and_stderr_are_kept_apart():
    result = execute(program("import sys; print('out'); print('err', file=sys.stderr)"))
    assert (result.stdout, result.stderr) == ("out\n", "err\n")


# --- how a command ended --------------------------------------------------------------------


def test_an_ordinary_exit_is_recorded_with_its_status():
    ok = execute(program("print('hi')"))
    failed = execute(program("import sys; sys.exit(3)"))
    assert (ok.ending, ok.returncode, ok.ok) == (spawn.Ending.EXITED, 0, True)
    assert (failed.ending, failed.returncode, failed.ok) == (spawn.Ending.EXITED, 3, False)


def test_a_signal_the_tool_did_not_send_is_its_own_ending():
    # SIGUSR1 ends the child without a core dump, so no crash report is left behind.
    result = execute(program("import os, signal; os.kill(os.getpid(), signal.SIGUSR1)"))
    assert result.ending is spawn.Ending.SIGNALED
    assert result.returncode == -signal.SIGUSR1 and not result.ok


def test_a_missing_program_is_not_started_and_marked_missing(tmp_path):
    result = execute([str(tmp_path / "absent")])
    assert result.ending is spawn.Ending.NOT_STARTED
    assert result.missing_executable and result.returncode is None and not result.ok


def test_a_program_that_cannot_be_executed_is_not_started_but_not_missing(tmp_path):
    plain = tmp_path / "plain"
    plain.write_text("not a program\n")
    plain.chmod(0o644)
    result = execute([str(plain)])
    assert result.ending is spawn.Ending.NOT_STARTED and not result.missing_executable


def test_the_deadline_stops_a_hung_command():
    started = time.monotonic()
    result = execute(program("import time; time.sleep(30)"), deadline_s=0.3)
    elapsed = time.monotonic() - started
    assert result.ending is spawn.Ending.DEADLINE and result.reaped
    assert elapsed < 5, elapsed
    assert 250 <= result.duration_ms < 5000


def test_a_command_that_ignores_sigterm_gets_sigkill_after_the_grace():
    started = time.monotonic()
    with sigterm_ignored_by_children():
        result = execute(program("import time; time.sleep(30)"), deadline_s=0.5, grace_s=0.5)
    elapsed = time.monotonic() - started
    assert result.ending is spawn.Ending.DEADLINE and result.reaped
    assert result.returncode == -signal.SIGKILL
    assert 0.9 <= elapsed < 6, elapsed


def test_a_listing_is_killed_at_its_deadline_without_a_grace():
    code = """
        import signal, time
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        time.sleep(30)
    """
    started = time.monotonic()
    result = execute(program(code), deadline_s=0.3, stop=spawn.Stop.KILL)
    elapsed = time.monotonic() - started
    assert result.ending is spawn.Ending.DEADLINE and result.returncode == -signal.SIGKILL
    assert elapsed < 3, elapsed


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_output_past_the_cap_stops_the_command(stream):
    code = f"""
        import sys, time
        chunk = b"x" * 65536
        for _ in range(100):
            sys.{stream}.buffer.write(chunk)
            sys.{stream}.buffer.flush()
        time.sleep(30)
    """
    result = execute(program(code), deadline_s=20, cap=1024 * 1024)
    assert result.ending is spawn.Ending.OUTPUT_CAP and result.reaped
    assert len(getattr(result, stream)) <= 1024 * 1024


def test_a_command_still_writing_past_the_cap_is_stopped_there():
    code = "import sys; sys.stdout.buffer.write(b'x' * 300000)"
    result = execute(program(code), cap=100000)
    assert result.ending is spawn.Ending.OUTPUT_CAP


def test_the_cap_still_applies_to_a_command_that_already_exited(monkeypatch):
    # Force the order: the waiting drain reads nothing, so the output is first read in the
    # pass that collects the exit, and that pass finds the cap.
    real_drain = spawn._drain

    def late_drain(selector, timeout, cap):
        if timeout > 0:
            time.sleep(0.3)
            return False
        return real_drain(selector, timeout, cap)

    monkeypatch.setattr(spawn, "_drain", late_drain)
    code = "import sys; sys.stdout.buffer.write(b'x' * 30000)"
    result = execute(program(code), cap=10000)
    assert (result.ending, result.returncode, result.reaped) == (
        spawn.Ending.OUTPUT_CAP,
        0,
        True,
    )
    assert len(result.stdout) == 10000


def test_output_exactly_at_the_cap_is_kept():
    code = "import sys; sys.stdout.buffer.write(b'x' * 100000)"
    result = execute(program(code), cap=100000)
    assert result.ending is spawn.Ending.EXITED and len(result.stdout) == 100000


def test_the_production_cap_and_stop_timings_are_the_spec_values():
    assert spawn.OUTPUT_CAP == 4 * 1024 * 1024
    assert spawn.USER_GRACE_S == 2
    assert spawn.PAYLOAD_GRACE_S == 3
    assert spawn.REAP_S == 1


# --- the pass order -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("cap_hit", "exited", "deadline_passed", "expected"),
    [
        (False, False, False, None),
        (False, True, False, "exit"),
        (False, True, True, "exit"),  # a deadline seen with the exit is ignored
        (False, False, True, spawn.Ending.DEADLINE),
        (True, False, False, spawn.Ending.OUTPUT_CAP),
        (True, True, False, spawn.Ending.OUTPUT_CAP),  # the cap is not ignored
        (True, False, True, spawn.Ending.OUTPUT_CAP),  # the cap comes first
        (True, True, True, spawn.Ending.OUTPUT_CAP),
    ],
)
def test_the_pass_order(cap_hit, exited, deadline_passed, expected):
    assert spawn._judge(cap_hit, exited, deadline_passed) == expected


# --- the payload stop, and a process the tool cannot signal ---------------------------------


def test_the_payload_stop_reports_eperm_and_stops_waiting(monkeypatch):
    proc = subprocess.Popen(  # noqa: S603 - a test-owned child
        [PY, "-c", "import time; time.sleep(30)"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
    )
    try:
        real_kill = os.kill

        def refuse(pid, sig):
            if pid == proc.pid:
                raise PermissionError(errno.EPERM, "Operation not permitted")
            real_kill(pid, sig)

        monkeypatch.setattr(os, "kill", refuse)
        started = time.monotonic()
        stopped = spawn._stop(proc, spawn.Stop.PAYLOAD)
        assert stopped.eperm and not stopped.reaped
        assert time.monotonic() - started < 1
        assert proc.stdout is not None and proc.stdout.closed
        assert proc.stderr is not None and proc.stderr.closed
    finally:
        monkeypatch.undo()
        proc.kill()
        proc.wait(timeout=5)


def test_the_payload_stop_uses_a_three_second_grace(monkeypatch):
    sent = []
    monkeypatch.setattr(spawn, "PAYLOAD_GRACE_S", 0.3)
    with sigterm_ignored_by_children():
        proc = subprocess.Popen([PY, "-c", "import time; time.sleep(30)"])  # noqa: S603
    real_kill = os.kill

    def record(pid, sig):
        sent.append(sig)
        real_kill(pid, sig)

    try:
        monkeypatch.setattr(os, "kill", record)
        stopped = spawn._stop(proc, spawn.Stop.PAYLOAD)
        assert stopped.reaped and not stopped.eperm
        assert sent == [signal.SIGTERM, signal.SIGKILL]
    finally:
        monkeypatch.undo()
        proc.kill()
        proc.wait(timeout=5)


def _sleeper() -> subprocess.Popen:
    return subprocess.Popen(  # noqa: S603 - a test-owned child
        [PY, "-c", "import time; time.sleep(30)"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
    )


def test_a_listing_that_cannot_be_signalled_is_left_and_its_pipes_closed(monkeypatch):
    proc = _sleeper()
    try:

        def refuse(pid, sig):
            raise PermissionError(errno.EPERM, "Operation not permitted")

        monkeypatch.setattr(os, "kill", refuse)
        stopped = spawn._stop(proc, spawn.Stop.KILL)
        assert stopped == spawn.Stopped(reaped=False, eperm=True)
        assert proc.stdout is not None and proc.stdout.closed
    finally:
        monkeypatch.undo()
        proc.kill()
        proc.wait(timeout=5)


def test_a_process_that_changes_identity_after_sigterm_is_left_at_sigkill(monkeypatch):
    # sudo executing the payload directly: SIGTERM reaches sudo, then the process is
    # the payload under another identity and SIGKILL meets EPERM.
    monkeypatch.setattr(spawn, "PAYLOAD_GRACE_S", 0.2)
    with sigterm_ignored_by_children():
        proc = subprocess.Popen(  # noqa: S603 - a test-owned child
            [PY, "-c", "import time; time.sleep(30)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    real_kill = os.kill

    def term_then_refuse(pid, sig):
        if sig == signal.SIGKILL:
            raise PermissionError(errno.EPERM, "Operation not permitted")
        real_kill(pid, sig)

    monkeypatch.setattr(os, "kill", term_then_refuse)
    try:
        stopped = spawn._stop(proc, spawn.Stop.PAYLOAD)
        assert stopped == spawn.Stopped(reaped=False, eperm=True)
        assert proc.stdout is not None and proc.stdout.closed
    finally:
        monkeypatch.undo()
        proc.kill()
        proc.wait(timeout=5)


def test_a_command_that_closes_its_output_still_meets_its_deadline():
    code = """
        import os, time
        os.close(1)
        os.close(2)
        time.sleep(30)
    """
    started = time.monotonic()
    result = execute(program(code), deadline_s=0.4)
    assert result.ending is spawn.Ending.DEADLINE and result.reaped
    assert time.monotonic() - started < 5


# --- run(): the allow-list is checked before anything starts --------------------------------


class RefusingPopen:
    def __init__(self, *args, **kwargs):
        raise AssertionError("a process was started")


def test_run_refuses_an_id_that_is_not_on_the_list(monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", RefusingPopen)
    with pytest.raises(spawn.Refused):
        spawn.Runner().run("C10")


def test_run_refuses_open_without_the_path_just_published(monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", RefusingPopen)
    with pytest.raises(spawn.Refused):
        spawn.Runner().run("O1")  # nothing has been published
    with pytest.raises(spawn.Refused):
        spawn.Runner().published("relative.pdf")


def test_c28_with_no_usable_interpreter_starts_nothing_and_is_a_failed_run(monkeypatch):
    # C28's outcome table, row 1: the child could not be started. The report still needs
    # its one record for C28, so the run is recorded as failed rather than refused.
    monkeypatch.setattr(subprocess, "Popen", RefusingPopen)
    monkeypatch.setattr(sys, "executable", "python3")
    runner = spawn.Runner()
    result = runner.run("C28")
    assert result.ending is spawn.Ending.NOT_STARTED and not result.missing_executable
    assert runner.records() == [spawn.CommandRecord("C28", 1, 1, 0)]


def test_run_refuses_a_template_with_a_forbidden_shape(monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", RefusingPopen)
    tampered = allowlist.Command("C8", ("/usr/bin/pmset", "-a", "sleep", "0"), "user", 10)
    table = dict(allowlist.BY_ID)
    table["C8"] = tampered
    monkeypatch.setattr(allowlist, "BY_ID", table)
    with pytest.raises(spawn.Refused):
        spawn.Runner().run("C8")


def test_a_forbidden_shape_is_refused_even_if_matching_were_broken(monkeypatch):
    # Defense in depth: the shape scan runs after the exact match and catches a writer
    # even if the table and the matcher were both wrong.
    monkeypatch.setattr(subprocess, "Popen", RefusingPopen)
    tampered = allowlist.Command("C8", ("/usr/bin/pmset", "-a", "sleep", "0"), "user", 10)
    table = dict(allowlist.BY_ID)
    table["C8"] = tampered
    monkeypatch.setattr(allowlist, "BY_ID", table)
    monkeypatch.setattr(allowlist, "match", lambda argv, **kwargs: tampered)
    with pytest.raises(spawn.Refused, match="forbidden shape"):
        spawn.Runner().run("C8")


def test_payload_commands_are_not_run_through_run(monkeypatch):
    # S2 to S4 belong to the elevation broker's own loop and clocks.
    monkeypatch.setattr(subprocess, "Popen", RefusingPopen)
    for command_id in ("S2", "S3", "S4", "S2n", "S3n", "S4n"):
        with pytest.raises(spawn.Refused):
            spawn.Runner().run(command_id)


def test_run_gives_each_command_its_argv_deadline_and_stop(monkeypatch):
    calls = []

    def fake_execute(argv, **kwargs):
        calls.append((argv, kwargs))
        return spawn.Result(kwargs["command_id"], spawn.Ending.EXITED, 0, "", "", 5, False, True)

    monkeypatch.setattr(spawn, "_execute", fake_execute)
    runner = spawn.Runner()
    runner.run("C2")
    runner.run("P1")
    runner.run("C28")
    runner.run("S1")
    (c2, c2_kwargs), (p1, p1_kwargs), (c28, c28_kwargs), (s1, s1_kwargs) = calls
    assert c2 == ["/usr/sbin/system_profiler", "-json", "SPHardwareDataType"]
    assert (c2_kwargs["deadline_s"], c2_kwargs["stop"]) == (10, spawn.Stop.TERM_THEN_KILL)
    assert (p1_kwargs["deadline_s"], p1_kwargs["stop"]) == (2, spawn.Stop.KILL)
    assert c28 == [PY, "-I", "-B", "-m", "voltry_mac.smart_iokit"]
    assert c28_kwargs["deadline_s"] == 15
    assert s1 == ["/usr/bin/sudo", "-k"] and s1_kwargs["stop"] is spawn.Stop.TERM_THEN_KILL


def test_the_engine_calls_popen_with_a_list_no_shell_and_the_environment(monkeypatch):
    seen = {}
    real_popen = subprocess.Popen

    def spy(argv, **kwargs):
        seen.update(kwargs, argv=argv)
        return real_popen(argv, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", spy)
    execute(program("pass"))
    assert isinstance(seen["argv"], list)
    assert seen.get("shell", False) is False
    assert seen["env"] == dict(spawn.ENVIRONMENT)
    assert seen["stdin"] is subprocess.DEVNULL
    assert seen["close_fds"] is True


# --- command records ------------------------------------------------------------------------


def test_records_count_runs_failures_and_total_duration(monkeypatch):
    outcomes = iter(
        [
            spawn.Result("P1", spawn.Ending.EXITED, 0, "", "", 10, False, True),
            spawn.Result("P1", spawn.Ending.DEADLINE, -9, "", "", 2000, False, True),
            spawn.Result("P1", spawn.Ending.EXITED, 0, "", "", 12, False, True),
            spawn.Result("C1", spawn.Ending.EXITED, 1, "", "", 7, False, True),
        ]
    )
    monkeypatch.setattr(spawn, "_execute", lambda argv, **kwargs: next(outcomes))
    runner = spawn.Runner()
    for command_id in ("P1", "P1", "P1", "C1"):
        runner.run(command_id)
    records = {r.id: r for r in runner.records()}
    assert (records["P1"].runs, records["P1"].failed_runs, records["P1"].duration_ms) == (
        3,
        1,
        2022,
    )
    assert (records["C1"].runs, records["C1"].failed_runs) == (1, 1)
    assert [r.id for r in runner.records()] == ["C1", "P1"], "allow-list order"


def test_a_caller_can_judge_failure_itself(monkeypatch):
    # C28 exits 2 when no controller answers, which is not a failed run by its table.
    result = spawn.Result("C28", spawn.Ending.EXITED, 2, "{}", "", 30, False, True)
    monkeypatch.setattr(spawn, "_execute", lambda argv, **kwargs: result)
    runner = spawn.Runner()
    runner.run("C28", failed=lambda r: r.ending is not spawn.Ending.EXITED)
    assert runner.records()[0].failed_runs == 0


def test_the_debug_hook_sees_templates_and_codes_never_output(monkeypatch):
    lines = []
    result = spawn.Result(
        "C28", spawn.Ending.EXITED, 0, "SECRET-OUT", "SECRET-ERR", 42, False, True
    )
    monkeypatch.setattr(spawn, "_execute", lambda argv, **kwargs: result)
    spawn.Runner(on_result=lambda r: lines.append(spawn.debug_line(r))).run("C28")
    assert lines == ["C28 <the running interpreter> -I -B -m voltry_mac.smart_iokit: exit 0, 42 ms"]
    assert "SECRET" not in lines[0] and PY not in lines[0]


def test_debug_lines_name_how_a_command_ended():
    def line(ending, code):
        return spawn.debug_line(spawn.Result("C1", ending, code, "", "", 3, False, True))

    # Never "passed", which the copy rules keep for verdicts (the copy pass's review, round 2).
    assert line(spawn.Ending.DEADLINE, -9).endswith(": ran past its deadline, then signal 9, 3 ms")
    assert line(spawn.Ending.OUTPUT_CAP, 0).endswith(
        ": went over the output cap, then exit 0, 3 ms"
    )
    assert line(spawn.Ending.SIGNALED, -6).endswith(": ended on signal 6, 3 ms")
    assert line(spawn.Ending.NOT_STARTED, None).endswith(": could not start, 3 ms")
    assert line(spawn.Ending.CANCELLED, -15).endswith(": cancelled, then signal 15, 3 ms")
    unreaped = spawn.Result("C1", spawn.Ending.DEADLINE, None, "", "", 3, False, False)
    assert spawn.debug_line(unreaped).endswith(": ran past its deadline, not reaped, 3 ms")
    eperm = spawn.Result("C1", spawn.Ending.DEADLINE, None, "", "", 3, False, False, eperm=True)
    assert spawn.debug_line(eperm).endswith(": ran past its deadline, could not be signalled, 3 ms")


# --- a real allow-listed read, where the platform has it ------------------------------------


@pytest.mark.skipif(sys.platform != "darwin", reason="sw_vers exists only on macOS")
def test_a_real_user_read_runs_through_the_chokepoint():
    result = spawn.Runner().run("C1")
    assert result.ok and "ProductVersion" in result.stdout


@pytest.mark.skipif(sys.platform == "darwin", reason="off macOS the Apple tool is absent")
def test_off_macos_an_apple_tool_is_simply_missing():
    result = spawn.Runner().run("C1")
    assert result.ending is spawn.Ending.NOT_STARTED and result.missing_executable


@pytest.fixture(autouse=True)
def _no_abandoned_leftovers():
    """Each test starts and ends with no abandoned process kept by the engine."""
    spawn._ABANDONED.clear()
    yield
    spawn._ABANDONED.clear()


# --- the #341 review: O1 opens only the file the Runner was told was published -------------


def _pdf(tmp_path, name: str = "Voltry Mac Report 2026-09-23 14.05.pdf") -> str:
    path = tmp_path / name
    path.write_bytes(b"%PDF-1.7\n")
    path.chmod(0o600)  # the output writer's mode (spec, "Output writer")
    return str(path)


def test_run_takes_no_path_from_its_caller():
    assert "published_path" not in inspect.signature(spawn.Runner.run).parameters


def test_open_runs_the_published_file_once_and_leaves_no_record(monkeypatch, tmp_path):
    calls = []

    def fake_execute(argv, **kwargs):
        calls.append(argv)
        return spawn.Result("O1", spawn.Ending.EXITED, 0, "", "", 5, False, True)

    monkeypatch.setattr(spawn, "_execute", fake_execute)
    runner = spawn.Runner()
    path = _pdf(tmp_path)
    runner.published(path)
    runner.run("O1")
    assert calls == [["/usr/bin/open", path]]
    with pytest.raises(spawn.Refused):
        runner.run("O1")  # the file is opened once
    assert runner.records() == [], "O1 runs after publication and never has a record"


def test_the_published_path_is_set_once(tmp_path):
    runner = spawn.Runner()
    runner.published(_pdf(tmp_path))
    with pytest.raises(spawn.Refused):
        runner.published(_pdf(tmp_path))


@pytest.mark.parametrize(
    "path",
    [
        "Voltry Mac Report.pdf",  # relative
        "/Users/owner/Desktop/../Desktop/Voltry Mac Report.pdf",  # not in normal form
        "//Users/owner/Desktop/Voltry Mac Report.pdf",
        "/Users/owner/Desktop/x\x00.pdf",  # a NUL byte
        "/Users/owner/Desktop/x\udc80.pdf",  # a lone surrogate
        "/usr/bin/true",  # not a PDF
        "/System/Applications/Utilities/Terminal.app",
        "/Users/owner/Desktop/evil.command",  # open runs a .command in Terminal
    ],
    ids=[
        "relative",
        "dot-dot",
        "double slash",
        "nul",
        "surrogate",
        "a program",
        "an app",
        "command",
    ],
)
def test_published_refuses_anything_but_a_plain_pdf(monkeypatch, tmp_path, path):
    # Every path "exists" as a regular 0600 file the user owns, so only the property under
    # test can refuse it.
    real = os.lstat(_pdf(tmp_path))
    monkeypatch.setattr(spawn.os, "lstat", lambda _path: real)
    with pytest.raises(spawn.Refused):
        spawn.Runner().published(path)


def test_published_refuses_a_path_where_nothing_is(tmp_path):
    with pytest.raises(spawn.Refused):
        spawn.Runner().published(str(tmp_path / "absent.pdf"))


def test_published_refuses_a_file_others_can_read(tmp_path):
    path = _pdf(tmp_path)
    os.chmod(path, 0o644)
    with pytest.raises(spawn.Refused):
        spawn.Runner().published(path)


def test_published_refuses_a_second_name_for_another_file(tmp_path):
    older = _pdf(tmp_path, "older.pdf")
    link = tmp_path / "Voltry Mac Report.pdf"
    os.link(older, link)
    with pytest.raises(spawn.Refused):
        spawn.Runner().published(str(link))


@pytest.mark.parametrize("swap", ["a link", "another file"])
def test_open_refuses_a_file_swapped_after_publication(monkeypatch, tmp_path, swap):
    monkeypatch.setattr(subprocess, "Popen", RefusingPopen)
    path = _pdf(tmp_path)
    runner = spawn.Runner()
    runner.published(path)
    os.unlink(path)
    if swap == "a link":
        os.symlink("/System/Applications/Calculator.app", path)
    else:
        _pdf(tmp_path)  # a new file, a new inode, at the same name
    with pytest.raises(spawn.Refused):
        runner.run("O1")


def test_published_refuses_a_link_or_a_folder(tmp_path):
    target = _pdf(tmp_path)
    link = tmp_path / "link.pdf"
    link.symlink_to(target)
    folder = tmp_path / "folder.pdf"
    folder.mkdir()
    for path in (link, folder):
        with pytest.raises(spawn.Refused):
            spawn.Runner().published(str(path))


def test_published_refuses_a_file_another_user_owns(monkeypatch, tmp_path):
    path = _pdf(tmp_path)
    monkeypatch.setattr(spawn.os, "getuid", lambda: os.stat(path).st_uid + 1)
    with pytest.raises(spawn.Refused):
        spawn.Runner().published(path)


# --- the #341 review: every stop and every bound, with fake processes and a fake clock -----


class NeverDies:
    """A started process that ignores every signal and is never reaped."""

    def __init__(self, clock=None, refuse=False):
        self.signals: list[int] = []
        self.waits: list[float | None] = []
        self.returncode = None
        self.pid = 999999
        self.clock = clock
        self.refuse = refuse
        read_out, self._w1 = os.pipe()
        read_err, self._w2 = os.pipe()
        self.stdout = open(read_out, "rb")  # noqa: SIM115 - closed by the engine
        self.stderr = open(read_err, "rb")  # noqa: SIM115 - closed by the engine

    def send_signal(self, sig):
        if self.refuse:
            raise PermissionError(errno.EPERM, "Operation not permitted")
        self.signals.append(sig)

    def wait(self, timeout=None):
        self.waits.append(timeout)
        if self.clock is not None and timeout is not None:
            self.clock.now += timeout
        raise subprocess.TimeoutExpired("fake", timeout)

    def poll(self):
        return self.returncode

    def close_writers(self):
        for fd in (self._w1, self._w2):
            with contextlib.suppress(OSError):
                os.close(fd)


@pytest.mark.parametrize(
    ("stop", "signals", "waits"),
    [
        (spawn.Stop.KILL, [signal.SIGKILL], [1]),
        (spawn.Stop.TERM_THEN_KILL, [signal.SIGTERM, signal.SIGKILL], [2, 1]),
        (spawn.Stop.PAYLOAD, [signal.SIGTERM, signal.SIGKILL], [3, 1]),
    ],
)
def test_each_stop_sends_its_signals_and_bounds_every_wait(stop, signals, waits):
    proc = NeverDies()
    try:
        stopped = spawn._stop(proc, stop)
        assert (proc.signals, proc.waits) == (signals, waits)
        assert stopped == spawn.Stopped(reaped=False, eperm=False)
    finally:
        proc.close_writers()
        proc.stdout.close()
        proc.stderr.close()


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def _fake_run(monkeypatch, deadline_s, stop):
    clock = FakeClock()
    proc = NeverDies(clock)
    monkeypatch.setattr(spawn, "time", clock)
    monkeypatch.setattr(spawn.subprocess, "Popen", lambda *args, **kwargs: proc)

    def fake_drain(selector, timeout, cap):
        clock.now += timeout
        return False

    monkeypatch.setattr(spawn, "_drain", fake_drain)
    try:
        return spawn._execute(["/bin/x"], command_id="C1", deadline_s=deadline_s, stop=stop), proc
    finally:
        proc.close_writers()


@pytest.mark.parametrize(
    ("deadline_s", "stop", "bound_ms"),
    [
        (10, spawn.Stop.TERM_THEN_KILL, 13000),  # user commands, X1, S1, S5
        (15, spawn.Stop.TERM_THEN_KILL, 18000),  # C28
        (2, spawn.Stop.KILL, 3000),  # one P1 listing
        (10, spawn.Stop.PAYLOAD, 14000),  # a payload's runtime deadline and its stop
    ],
)
def test_each_time_bound_holds_for_a_process_that_is_never_reaped(
    monkeypatch, deadline_s, stop, bound_ms
):
    result, _ = _fake_run(monkeypatch, deadline_s, stop)
    assert (result.ending, result.returncode, result.reaped) == (spawn.Ending.DEADLINE, None, False)
    assert result.duration_ms == bound_ms, "abandoned at the end of its stop sequence"


def test_an_abandoned_process_is_kept_and_collected_later(monkeypatch):
    result, proc = _fake_run(monkeypatch, 10, spawn.Stop.TERM_THEN_KILL)
    assert not result.reaped and not result.eperm
    assert proc in spawn._ABANDONED
    assert spawn.collect_abandoned() >= 1
    proc.returncode = -9  # it ends later
    spawn.collect_abandoned()
    assert proc not in spawn._ABANDONED


def test_a_process_that_cannot_be_signalled_is_marked(monkeypatch):
    clock = FakeClock()
    proc = NeverDies(clock, refuse=True)
    monkeypatch.setattr(spawn, "time", clock)
    monkeypatch.setattr(spawn.subprocess, "Popen", lambda *args, **kwargs: proc)
    monkeypatch.setattr(spawn, "_drain", lambda selector, timeout, cap: False)
    try:
        result = spawn._execute(
            ["/bin/x"], command_id="S1", deadline_s=0, stop=spawn.Stop.TERM_THEN_KILL
        )
    finally:
        proc.close_writers()
        spawn._ABANDONED.clear()
    assert (result.reaped, result.eperm) == (False, True)


# --- the #341 review: nothing escapes a run --------------------------------------------------


def test_an_exception_mid_run_stops_the_child(monkeypatch):
    started = []
    real_popen = subprocess.Popen

    def spy(argv, **kwargs):
        proc = real_popen(argv, **kwargs)
        started.append(proc)
        return proc

    calls = {"n": 0}
    real_drain = spawn._drain

    def interrupting_drain(selector, timeout, cap):
        calls["n"] += 1
        if calls["n"] == 3:
            raise KeyboardInterrupt
        return real_drain(selector, timeout, cap)

    monkeypatch.setattr(subprocess, "Popen", spy)
    monkeypatch.setattr(spawn, "_drain", interrupting_drain)
    with pytest.raises(KeyboardInterrupt):
        execute(program("import time; time.sleep(30)"), deadline_s=20)
    (proc,) = started
    try:
        assert proc.poll() is not None, "the child was stopped before the exception left"
    finally:
        proc.kill()
        proc.wait(timeout=5)


def test_a_selector_that_cannot_be_made_starts_nothing(monkeypatch):
    def no_selector():
        raise OSError(errno.EMFILE, "Too many open files")

    monkeypatch.setattr(spawn.selectors, "DefaultSelector", no_selector)
    monkeypatch.setattr(subprocess, "Popen", RefusingPopen)
    with pytest.raises(OSError):
        execute(program("pass"))


def test_a_cancellation_stops_the_command():
    # The flag turns true while the command runs (it was false when the command started).
    checks = iter([False, False])
    started = time.monotonic()
    result = execute(
        program("import time; time.sleep(30)"),
        deadline_s=20,
        cancelled=lambda: next(checks, True),
    )
    assert result.ending is spawn.Ending.CANCELLED and result.reaped
    assert time.monotonic() - started < 5


def test_the_runner_passes_its_cancellation_check_to_every_command(monkeypatch):
    seen = []

    def fake_execute(argv, **kwargs):
        seen.append(kwargs["cancelled"])
        return spawn.Result("C1", spawn.Ending.EXITED, 0, "", "", 1, False, True)

    monkeypatch.setattr(spawn, "_execute", fake_execute)

    def check() -> bool:
        return False

    spawn.Runner(cancelled=check).run("C1")
    assert seen == [check]


# --- the #341 review: records ------------------------------------------------------------------


def test_a_failure_rule_that_raises_records_nothing(monkeypatch):
    result = spawn.Result("C28", spawn.Ending.EXITED, 0, "", "", 5, False, True)
    monkeypatch.setattr(spawn, "_execute", lambda argv, **kwargs: result)
    runner = spawn.Runner()

    def broken(_result):
        raise RuntimeError("a bug in the caller's rule")

    with pytest.raises(RuntimeError):
        runner.run("C28", failed=broken)
    assert runner.records() == []


def test_a_failure_rule_counts_one_failure_at_most(monkeypatch):
    result = spawn.Result("C28", spawn.Ending.EXITED, 0, "", "", 5, False, True)
    monkeypatch.setattr(spawn, "_execute", lambda argv, **kwargs: result)
    runner = spawn.Runner()
    runner.run("C28", failed=lambda _result: 2)  # type: ignore[arg-type, return-value]
    assert runner.records() == [spawn.CommandRecord("C28", 1, 1, 5)]


@pytest.mark.parametrize(
    ("ending", "code", "failed"),
    [
        ("exited", 0, 0),
        ("exited", 1, 1),
        ("signaled", -6, 1),
        ("deadline", -9, 1),
        ("output_cap", 0, 1),
        ("not_started", None, 1),
        ("cancelled", -15, 1),
    ],
)
def test_the_default_failure_rule(monkeypatch, ending, code, failed):
    result = spawn.Result("C1", spawn.Ending(ending), code, "", "", 5, False, True)
    monkeypatch.setattr(spawn, "_execute", lambda argv, **kwargs: result)
    runner = spawn.Runner()
    runner.run("C1")
    assert runner.records()[0].failed_runs == failed


def test_an_argv_the_exact_match_refuses_never_starts(monkeypatch):
    # The mirror of the shape-scan test: a clean shape does not excuse a failed match.
    monkeypatch.setattr(subprocess, "Popen", RefusingPopen)
    monkeypatch.setattr(
        allowlist, "resolve", lambda command_id, **kwargs: ("/usr/bin/sw_vers", "-buildVersion")
    )
    monkeypatch.setattr(allowlist, "forbidden_shape", lambda argv, **kwargs: None)
    with pytest.raises(spawn.Refused, match="does not match"):
        spawn.Runner().run("C1")


def test_the_broker_only_commands_come_from_the_allow_list():
    assert {"S2", "S3", "S4", "S2n", "S3n", "S4n"} == spawn._BROKER_ONLY


def test_a_results_repr_leaves_the_output_out():
    result = spawn.Result("C1", spawn.Ending.EXITED, 0, "SECRET-OUT", "SECRET-ERR", 5, False, True)
    assert "SECRET" not in repr(result)


def test_a_forced_ending_with_no_code_says_only_how_it_ended():
    result = spawn.Result("C1", spawn.Ending.DEADLINE, None, "", "", 3, False, True)
    assert spawn.debug_line(result).endswith(": ran past its deadline, 3 ms")


def test_a_dynamic_value_missing_for_another_command_is_refused(monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", RefusingPopen)

    def unresolved(command_id, **kwargs):
        raise ValueError(f"{command_id} needs a dynamic value")

    monkeypatch.setattr(allowlist, "resolve", unresolved)
    with pytest.raises(spawn.Refused):
        spawn.Runner().run("C1")


# --- the #341 review, round 2 ------------------------------------------------------------------


def test_no_command_starts_once_the_run_is_cancelled(monkeypatch):
    # The GPT audit, pass 1, G1-01: a flag set between the caller's check and the start
    # started the command unwatched, to run to its deadline. The one cleanup the runner
    # starts after the flag, the final sudo -k, passes no flag (see below); tracking's last
    # listing goes through its own engine. The stand-in fails on the reason itself (the
    # review of #326, round 1, N4), and every field of the refusal is pinned: a command
    # that never started was never left unreaped (N5).
    monkeypatch.setattr(spawn, "_popen", RefusingPopen)
    result = execute(program("print('never')"), deadline_s=5, cancelled=lambda: True)
    assert result == spawn.Result("C1", spawn.Ending.CANCELLED, None, "", "", 0, False, True)
    assert (result.reaped, result.eperm, result.missing_executable) == (True, False, False)
    assert spawn.debug_line(result).endswith(": cancelled, 0 ms")


def test_a_flag_that_turns_true_as_a_command_starts_stops_it_at_once():
    checks = iter([False])
    started = time.monotonic()
    result = execute(["/bin/sleep", "5"], deadline_s=10, cancelled=lambda: next(checks, True))
    assert result.ending is spawn.Ending.CANCELLED
    assert time.monotonic() - started < 2


@pytest.mark.parametrize(
    "command_id", [*allowlist.USER_COMMAND_IDS, "X1", "P1", "S1", "O1"], ids=str
)
def test_the_runner_starts_no_command_but_the_final_clear_once_cancelled(
    monkeypatch, tmp_path, command_id
):
    # O1 with a report published as the writer leaves it, so only the flag can refuse it
    # (the review of #326, round 1, M7: O1 was the one command no test watched).
    monkeypatch.setattr(spawn, "_popen", RefusingPopen)
    runner = spawn.Runner(cancelled=lambda: True)
    if command_id == "O1":
        runner.published(_pdf(tmp_path))
    result = runner.run(command_id)
    assert result == spawn.Result(command_id, spawn.Ending.CANCELLED, None, "", "", 0, False, True)


@pytest.mark.parametrize("command_id", ["S2", "S2n"])
def test_the_password_prompt_never_starts_once_cancelled(monkeypatch, command_id):
    # A prompt started after the signal waited out its 180 s clock (G1-01).
    monkeypatch.setattr(spawn, "_popen", RefusingPopen)
    result = spawn.Runner(cancelled=lambda: True).authenticate(command_id)
    assert result == spawn.Result(command_id, spawn.Ending.CANCELLED, None, "", "", 0, False, True)


def test_an_open_running_when_the_flag_turns_true_is_stopped(monkeypatch, tmp_path):
    # O1 is watched as every other command given the flag is: a stand-in argv that would
    # run for 3 s is stopped at the loop's first pass (M7). The real /usr/bin/open never runs.
    real_execute = spawn._execute
    handed: list[list[str]] = []

    def stand_in(argv, **kwargs):  # type: ignore[no-untyped-def]
        handed.append(list(argv))
        return real_execute(["/bin/sleep", "3"], **kwargs)

    monkeypatch.setattr(spawn, "_execute", stand_in)
    checks = iter([False])
    runner = spawn.Runner(cancelled=lambda: next(checks, True))
    path = _pdf(tmp_path)
    runner.published(path)
    started = time.monotonic()
    result = runner.run("O1")
    assert handed == [["/usr/bin/open", path]]
    assert result.ending is spawn.Ending.CANCELLED and result.returncode is not None
    assert time.monotonic() - started < 2.5


def test_the_runner_runs_the_final_clear_after_a_cancellation(monkeypatch):
    real_execute = spawn._execute

    def stand_in(argv, **kwargs):
        # The command's own deadline, stop and cancellation, with a harmless stand-in argv
        # that starts at once (no interpreter start that a slow runner could stretch).
        return real_execute(["/bin/sleep", "0.3"], **kwargs)

    monkeypatch.setattr(spawn, "_execute", stand_in)
    result = spawn.Runner(cancelled=lambda: True).run("S5")
    assert result.ending is spawn.Ending.EXITED and result.ok


@pytest.mark.parametrize(
    ("cap_hit", "exited", "deadline_passed", "expected"),
    [
        (False, False, False, spawn.Ending.CANCELLED),
        (False, True, False, "exit"),  # a cancellation seen with the exit is ignored
        (True, False, False, spawn.Ending.OUTPUT_CAP),  # the cap comes first
        (False, False, True, spawn.Ending.CANCELLED),  # before the deadline
    ],
)
def test_the_pass_order_with_a_cancellation(cap_hit, exited, deadline_passed, expected):
    assert spawn._judge(cap_hit, exited, deadline_passed, True) == expected


def test_an_exception_mid_run_kills_the_child_without_a_grace(monkeypatch):
    calls = {"n": 0}
    real_drain = spawn._drain

    def interrupting_drain(selector, timeout, cap):
        calls["n"] += 1
        if calls["n"] == 3:
            raise KeyboardInterrupt
        return real_drain(selector, timeout, cap)

    monkeypatch.setattr(spawn, "_drain", interrupting_drain)
    started = time.monotonic()
    with sigterm_ignored_by_children(), pytest.raises(KeyboardInterrupt):
        execute(program("import time; time.sleep(30)"), deadline_s=20)
    assert time.monotonic() - started < 2, "SIGKILL at once, no SIGTERM grace"


def test_a_second_interrupt_during_the_reap_still_keeps_the_child(monkeypatch):
    started = []
    real_popen = subprocess.Popen

    def spy(argv, **kwargs):
        proc = real_popen(argv, **kwargs)
        started.append(proc)
        return proc

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(subprocess, "Popen", spy)
    calls = {"n": 0}
    real_drain = spawn._drain

    def interrupting_drain(selector, timeout, cap):
        calls["n"] += 1
        if calls["n"] == 2:
            raise KeyboardInterrupt  # the first Ctrl-C
        return real_drain(selector, timeout, cap)

    monkeypatch.setattr(spawn, "_drain", interrupting_drain)
    monkeypatch.setattr(spawn, "_stop", interrupt)  # the second, during the stop
    with pytest.raises(KeyboardInterrupt):
        execute(program("import time; time.sleep(30)"), deadline_s=20)
    (proc,) = started
    try:
        assert proc in spawn._ABANDONED, "an interrupted stop leaves the child kept, not lost"
        assert proc.stdout is not None and proc.stdout.closed
    finally:
        proc.kill()
        proc.wait(timeout=5)
        for stream in (proc.stdout, proc.stderr):
            if stream is not None:
                stream.close()


# --- the #341 review, round 3 ------------------------------------------------------------------


def test_a_flag_that_cannot_be_read_starts_nothing(monkeypatch):
    # The cancellation flag is read before the child exists, so a reader that fails, or
    # an interrupt at that read, leaves nothing running.
    monkeypatch.setattr(subprocess, "Popen", RefusingPopen)

    def broken() -> bool:
        raise RuntimeError("the flag cannot be read")

    with pytest.raises(RuntimeError):
        execute(program("pass"), cancelled=broken)


def test_published_holds_the_file_open_until_it_is_opened(monkeypatch, tmp_path):
    # Holding the file keeps its inode in use, so no file system can give a new file the
    # same identity before O1 compares them.
    monkeypatch.setattr(
        spawn,
        "_execute",
        lambda argv, **kwargs: spawn.Result("O1", spawn.Ending.EXITED, 0, "", "", 1, False, True),
    )
    path = _pdf(tmp_path)
    runner = spawn.Runner()
    runner.published(path)
    held = runner._pin
    assert held is not None and os.fstat(held).st_ino == os.stat(path).st_ino
    runner.run("O1")
    assert runner._pin is None
    with pytest.raises(OSError):
        os.fstat(held)


def test_close_lets_go_of_a_report_that_was_never_opened(tmp_path):
    runner = spawn.Runner()
    runner.published(_pdf(tmp_path))
    held = runner._pin
    runner.close()
    runner.close()  # a second close is harmless
    assert runner._pin is None
    with pytest.raises(OSError):
        os.fstat(held)


def test_a_refused_publication_holds_nothing(tmp_path):
    path = _pdf(tmp_path)
    os.chmod(path, 0o644)
    runner = spawn.Runner()
    with pytest.raises(spawn.Refused):
        runner.published(path)
    assert runner._pin is None


def test_a_report_that_cannot_be_opened_is_refused(monkeypatch, tmp_path):
    path = _pdf(tmp_path)

    def denied(*args, **kwargs):
        raise PermissionError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(spawn.os, "open", denied)
    runner = spawn.Runner()
    with pytest.raises(spawn.Refused):
        runner.published(path)
    assert runner._pin is None


def test_a_report_swapped_between_the_check_and_the_open_is_refused(monkeypatch, tmp_path):
    path = _pdf(tmp_path)
    real_fstat = os.fstat
    opened = []
    real_open = os.open

    def remember(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd

    def other_inode(fd):
        info = real_fstat(fd)
        return os.stat_result((info.st_mode, info.st_ino + 1, *tuple(info)[2:]))

    monkeypatch.setattr(spawn.os, "open", remember)
    monkeypatch.setattr(spawn.os, "fstat", other_inode)
    runner = spawn.Runner()
    with pytest.raises(spawn.Refused):
        runner.published(path)
    monkeypatch.undo()
    assert runner._pin is None
    with pytest.raises(OSError):
        os.fstat(opened[0])  # the descriptor was let go


# --- the #341 review, round 4 ------------------------------------------------------------------


def _counting_open(monkeypatch) -> list[list[str]]:
    started: list[list[str]] = []

    def fake_execute(argv, **kwargs):
        started.append(argv)
        return spawn.Result("O1", spawn.Ending.EXITED, 0, "", "", 1, False, True)

    monkeypatch.setattr(spawn, "_execute", fake_execute)
    return started


def test_o1_after_close_starts_nothing(monkeypatch, tmp_path):
    # With the pin let go, nothing keeps the inode in use, so O1 could not tell the
    # published file from a new one that took its identity.
    started = _counting_open(monkeypatch)
    runner = spawn.Runner()
    runner.published(_pdf(tmp_path))
    runner.close()
    with pytest.raises(spawn.Refused):
        runner.run("O1")
    assert started == []


def test_o1_after_a_refused_o1_starts_nothing(monkeypatch, tmp_path):
    # A refused O1 lets go of the pin, so a second try would compare with nothing held.
    started = _counting_open(monkeypatch)
    path = _pdf(tmp_path)
    runner = spawn.Runner()
    runner.published(path)
    os.chmod(path, 0o644)
    with pytest.raises(spawn.Refused):
        runner.run("O1")
    os.chmod(path, 0o600)
    with pytest.raises(spawn.Refused):
        runner.run("O1")
    assert started == []


def test_close_lets_go_of_the_pin_even_when_closing_it_fails(tmp_path):
    runner = spawn.Runner()
    runner.published(_pdf(tmp_path))
    held = runner._pin
    assert held is not None
    os.close(held)  # someone else closed the descriptor first
    with pytest.raises(OSError):
        runner.close()
    assert runner._pin is None
    runner.close()  # and nothing is closed twice


def test_a_runner_used_as_a_context_lets_go_of_its_report(tmp_path):
    with spawn.Runner() as runner:
        runner.published(_pdf(tmp_path))
        held = runner._pin
        assert held is not None
    assert runner._pin is None
    with pytest.raises(OSError):
        os.fstat(held)


# --- S2, the one password prompt (MAC 3.7) ------------------------------------------------------


def test_authenticate_runs_only_s2_or_s2n(monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", RefusingPopen)
    for command_id in ("S1", "S3", "S4", "S3n", "S4n", "S5", "C1", "O1", "P1"):
        with pytest.raises(spawn.Refused):
            spawn.Runner().authenticate(command_id)


@pytest.mark.parametrize("command_id", ["S2", "S2n"])
def test_authenticate_is_a_plain_wait_under_the_authentication_clock(monkeypatch, command_id):
    calls = []

    def fake_execute(argv, **kwargs):
        calls.append((argv, kwargs))
        return spawn.Result(command_id, spawn.Ending.EXITED, 0, "", "", 5, False, True)

    monkeypatch.setattr(spawn, "_execute", fake_execute)
    runner = spawn.Runner(cancelled=lambda: False)
    runner.authenticate(command_id)
    argv, kwargs = calls[0]
    assert argv == list(allowlist.BY_ID[command_id].template)
    assert kwargs["deadline_s"] == 180
    assert kwargs["stop"] is spawn.Stop.PAYLOAD
    assert kwargs["cancelled"] is not None, "Ctrl-C at the prompt stops sudo too"
    assert runner.records() == [spawn.CommandRecord(command_id, 1, 0, 5)]


def test_authenticate_records_the_brokers_judgment(monkeypatch):
    monkeypatch.setattr(
        spawn,
        "_execute",
        lambda argv, **kwargs: spawn.Result("S2", spawn.Ending.EXITED, 1, "", "x", 7, False, True),
    )
    seen = []
    runner = spawn.Runner(on_result=seen.append)
    result = runner.authenticate("S2", failed=lambda found: found.returncode != 0)
    assert result.returncode == 1
    assert runner.records() == [spawn.CommandRecord("S2", 1, 1, 7)]
    assert seen == [result], "the --debug hook sees S2 like any other command"


def test_s2_is_still_refused_by_run(monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", RefusingPopen)
    with pytest.raises(spawn.Refused):
        spawn.Runner().run("S2")


# --- a payload's record, once the broker has judged it (MAC 3.7) -------------------------------


def test_a_payloads_record_is_kept_once_judged():
    runner = spawn.Runner()
    runner.note_payload("S3", failed=False, duration_ms=204)
    runner.note_payload("S4n", failed=True, duration_ms=5311)
    assert runner.records() == [
        spawn.CommandRecord("S3", 1, 0, 204),
        spawn.CommandRecord("S4n", 1, 1, 5311),
    ]


@pytest.mark.parametrize("command_id", ["S1", "S2", "S5", "C1", "P1", "O1", "X1"])
def test_only_a_payload_is_noted_after_the_fact(command_id):
    with pytest.raises(spawn.Refused):
        spawn.Runner().note_payload(command_id, failed=False, duration_ms=1)


def test_a_negative_duration_is_refused():
    with pytest.raises(ValueError):
        spawn.Runner().note_payload("S3", failed=False, duration_ms=-1)


# --- the final clear, and what a tracked payload hands back (MAC 3.7) ---------------------------


def test_the_final_clear_is_never_cut_short(monkeypatch):
    # S5 is the cleanup: a Ctrl-C that lands while it runs must not stop it, or the
    # authorization it clears would outlive the run.
    real_execute = spawn._execute
    seen = []

    def stand_in(argv, **kwargs):
        seen.append(kwargs["cancelled"])
        return real_execute(["/bin/sleep", "0.3"], **kwargs)

    monkeypatch.setattr(spawn, "_execute", stand_in)
    checks = iter([False])
    result = spawn.Runner(cancelled=lambda: next(checks, True)).run("S5")
    assert seen == [None]
    assert result.ending is spawn.Ending.EXITED and result.ok


SURVIVOR = tracking.Survivor(pid=4242, uid=0, started="Sat Sep 26 12:00:00 2026", name="sudo")


def payload_run(**changes: object) -> spawn.PayloadRun:
    fields: dict[str, object] = {
        "command_id": "S3",
        "started": True,
        "forced": None,
        "returncode": 0,
        "stdout": "",
        "stderr": "",
        "cleanup": "verified",
        "duration_ms": 1,
    }
    fields.update(changes)
    if fields["cleanup"] == "survivor":
        fields.setdefault("survivors", (SURVIVOR,))
    return spawn.PayloadRun(**fields)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "changes",
    [
        {"command_id": "S3n"},
        {"command_id": "S4"},
        {"command_id": "S4n"},
        {"started": False, "returncode": None},
        {"started": False, "returncode": None, "cleanup": "listing_failed"},
        {"forced": "runtime_deadline", "returncode": None, "cleanup": "survivor"},
        {"forced": "auth_failed", "returncode": -15},
        {"forced": "launch_deadline", "returncode": None},
        {"forced": "output_cap", "returncode": -9},
        {"forced": "tracking_failed", "returncode": None, "cleanup": "listing_failed"},
        {"returncode": -15},
    ],
)
def test_a_payload_run_holds_what_its_loop_found(changes):
    payload_run(**changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"command_id": "S2"},
        {"command_id": "C1"},
        {"cleanup": "not_applicable"},
        {"cleanup": "gone"},
        {"duration_ms": -1},
        {"started": False, "returncode": None, "cleanup": "survivor"},
        {"started": False, "returncode": 1},
        {"started": False, "returncode": None, "forced": "output_cap"},
        {"returncode": None},
        {"forced": "parsed"},
        {"forced": "spawn_failed", "returncode": None},
    ],
)
def test_a_payload_run_the_loop_cannot_produce_is_refused(changes):
    with pytest.raises(ValueError):
        payload_run(**changes)


def test_a_payload_runs_output_stays_out_of_its_repr():
    text = repr(payload_run(stdout="secret-out", stderr="secret-err"))
    assert "secret" not in text


# --- the #346 review ----------------------------------------------------------------------------


def test_a_payload_of_no_measurable_duration_is_recorded():
    runner = spawn.Runner()
    runner.note_payload("S3", failed=True, duration_ms=0)
    assert runner.records() == [spawn.CommandRecord("S3", 1, 1, 0)]
    payload_run(started=False, returncode=None, duration_ms=0)


@pytest.mark.parametrize("duration", [1.5, True, "5"], ids=["a float", "a bool", "text"])
def test_a_duration_is_a_whole_number_of_milliseconds(duration):
    with pytest.raises((TypeError, ValueError)):
        spawn.Runner().note_payload("S3", failed=False, duration_ms=duration)
    with pytest.raises((TypeError, ValueError)):
        payload_run(duration_ms=duration)


@pytest.mark.parametrize("started", [1, "yes", None])
def test_started_is_a_bool(started):
    with pytest.raises((TypeError, ValueError)):
        payload_run(started=started)
