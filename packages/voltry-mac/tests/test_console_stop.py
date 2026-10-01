"""A stop while stdout takes nothing (the GPT audit, pass 3, G3-03, and pass 4).

A signal only sets the command's flag, and Python resumes a wait a signal interrupts, so the
console's wait on a full stream must read the flag itself: a reader that stays open and never
drains must not hold a Ctrl-C, SIGTERM or SIGHUP. Each case fills a real pipe or terminal,
never reads it, and runs the command in a child with that stream as its stdout, buffered and
write-through: the stop ends the command with exit 130 and the stop line.

The stream is left as a program would find it: non-blocking, as another program can leave a
terminal, or blocking, as a pipe or terminal normally is, where a write that waits sits in
the system call itself (pass 4). And stderr is either a pipe of its own, which then ends with
the stop line, or the same full stream, as a terminal is or `2>&1` makes it, where the stop
line has nowhere to go and the command must end all the same.
"""

from __future__ import annotations

import contextlib
import os
import pty
import select
import signal
import subprocess
import sys
import time

import pytest

SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
READY = b"ready\n"
# The child says it is ready, on a pipe of its own, just before cli.main takes the signals,
# then answers --dry-run into a stream that takes nothing.
CHILD = (
    "import os, sys\n"
    "from voltry_mac import cli\n"
    f"os.write(int(sys.argv[1]), {READY!r})\n"
    "sys.exit(cli.main(['--dry-run']))\n"
)


def _full_pipe(blocking: bool) -> tuple[int, int]:
    """A pipe whose buffer is full, and its reader, which never reads: (keep, stream)."""
    reader, writer = os.pipe()
    os.set_blocking(writer, False)
    with contextlib.suppress(BlockingIOError):
        while True:
            os.write(writer, b"x" * 65536)
    os.set_blocking(writer, blocking)
    return reader, writer


def _full_terminal(blocking: bool) -> tuple[int, int]:
    """A pseudo-terminal whose input side nobody reads, filled: (keep, stream)."""
    master, slave = pty.openpty()
    os.set_blocking(slave, False)
    with contextlib.suppress(BlockingIOError):
        while True:
            os.write(slave, b"x" * 1024)
    os.set_blocking(slave, blocking)
    return master, slave


def _full(kind: str, blocking: bool) -> tuple[int, int]:
    return _full_pipe(blocking) if kind == "pipe" else _full_terminal(blocking)


def _stopped(tmp_path, stream: int, unbuffered: bool, signum: int, *, both: bool):
    """Run the child on the full stream, stop it once it is ready, and give back its exit
    code and, when stderr is a pipe of its own, what it said there. The stream is the
    child's alone once it starts; its reader stays with the caller."""
    ready, said = os.pipe()
    argv = [sys.executable, *(["-u"] if unbuffered else []), "-c", CHILD, str(said)]
    env = dict(os.environ, HOME=str(tmp_path), TMPDIR=str(tmp_path))
    child = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=stream,
        stderr=stream if both else subprocess.PIPE,
        env=env,
        pass_fds=(said,),
    )
    os.close(stream)
    os.close(said)
    err = ""
    try:
        seen, _, _ = select.select([ready], [], [], 10)
        assert seen and os.read(ready, len(READY)) == READY, "the child never said it was ready"
        time.sleep(0.3)  # cli.main holds the signals and waits on the full stream by now
        child.send_signal(signum)
        try:
            code = child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pytest.fail("the stop never ended the command while its output took nothing")
        if child.stderr is not None:
            err = child.stderr.read().decode()
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
        if child.stderr is not None:
            child.stderr.close()
        os.close(ready)
    return code, err


def _run(tmp_path, kind, unbuffered, signum, *, blocking: bool, both: bool):
    keep, stream = _full(kind, blocking)
    try:
        return _stopped(tmp_path, stream, unbuffered, signum, both=both)
    finally:
        os.close(keep)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX streams and signals")
@pytest.mark.parametrize("unbuffered", [False, True], ids=["buffered", "write-through"])
@pytest.mark.parametrize("kind", ["pipe", "terminal"])
@pytest.mark.parametrize("signum", SIGNALS, ids=lambda signum: signal.Signals(signum).name)
def test_a_stop_ends_the_command_while_stdout_takes_nothing(tmp_path, kind, unbuffered, signum):
    code, err = _run(tmp_path, kind, unbuffered, signum, blocking=False, both=False)
    assert code == 130
    assert err.endswith("Stopped. Nothing was saved.\n")
    assert "Traceback" not in err


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX streams and signals")
@pytest.mark.parametrize("both", [False, True], ids=["stdout", "stdout-and-stderr"])
@pytest.mark.parametrize("unbuffered", [False, True], ids=["buffered", "write-through"])
@pytest.mark.parametrize("kind", ["pipe", "terminal"])
@pytest.mark.parametrize("signum", SIGNALS, ids=lambda signum: signal.Signals(signum).name)
def test_a_stop_ends_the_command_while_a_blocking_stream_takes_nothing(
    tmp_path, kind, unbuffered, signum, both
):
    # The GPT audit, pass 4: a blocking stream kept the write inside the system call, where
    # a signal that only sets the flag is resumed, so no stop ever ended the command.
    code, err = _run(tmp_path, kind, unbuffered, signum, blocking=True, both=both)
    assert code == 130
    if not both:
        assert err.endswith("Stopped. Nothing was saved.\n")
        assert "Traceback" not in err


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX streams and signals")
@pytest.mark.parametrize("kind", ["pipe", "terminal"])
def test_the_stream_is_left_blocking_as_the_command_found_it(tmp_path, kind):
    # The console makes a write non-blocking only while it lasts: a terminal or pipe the
    # command shares with the shell and other programs is handed back as it came.
    keep, stream = _full(kind, True)
    probe = os.dup(stream)  # the same open file, whatever the child does with its own
    try:
        code, _ = _stopped(tmp_path, stream, False, signal.SIGINT, both=False)
        assert code == 130
        assert os.get_blocking(probe), "the stream was left non-blocking"
    finally:
        os.close(probe)
        os.close(keep)
