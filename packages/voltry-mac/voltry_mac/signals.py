"""SIGINT, SIGTERM and SIGHUP for the whole command, and the cancellation flag they set
(docs/VOLTRY_MAC_SPEC.md, Failure modes: the Ctrl-C rows and the exit codes; change record
10).

From the start of cli.main the three only set the flag, and every cleanup, the final sudo -k
included, runs in ordinary control flow. The run and render read the flag at their steps and
one last time as the last step of every exit; render's read and draw stop at once instead
(stopping). A signal ignored when the command starts, SIGHUP under nohup say, stays ignored.
Once the command has read the flag for the last time, all three are ignored until the
process exits: Python puts its own handlers back as it shuts down, and a signal then printed
a traceback naming the installed package's files or ended the process by the signal (the
audit fixes' review, round 3, m2).
"""

from __future__ import annotations

import contextlib
import signal
from collections.abc import Iterator
from typing import Final

SIGNALS: Final = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


class Flag:
    """The cancellation flag, a plain attribute. CPython can run a handler inside another,
    and a threading.Event's set() would then wait on a lock its own thread holds, for good
    (the run's review, round 2, n18); nothing waits on the flag. Called, it says whether a
    signal came. While ``stopping`` is set, the next signal also stops what runs, once."""

    up = False
    stopping = False

    def __call__(self) -> bool:
        return self.up


# The command's flag while it holds the signals, from the start of cli.main to its exit.
_HELD: list[Flag] = []


def asked() -> bool:
    """Whether the command holding the signals has been asked to stop. The console reads it
    while it waits on a stream that takes nothing (the GPT audit, pass 3, G3-03)."""
    return bool(_HELD) and _HELD[-1].up


@contextlib.contextmanager
def cancellation() -> Iterator[Flag]:
    """The three signals set the flag while the command lasts, and do nothing else. The run
    and render take it inside the command and share its flag; the command's own, taken by
    cli.main, ignores all three as it ends."""
    if _HELD:
        yield _HELD[-1]
        return
    flag = Flag()

    def handler(signum: int, frame: object) -> None:
        flag.up = True
        if flag.stopping:
            flag.stopping = False
            raise KeyboardInterrupt

    for signum in SIGNALS:
        if signal.getsignal(signum) is not signal.SIG_IGN:
            signal.signal(signum, handler)
    _HELD.append(flag)
    try:
        yield flag
    finally:
        _HELD.pop()
        for signum in SIGNALS:
            signal.signal(signum, signal.SIG_IGN)


@contextlib.contextmanager
def stopping(flag: Flag) -> Iterator[None]:
    """A signal stops what runs here at once, as a Ctrl-C would, once: render's read, which
    can stall on a slow or dead volume, where a signal that only set the flag would wait on
    it (the run's review, round 1, m7), and its draw. One that came before stops it too."""
    flag.stopping = True
    try:
        if flag.up:
            raise KeyboardInterrupt
        yield
    finally:
        flag.stopping = False
