"""What voltry-mac prints, and how it reaches the terminal (docs/VOLTRY_MAC_SPEC.md, "CLI
transcripts").

The header line every run starts with, the Python the tool runs on as the report and
``--version`` name it, and writing to stdout or stderr so that neither a reader that went
away early, a terminal window closed mid-run, nor a stream closed before Python started
stops a run or changes its exit code. A stream that takes nothing is waited on outside the
system call, reading the command's stop flag, so a full pipe or terminal never holds a stop,
and the stream is handed back as it came. Any other failure to write stdout, a full disk
behind it say, is said once on stderr, whether the write or the flush meets it. So is a
character stdout's encoding cannot spell, the degree sign in an ASCII locale say, which
prints replaced.
The command line and the run both print through here.
"""

from __future__ import annotations

import codecs
import contextlib
import errno
import os
import select
import sys
import weakref
from collections.abc import Iterator
from dataclasses import dataclass
from typing import BinaryIO, Final, TextIO

from voltry_mac import __version__, signals

HEADER: Final = f"Voltry Mac hardware observation report {__version__} (preview)"
INCOMPLETE: Final = "The terminal report could not be written in full."

# Nowhere to go, and nothing to say: a terminal window that was closed (every write then
# fails, EIO) or a device that is gone (ENXIO), as with a reader that went away early
# (BrokenPipeError).
_GONE: Final = frozenset({errno.EIO, errno.ENXIO})


@dataclass
class _Kept:
    """What a stream keeps between writes: the one encoder its text goes through, as its
    text layer keeps its own, so a byte-order mark is written once, where the stream
    starts; and whether stdout is known not to be written in full, which is said once,
    whatever the cause (the pass-3 pre-audit, P3-output-01)."""

    encoder: codecs.IncrementalEncoder | None = None
    incomplete: bool = False


# Each stream's, for as long as the stream lasts.
_KEPT: Final[weakref.WeakKeyDictionary[TextIO, _Kept]] = weakref.WeakKeyDictionary()


def _kept(stream: TextIO) -> _Kept:
    """What the stream keeps between writes, from its first."""
    found = _KEPT.get(stream)
    if found is None:
        found = _KEPT[stream] = _Kept()
    return found


def python_version() -> str:
    """The running Python as the report records it, such as ``3.12.11`` or ``3.14.0rc1``."""
    info = sys.version_info
    suffix = {"alpha": "a", "beta": "b", "candidate": "rc"}.get(info.releaselevel, "")
    serial = str(info.serial) if suffix else ""
    return f"{info.major}.{info.minor}.{info.micro}{suffix}{serial}"


def flush(stream: TextIO | None) -> None:
    """Flush stdout or stderr. A reader that went away early, a terminal window that was
    closed, a device that is gone, or no stream at all, is not an error: the rest has
    nowhere to go. A terminal left non-blocking is waited on until it takes the rest. Any
    other error on stdout, a full disk behind it say, is said once on stderr in a fixed
    line; the rest goes nowhere, and the exit code stays the run's (the run's review, round
    2, m13)."""
    if stream is None:  # closed before Python started
        return
    try:
        _flushed(stream)
    except OSError as error:
        _lost(stream, error)


def _flushed(stream: TextIO) -> None:
    """Flush, waiting while a stream that would block takes more: what the terminal did not
    take yet is still in the stream's buffer. Any other error is raised."""
    while True:
        try:
            with _not_blocking(stream):
                stream.flush()
        except BlockingIOError:
            if not _takes_more(stream):
                raise
        else:
            return


@contextlib.contextmanager
def _not_blocking(stream: TextIO) -> Iterator[None]:
    """One write or flush that cannot wait inside the system call. On a full pipe or
    terminal that blocks, a write waits there, and Python resumes it after a signal that
    only sets the flag, so no stop would end the command (the GPT audit, pass 4, G3-03).
    While the attempt lasts, the stream's open file is non-blocking: a write that would
    wait raises BlockingIOError instead, and the console waits on the stream itself,
    reading the flag as it waits (_takes_more). The file is shared with the shell and any
    other program writing to it, so it is handed back as it came, through a descriptor of
    the console's own, which still names it when the stream's is pointed at /dev/null."""
    try:
        held = os.dup(stream.fileno())
    except (OSError, ValueError):  # no descriptor: nothing can hold the write there
        yield
        return
    changed = False
    try:
        with contextlib.suppress(OSError):
            if os.get_blocking(held):
                os.set_blocking(held, False)
                changed = True
        yield
    finally:
        if changed:
            with contextlib.suppress(OSError):
                os.set_blocking(held, True)
        os.close(held)


def _lost(stream: TextIO, error: OSError) -> None:
    """What the stream did not take has nowhere to go, and neither has the rest. A reader
    that went away, a closed terminal window or a device that is gone is said nowhere; any
    other failure of stdout is said once on stderr, in a fixed line."""
    _nowhere(stream)
    gone = isinstance(error, BrokenPipeError) or error.errno in _GONE
    _incomplete(stream, say=not gone)


def _incomplete(stream: TextIO, *, say: bool = True) -> None:
    """stdout was not written in full: it failed, or it could not spell a character. That
    is said once on stderr, in a fixed line, and never after its reader went away, its
    terminal window closed or its device is gone. Any other stream's is said nowhere."""
    if stream is not sys.stdout:
        return
    kept = _kept(stream)
    if not kept.incomplete:
        kept.incomplete = True
        if say:
            write(sys.stderr, INCOMPLETE + "\n")


# How long one wait on a stream that takes nothing lasts before the command's flag is read
# again. A signal only sets the flag, and Python resumes a wait a signal interrupts, so a
# wait with no end would hold a stop for as long as the reader never drains (the GPT audit,
# pass 3, G3-03).
_WAIT_S: Final = 0.1


def _takes_more(stream: TextIO) -> bool:
    """Wait until a stream that would block can take more; False with nothing to wait on, or
    once the command has been asked to stop and the stream still takes nothing: what it did
    not take is then lost, and the command's last read of the flag decides its exit."""
    try:
        fd = stream.fileno()
    except (OSError, ValueError):
        return False
    while True:
        try:
            _, ready, _ = select.select([], [fd], [], _WAIT_S)
        except (OSError, ValueError):
            return False
        if ready:
            return True
        if signals.asked():
            return False


def _nowhere(stream: TextIO) -> None:
    """The rest of the output has nowhere to go, including the interpreter's own flush at
    exit, so the stream is pointed at /dev/null before anything writes again."""
    with contextlib.suppress(OSError, ValueError):
        devnull = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(devnull, stream.fileno())
        finally:
            os.close(devnull)


def write(stream: TextIO | None, text: str) -> None:
    """Write to stdout or stderr and flush it, as ``flush`` does. The text goes to the
    stream's binary layer and is checked by count: a stream made write-through (python -u,
    PYTHONUNBUFFERED) hands a write to its file once and says nothing when the file takes
    only part of it, or none because it would block, or fails as it writes (the GPT audit,
    pass 2, G2-06). A write that would block is waited on, and any other failure is handled
    as a flush's is. The text is encoded as the stream's text layer would encode it
    (_encoded), and a character the stream cannot spell is said as a failure is. A text
    stream with no binary layer, one a test reads say, takes all it is given. With no
    stream, the text has nowhere to go, and the exit code still says what happened."""
    if stream is None:
        return
    binary: BinaryIO | None = getattr(stream, "buffer", None)
    replaced = False
    try:
        if binary is None:
            stream.write(text)
        else:
            _flushed(stream)  # what the text layer holds goes first
            data, replaced = _encoded(stream, binary, text)
            _write_all(stream, binary, data)
        _flushed(stream)
    except OSError as error:
        _lost(stream, error)
    else:
        if replaced:
            _incomplete(stream)


def _encoded(stream: TextIO, binary: BinaryIO, text: str) -> tuple[bytes, bool]:
    """The text in the stream's encoding, through the one encoder the stream keeps, made at
    its first write as its text layer makes its own: with the stream's own errors, and with
    no byte-order mark when the stream already holds something (a file it adds to). A
    character the stream cannot encode is replaced from then on (a ? in most encodings),
    and True says so the first time: the text layer raised there, and the run lost a
    report it could save, which only a few failures may cost (spec, Failure modes; the
    pass-3 pre-audit, P3-output-01)."""
    kept = _kept(stream)
    if kept.encoder is None:
        kept.encoder = codecs.getincrementalencoder(stream.encoding)(stream.errors)
        with contextlib.suppress(OSError, ValueError):
            if binary.seekable() and binary.tell() != 0:
                kept.encoder.setstate(0)
    state = kept.encoder.getstate()
    try:
        return kept.encoder.encode(text), False
    except UnicodeEncodeError:
        kept.encoder = codecs.getincrementalencoder(stream.encoding)("replace")
        kept.encoder.setstate(state)
        return kept.encoder.encode(text), True


def _write_all(stream: TextIO, binary: BinaryIO, data: bytes) -> None:
    """Hand the bytes to the binary layer until it has taken them all. A file takes what
    it can: part of them, or none when it would block, and then the rest waits until it
    takes more, as a flush waits; a buffered layer that would block says how much it took.
    With nothing to wait on, BlockingIOError."""
    rest = memoryview(data)
    while rest:
        try:
            with _not_blocking(stream):
                taken = binary.write(rest)
        except BlockingIOError as error:
            taken = getattr(error, "characters_written", 0)
        if taken:
            rest = rest[taken:]
        elif not _takes_more(stream):
            raise BlockingIOError(errno.EAGAIN, os.strerror(errno.EAGAIN))
