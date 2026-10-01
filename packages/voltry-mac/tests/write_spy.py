"""A runtime spy over the package's test run: the other half of the one-writer rule
(docs/VOLTRY_MAC_SPEC.md, the Architecture's one output writer; Test strategy part 2's
runtime spy).

tests/test_static_guards.py reads the source, and its docstring names what it cannot
follow. This audit hook sees the calls themselves: an ``open`` for writing, the ``os``,
``shutil`` and ``tempfile`` calls that create, change or remove a file, a socket bound to a
path, and a database file sqlite3 connects to. A call counts when the nearest frame of the
package's own source or of the tests on the stack is the package's: a test's own files,
and a test's stand-in that writes, are the test's. writer.py's frames are exempt only when
the writer was entered through ``save``, ``home`` or ``base_name``, its public functions;
entered any other way (a private seam reached from other package code, say), the frame
that called into it is judged instead, or writer.py itself when no package or test frame
did. Three kinds of call are not counted: an open of /dev/null, which creates nothing; an
open of a descriptor already open, whose own open was judged; and a call on a path inside
a folder named ``__pycache__``, Python's bytecode cache, which any import writes.
conftest.py installs the hook once. Its fixtures fail a test during which such a call was
seen, the next test when one was seen before it began (at import, or late from an earlier
test's thread), and the session when one came after the last test.

What it cannot see (the #354 review, round 4): a call whose nearest frame is not the
package's, such as a thread whose target is a standard-library function, a weakref
finalizer that runs as a test drops the object, and an atexit callback, which also runs
after the last check; a frame whose code names a test file as its own; a write that raises
no audit event, such as ``os.write`` or ``mmap`` through a descriptor already open, or a
foreign function called through ctypes; and a file written inside a folder named
``__pycache__``. A write from a thread that outlives its test is blamed on whichever test
is running when it lands. Registered as ``voltry_mac_test_write_spy``.
"""

from __future__ import annotations

import os
import sys
import types

import voltry_mac


def _both(folder: str) -> tuple[str, ...]:
    """A folder as a prefix, as given and resolved: a frame names its file by the path its
    module was loaded from, which may or may not pass through a symlink (/tmp, say)."""
    return tuple({folder.rstrip(os.sep) + os.sep, os.path.realpath(folder) + os.sep})


PACKAGE = _both(os.path.dirname(voltry_mac.__file__))
WRITER = tuple(folder + "writer.py" for folder in PACKAGE)
TESTS = _both(os.path.dirname(__file__))
# The writer's public functions: its writes are its own only when it was entered by one.
ENTRIES = frozenset({"save", "home", "base_name"})
# The audit events of a call that creates, changes or removes a file, besides open.
EVENTS = frozenset(
    {
        "os.remove",
        "os.rename",
        "os.link",
        "os.symlink",
        "os.mkdir",
        "os.rmdir",
        "os.truncate",
        "os.chmod",
        "os.chown",
        "os.chflags",
        "os.utime",
        "os.mkfifo",
        "os.mknod",
        "os.setxattr",
        "os.removexattr",
        "shutil.rmtree",
        "shutil.copyfile",
        "shutil.copymode",
        "shutil.copystat",
        "shutil.move",
        "shutil.make_archive",
        "shutil.unpack_archive",
        "tempfile.mkstemp",
        "tempfile.mkdtemp",
        "socket.bind",
        "sqlite3.connect",
    }
)
_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
WRITES: list[str] = []


def _cached(path: object) -> bool:
    """A path inside Python's bytecode cache, which an import writes, whoever imports."""
    if not isinstance(path, str | bytes | os.PathLike):
        return False
    return "__pycache__" in os.fsdecode(path).split(os.sep)


def _writes(event: str, args: tuple) -> bool:
    if event == "socket.bind":
        # A path makes a file; an address, or an abstract name that starts with NUL, does
        # not.
        address = args[1]
        return isinstance(address, str | bytes) and address[:1] not in ("", "\0", b"", b"\0")
    if event == "sqlite3.connect":
        return args[0] != ":memory:"
    if _cached(args[0]):
        return False
    if event != "open":
        return event in EVENTS
    path, mode, flags = args[0], args[1], args[2]
    if isinstance(path, int):
        return False  # a descriptor already open: the open that made it was judged
    if isinstance(path, str | bytes) and os.fsdecode(path) == os.devnull:
        return False
    if isinstance(mode, str):
        return bool(set(mode) & set("wax+"))
    return isinstance(flags, int) and bool(flags & _WRITE_FLAGS)


def _caller() -> types.FrameType | None:
    """The frame that made the audited call, or None on a stack too shallow to hold one, as
    in a callback at exit."""
    try:
        return sys._getframe(3)  # past this function, _origin or _nearest, and the hook
    except ValueError:
        return None


def _nearest() -> str | None:
    """The package file whose frame is nearest on the stack, or None when a test's is
    nearer, or neither is there."""
    frame = _caller()
    while frame is not None:
        name = frame.f_code.co_filename
        if name.startswith(TESTS):
            return None
        if name.startswith(PACKAGE):
            return name
        frame = frame.f_back
    return None


def _origin() -> str | None:
    """The package file a call is blamed on, or None when it is a test's or the writer's
    own. writer.py is the writer's own only when entered through one of its public
    functions; entered any other way, the frame that called into it is judged instead, or
    writer.py itself when nothing of the package's or the tests' did."""
    frame = _caller()
    while frame is not None:
        name = frame.f_code.co_filename
        if name.startswith(TESTS):
            return None  # the test's own call, or a stand-in it put there
        if name in WRITER:
            entry, frame = _entered(frame)
            if entry in ENTRIES:
                return None  # the writer's own save
            if frame is None:
                return name
            continue
        if name.startswith(PACKAGE):
            return name
        frame = frame.f_back
    return None


def _entered(frame: types.FrameType) -> tuple[str, types.FrameType | None]:
    """The writer's function a call entered it through, and the frame that called that
    function: the nearest beyond it of the tests' or another package file's, or None."""
    entry = frame.f_code.co_name
    found: types.FrameType | None = frame
    while found is not None:
        name = found.f_code.co_filename
        if name in WRITER:
            entry = found.f_code.co_name
        elif name.startswith(TESTS) or name.startswith(PACKAGE):
            return entry, found
        found = found.f_back
    return entry, None


# Package files seen opening anything, while a test watches (see watching()).
_watch: list[list[str]] = []


def _hook(event: str, args: tuple) -> None:
    if event != "open" and event not in EVENTS:
        return
    writes = _writes(event, args)
    if _watch and event == "open":
        seen = _nearest()
        if seen is not None:
            _watch[-1].append(seen)
    if not writes:
        return
    origin = _origin()
    if origin is not None:
        folder = next(prefix for prefix in PACKAGE if origin.startswith(prefix))
        what = args[1] if event == "socket.bind" else args[0]
        WRITES.append(f"{event} {what!r} from {origin[len(folder) :]}")


def watching(call) -> list[str]:  # type: ignore[no-untyped-def]
    """The package files seen opening a file while ``call`` runs: the spy's own check that
    a real module's frames are recognized as the package's."""
    _watch.append([])
    try:
        call()
    finally:
        seen = _watch.pop()
    return seen


def check(when: str) -> None:
    """Fail when package code other than the writer wrote a file since the last check,
    saying when; the next check starts clean either way."""
    found = list(WRITES)
    WRITES.clear()
    if found:
        raise AssertionError(f"package code other than writer.py wrote a file {when}: {found}")


_installed: list[bool] = []


def install() -> None:
    """Add the hook, once; an audit hook cannot be taken back."""
    if not _installed:
        sys.addaudithook(_hook)
        _installed.append(True)
