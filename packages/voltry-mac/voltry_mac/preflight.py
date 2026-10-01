"""The preflight: the root user, the platform, the admin group and the terminal.

docs/VOLTRY_MAC_SPEC.md, the Architecture's preflight row, Decision 2's step 1, Decision 7,
Failure modes, and transcripts 3 and 6. Before any read, the run refuses the root user
(exit 5) and any platform the spec does not cover (exit 3): not macOS, an Intel Mac,
macOS 14 or older, and, by change record 2, a processor type, Rosetta state or Darwin
release it cannot read. The processor type and Rosetta come from R4, in-process through
sysctlbyname, so a translated interpreter is known before any command runs; with change
record 2, R4 also reads the Darwin release (kern.osrelease), since os.uname() would read
the host name too and kern.osproductversion answers 10.16 in compatibility mode. ctypes is
imported only when R4 reads, with os.uname set aside, because on macOS ctypes' own
__init__ calls it. The admin group and the terminal decide the elevation's skip causes.
Only --version and --dry-run skip the refusals, and --version still reads R4's two flags.
This module and the SMART child are the only two allowed ctypes.
"""

from __future__ import annotations

import contextlib
import errno
import os
import re
import sys
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Final

EXIT_UNSUPPORTED: Final = 3
EXIT_ROOT: Final = 5
MINIMUM_DARWIN: Final = 24  # macOS 15
ADMIN_GID: Final = 80  # macOS's admin group, the same ID on every release
ADMIN_S: Final = 5  # the bound R5 has, for the same reason: the directory can stall
_NO_DATA: Final = "No report data was collected and no report file was written."
_RELEASE: Final = re.compile(r"([0-9]{1,3})\.[0-9]{1,3}\.[0-9]{1,3}", re.ASCII)
_TEXT_MAX: Final = 256

ROOT: Final = (
    "Run voltry-mac without sudo. It asks for your password only for the\n"
    "two steps that need it, and it saves the report as you, not as root.\n" + _NO_DATA
)
INTEL: Final = (
    "This version of voltry-mac reads Apple silicon Macs (M1 and later).\n"
    "This Mac has an Intel processor, which uses different sensors and\n"
    "storage interfaces, so voltry-mac cannot give you an honest report\n"
    "yet. " + _NO_DATA
)
NOT_MACOS: Final = (
    "This version of voltry-mac reads Apple silicon Macs (M1 and later)\n"
    "running macOS 15 or later, and this computer does not run macOS.\n" + _NO_DATA
)
UNKNOWN_PROCESSOR: Final = (
    "This version of voltry-mac reads Apple silicon Macs (M1 and later),\n"
    "and could not read this Mac's processor type.\n" + _NO_DATA
)
UNKNOWN_ROSETTA: Final = (
    "voltry-mac could not read whether this Python runs under Rosetta,\n"
    "which the report must record.\n" + _NO_DATA
)
UNKNOWN_MACOS: Final = (
    "voltry-mac needs macOS 15 or later, and could not read this Mac's\n"
    "macOS version.\n" + _NO_DATA
)


@dataclass(frozen=True)
class Platform:
    """What R4 read: macOS or not; Apple silicon (hw.optional.arm64: False only when the
    OID does not exist, as on an Intel Mac); a translated interpreter
    (sysctl.proc_translated, False when it does not exist); and the Darwin release
    (kern.osrelease). None is a read that failed, or one not made."""

    macos: bool
    arm64: bool | None
    translated: bool | None
    release: str | None


class _NoHostName:
    """All that ctypes reads of uname on macOS: a release past Darwin 7. No host name."""

    release = "24.0.0"


def _no_host_name() -> _NoHostName:
    return _NoHostName()


@contextlib.contextmanager
def _uname_swapped_out() -> Iterator[None]:
    """os.uname set aside while ctypes is imported. On macOS, ctypes' own __init__ calls it
    to choose a dlopen mode for Darwin 7 and older; uname(3) also returns the host name,
    which the spec never reads, and it fails when a sandbox denies that name. The real
    function is put back, and never called here."""
    real = os.uname
    setattr(os, "uname", _no_host_name)  # noqa: B010 - set aside, not called
    try:
        yield
    finally:
        setattr(os, "uname", real)  # noqa: B010


def _sysctlbyname() -> Callable[..., int]:
    """libSystem's sysctlbyname, keeping errno. OSError when ctypes or the library cannot
    be loaded, so R4 then reads nothing."""
    try:
        if "ctypes" in sys.modules:
            import ctypes  # its __init__ ran long ago, and never runs again
        else:
            with _uname_swapped_out():
                import ctypes
    except Exception as missing:  # noqa: BLE001 - any failure to load it is a failed read
        raise OSError(errno.ENOENT, "ctypes could not be loaded") from missing
    call = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True).sysctlbyname
    call.restype = ctypes.c_int
    call.argtypes = [
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    return call


def sysctl_number(name: str) -> int | None:
    """One integer OID: its value, or None when the OID does not exist (ENOENT). Any other
    failure raises OSError, so a read that failed is never taken for an absent OID."""
    call = _sysctlbyname()
    import ctypes  # already loaded by _sysctlbyname(), so nothing runs again

    value = ctypes.c_int(0)
    size = ctypes.c_size_t(ctypes.sizeof(value))
    ctypes.set_errno(0)
    if call(name.encode("ascii"), ctypes.byref(value), ctypes.byref(size), None, 0) != 0:
        error = ctypes.get_errno()
        if error == errno.ENOENT:
            return None
        raise OSError(error, "sysctlbyname failed")
    if size.value != ctypes.sizeof(value):
        raise OSError(errno.EINVAL, "sysctlbyname gave a value of another size")
    return value.value


def sysctl_text(name: str) -> str | None:
    """One string OID, or None when it does not exist, cannot be read, is too long, or
    holds anything but printable ASCII."""
    try:
        call = _sysctlbyname()
    except OSError:
        return None
    import ctypes  # already loaded by _sysctlbyname(), so nothing runs again

    size = ctypes.c_size_t(0)
    if call(name.encode("ascii"), None, ctypes.byref(size), None, 0) != 0:
        return None
    if not 0 < size.value <= _TEXT_MAX:
        return None
    buffer = ctypes.create_string_buffer(size.value)
    if call(name.encode("ascii"), buffer, ctypes.byref(size), None, 0) != 0:
        return None
    try:
        text = buffer.value.decode("ascii")
    except UnicodeDecodeError:
        return None
    return text if text.isprintable() else None


def _flag(number: Callable[[str], int | None], name: str) -> bool | None:
    """A 0-or-1 OID: an OID that does not exist is False; a failed read, or any other
    value, is None."""
    try:
        value = number(name)
    except OSError:
        return None
    return {None: False, 0: False, 1: True}.get(value)


def read(
    number: Callable[[str], int | None] | None = None,
    text: Callable[[str], str | None] | None = None,
    *,
    release: bool = True,
) -> Platform:
    """R4. Off macOS nothing is read. release=False reads only the two flags, which is
    all --version needs."""
    if sys.platform != "darwin":
        return Platform(macos=False, arm64=None, translated=None, release=None)
    number = sysctl_number if number is None else number
    text = sysctl_text if text is None else text
    return Platform(
        macos=True,
        arm64=_flag(number, "hw.optional.arm64"),
        translated=_flag(number, "sysctl.proc_translated"),
        release=text("kern.osrelease") if release else None,
    )


def _old_macos(darwin: int) -> str:
    # Darwin 20 to 23 are macOS 11 to 14. Apple silicon never ran an earlier release, so
    # a smaller number names no version.
    named = f" This Mac runs macOS {darwin - 9}." if 20 <= darwin <= 23 else ""
    return f"voltry-mac needs macOS 15 or later.{named}\n{_NO_DATA}"


def refusal(found: Platform) -> str | None:
    """The plain reason a platform is refused (exit 3), or None for a supported one. A
    macOS release too old to support is named first when it is readable (change record 2),
    before a processor type or Rosetta state R4 could not read; only an Intel Mac comes
    before it, since a newer macOS would not change that answer (transcript 3)."""
    if not found.macos:
        return NOT_MACOS
    if found.arm64 is False:
        return INTEL
    match = _RELEASE.fullmatch(found.release or "")
    if match is not None and int(match[1]) < MINIMUM_DARWIN:
        return _old_macos(int(match[1]))  # the more useful reason, when both apply
    if found.arm64 is None:
        return UNKNOWN_PROCESSOR
    if found.translated is None:
        return UNKNOWN_ROSETTA
    return UNKNOWN_MACOS if match is None else None


def is_root() -> bool:
    return os.geteuid() == 0


def admin() -> bool | None:
    """Whether this account is in the admin group: the group's fixed ID among the groups
    macOS gives the process (os.getgroups(), the list sudo's own check uses), so no group
    or account name is read. macOS may ask the directory service for that list, so the
    check runs in a worker thread bounded to ADMIN_S, as R5 is; a check that fails or
    does not answer in time gives None, and a thread that never returns ends with the
    process."""
    answer: list[bool] = []

    def check() -> None:
        # Any failure is an unknown answer, never a traceback on the owner's terminal.
        with contextlib.suppress(Exception):
            answer.append(ADMIN_GID in os.getgroups())

    worker = threading.Thread(target=check, name="voltry-mac admin check", daemon=True)
    worker.start()
    worker.join(ADMIN_S)
    return answer[0] if answer and not worker.is_alive() else None


def terminal() -> bool:
    """Whether a terminal is present to ask the question on: stdin is one."""
    return sys.stdin is not None and sys.stdin.isatty()


def architecture(found: Platform) -> str:
    """The interpreter's architecture, as --version and the report's tool object name it:
    x86_64 under Rosetta or on an Intel Mac, arm64 natively on Apple silicon."""
    if not found.macos:
        return "unknown"
    if found.translated or found.arm64 is False:
        return "x86_64"
    if found.arm64 and found.translated is False:
        return "arm64"
    return "unknown"


def rosetta(found: Platform) -> str:
    """Whether this Python runs under Rosetta, as --version names it."""
    if not found.macos or found.translated is None:
        return "unknown"
    return "yes" if found.translated else "no"
