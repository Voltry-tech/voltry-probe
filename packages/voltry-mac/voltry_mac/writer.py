"""The output writer: the one component that creates the report's files.

docs/VOLTRY_MAC_SPEC.md, Decision 5, the Architecture's output writer row, Failure modes and
the Threat model. The report goes to ~/Desktop by default, the home folder read from the
account database, never $HOME, or to a folder the owner named, which must exist and is
opened exactly as given. Its name is the report's local time, `Voltry Mac Report
2026-09-23 14.05`, the first one from there to `(99)` free for both the PDF and the JSON.

One file at a time, the JSON first when asked for and the PDF last: a temporary
`.voltry-mac-<random>.tmp` beside it, created with O_CREAT, O_EXCL and O_NOFOLLOW and set
to mode 0600 whatever the umask, written and flushed to the disk, hard-linked to its final
name, which fails if the name is taken, and unlinked. No temporary is made while one of
this run's is still there, so at most one exists at any moment. A hard kill leaves at most
it and a JSON without its PDF, both safe to delete, as is a file an earlier refused
removal left (change record 21). Mode 0600 holds unless the folder carries an inheritable
ACL that grants more, which the standard library cannot strip. A name taken in between
moves both files to the next one. Every name is made inside the folder as it was opened
once, so no symlink at a name is followed and a folder swapped mid-run cannot redirect the
write, and the paths returned name the folder that was opened, where it is now. When macOS
refuses the default Desktop (Operation not permitted), the report goes to the top of the
home folder instead, but never while a temporary is left on the Desktop; an explicit
folder is never relocated. Each published file must be this user's, and nothing is saved
as root.

Each file stays open from its create until the save ends, so no other file can take its
number on any disk, and a name is this run's file only while it leads to a regular file
that matches the one held open in number, size and count of names (the #354 review,
round 4). The temporary is checked by name just before its link and its final name just
after, so another file that took the temporary's place is never published. A failure, or
a cancellation through ``cancelled``, removes the temporary and any file this run
published, newest first, and nothing else: each name is checked just before its unlink,
and a name this run's link made for another file goes only while it and the temporary's
name still lead to one file. Two gaps remain, each needing another process to act on this
run's names during the save. One that moves its own file onto a name between the check
and the unlink loses that file. One whose file took the temporary's place and then moves
on can leave the name this run's link made for it, which ``left`` does not name. The flag
is read last after the folder's flush, just before the save returns, so a cancellation
that comes as the PDF is linked still undoes the whole save, and one that meets a failure
is still a cancellation. A save raises NotSaved or Cancelled, naming in ``left`` any file
of this run it could not remove, never a raw error; an error that is not the file
system's (a bug) is raised as it is, after the same cleanup. The run's signal handlers set
the cancellation flag for the whole save; a KeyboardInterrupt raised anywhere else is
cleaned up as far as it can be, with no promise that ``left`` names everything (the #354
review, round 2). It spawns nothing: the open is the chokepoint's (O1), which pins
whatever the published path leads to when the run names it.
"""

from __future__ import annotations

import contextlib
import dataclasses
import errno
import fcntl
import os
import posixpath
import pwd
import re
import secrets
import stat
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

LAST: Final = 99  # the last suffix a name takes
MODE: Final = 0o600
PATH_MAX: Final = 1024  # macOS's, its NUL included: a longer path cannot be opened
_PREFIX: Final = ".voltry-mac-"
_SUFFIX: Final = ".tmp"
_TRIES: Final = 8  # temporary names tried before the save gives up
# collected_at_local's shape (the schema's): a date, a time and a UTC offset.
_LOCAL: Final = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[+-][0-9]{2}:[0-9]{2}", re.ASCII
)
# What F_FULLFSYNC fails with where the file system does not offer it.
_NOT_OFFERED: Final = frozenset({errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOTTY, errno.EINVAL})

# Why a report was not saved, in the writer's own words; any other reason is the system's.
_NO_HOME: Final = "the account database has no home folder for this account"
_HOME_NOT_ABSOLUTE: Final = "this account's home folder is not an absolute path"
_ROOT: Final = "voltry-mac does not save a report as root"
_UNNAMED: Final = "the folder's path could not be read"
_ALL_TAKEN: Final = "every name for this minute, up to (99), is taken"  # 99 is LAST
_TOO_LONG: Final = "the folder's path is too long for the report's name"
_NO_TEMPORARY: Final = "no temporary name was free"
_NO_LINKS: Final = (
    "this folder's disk cannot save the report safely, because its format has no hard links"
)
# The run names the file it could not remove on the lines that follow, so the reason says only
# why the save stopped (the copy pass's review, round 2, n4).
_STUCK: Final = "no second temporary file is made while the first is still there"
_NOT_OWNED: Final = "a saved file's owner is not this user"
_REPLACED: Final = "a saved file was replaced before it was checked"
# Every one, in a fixed order, for the copy pass to pin word for word (MAC 3.11).
REASONS: Final = (
    _NO_HOME,
    _HOME_NOT_ABSOLUTE,
    _ROOT,
    _UNNAMED,
    _ALL_TAKEN,
    _TOO_LONG,
    _NO_TEMPORARY,
    _NO_LINKS,
    _STUCK,
    _NOT_OWNED,
    _REPLACED,
)


class NotSaved(Exception):
    """The report could not be saved (exit 4): why, in the writer's own words (REASONS) or
    the system's; the folder, as given when the owner named one, else the Desktop's or the
    home folder's path, or ``~/Desktop`` or ``~`` when the save stopped before the home
    folder was known; and any file of this run that could not be removed (``left``), each
    safe to delete."""

    def __init__(self, reason: str, folder: str, left: tuple[str, ...] = ()) -> None:
        super().__init__(reason)
        self.folder = folder
        self.left = left


class Cancelled(Exception):
    """The run's flag stopped the save before it was done, its PDF's link included, or was
    set when a failure stopped it. Every file of this run is gone but those named in
    ``left``, each safe to delete; after a KeyboardInterrupt raised outside the flag,
    ``left`` may miss some (the #354 review, round 2)."""

    def __init__(self, left: tuple[str, ...] = ()) -> None:
        super().__init__("the save was cancelled")
        self.left = left


class _NoLinks(OSError):
    """The folder's disk refused the link: its format keeps no hard links."""


class _Refused(Exception):
    """macOS refused the default Desktop: the save moves to the home folder."""

    def __init__(self, left: tuple[str, ...] = ()) -> None:
        super().__init__("macOS refused the Desktop")
        self.left = left


@dataclass(frozen=True)
class Saved:
    """Where the report was published: the PDF, the JSON when asked for, whether macOS
    refused the Desktop so it went to the home folder, whether the first name was taken,
    and any file of this run that could not be removed (``left``), each safe to delete. A
    temporary left after its publish is a second name for a published file, so the
    chokepoint's O1 refuses to open it (mode 0600, one name), and the run says so
    (``second_name``, change record 21)."""

    pdf: str
    json: str | None
    fallback: bool
    renamed: bool
    left: tuple[str, ...] = ()

    @property
    def second_name(self) -> bool:
        """Whether the PDF's temporary is still there as a second name for it: once a save
        is complete, a temporary it left can only be the PDF's, since no temporary is made
        while one is left and the save never moves home while one is."""
        return any(_is_temporary(path) for path in self.left)


def home() -> str:
    """This user's home folder, from the account database, never $HOME. An account with no
    entry there, or whose home folder is not an absolute path, has no folder to save in."""
    try:
        folder = pwd.getpwuid(os.getuid()).pw_dir
    except KeyError:
        raise NotSaved(_NO_HOME, "~") from None
    if not folder.startswith("/"):
        raise NotSaved(_HOME_NOT_ABSOLUTE, folder)
    return folder


def base_name(local: str) -> str:
    """The report's name at its local time (collected_at_local), with a period for the
    colon, which Finder shows as a slash. A time not in the report's shape names nothing."""
    if _LOCAL.fullmatch(local) is None:
        raise ValueError("the local time is not in the report's shape")
    return f"Voltry Mac Report {local[0:10]} {local[11:13]}.{local[14:16]}"


# The file system calls, one each, so a test can stand in for one.


def _uid() -> int:
    return os.getuid()


def _open_folder(path: str) -> int:
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)


def _close_folder(folder_fd: int) -> None:
    os.close(folder_fd)


def _token() -> str:
    return secrets.token_hex(8)


def _create(folder_fd: int, name: str) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    return os.open(name, flags, MODE, dir_fd=folder_fd)


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(descriptor, view) :]


def _sync(descriptor: int) -> None:
    """Flush to the disk itself: F_FULLFSYNC on macOS, where fsync stops at the drive's
    cache, and fsync where the file system does not offer it. A full flush that fails for
    any other reason is a failed save."""
    full = getattr(fcntl, "F_FULLFSYNC", None)
    if full is not None:
        try:
            fcntl.fcntl(descriptor, full)
        except OSError as error:
            if error.errno not in _NOT_OFFERED:
                raise
        else:
            return
    os.fsync(descriptor)


def _publish(folder_fd: int, temporary: str, final: str) -> None:
    os.link(temporary, final, src_dir_fd=folder_fd, dst_dir_fd=folder_fd, follow_symlinks=False)


def _unlink(folder_fd: int, name: str) -> None:
    os.unlink(name, dir_fd=folder_fd)


def _identity(folder_fd: int, name: str) -> os.stat_result:
    return os.stat(name, dir_fd=folder_fd, follow_symlinks=False)


def _taken(folder_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=folder_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def _kernel_path(folder_fd: int) -> str:
    """The path the system keeps for an open folder: F_GETPATH on macOS, /proc's link on
    Linux, where the tests also run."""
    getpath = getattr(fcntl, "F_GETPATH", None)
    if getpath is not None:
        raw = fcntl.fcntl(folder_fd, getpath, bytes(PATH_MAX))
        return os.fsdecode(raw.split(b"\0", 1)[0])
    return os.readlink(f"/proc/self/fd/{folder_fd}")


# What this run made.


class _Made:
    """What this run made in one open folder: each name with the descriptor of its file,
    held open until the save ends so that no other file can take that file's number on any
    disk (the #354 review, round 4), and each final name with the temporary it was linked
    from. A name is removed only while it still leads to a regular file that matches the
    one held open (_ours), or, when this run's link made it for another file that had
    taken the temporary's place, while it and the temporary's name still lead to that one
    file; each check comes just before its unlink. Names go newest first, so a kill during the
    cleanup leaves at most a JSON without its PDF, and a removal that fails is kept in
    ``left``, never raised, so every other name is still tried."""

    def __init__(self, folder_fd: int) -> None:
        self.folder_fd = folder_fd
        self.names: dict[str, int] = {}
        self.links: dict[str, str] = {}
        self.left: list[str] = []

    def ours(self, name: str) -> bool:
        """Whether a name still leads to the file held open for it."""
        return _ours(_identity(self.folder_fd, name), os.fstat(self.names[name]))

    def remove(self, name: str) -> None:
        descriptor = self.names.pop(name)
        if not self._gone(name, descriptor):
            self.left.append(name)
        self.links.pop(name, None)
        if descriptor not in self.names.values():
            _let_go(descriptor)

    def undo(self) -> None:
        for name in reversed(list(self.names)):
            self.remove(name)

    def close(self) -> None:
        """Let go of every file still held, once the save is over."""
        for descriptor in set(self.names.values()):
            _let_go(descriptor)

    def _gone(self, name: str, descriptor: int) -> bool:
        try:
            found = _identity(self.folder_fd, name)
            if not (_ours(found, os.fstat(descriptor)) or self._linked_for(name, found)):
                return True  # another file took the name: not this run's, left alone
            _unlink(self.folder_fd, name)
        except FileNotFoundError:
            return True
        except OSError:
            return False
        return True

    def _linked_for(self, name: str, found: os.stat_result) -> bool:
        """Whether this run's link made ``name`` for another file that had taken the
        temporary's place: the two names still lead to that one file, so removing ``name``
        takes away only this run's name for it."""
        temporary = self.links.get(name)
        if temporary is None or found.st_nlink < 2:
            return False
        try:
            return os.path.samestat(found, _identity(self.folder_fd, temporary))
        except FileNotFoundError:
            return False


def _ours(found: os.stat_result, held: os.stat_result) -> bool:
    """Whether a name, as found, leads to the file held open: a regular file with its
    number, size and count of names, both read at the check. So a disk that settles a new
    file's number only once it is written (FAT, exFAT) is judged right at every step (the
    #354 review, round 2), and another kind of file is never this run's (round 3). While
    the file is held no other can take its number; a file shown with it all the same, as
    a volume that numbers files some other way might show one, must also match the size
    and the count of names (round 4)."""
    return stat.S_ISREG(found.st_mode) and _facts(found) == _facts(held)


def _facts(info: os.stat_result) -> tuple[int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_nlink)


def _let_go(descriptor: int) -> None:
    with contextlib.suppress(OSError):
        os.close(descriptor)


# The save.


def save(
    pdf: bytes,
    json: bytes | None,
    *,
    local: str,
    folder: str | None,
    cancelled: Callable[[], bool],
    before_desktop: Callable[[], None] | None = None,
) -> Saved:
    """Publish the report, the JSON first when there is one, then the PDF.

    ``folder`` None is the default Desktop, announced through ``before_desktop`` just
    before anything is opened there. Raises ``NotSaved`` or ``Cancelled``, having removed
    everything this run made but what their ``left`` names. A failure that meets a
    cancellation is Cancelled, since the run's exit 130 comes before 4. The flag is read
    last after the folder's flush: a stop that comes after that read returns Saved, and the
    caller reads the flag (the #354 review, round 4)."""
    try:
        return _save(pdf, json, local, folder, cancelled, before_desktop)
    except NotSaved as failed:
        if _stopped(cancelled):
            raise Cancelled(failed.left) from None
        raise


def _save(
    pdf: bytes,
    json: bytes | None,
    local: str,
    folder: str | None,
    cancelled: Callable[[], bool],
    before_desktop: Callable[[], None] | None,
) -> Saved:
    _check(cancelled)  # before the announcement, and before any folder is opened
    base = base_name(local)
    if folder is not None:
        if _uid() == 0:
            raise NotSaved(_ROOT, folder)
        if not folder:
            raise NotSaved(os.strerror(errno.ENOENT), folder)
        return _save_in(folder, pdf, json, base, cancelled)
    if _uid() == 0:
        raise NotSaved(_ROOT, "~/Desktop")
    root = home()
    desktop = os.path.join(root, "Desktop")
    if before_desktop is not None:
        before_desktop()
    _check(cancelled)  # after the announcement, before the Desktop is opened
    try:
        return _save_in(desktop, pdf, json, base, cancelled, refusable=True)
    except _Refused as refused:
        try:
            _check(cancelled)  # before the move home starts anything
            if any(_is_temporary(path) for path in refused.left):
                # At most one temporary at any time: none is made at home while the Desktop
                # still holds one (the GPT audit, G1-06).
                raise NotSaved(os.strerror(errno.EPERM), desktop)
            saved = _save_in(root, pdf, json, base, cancelled)
        except NotSaved as failed:
            raise NotSaved(str(failed), failed.folder, refused.left + failed.left) from None
        except Cancelled as stopped:
            raise Cancelled(refused.left + stopped.left) from None
        return dataclasses.replace(saved, fallback=True, left=refused.left + saved.left)


def _is_temporary(path: str) -> bool:
    name = os.path.basename(path)
    return name.startswith(_PREFIX) and name.endswith(_SUFFIX)


def _stopped(cancelled: Callable[[], bool]) -> bool:
    try:
        return bool(cancelled())
    except KeyboardInterrupt:  # a Ctrl-C no handler turned into the flag
        return True


def _check(cancelled: Callable[[], bool]) -> None:
    if _stopped(cancelled):
        raise Cancelled


def _refusal(error: OSError, refusable: bool) -> bool:
    return refusable and error.errno == errno.EPERM


def _reason(error: OSError) -> str:
    if isinstance(error, _NoLinks):
        return _NO_LINKS
    return error.strerror or str(error)


def _save_in(
    path: str,
    pdf: bytes,
    json: bytes | None,
    base: str,
    cancelled: Callable[[], bool],
    *,
    refusable: bool = False,
) -> Saved:
    try:
        folder_fd = _open_folder(path)
    except OSError as error:
        if _refusal(error, refusable):
            raise _Refused from None
        raise NotSaved(_reason(error), path) from None
    made = _Made(folder_fd)
    where = path  # nothing is made until the folder is named
    try:
        try:
            # macOS asks about the Desktop inside the open, so a Ctrl-C there counts before
            # anything is made.
            _check(cancelled)
            where = _named(folder_fd, path)
            return _steps(made, where, path, pdf, json, base, cancelled)
        except BaseException as error:
            # Whatever stopped the save, everything this run made here goes first.
            made.undo()
            left = tuple(os.path.join(where, name) for name in made.left)
            if isinstance(error, Cancelled | KeyboardInterrupt):
                raise Cancelled(left) from None
            if isinstance(error, NotSaved):
                raise NotSaved(str(error), error.folder, left) from None
            if isinstance(error, OSError):
                # macOS refusing the Desktop at any step moves the whole save home.
                if _refusal(error, refusable):
                    raise _Refused(left) from None
                raise NotSaved(_reason(error), path, left) from None
            raise
    finally:
        made.close()
        with contextlib.suppress(OSError):
            _close_folder(folder_fd)


def _normal(path: str) -> bool:
    """An absolute path in normal form, as the chokepoint's open requires."""
    try:
        path.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return (
        path.startswith("/")
        and not path.startswith("//")
        and "\x00" not in path
        and posixpath.normpath(path) == path
    )


def _leads_to(path: str, here: os.stat_result) -> bool:
    if not _normal(path):
        return False
    try:
        return os.path.samestat(os.stat(path), here)
    except OSError:
        return False


def _named(folder_fd: int, path: str) -> str:
    """The open folder's path in normal form: the path as given, made absolute, while it
    still leads to that folder, else the path the system keeps for it. A folder that
    cannot be named takes no report."""
    here = os.fstat(folder_fd)
    typed = os.path.abspath(path)
    if _leads_to(typed, here):
        return typed
    try:
        kept = _kernel_path(folder_fd)
    except OSError:
        kept = ""
    if _leads_to(kept, here):
        return kept
    raise NotSaved(_UNNAMED, path)


def _temporary(made: _Made, data: bytes, folder: str) -> str:
    """A new temporary holding ``data``, mode 0600, flushed to the disk and held open. None
    is made while one of this run's could not be removed, so at most one exists at any
    moment (the GPT audit, G1-06; the #354 review, round 4)."""
    if any(_is_temporary(name) for name in made.left):
        raise NotSaved(_STUCK, folder)
    for _ in range(_TRIES):
        name = f"{_PREFIX}{_token()}{_SUFFIX}"
        try:
            descriptor = _create(made.folder_fd, name)
        except FileExistsError:
            continue  # not this run's name: left alone
        made.names[name] = descriptor
        os.fchmod(descriptor, MODE)  # whatever the umask took away
        _write_all(descriptor, data)
        _sync(descriptor)
        return name
    raise OSError(errno.EEXIST, _NO_TEMPORARY)


def _put(
    made: _Made, data: bytes, final: str, cancelled: Callable[[], bool] | None, folder: str
) -> bool:
    """One file start to finish: its temporary, the last cancellation check when one is
    given, the link to its final name and the temporary's name gone. False when another
    file took the name first, with nothing of it left but a temporary that will not go.
    The temporary is checked by name just before the link and the final name just after,
    so another file that took the temporary's place is never published (the #354 review,
    round 4)."""
    temporary = _temporary(made, data, folder)
    if cancelled is not None:
        _check(cancelled)
    if not made.ours(temporary):
        raise NotSaved(_REPLACED, folder)
    try:
        _publish(made.folder_fd, temporary, final)
    except FileExistsError:
        made.remove(temporary)
        return False
    except OSError as error:
        if error.errno in (errno.ENOTSUP, errno.EOPNOTSUPP):
            raise _NoLinks(error.errno, _NO_LINKS) from None
        if error.errno == errno.EPERM and not made.ours(temporary):
            # link(2) refuses a folder at the temporary's name with EPERM too: that is not
            # macOS refusing this folder, so the save does not move home.
            raise NotSaved(_REPLACED, folder) from None
        raise
    made.names[final] = made.names[temporary]
    made.links[final] = temporary
    if not made.ours(final):
        # Another file took the temporary's place just before the link, which named that
        # file: the cleanup takes this run's name for it away again.
        raise NotSaved(_REPLACED, folder)
    # The file stays under its final name. A temporary that will not go is named in
    # ``left``: for the last file the save itself is done, and before another file the
    # save stops (_temporary).
    made.remove(temporary)
    return True


def _free(folder_fd: int, base: str, start: int, folder: str) -> tuple[int, str]:
    """The first name from ``start`` free for both the PDF and the JSON."""
    for number in range(start, LAST + 1):
        stem = base if number == 1 else f"{base} ({number})"
        if not _taken(folder_fd, f"{stem}.pdf") and not _taken(folder_fd, f"{stem}.json"):
            return number, stem
    raise NotSaved(_ALL_TAKEN, folder)


def _fits(where: str, final: str, folder: str) -> None:
    if len(os.fsencode(os.path.join(where, final))) >= PATH_MAX:
        raise NotSaved(_TOO_LONG, folder)


def _steps(
    made: _Made,
    where: str,
    path: str,
    pdf: bytes,
    json: bytes | None,
    base: str,
    cancelled: Callable[[], bool],
) -> Saved:
    folder_fd = made.folder_fd
    number = 1
    while True:
        number, stem = _free(folder_fd, base, number, path)
        _fits(where, f"{stem}.pdf" if json is None else f"{stem}.json", path)
        if json is not None:
            if not _put(made, json, f"{stem}.json", None, path):
                number += 1  # taken since it was checked: both move on
                continue
            _check(cancelled)
        if _put(made, pdf, f"{stem}.pdf", cancelled, path):
            break
        # The PDF's name was taken since it was checked: this run's JSON under it goes, and
        # both move on.
        if json is not None:
            made.remove(f"{stem}.json")
        number += 1
    uid = _uid()
    for name, descriptor in made.names.items():
        found = _identity(folder_fd, name)
        if found.st_uid != uid:
            raise NotSaved(_NOT_OWNED, path)
        if not _ours(found, os.fstat(descriptor)):
            raise NotSaved(_REPLACED, path)
    with contextlib.suppress(OSError):
        _sync(folder_fd)  # the folder's new names, on the disk
    # The last read of the flag, while every file is still this run's to remove: a
    # cancellation that came as the PDF was linked undoes the whole save (the GPT audit,
    # G1-09).
    _check(cancelled)
    # Named where the folder is now, in case it moved during the save; the report is saved
    # either way, so a folder that cannot be named again keeps the first name.
    with contextlib.suppress(NotSaved, OSError):
        where = _named(folder_fd, path)
    json_path = None if json is None else os.path.join(where, f"{stem}.json")
    return Saved(
        os.path.join(where, f"{stem}.pdf"),
        json_path,
        False,
        number > 1,
        tuple(os.path.join(where, name) for name in made.left),
    )
