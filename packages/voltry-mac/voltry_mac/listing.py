"""The process listing, P1: `/bin/ps -axo pid,ppid,uid,lstart,comm`.

docs/VOLTRY_MAC_SPEC.md, Decision 2: the capability check after consent, and the tracking
of a payload command's process and what it starts. Each row is the process ID, its
parent's, the numeric user ID (the effective one, which ps reports), the start time as
five words, and the command, which may hold spaces and is sometimes a full path, or a short
name in parentheses, so only its basename is kept for any comparison. A listing is read
transiently and discarded; a row that does not parse makes the whole listing a failed one,
never a guess.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

_HEADER: Final = ["PID", "PPID", "UID", "STARTED", "COMM"]
_NUMBER: Final = re.compile(r"[0-9]{1,10}", re.ASCII)
_SIGNED: Final = re.compile(r"-?[0-9]{1,10}", re.ASCII)  # nobody is uid -2 on macOS
_DAYS: Final = frozenset({"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"})
_MONTHS: Final = frozenset(
    {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
)
_DAY_OF_MONTH: Final = re.compile(r"(?:[1-9]|[12][0-9]|3[01])", re.ASCII)
_CLOCK: Final = re.compile(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]", re.ASCII)
_YEAR: Final = re.compile(r"[0-9]{4}", re.ASCII)


class Unreadable(ValueError):
    """The listing is not in ps's shape: a failed listing."""


@dataclass(frozen=True)
class Process:
    """One process as the listing shows it."""

    pid: int
    ppid: int
    uid: int
    started: str
    name: str


def _number(word: str, pattern: re.Pattern[str] = _NUMBER) -> int:
    if not pattern.fullmatch(word):
        raise Unreadable("not a number where one belongs")
    return int(word)


def _basename(command: str) -> str:
    """The command's basename. ps prints a process whose path it cannot read, as while it
    starts or ends, by the kernel's short name in parentheses, such as (powermetrics): that
    is the name, as the first live run found on macOS 26 (2026-09-29)."""
    if len(command) > 2 and command[0] == "(" and command[-1] == ")":
        command = command[1:-1]
    return command.rsplit("/", 1)[-1]


def _row(line: str) -> Process:
    words = line.split(maxsplit=8)
    if len(words) != 9:
        raise Unreadable("a row without all its fields")
    pid, ppid, uid, day, month, date, clock, year, command = words
    if (
        day not in _DAYS
        or month not in _MONTHS
        or not _DAY_OF_MONTH.fullmatch(date)
        or not _CLOCK.fullmatch(clock)
        or not _YEAR.fullmatch(year)
    ):
        raise Unreadable("not a start time")
    name = _basename(command.rstrip())
    if not name:
        raise Unreadable("a command with no name")
    return Process(
        _number(pid),
        _number(ppid),
        _number(uid, _SIGNED),
        f"{day} {month} {date} {clock} {year}",
        name,
    )


def processes(stdout: str) -> list[Process]:
    """Every process the listing shows, or ``Unreadable``."""
    # Only a newline ends a row: macOS's ps prints U+2028 and U+2029 in a name raw, and any
    # local process can take such a name.
    lines = stdout.split("\n")
    if not lines or lines[0].split() != _HEADER:
        raise Unreadable("not ps's header")
    found = [_row(line) for line in lines[1:] if line.strip()]
    if not found:
        raise Unreadable("no process")
    return found
