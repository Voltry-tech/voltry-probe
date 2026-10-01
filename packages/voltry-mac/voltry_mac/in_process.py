"""The reads voltry-mac makes in its own process, with no command: R1, R2 and R3.

docs/VOLTRY_MAC_SPEC.md, the allow-list's in-process reads, Decision 8's time fields and
the page setup's paper rule. Each is one read, bounded in time, spawns nothing, writes
nothing and keeps nothing but its answer:

- R1 lists /Library/Logs/DiagnosticReports once and counts the names ending in .panic;
  the names are read to count and then discarded. The folder is readable by
  administrators only, so a standard account, which macOS refuses with EACCES, gets
  no_admin; a refusal by policy (EPERM, a sandbox or a managed Mac) is tool_error.
- R2 reads where the /etc/localtime link points and keeps the part after its last
  zoneinfo folder as the IANA time zone identifier, or unknown when there is no link or
  the part is malformed.
- R3 reads one key, AppleLocale, from the owner's
  ~/Library/Preferences/.GlobalPreferences.plist with the standard plist parser: US
  Letter when its region, as this Mac's ICU (78.1) reads it, is US or CA, A4 otherwise,
  including when nothing can be read. The file is opened without following a link at its
  name and without waiting, read once only if it is a regular file, within a cap, and
  parsed only while every key is text; nothing else in it is kept.

R4 is the preflight's and R5 the elevation broker's.
"""

from __future__ import annotations

import contextlib
import errno
import os
import plistlib
import re
import stat
from typing import Final

from voltry_mac.availability import Unavailable

DIAGNOSTIC_REPORTS: Final = "/Library/Logs/DiagnosticReports"
LOCALTIME: Final = "/etc/localtime"
PREFERENCES: Final = ("Library", "Preferences", ".GlobalPreferences.plist")
PREFERENCES_CAP: Final = 1024 * 1024  # a bound on the one read R3 makes
UNKNOWN_ZONE: Final = "unknown"
LETTER_REGIONS: Final = frozenset({"US", "CA"})
# Our own bound on a locale, not ICU's: ICU reads longer ones, but CoreFoundation aborts on
# some past 157 characters, so a longer AppleLocale is not a setting that works.
LOCALE_MAX: Final = 157

# One step of an IANA identifier: letters, digits and _ + - ., never . or .. alone; the
# whole identifier within the schema's 64 characters.
_STEP: Final = re.compile(r"[A-Za-z0-9_+.-]+", re.ASCII)
_ZONE_MAX: Final = 64
# A locale's region, as this Mac's ICU 78.1 reads it (the #355 review, round 2): the
# language is anything up to a separator; a script, if any, is four letters; the region is
# two letters, or USA or CAN, before a separator or the end.
_REGION: Final = re.compile(
    r"[^-_.@]*(?:[-_][A-Za-z]{4}(?=[-_.]|$))?[-_]([A-Za-z]{2,3})(?=[-_.]|$)", re.ASCII
)
_THREE_LETTERS: Final = {"USA": "US", "CAN": "CA"}


def panic_count(folder: str = DIAGNOSTIC_REPORTS) -> int | Unavailable:
    """R1: how many names in the folder end in .panic, or why they could not be counted."""
    try:
        names = os.listdir(folder)
    except PermissionError as refused:
        return Unavailable("no_admin" if refused.errno == errno.EACCES else "tool_error")
    except FileNotFoundError:
        return Unavailable("source_absent")
    except (OSError, ValueError):
        return Unavailable("tool_error")
    return sum(name.endswith(".panic") for name in names)


def time_zone(link: str = LOCALTIME) -> str:
    """R2: the IANA identifier the link names after its last zoneinfo folder, or unknown."""
    try:
        target = os.readlink(link)
    except (OSError, ValueError):
        return UNKNOWN_ZONE
    steps = target.split("/")
    if "zoneinfo" not in steps:
        return UNKNOWN_ZONE
    steps = steps[len(steps) - steps[::-1].index("zoneinfo") :]
    zone = "/".join(steps)
    well_formed = 0 < len(zone) <= _ZONE_MAX and all(
        _STEP.fullmatch(step) and step not in (".", "..") for step in steps
    )
    return zone if well_formed else UNKNOWN_ZONE


def _preferences(home: str) -> bytes | None:
    """The preferences file's bytes: opened without following a link at its name and
    without waiting (a FIFO there never answers), and read once if it is a regular file
    within the cap."""
    if not home.startswith("/"):
        return None
    path = os.path.join(home, *PREFERENCES)
    try:
        # The flags sit in the call, where the static guards' write scan reads them.
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except (OSError, ValueError):
        return None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            return None
        data = os.read(descriptor, PREFERENCES_CAP + 1)
    except OSError:
        return None
    finally:
        with contextlib.suppress(OSError):
            os.close(descriptor)
    return data if len(data) <= PREFERENCES_CAP else None


def _region(locale: str) -> str | None:
    """The region ICU reads from a locale: the first region override (@rg=, whatever the
    case of its key, among the other keywords), then the locale's own region.

    ICU reads an override of 3 to 6 characters, spaces trimmed, that starts with two
    letters: a region and a subdivision (gbzzzz, usca, gbsct). Any other value, three
    digits among them, it ignores, and the locale's own region stands. Two forms macOS
    never writes are left out: an override naming a region ICU does not know, which ICU
    ignores, and a BCP 47 override (-u-rg-)."""
    if len(locale) > LOCALE_MAX:
        return None
    base, _, keywords = locale.partition("@")
    for keyword in keywords.split(";"):
        key, _, value = keyword.partition("=")
        if key.strip(" ").lower() != "rg":
            continue
        value = value.strip(" ")
        if 3 <= len(value) <= 6 and value[:2].isascii() and value[:2].isalpha():
            return value[:2].upper()
        break  # only the first override counts
    found = _REGION.match(base)
    if found is None:
        return None
    region = found.group(1).upper()
    return _THREE_LETTERS.get(region, region)


class _TextKeys(dict[str, object]):
    """The parser's dictionaries, which take text keys only, each once. No preferences file
    has any other, and a crafted one keyed by integers that share a hash would make each
    insert compare with every key before it (the #355 review, round 2); the first such key
    ends the parse instead. A key given twice, AppleLocale among them, ends it too, so the
    paper is A4, as for any file the parser cannot read, rather than the last one's (the
    review of #326, round 1, N1)."""

    def __setitem__(self, key: object, value: object) -> None:
        if not isinstance(key, str):
            raise TypeError("a preferences key is text")
        if key in self:
            raise ValueError("a preferences key given twice")
        super().__setitem__(key, value)


def paper(home: str) -> str:
    """R3: "letter" when the owner's region is the US or Canada, "a4" otherwise."""
    data = _preferences(home)
    if data is None:
        return "a4"
    try:
        preferences = plistlib.loads(data, dict_type=_TextKeys)
    except Exception:  # noqa: BLE001 - any file the parser cannot read means A4
        return "a4"
    locale = preferences.get("AppleLocale") if isinstance(preferences, dict) else None
    if not isinstance(locale, str):
        return "a4"
    return "letter" if _region(locale) in LETTER_REGIONS else "a4"
