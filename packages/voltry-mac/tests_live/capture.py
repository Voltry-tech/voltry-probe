"""The sudo message and topology capture (docs/VOLTRY_MAC_SPEC.md, Test strategy part 5,
"Live macOS CI", its second bullet; Decision 2, "Stopping a payload" and the pinned
templates; the Acceptance lines on the live jobs; change records 12, 13 and 23; board item
MAC 4.2, issue #324).

A release prerequisite. .github/workflows/voltry-mac.yml's capture job runs this as root on
each pinned image, on the throwaway virtual machine alone; anywhere else it refuses before
it reads or changes anything (tests_live/gate.py). In order:

1. `sudo -V`. Its first line gives sudo's version, which decides what the cases and checks
   below expect: Apple ships 1.9.13p2 on macOS 15.0 to 15.6 and 26.0 and 1.9.17p2 on 26.1
   and later, and they differ in the ssh hint, the monitor and cmddenial_message (change
   record 12); the log says what this one does. It must show no I/O log, log server or
   command timeout, with which sudo never executes a command directly (sudo 1.9.17p2's
   plugins/sudoers/policy.c, src/exec.c). As root it lists root's defaults alone, so that
   is a necessary check, not the proof: the identifications at level 0 in step 4 are.
2. The image's own policy must pass `visudo -c` before anything is added. Then disposable
   test accounts, each with a password made for this run, and disposable sudoers drop-ins,
   each checked with `visudo -c` before it is installed and the whole policy after.
3. The messages: sudo in each situation the bullet names (tests_live/messages.py), run as
   a test account under the fixed LC_ALL=en_US.UTF-8, on a pseudo-terminal or with none.
   Which lines reach stderr and which the terminal is recorded, and each stderr line is
   held to its pinned template and no other. A template no case reproduced is held to
   its sudo source file by the package's own test, which the log names with the reason
   this image could not print it. The account-state lines never print on stock macOS,
   which the log says from the image's own /etc/pam.d/sudo; there what sudo does instead
   is held to change record 13, where pwpolicy set the account's state. Each line of a
   case not judged, and of the failed attempt before the locked-out case, must still match
   one template or be one to ignore.
4. Direct execution: S3n and S4n through the payload runner as the runner user, whose
   drop-in turns off use_pty, pam_session, pam_setcred and log_exit_status; the tracker
   must identify each payload at level 0.
5. The slow prompt: S3 and S4 as a disposable administrator whose drop-in requires a
   password and sets timestamp_timeout=0, on a pseudo-terminal this script answers only
   after 10 s; no launch clock may start during any wait, for S3, whose user ID changes,
   and for S4, whose user ID does not. Once while sudo executes them directly, and again
   with sudo's defaults: through its monitor on sudo 1.9.14 and later, and as its own
   child before. The count ends in milliseconds, so a listing every 200 ms rarely sees it
   after the answer; its subtree and clocks are recorded, and the topology is asserted on
   S4, which runs for seconds and must show a runtime clock armed after its answer.
6. The broker in-process, as the runner user, with the runtime clock at 1 s and sudo
   executing directly: first with the count's payload a sandboxed /bin/sleep 8 as
   _mmaintenanced, then the real S4n alone (tests_live/topology.py). Each stop meets
   EPERM, the cleanup is survivor, the owner's verification-first note is the one the
   spec gives, and the nonblocking wait collects the process once it ends on its own. The
   real S4n may instead have ended on SIGPIPE right after EPERM, once the tool closed its
   pipes, and before the final listing: its cleanup is then verified, which is true, and
   the log says why (change record 23).

What ps printed for comm is recorded for every process of each subtree, and so is every
descendant seen before the monitor on the password path. Touch ID, which the virtual
machines lack, is covered by the stage 3 spike on real Macs. A check that fails prints
what was seen beside it. The accounts and drop-ins go at the end whatever failed, and
`capture.py --cleanup`, which the job runs even when a step failed, removes whatever of
them is left; sudo's own records of the test accounts (their lecture and timestamp files
under /var/db/sudo) stay, with the throwaway virtual machine. The log names templates,
classes, counts and states: never a password, a host name or a line sudo printed. A
password never stands in an argv either: dscl reads it on its standard input.
"""

from __future__ import annotations

import contextlib
import dataclasses
import importlib.util
import json
import os
import pty
import pwd
import re
import secrets
import select
import signal
import stat
import subprocess
import sys
import time
import traceback
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType, ModuleType
from typing import Any, Final

HERE: Final = Path(__file__).resolve().parent


def _load(name: str, file: str) -> ModuleType:
    """A sibling module by its path, as conftest.py loads it: tests_live is not a package."""
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, HERE / file)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


gate = _load("voltry_mac_live_gate", "gate.py")
messages = _load("voltry_mac_live_messages", "messages.py")
topology: Any = None  # tests_live/topology.py, loaded once the gate has passed

# Every child's environment, as the tool gives it (the allow-list's "Environment for every
# child"): the fixed locale sudo's messages are pinned under.
ENV: Final = MappingProxyType({"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "en_US.UTF-8"})
SUDO: Final = "/usr/bin/sudo"
VISUDO: Final = "/usr/sbin/visudo"
DSCL: Final = "/usr/bin/dscl"
DSEDITGROUP: Final = "/usr/sbin/dseditgroup"
DSCACHEUTIL: Final = "/usr/bin/dscacheutil"
PWPOLICY: Final = "/usr/bin/pwpolicy"
SYSCTL: Final = "/usr/sbin/sysctl"
SUDOERS: Final = Path("/private/etc/sudoers")
SUDOERS_D: Final = Path("/private/etc/sudoers.d")
PAM_SUDO: Final = Path("/private/etc/pam.d/sudo")

# The drop-ins, named without a dot, since sudo reads no drop-in whose name has one; and
# the line each begins with, which the cleanup checks before it removes anything.
MESSAGES_DROP_IN: Final = "zz-voltry-mac-capture"
DENIAL_DROP_IN: Final = "zz-voltry-mac-denial"
RUNNER_DIRECT: Final = "zz-voltry-mac-runner-direct"
ADMIN_DIRECT: Final = "zz-voltry-mac-admin-direct"
DROP_INS: Final = (MESSAGES_DROP_IN, DENIAL_DROP_IN, RUNNER_DIRECT, ADMIN_DIRECT)
MARK: Final = "# voltry-mac capture (MAC 4.2): disposable, removed when the capture ends"
STAGED: Final = ".staged"
# What makes sudo execute a payload directly, with no monitor ("Stopping a payload").
DIRECT: Final = "!use_pty, !pam_session, !pam_setcred, !log_exit_status"

# The test accounts: one for each case's settings (tests_live/messages.py), and the
# disposable administrator the slow prompt runs as. Each is marked by its full name, which
# the cleanup checks before it removes anything.
ADMIN: Final = "vmcap_admin"
ACCOUNTS: Final = (
    "vmcap_plain",
    "vmcap_denial",
    "vmcap_once",
    "vmcap_thrice",
    "vmcap_timeout",
    "vmcap_authfail",
    "vmcap_unlisted",
    "vmcap_elsewhere",
    "vmcap_locked",
    "vmcap_expired",
    "vmcap_lockout",
    ADMIN,
)
# What pwpolicy sets on the accounts whose state the cases try, where the image allows it.
STATES: Final = (
    ("vmcap_locked", ("-disableuser",), "disabled"),
    ("vmcap_expired", ("-setpolicy", "newPasswordRequired=1"), "a password that must change"),
    (
        "vmcap_lockout",
        ("-setpolicy", "maxFailedLoginAttempts=1"),
        "locked after one failed attempt",
    ),
)
REAL_NAME: Final = "Voltry capture test account"
FIRST_UID: Final = 7401
STAFF: Final = 20
WRONG: Final = "not-this-account-s-password"

# sudo -V's lines, as root, for the settings that stop direct execution (sudo 1.9.17p2's
# plugins/sudoers/def_data.in, the same in 1.9.13p2): the seven I/O log flags, the log
# servers and the command timeout. The timestamp timeout's line is always there, so its
# absence means sudo -V listed no defaults at all. And the lecture file it names, whose
# lines sudo prints on an account's first use (plugins/sudoers/check.c).
IO_LOG: Final = (
    "Log user's input for the command being run",
    "Log the command's standard input if not connected to a terminal",
    "Log the user's terminal input for the command being run",
    "Log the output of the command being run",
    "Log the command's standard output if not connected to a terminal",
    "Log the command's standard error if not connected to a terminal",
    "Log the terminal output of the command being run",
)
LOG_SERVERS: Final = "Sudo log server(s) to connect to with optional port"
COMMAND_TIMEOUT: Final = "Time in seconds after which the command will be terminated:"
LISTED: Final = "Authentication timestamp timeout:"
LECTURE_FILE: Final = "File containing the sudo lecture: "

# Deadlines. The job's own worst case stays under the capture step's timeout, which stays
# under the job's (the workflow and tests/ci hold those): at most 17 sudo runs for the
# cases, then one direct, two slow and two broker probes.
WAIT_S: Final = 10.0  # the slow prompt: how long the driver waits before it answers
CASE_S: Final = 30.0  # one message case: three wrong passwords take a few seconds each
DIRECT_S: Final = 240.0  # S3n again and again for up to 90 s, then S4n
SLOW_S: Final = 120.0  # two prompts answered after 10 s each, and two payloads
BROKER_S: Final = 75.0  # a 1 s runtime clock, the stop, and up to 15 s for the wait
DRAIN_S: Final = 2.0  # after a child ends, how long its pipes may stay open
POLL_S: Final = 0.05
# The most the cases and probes can take: each drive, a sudo run or a probe, runs to its
# deadline and then keeps its pipes open DRAIN_S more. Every case's sudo run, the locked-out
# case's failed attempt too, then the direct, two slow and two broker probes: 22 drives, 19.7
# minutes. Setting up and removing the accounts and drop-ins normally takes a minute or two
# more, inside the capture step's 22.
_DRIVES: Final = (
    *([CASE_S] * (len(messages.CASES) + 1)),
    DIRECT_S,
    SLOW_S,
    SLOW_S,
    BROKER_S,
    BROKER_S,
)
WORST_S: Final = sum(_DRIVES) + len(_DRIVES) * DRAIN_S

# The broker's two runs, as Decision 2's outcome tables make them.
STAND_IN_RECORD: Final = {
    "consent": "flag",
    "skip_cause": None,
    "mode": "noninteractive",
    "checks": {"service_account": "present", "sandbox_probe": "ok", "listing": "ok"},
    "prepare": "ok",
    "authenticate": "ok",
    "count": {"ending": "runtime_deadline", "cleanup": "survivor"},
    "power": {"ending": "not_run", "cleanup": "not_applicable"},
    "cleared": "cleared",
    "clear_error": None,
}
POWER_ALONE_RECORD: Final = {
    **STAND_IN_RECORD,
    "checks": {"service_account": "missing", "sandbox_probe": "ok", "listing": "ok"},
    "count": {"ending": "not_run", "cleanup": "not_applicable"},
    "power": {"ending": "runtime_deadline", "cleanup": "survivor"},
}
# Change record 23: after EPERM the tool closes its pipes, and powermetrics' next write ends
# it on SIGPIPE, often before the final listing, which then shows it ended and finds no
# survivor. The tool's cleanup is then verified, which is true, and the run passes with the
# reason in the log. The stand-in, a sleep, writes nothing, so SIGPIPE cannot end it.
POWER_ALONE_ENDED_RECORD: Final = {
    **POWER_ALONE_RECORD,
    "power": {"ending": "runtime_deadline", "cleanup": "verified"},
}
# What each broker run must show beside the payload's identity (Decision 2's tables and
# "Stopping a payload"): its record, and the record it may show instead when the payload
# ended on SIGPIPE right after EPERM (change record 23), the count's and the power sample's
# outcomes, how the owner's note names the survivor, and the command that must never start.
# The stand-in is a sleep, none of the four names the subtree can contain, so the note names
# it an unexpected process.
STAND_IN_EXPECTED: Final = MappingProxyType(
    {
        "ended": None,
        "record": STAND_IN_RECORD,
        "outcomes": (["timeout", "runtime_deadline"], ["tool_error", "skipped_after_unsafe_stop"]),
        "shown_as": "an unexpected process",
        "not_run": "S4n",
    }
)
POWER_ALONE_EXPECTED: Final = MappingProxyType(
    {
        "ended": POWER_ALONE_ENDED_RECORD,
        "record": POWER_ALONE_RECORD,
        "outcomes": (["unsupported", "service_account_missing"], ["timeout", "runtime_deadline"]),
        "shown_as": "powermetrics",
        "not_run": "S3n",
    }
)
# How ps names a process that has ended and whose exit is not collected yet; the probe says
# "gone" for one the final listing does not show at all.
ZOMBIE: Final = "<defunct>"
ENDED: Final = (ZOMBIE, "gone")


class Failed(Exception):
    """A step the capture cannot go on without."""


@dataclass(frozen=True)
class Check:
    """One check: whether it holds, what it claims, and what was seen, which the log prints
    beside a failure. What was seen is an ending, a state, a class, a count or a clock:
    never a line sudo printed, a name or a password."""

    holds: bool
    what: str
    seen: object = None


class Checks:
    """Each check's line, what was seen beside each that failed, and the ones that failed."""

    def __init__(self) -> None:
        self.failed: list[str] = []

    def that(self, holds: bool, what: str, seen: object = None) -> None:
        print(f"  {'ok  ' if holds else 'FAIL'}  {what}")
        if not holds:
            self.failed.append(what)
            if seen is not None:
                print(f"        seen: {seen}")

    def every(self, checks: Sequence[Check]) -> None:
        for check in checks:
            self.that(check.holds, check.what, check.seen)


@dataclass(frozen=True)
class Account:
    """An account a child becomes: the runner user, or a test account with its password,
    which is never printed."""

    name: str
    uid: int
    gid: int
    password: str = field(default="", repr=False)


# --- the drop-ins -------------------------------------------------------------------------


def messages_drop_in() -> str:
    """What each case needs, an account apiece (tests_live/messages.py), but the denial
    message, which has a drop-in of its own. Every account authenticates with its
    password: the drop-in grants nothing without one. No account keeps an authorization
    from one case to the next (timestamp_timeout=0)."""
    true = "ALL = (root) /usr/bin/true"
    return (
        "\n".join(
            (
                MARK,
                "Defaults:vmcap_plain timestamp_timeout=0",
                f"vmcap_plain {true}",
                "Defaults:vmcap_denial timestamp_timeout=0",
                f"vmcap_denial {true}",
                "Defaults:vmcap_once timestamp_timeout=0, passwd_tries=1",
                f"vmcap_once {true}",
                "Defaults:vmcap_thrice timestamp_timeout=0",
                f"vmcap_thrice {true}",
                "Defaults:vmcap_timeout timestamp_timeout=0, passwd_timeout=0.05",
                f"vmcap_timeout {true}",
                "Defaults:vmcap_authfail timestamp_timeout=0, passwd_tries=1, "
                f'authfail_message="{messages.AUTHFAIL}"',
                f"vmcap_authfail {true}",
                "Defaults:vmcap_elsewhere timestamp_timeout=0",
                "vmcap_elsewhere voltry-capture-elsewhere = (root) /usr/bin/true",
                "Defaults:vmcap_locked timestamp_timeout=0, passwd_tries=1",
                f"vmcap_locked {true}",
                "Defaults:vmcap_expired timestamp_timeout=0, passwd_tries=1",
                f"vmcap_expired {true}",
                "Defaults:vmcap_lockout timestamp_timeout=0, passwd_tries=1",
                f"vmcap_lockout {true}",
                f"Defaults:{ADMIN} timestamp_timeout=0",
                f"{ADMIN} ALL = (ALL) PASSWD: ALL",
            )
        )
        + "\n"
    )


def denial_drop_in() -> str:
    """The denial message sudo prints after its refusal, for the one case that needs it."""
    return f'{MARK}\nDefaults:vmcap_denial cmddenial_message="{messages.CMDDENIAL}"\n'


def direct_drop_in(account: str) -> str:
    """What makes sudo execute ``account``'s commands directly, with no monitor."""
    return f"{MARK}\nDefaults:{account} {DIRECT}\n"


def _run(
    argv: Sequence[str], *, timeout: float = 60.0, given: str | None = None
) -> subprocess.CompletedProcess[str]:
    """One of the macOS tools this script needs, in the fixed environment, with ``given``
    on its standard input. A tool that cannot start or does not finish in time is a Failed
    that names the tool alone: an argv is never printed, and nothing given on standard
    input leaves this call."""
    tool = Path(argv[0]).name
    try:
        return subprocess.run(
            list(argv),
            env=dict(ENV),
            input=given,
            stdin=None if given is not None else subprocess.DEVNULL,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise Failed(f"{tool} did not finish within {timeout:.0f} s") from None
    except OSError as error:
        raise Failed(f"{tool} could not start (errno {error.errno})") from None


def _must(argv: Sequence[str], what: str) -> str:
    """Run one of the macOS tools this script needs; it must exit 0."""
    done = _run(argv)
    if done.returncode != 0:
        raise Failed(f"{what} failed with exit {done.returncode}")
    return done.stdout


def _dscl(commands: Sequence[str], what: str) -> None:
    """dscl's interactive mode on the local node, its commands read from standard input
    (dscl(1)), so a password never stands in an argv, where another process on the machine
    could read it while dscl runs: dscl(1) says passing one on the command line "is
    inherently insecure". -q prints no prompt, so a session that did all it was asked
    prints nothing: an exit other than 0, or any line printed, fails it. What dscl printed
    is counted, never shown, since an error can quote the command it read."""
    session = "".join(f"{command}\n" for command in (*commands, "quit"))
    done = _run([DSCL, "-q", "."], given=session)
    printed = [line for line in (done.stdout + done.stderr).split("\n") if line.strip()]
    if done.returncode != 0 or printed:
        raise Failed(f"{what} failed: dscl exit {done.returncode}, {len(printed)} lines printed")


def _includes_drop_ins() -> bool:
    """Whether the image's sudoers reads the drop-in folder at all."""
    lines = SUDOERS.read_text(encoding="utf-8", errors="replace").split("\n")
    includes = {
        (word, folder)
        for word in ("#includedir", "@includedir")
        for folder in (str(SUDOERS_D), "/etc/sudoers.d")
    }
    return any(tuple(line.split()) in includes for line in lines)


def check_base_policy() -> None:
    """The image's own policy passes visudo -c before any drop-in goes in, so a whole
    policy that fails later fails for a drop-in, never for the image."""
    checked = _run([VISUDO, "-c"])
    if checked.returncode != 0:
        said = (checked.stdout + checked.stderr).strip()
        raise Failed(f"the image's own sudoers policy fails visudo -c before any drop-in: {said}")
    print("  the image's own policy: checked with visudo -c before anything was added")


def install(name: str, text: str) -> None:
    """A drop-in, staged under a name with a dot, which sudo never reads, made new and
    never through a link, mode 0440 whatever the umask, every byte written; checked with
    visudo -c, renamed into place, and the whole policy checked again. One that fails
    either check is never left in place, and neither is its staged copy."""
    final, staged = SUDOERS_D / name, SUDOERS_D / f"{name}{STAGED}"
    descriptor = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o440)
    try:
        os.fchmod(descriptor, 0o440)  # the umask may have taken bits off at the open
        view = memoryview(text.encode("utf-8"))
        while view:
            view = view[os.write(descriptor, view) :]
    finally:
        os.close(descriptor)
    try:
        checked = _run([VISUDO, "-c", "-f", str(staged)])
        if checked.returncode != 0:
            said = (checked.stdout + checked.stderr).strip()
            raise Failed(f"visudo -c refused the drop-in {name}: {said}")
        os.rename(staged, final)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(staged)
    if _run([VISUDO, "-c"]).returncode != 0:
        os.unlink(final)
        raise Failed(f"visudo -c refused the policy with {name} in it, so it was removed")
    print(f"  {name}: checked with visudo -c, installed, and the whole policy checked again")


def _ours(path: Path) -> bool | None:
    """Whether a drop-in file is the capture's: a regular file that begins with the
    capture's line. A staged copy may hold only the start of that line, or nothing, when
    the capture was stopped between making it and writing it; sudo reads no name with a
    dot, so such a copy was never read, and it is the capture's too. None when the file
    is not there."""
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            return False
        text = path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return None
    if text.split("\n", 1)[0] == MARK:
        return True
    return path.name.endswith(STAGED) and "\n" not in text and MARK.startswith(text)


def remove_drop_in(name: str) -> bool:
    """Remove one of the capture's drop-ins and its staged copy, if they are there and are
    the capture's; false when one is left."""
    removed = True
    for path in (SUDOERS_D / name, SUDOERS_D / f"{name}{STAGED}"):
        ours = _ours(path)
        if ours is None:
            continue
        if ours:
            path.unlink()
            print(f"  {path.name}: removed")
        else:
            print(f"  {path.name}: not the capture's, left alone")
            removed = False
    return removed


# --- the accounts -------------------------------------------------------------------------


def _read(name: str) -> subprocess.CompletedProcess[str]:
    return _run([DSCL, ".", "-read", f"/Users/{name}", "RealName"])


def _free_uids(count: int) -> list[int]:
    listed = _must([DSCL, ".", "-list", "/Users", "UniqueID"], "listing the user IDs")
    used = {int(line.split()[-1]) for line in listed.split("\n") if line.strip()}
    return [uid for uid in range(FIRST_UID, FIRST_UID + 1000) if uid not in used][:count]


def _password() -> str:
    """A password made for this run: 32 hexadecimal digits, which no parser can take for
    an option or split."""
    return secrets.token_hex(16)


def _make(name: str, uid: int) -> Account:
    """One test account: marked by its full name before anything else is set, a member of
    staff, no shell and no home, hidden, and a password made for this run, given to dscl
    on its standard input."""
    path = f"/Users/{name}"
    _must([DSCL, ".", "-create", path, "RealName", REAL_NAME], f"creating {name}")
    for key, value in (
        ("UniqueID", str(uid)),
        ("PrimaryGroupID", str(STAFF)),
        ("UserShell", "/usr/bin/false"),
        ("NFSHomeDirectory", "/var/empty"),
        ("IsHidden", "1"),
    ):
        _must([DSCL, ".", "-create", path, key, value], f"setting {name}'s {key}")
    password = _password()
    _dscl([f"passwd {path} {password}"], f"setting {name}'s password")
    if name == ADMIN:
        _must(
            [DSEDITGROUP, "-o", "edit", "-a", name, "-t", "user", "admin"],
            f"making {name} an administrator",
        )
    return Account(name, uid, STAFF, password)


def make_accounts() -> dict[str, Account]:
    """Every test account, each seen by the account database and its password checked
    through dscl, as the password module checks it."""
    made = {
        name: _make(name, uid)
        for name, uid in zip(ACCOUNTS, _free_uids(len(ACCOUNTS)), strict=True)
    }
    _run([DSCACHEUTIL, "-flushcache"])
    deadline = time.monotonic() + 30
    while any(_looked_up(account) != account.uid for account in made.values()):
        if time.monotonic() > deadline:
            raise Failed("the account database did not show every test account within 30 s")
        time.sleep(0.5)
    for account in made.values():
        _dscl([f"authonly {account.name} {account.password}"], f"{account.name}'s password check")
    print(f"  {len(made)} test accounts made, each with a password of its own, none printed")
    return made


def set_states() -> dict[str, int]:
    """The states the cases try, each set by pwpolicy on its own account where the image
    allows it; pwpolicy's exit for each, which the cases word their log from (change record
    13)."""
    results = {}
    for name, options, state in STATES:
        done = _run([PWPOLICY, "-u", name, *options])
        said = "yes" if done.returncode == 0 else f"no, pwpolicy exit {done.returncode}"
        print(f"  {name}, {state}: {said}")
        results[name] = done.returncode
    return results


def _looked_up(account: Account) -> int | None:
    try:
        return pwd.getpwnam(account.name).pw_uid
    except KeyError:
        return None


def remove_account(name: str) -> bool:
    """Remove one test account if it is there and marked as the capture's; false when an
    account by that name is left."""
    found = _read(name)
    if found.returncode != 0:
        return True
    if REAL_NAME not in found.stdout:
        print(f"  {name}: not the capture's, left alone")
        return False
    if name == ADMIN:
        _run([DSEDITGROUP, "-o", "edit", "-d", name, "-t", "user", "admin"])
    done = _run([DSCL, ".", "-delete", f"/Users/{name}"])
    said = "removed" if done.returncode == 0 else f"not removed, dscl exit {done.returncode}"
    print(f"  {name}: {said}")
    return done.returncode == 0


def cleanup() -> bool:
    """Every drop-in and test account the capture makes, removed if present and the
    capture's; true when none is left. Each is tried whatever happened to the one before.
    Safe to run twice, and after a capture that never started. sudo's own records of the
    accounts, their lecture and timestamp files under /var/db/sudo, stay: they go with the
    throwaway virtual machine."""
    print("Cleanup")
    removed = True
    items: list[tuple[str, Callable[[], bool]]] = [
        *((name, lambda name=name: remove_drop_in(name)) for name in DROP_INS),
        *((name, lambda name=name: remove_account(name)) for name in ACCOUNTS),
    ]
    for name, remove in items:
        try:
            removed = remove() and removed
        except Exception as failure:  # noqa: BLE001 - named in the log, then the next item
            print(f"  {name}: could not be checked or removed: {failure!r}")
            removed = False
    return removed


# --- children as other accounts ----------------------------------------------------------


@dataclass
class Seen:
    """One child's run: its exit status (minus the signal that ended it); what it wrote
    to each stream and to its terminal; when each prompt showed and each answer was typed;
    and whether it outran its deadline and was killed."""

    code: int | None = None
    streams: dict[int, bytearray] = field(default_factory=dict)
    terminal: str | None = None
    prompts: list[float] = field(default_factory=list)
    answers: list[float] = field(default_factory=list)
    killed: bool = False


def _become(account: Account, *, terminal: bool, onto: Sequence[tuple[int, int]]) -> None:
    """In a new child: its own session, with the pseudo-terminal as its controlling
    terminal or none; ``onto``'s descriptors on its 0, 1 and 2; then the account's groups,
    group and user, in that order, so nothing of root's is left."""
    if not terminal:
        os.setsid()
    for source, target in onto:
        os.dup2(source, target)
    os.chdir("/")
    os.initgroups(account.name, account.gid)
    os.setgid(account.gid)
    os.setuid(account.uid)
    if (os.getuid(), os.geteuid()) != (account.uid, account.uid):
        raise PermissionError("the child is still root")


def _fork(
    account: Account,
    then: Callable[[], int],
    *,
    terminal: bool,
    onto: Sequence[tuple[int, int]] = (),
) -> tuple[int, int | None]:
    """A child that becomes ``account`` and runs ``then``, which execs or returns an exit
    status; its process ID, and the pseudo-terminal's master with ``terminal``."""
    sys.stdout.flush()
    sys.stderr.flush()
    pid, master = pty.fork() if terminal else (os.fork(), None)
    if pid == 0:
        code = 126
        try:
            _become(account, terminal=terminal, onto=onto)
            code = then()
        except BaseException:  # noqa: BLE001 - a child never returns into the capture
            code = 126
        os._exit(code)
    return pid, master


def _drive(
    pid: int,
    *,
    master: int | None,
    streams: Sequence[int],
    answers: Sequence[str] = (),
    delay_s: float = 0.0,
    deadline_s: float,
) -> Seen:
    """Read a child's streams and its terminal until it ends, typing each answer
    ``delay_s`` after the prompt it answers; a child that outruns ``deadline_s`` is killed,
    with its process group."""
    seen = Seen(streams={fd: bytearray() for fd in streams})
    shown = bytearray()
    live = {*streams, *([master] if master is not None else [])}
    prompt = messages.PROMPT.encode()
    due: list[tuple[float, str]] = []
    started, ended = time.monotonic(), None
    while True:
        now = time.monotonic()
        while master is not None and due and due[0][0] <= now:
            # The wait ends as the answer is typed, so its time is taken first.
            seen.answers.append(time.monotonic())
            with contextlib.suppress(OSError):
                os.write(master, due.pop(0)[1].encode() + b"\n")
        if seen.code is None:
            done, status = os.waitpid(pid, os.WNOHANG)
            if done:
                seen.code, ended = os.waitstatus_to_exitcode(status), now
        if ended is not None and (not live or now > ended + DRAIN_S):
            break
        if now > started + deadline_s:
            seen.killed = True
            with contextlib.suppress(OSError):
                os.killpg(pid, signal.SIGKILL)
            if seen.code is None:
                seen.code = os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])
            break
        wait = POLL_S if not due else min(POLL_S, max(0.0, due[0][0] - now))
        for fd in select.select(list(live), [], [], wait)[0] if live else []:
            try:
                chunk = os.read(fd, 65536)
            except OSError:  # EIO: the last process holding the terminal has closed it
                chunk = b""
            if not chunk:
                live.discard(fd)
            elif fd == master:
                shown.extend(chunk)
                while len(seen.prompts) < shown.count(prompt):
                    seen.prompts.append(time.monotonic())
                    if len(seen.prompts) <= len(answers):
                        due.append((seen.prompts[-1] + delay_s, answers[len(seen.prompts) - 1]))
            else:
                seen.streams[fd].extend(chunk)
        if not live and ended is None:
            time.sleep(POLL_S)
    for fd in (*streams, *([master] if master is not None else [])):
        with contextlib.suppress(OSError):
            os.close(fd)
    if master is not None:
        seen.terminal = shown.decode("utf-8", errors="replace").replace("\r\n", "\n")
    return seen


def environment(case: Any) -> dict[str, str]:
    """A case's environment: the tool's own, and over ssh without -t, SSH_CONNECTION with
    documentation addresses (RFC 5737) and no SSH_TTY."""
    env = dict(ENV)
    if case.ssh:
        env["SSH_CONNECTION"] = "192.0.2.1 50000 192.0.2.2 22"
    return env


def _sudo_as(case: Any, account: Account) -> tuple[Seen, str]:
    """One message case: sudo as the case's account, as the case says. Returns what was
    seen and sudo's stderr."""
    env = environment(case)
    given = {
        "devnull": None,
        "empty": b"",
        "password": account.password.encode() + b"\n",
        "wrong": WRONG.encode() + b"\n",
    }[case.stdin]
    out_r, out_w = os.pipe()
    err_r, err_w = os.pipe()
    in_r, in_w = os.pipe() if given is not None else (os.open(os.devnull, os.O_RDONLY), None)
    # On a terminal, stdin stays the terminal, as in a Terminal window.
    onto = ((out_w, 1), (err_w, 2)) if case.terminal else ((in_r, 0), (out_w, 1), (err_w, 2))

    def then() -> int:
        os.execve(case.argv[0], list(case.argv), env)  # noqa: S606 - sudo's fixed argv, no shell
        return 127

    pid, master = _fork(account, then, terminal=case.terminal, onto=onto)
    for fd in (out_w, err_w, in_r):
        os.close(fd)
    if in_w is not None:
        with contextlib.suppress(OSError):
            os.write(in_w, given or b"")
        os.close(in_w)
    typed = [account.password if answer == "password" else WRONG for answer in case.answers]
    seen = _drive(pid, master=master, streams=(out_r, err_r), answers=typed, deadline_s=CASE_S)
    return seen, seen.streams[err_r].decode("utf-8", errors="replace")


def _probe_as(
    account: Account,
    work: Callable[[], Mapping[str, Any]],
    *,
    terminal: bool,
    answers: Sequence[str] = (),
    delay_s: float = 0.0,
    deadline_s: float,
) -> tuple[Mapping[str, Any], Seen]:
    """One of topology.py's probes, in a child that has become ``account``; what it sent
    back, and what was seen. On a terminal the child's 0, 1 and 2 stay the terminal, as
    the tool's are in a Terminal window."""
    result_r, result_w = os.pipe()

    def then() -> int:
        os.close(result_r)
        try:
            sent: dict[str, object] = {"found": dict(work())}
        except BaseException:  # noqa: BLE001 - sent back whole, for the log
            sent = {"error": traceback.format_exc()}
        view = memoryview(json.dumps(sent).encode())
        while view:
            view = view[os.write(result_w, view) :]
        return 0

    pid, master = _fork(account, then, terminal=terminal)
    os.close(result_w)
    seen = _drive(
        pid,
        master=master,
        streams=(result_r,),
        answers=answers,
        delay_s=delay_s,
        deadline_s=deadline_s,
    )
    try:
        sent = json.loads(bytes(seen.streams[result_r]))
    except ValueError:
        raise Failed(f"a probe as {account.name} sent nothing back (exit {seen.code})") from None
    if "error" in sent:
        print(sent["error"])
        raise Failed(f"a probe as {account.name} stopped on an error")
    return sent["found"], seen


# --- what the image is ------------------------------------------------------------------


def _virtual_machine() -> bool:
    """kern.hv_vmm_present, as C26 reads it: 1 on a virtual machine; anything else, or a
    read that fails, is not one."""
    try:
        found = _run([SYSCTL, "-n", "kern.hv_vmm_present"], timeout=10)
    except Failed:
        return False
    return found.returncode == 0 and found.stdout.strip() == "1"


def _invoker() -> Account:
    """The account that ran sudo to start this, the runner user: the tool runs as it. Its
    user ID must be a number and not root's, and its name one a drop-in can hold as it is."""
    raw = os.environ.get("SUDO_UID", "")
    if not raw.isdigit() or int(raw) == 0:
        raise Failed("capture.py runs through sudo from the runner user's account")
    entry = pwd.getpwuid(int(raw))
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", entry.pw_name):
        raise Failed("the runner user's name cannot stand in a drop-in as it is")
    return Account(entry.pw_name, entry.pw_uid, entry.pw_gid)


def read_sudo_v(shown: str, returncode: int) -> tuple[messages.Version, str | None]:
    """Step 1, from what `sudo -V` printed as root: sudo's version from its first line,
    parsed strictly, and the lecture file it names, if any. It must show no setting that
    stops direct execution; as root it lists root's defaults alone."""
    lines = [line.strip() for line in shown.split("\n")]
    version = messages.parse_version(shown.split("\n", 1)[0])
    problems = [f"sudo -V exited {returncode}"] if returncode else []
    if version is None:
        problems.append(
            "the first line of sudo -V is not sudo's version, so what this sudo prints is "
            "not known"
        )
    if not any(line.startswith(LISTED) for line in lines):
        problems.append("sudo -V listed no sudoers defaults")
    direct = [
        found
        for found, holds in (
            ("an I/O log", any(line in IO_LOG for line in lines)),
            ("a log server", LOG_SERVERS in lines),
            ("a command timeout", any(line.startswith(COMMAND_TIMEOUT) for line in lines)),
        )
        if holds
    ]
    if direct:
        problems.append(
            f"{' and '.join(direct)} configured, so sudo cannot execute a payload directly"
        )
    if problems or version is None:
        raise Failed("; ".join(problems))
    lecture = next(
        (line[len(LECTURE_FILE) :] for line in lines if line.startswith(LECTURE_FILE)), None
    )
    return version, lecture or None


def sudo_defaults() -> tuple[messages.Version, str | None]:
    """Step 1: sudo -V, as root."""
    shown = _run([SUDO, "-V"])
    version, lecture = read_sudo_v(shown.stdout, shown.returncode)
    print(f"sudo -V: sudo {messages.spelled(version)}")
    for line in messages.expectations(version):
        print(f"  {line}")
    print(
        "  ok    sudo -V, as root, lists no I/O log, log server or command timeout; it lists "
        "root's defaults alone, and step 4's identifications at level 0 are the proof that "
        "sudo executes each payload directly"
    )
    return version, lecture


def lecture_lines(path: str | None) -> tuple[str, ...]:
    """The lines of the lecture file sudo -V names, which sudo prints on an account's first
    use; none when it names none or the file cannot be read, and sudo's own lecture is
    among the lines that match no template anyway (tests_live/messages.py)."""
    if path is None:
        return ()
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ()
    return tuple(line.rstrip() for line in text.split("\n"))


def account_modules(text: str) -> tuple[str, ...]:
    """What the account stack of a PAM file runs, in order: the module each `account` line
    names, as a file name, never its arguments; or, for a line that includes another file,
    "include" and that file's name."""
    found = []
    for line in text.split("\n"):
        words = line.split("#", 1)[0].split()
        if len(words) >= 3 and words[0] == "account":
            found.append(f"include {words[2]}" if words[1] == "include" else words[2])
    return tuple(found)


def pam_account_modules() -> tuple[str, ...] | None:
    """What /etc/pam.d/sudo's account stack runs on this image, or None when the file could
    not be read (change record 13)."""
    try:
        return account_modules(PAM_SUDO.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return None


# --- step 3: the messages ------------------------------------------------------------------


def capture_messages(
    accounts: Mapping[str, Account],
    checks: Checks,
    *,
    version: messages.Version,
    lecture: Sequence[str],
    modules: Sequence[str] | None,
    states: Mapping[str, int],
) -> None:
    """Step 3: each case as this image's sudo can show it, what reached stderr and the
    terminal, and each stderr line held to its pinned template. A case the image did not
    let show what it tries for is not judged; on the stock account stack, where pwpolicy set
    the state, what sudo did instead is held to change record 13, and every line it printed
    must still match one template or be one to ignore, as must the failed attempt before
    the locked-out case. Then what the capture says of each pinned template."""
    print("\nThe messages, under LC_ALL=en_US.UTF-8, each case as the test account it needs")
    stack = "could not be read" if modules is None else ", ".join(modules) or "none"
    print(f"  /etc/pam.d/sudo's account stack: {stack}")
    ignorable = messages.ignorable(lecture)
    reproduced: set[str] = set()
    failed: set[str] = set()
    for number, case in enumerate(messages.CASES, 1):
        planned, why = messages.plan(case, version)
        if planned is None:
            print(f"\n{number}. {case.name}: not run. {why}")
            continue
        account = accounts[planned.account]
        how = "on a pseudo-terminal" if planned.terminal else "with no terminal"
        print(f"\n{number}. {planned.name}, {how}")
        if why is not None:
            print(f"   {why}")
        if planned.primed:
            first, said = _sudo_as(dataclasses.replace(planned, stdin="wrong"), account)
            print(f"   first a wrong password through -S: exit {first.code}")
            print(f"   its stderr: {messages.labels(said, case=planned, ignorable=ignorable)}")
            problems = messages.unjudged(planned, said, ignorable=ignorable)
            checks.that(
                not problems,
                f"{planned.name}: the failed attempt's stderr, each line one template or one "
                "to ignore",
                "; ".join(problems),
            )
        seen, stderr = _sudo_as(planned, account)
        print(f"   exit {seen.code}")
        print(f"   stderr:   {messages.labels(stderr, case=planned, ignorable=ignorable)}")
        shown = (
            messages.labels(seen.terminal, ignorable=ignorable)
            if seen.terminal is not None
            else "no terminal"
        )
        print(f"   terminal: {shown}")
        print(f"   the classifier: {messages.outcomes(stderr)}")
        reproduced |= messages.seen(stderr)
        checks.that(not seen.killed, f"{planned.name}: sudo ended within {CASE_S:.0f} s", "killed")
        if seen.killed:
            failed |= set(planned.expects)
            continue
        if not messages.reproduced(planned, stderr, seen.code):
            state = states.get(planned.account)
            print(f"   {messages.not_reproduced(planned, modules, state)}")
            stock = messages.stock_check(
                planned, seen.code, stderr, account_modules=modules, state=state
            )
            if stock is not None:
                checks.that(*stock)
            problems = messages.unjudged(planned, stderr, ignorable=ignorable)
            checks.that(
                not problems,
                f"{planned.name}: each stderr line matches one template or is one to ignore",
                "; ".join(problems),
            )
            continue
        problems = messages.judge(planned, stderr, ignorable=ignorable)
        holds = not problems and seen.code != 0
        checks.that(
            holds,
            f"{planned.name}: sudo failed, and each stderr line matches its pinned template "
            "and no other",
            "; ".join([f"exit {seen.code}", *problems]),
        )
        if not holds:
            failed |= set(planned.expects)
    print("\nThe pinned templates")
    for line in messages.pinned_lines(reproduced, failed, version=version, account_modules=modules):
        print(f"  {line}")


# --- step 4: direct execution -------------------------------------------------------------


def _comm(what: str, subtree: Sequence[Sequence[object]]) -> None:
    shown = "; ".join(f"level {level}, user ID {uid}: {comm!r}" for level, uid, comm in subtree)
    print(f"  {what}, what ps printed for comm in the subtree: {shown or 'nothing listed'}")


def _endings(runs: Sequence[Mapping[str, Any]]) -> list[tuple[object, object]]:
    return [(run["ending"], run["cleanup"]) for run in runs]


def direct_checks(found: Mapping[str, Any]) -> list[Check]:
    """Step 4's checks on what the direct probe sent back."""
    runs, power = found["S3n"], found["S4n"]
    return [
        Check(
            bool(runs)
            and all(run["ending"] == "parsed" and run["cleanup"] == "verified" for run in runs),
            "S3n: every run parsed, and the listing after it verified its stop",
            _endings(runs),
        ),
        Check(
            all(run["descendants"] == 0 for run in runs),
            "S3n: no run showed a process below level 0: sudo executed the payload directly",
            [run["descendants"] for run in runs],
        ),
        Check(
            bool(runs) and runs[-1]["identified_at_0"],
            "S3n: the tracker identified sqlite3 at level 0",
            f"no listing saw it in {len(runs)} runs",
        ),
        Check(
            power["ending"] == "parsed" and power["cleanup"] == "verified",
            "S4n: parsed, and the listing after it verified its stop",
            _endings([power]),
        ),
        Check(
            power["descendants"] == 0,
            "S4n: no process below level 0: sudo executed the payload directly",
            power["descendants"],
        ),
        Check(
            power["identified_at_0"],
            "S4n: the tracker identified powermetrics at level 0",
            power["subtree"],
        ),
    ]


def direct(runner: Account, service_uid: int, checks: Checks) -> None:
    """Step 4: S3n and S4n in -n mode, sudo executing each directly."""
    print("\nDirect execution: S3n and S4n in -n mode as the runner user, no terminal")
    found, _ = _probe_as(
        runner, lambda: topology.direct(service_uid), terminal=False, deadline_s=DIRECT_S
    )
    runs = found["S3n"]
    saw = (
        "a listing saw its payload on the last run"
        if runs and runs[-1]["identified"]
        else "no listing saw its payload in any run"
    )
    print(f"  S3n ran {len(runs)} times in at most {topology.S3N_S:.0f} s; {saw}")
    checks.every(direct_checks(found))
    _comm("S3n", runs[-1]["subtree"] if runs else [])
    _comm("S4n", found["S4n"]["subtree"])


# --- step 5: the slow prompt ----------------------------------------------------------------


def _name(comm: object) -> str:
    return str(comm).rsplit("/", 1)[-1]


def _levels(subtree: Sequence[Sequence[Any]], name: str) -> set[int]:
    """The levels a process of that basename was seen at."""
    return {level for level, _, comm in subtree if _name(comm) == name}


def slow_checks(
    found: Mapping[str, Any],
    prompts: Sequence[float],
    answers: Sequence[float],
    *,
    version: messages.Version,
    monitor: bool,
) -> list[Check]:
    """Step 5's checks on one slow-prompt run. For S3 and S4 alike: no launch clock armed
    before its answer, and the payload parsed and its stop verified. The count ends in
    milliseconds, so the topology is asserted on S4 alone, which runs for seconds: a
    runtime clock armed after its answer shows the tracker arms clocks, so the check before
    could have seen one; executed directly, the tracker identifies it at level 0; with
    sudo's defaults, it sits below the monitor on sudo 1.9.14 and later, and is sudo's own
    child before (change record 12)."""
    how = "through sudo's defaults" if monitor else "executed directly"
    found_checks = [
        Check(
            len(prompts) == 2 and len(answers) == 2,
            f"{how}: one prompt for each payload, each answered after {WAIT_S:.0f} s",
            f"{len(prompts)} prompts, {len(answers)} answers",
        )
    ]
    for index, command in enumerate(("S3", "S4")):
        run = found[command]
        answered = answers[index] if index < len(answers) else float("inf")
        armed = [(at, clock) for at, clock in run["armed"]]
        found_checks += [
            Check(
                all(at > answered for at, _ in armed),
                f"{how}, {command}: no launch clock started during the wait",
                [clock for at, clock in armed if at <= answered],
            ),
            Check(
                run["ending"] == "parsed" and run["cleanup"] == "verified",
                f"{how}, {command}: parsed, and the listing after it verified its stop",
                _endings([run]),
            ),
        ]
    power, answered = found["S4"], answers[1] if len(answers) == 2 else float("inf")
    subtree = power["subtree"]
    found_checks.append(
        Check(
            any(clock == "runtime" and at > answered for at, clock in power["armed"]),
            f"{how}, S4: a runtime clock started after the answer, so the check above could "
            "see a clock start",
            [clock for _, clock in power["armed"]],
        )
    )
    if not monitor:
        found_checks.append(
            Check(
                power["identified_at_0"],
                f"{how}, S4: the tracker identified powermetrics at level 0",
                subtree,
            )
        )
    elif version >= messages.MONITOR_SINCE:
        found_checks.append(
            Check(
                any(
                    level == 1 and uid == 0 and _name(comm) == "sudo"
                    for level, uid, comm in subtree
                )
                and _levels(subtree, "powermetrics") == {2},
                f"{how}, S4: sudo's monitor at level 1, and powermetrics below it at level 2",
                subtree,
            )
        )
    else:
        found_checks.append(
            Check(
                _levels(subtree, "powermetrics") == {1},
                f"{how}, S4: no monitor, so powermetrics is sudo's own child at level 1",
                subtree,
            )
        )
    return found_checks


def slow(
    admin: Account, service_uid: int, checks: Checks, *, version: messages.Version, monitor: bool
) -> None:
    """Step 5: S3 and S4 on a pseudo-terminal answered only after 10 s."""
    how = "through sudo's defaults" if monitor else "executed directly"
    print(f"\nThe slow prompt, {how}: S3 and S4 as a disposable administrator")
    if monitor and version >= messages.MONITOR_SINCE:
        print(f"  sudo {messages.spelled(version)} runs S4 behind its monitor on a terminal")
    elif monitor:
        print(
            f"  sudo {messages.spelled(version)} runs no monitor by default (use_pty became "
            "the default in 1.9.14), so S4 is sudo's own child (change record 12)"
        )
    print(
        "  S3: the count ends in milliseconds, so a listing every 200 ms rarely sees it after "
        "the answer; its subtree and clocks are recorded, not asserted"
    )
    found, seen = _probe_as(
        admin,
        lambda: topology.slow(service_uid),
        terminal=True,
        answers=(admin.password, admin.password),
        delay_s=WAIT_S,
        deadline_s=SLOW_S,
    )
    for command in ("S3", "S4"):
        armed = [clock for _, clock in found[command]["armed"]]
        print(f"  {command}: clocks armed after the auth clock, in order: {armed}")
    checks.every(slow_checks(found, seen.prompts, seen.answers, version=version, monitor=monitor))
    for command in ("S3", "S4"):
        run = found[command]
        _comm(f"{command}, {how}", run["subtree"])
        early = "; ".join(
            f"level {level}, user ID {uid}: {comm!r}" for level, uid, comm in run["early"]
        )
        print(
            f"  {command}, {how}, descendants before any sign of authentication: {early or 'none'}"
        )


# --- step 6: the broker's stop that meets EPERM ----------------------------------------------


def note_problems(note: str, pid: object, name: str) -> list[str]:
    """What is wrong with the owner's note on a survivor (Decision 2, "Stopping a payload";
    the Acceptance line on stopping payloads): it must name the process as ``name`` (one of
    the four subtree names, or "an unexpected process"), give the command that checks the
    four fields, and give the stop only after saying to run it only if all four still
    match, never as a bare kill command."""
    check = f"  ps -p {pid} -o pid,uid,lstart,comm\n"
    stop = f"  sudo /bin/kill -TERM {pid}"
    gate = "only if all four still match"
    problems = []
    if f", {name}, user ID " not in note:
        problems.append(f"it does not name the process as {name!r}")
    if check not in note:
        problems.append("it has no ps -p line to check the four fields")
    if note.count("kill") != 1 or stop not in note:
        problems.append("it has no stop line, or a kill command besides it")
    elif gate not in note or note.index(stop) < note.index(gate):
        problems.append("its stop does not come after 'only if all four still match'")
    return problems


def broker_checks(
    name: str,
    found: Mapping[str, Any],
    *,
    ended: Mapping[str, object] | None,
    record: Mapping[str, object],
    outcomes: tuple[list[str], list[str]],
    identity: list[object],
    shown_as: str,
    not_run: str,
) -> tuple[list[Check], list[str]]:
    """Step 6's checks on one broker run, and what the log says of it besides. The stop
    meets EPERM and the payload survives, named in the owner's note; or, where ``ended``
    names the record for it, the payload had already ended when the final listing looked
    right after EPERM, ended on SIGPIPE once the tool closed its pipes, so the cleanup is
    verified, which is true, and the log says why (change record 23). Every other check is
    the same either way."""
    payloads = found["payloads"]
    survivors = found["survivors"]
    notes = found["notes"]
    final = [payload["final"] for payload in payloads]
    one = payloads[0] if len(payloads) == 1 else None
    after_eperm = (
        ended is not None and found["stops"] == ["eperm"] and len(final) == 1 and final[0] in ENDED
    )
    found_checks = [
        Check(
            found["record"] == (ended if after_eperm else record),
            f"{name}: the elevation record",
            found["record"],
        ),
        Check(
            [found["ledger"], found["power"]] == list(outcomes),
            f"{name}: the count {outcomes[0]} and the power sample {outcomes[1]}",
            [found["ledger"], found["power"]],
        ),
        Check(found["stops"] == ["eperm"], f"{name}: the one stop met EPERM", found["stops"]),
        Check(
            one is not None and one["identity"] == identity and one["identified_at_0"],
            f"{name}: one payload started, identified at level 0 as {identity}",
            [(payload["identity"], payload["identified_at_0"]) for payload in payloads],
        ),
    ]
    if after_eperm:
        found_checks.append(
            Check(
                survivors == [] and notes == [],
                f"{name}: it had ended when the tool looked, so no survivor and no note",
                f"{len(survivors)} survivors, {len(notes)} notes",
            )
        )
    else:
        found_checks += [
            Check(
                final == ["alive"],
                f"{name}: the final listing still showed that payload running",
                final,
            ),
            Check(
                one is not None
                and [[survivor[0], survivor[1], survivor[3]] for survivor in survivors]
                == [[one["spawned"], identity[0], identity[1]]],
                f"{name}: the survivor is that payload, sudo's own process become it",
                [[survivor[1], survivor[3]] for survivor in survivors],
            ),
            Check(
                len(notes) == 1
                and len(survivors) == 1
                and not note_problems(notes[0], survivors[0][0], shown_as),
                f"{name}: the owner's note names it as {shown_as!r}, gives ps -p to check the "
                "four fields, and the stop only after 'only if all four still match'",
                [
                    note_problems(note, survivor[0], shown_as)
                    for note, survivor in zip(notes, survivors, strict=False)
                ]
                or "no note",
            ),
        ]
    found_checks += [
        Check(
            not_run not in found["commands"],
            f"{name}: {not_run} never started",
            found["commands"],
        ),
        Check(
            found["left"] == 0 and found["gone"],
            f"{name}: the nonblocking wait collected it once it ended on its own",
            f"{found['left']} left, gone {found['gone']}",
        ),
    ]
    explained = []
    if after_eperm:
        explained.append(
            f"{name}: the final listing showed powermetrics already ended ({final[0]}) right "
            "after EPERM: its next write ended it on SIGPIPE once the tool had closed its "
            "pipes, so no survivor was left, and the cleanup is verified, which is true of "
            "this run (change record 23)"
        )
    return found_checks, explained


def _broker(name: str, found: Mapping[str, Any], checks: Checks, **expected: Any) -> None:
    print(f"  {name}: stops {found['stops']}; commands {found['commands']}")
    for pid, uid, started, basename in found["survivors"]:
        print(
            f"  {name}, the survivor: process {pid}, user ID {uid}, started {started}, {basename}"
        )
    for payload in found["payloads"]:
        print(f"  {name}, what the final listing showed of the payload: {payload['final']}")
    found_checks, explained = broker_checks(name, found, **expected)
    checks.every(found_checks)
    for line in explained:
        print(f"  {line}")
    for payload in found["payloads"]:
        _comm(name, payload["subtree"])


def stand_in(runner: Account, service_uid: int, checks: Checks) -> None:
    """Step 6, first: the broker in-process with the runtime clock at 1 s, sudo executing
    directly, and the count's payload the stand-in, a sleep, which the note names as an
    unexpected process, since it is none of the four the subtree can contain."""
    print("\nThe broker in-process as the runner user, the runtime clock at 1 s")
    found, _ = _probe_as(runner, topology.stand_in, terminal=False, deadline_s=BROKER_S)
    _broker(
        "The count's stand-in",
        found,
        checks,
        identity=[service_uid, topology.STAND_IN_NAME],
        **STAND_IN_EXPECTED,
    )
    checks.that(
        found["held"] >= 1,
        "The count's stand-in: still held when the broker returned",
        found["held"],
    )


def power_alone(runner: Account, checks: Checks) -> None:
    """Step 6, then: the same with the real S4n alone."""
    found, _ = _probe_as(runner, topology.power_alone, terminal=False, deadline_s=BROKER_S)
    _broker(
        "The real S4n alone", found, checks, identity=[0, "powermetrics"], **POWER_ALONE_EXPECTED
    )


# --- the run ------------------------------------------------------------------------------


def _step(checks: Checks, what: str, step: Callable[[], None]) -> None:
    """One step of the capture. One that cannot finish is a failed check, and the next
    step still runs, so one run of the job says as much as it can."""
    try:
        step()
    except Exception as failure:  # noqa: BLE001 - named in the log, then the next step
        checks.that(False, f"{what} could not finish: {failure!r}")


def capture(checks: Checks) -> None:
    """Steps 1 and 2, which the rest needs, then steps 3 to 6, each on its own."""
    runner = _invoker()
    try:
        service_uid = pwd.getpwnam(topology.SERVICE_ACCOUNT).pw_uid
    except KeyError:
        raise Failed("this image has no _mmaintenanced account") from None
    version, lecture = sudo_defaults()
    if not _includes_drop_ins():
        raise Failed("the image's sudoers does not include sudoers.d, so no drop-in is read")
    left = [name for name in ACCOUNTS if _read(name).returncode == 0]
    left += [
        path.name
        for name in DROP_INS
        for path in (SUDOERS_D / name, SUDOERS_D / f"{name}{STAGED}")
        if os.path.lexists(path)
    ]
    if left:
        raise Failed(f"left from an earlier capture: {left}; run capture.py --cleanup")
    print("\nThe accounts and drop-ins")
    check_base_policy()
    accounts = make_accounts()
    states = set_states()
    admin = accounts[ADMIN]
    install(MESSAGES_DROP_IN, messages_drop_in())
    if version >= messages.CMDDENIAL_SINCE:
        install(DENIAL_DROP_IN, denial_drop_in())
    install(RUNNER_DIRECT, direct_drop_in(runner.name))
    install(ADMIN_DIRECT, direct_drop_in(ADMIN))
    lines, modules = lecture_lines(lecture), pam_account_modules()
    _step(
        checks,
        "The messages",
        lambda: capture_messages(
            accounts, checks, version=version, lecture=lines, modules=modules, states=states
        ),
    )
    _step(checks, "Direct execution", lambda: direct(runner, service_uid, checks))
    _step(
        checks,
        "The slow prompt",
        lambda: slow(admin, service_uid, checks, version=version, monitor=False),
    )
    print(f"\nWith sudo's defaults for {ADMIN}")
    if not remove_drop_in(ADMIN_DIRECT):
        raise Failed(f"{ADMIN_DIRECT} could not be removed")
    _step(
        checks,
        "The slow prompt",
        lambda: slow(admin, service_uid, checks, version=version, monitor=True),
    )
    _step(checks, "The count's stand-in", lambda: stand_in(runner, service_uid, checks))
    _step(checks, "The real S4n alone", lambda: power_alone(runner, checks))
    print("\nTouch ID for sudo: these virtual machines have none; the stage 3 spike covers it")


def main(argv: Sequence[str]) -> int:
    refused = gate.refusal_to_change(os.environ, euid=os.geteuid(), virtual=_virtual_machine)
    if refused is not None:
        print(refused, file=sys.stderr)
        return 2
    if list(argv) not in ([], ["--cleanup"]):
        print("capture.py takes no argument but --cleanup", file=sys.stderr)
        return 2
    if argv:
        return 0 if cleanup() else 1
    global topology
    topology = _load("voltry_mac_live_topology", "topology.py")
    checks = Checks()
    try:
        capture(checks)
    except Exception as failure:  # noqa: BLE001 - named in the log; the cleanup still runs
        checks.that(False, f"the capture could not go on: {failure}")
    finally:
        print()
        checks.that(cleanup(), "every drop-in and test account the capture made is gone")
    print(f"\n{len(checks.failed)} checks failed" if checks.failed else "\nEvery check passed")
    return 1 if checks.failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
