"""What the capture expects of sudo's messages (docs/VOLTRY_MAC_SPEC.md, Test strategy part
5, "Live macOS CI", its second bullet; Decision 2's classifier and pinned templates; change
records 12 and 13; board item MAC 4.2, issue #324).

The capture job runs sudo on a throwaway virtual machine in each situation the bullet
names, under the fixed LC_ALL=en_US.UTF-8, and holds what sudo writes to stderr to the
pinned templates. The templates are the package's (voltry_mac/sudo_messages.py, which
tests/ci holds to the spec's table), so a line checked here is checked against what the
classifier uses. The matching is written apart from the package's, a regular expression per
template anchored at both ends, so the capture tests the classifier's templates rather than
the classifier with itself. A line that matches a template must match exactly one; a case's
key template must be on stderr; any other line must be one sudo prints unchanged, the
lecture, or the case's own; and the classifier must give the whole of stderr the case's
class.

What sudo prints depends on its version (change record 12): Apple ships sudo 1.9.13p2 on
macOS 15.0 to 15.6 and 26.0, and 1.9.17p2 on 26.1 and later. A case that depends on the
version expects what this image's sudo does, and says why. A template no case reproduced is
held to the sudo 1.9.17p2 source file the spec's table names, by a test of the package's
own suite over that file's format strings (tests/test_sudo_sources.py); the capture names
that test and says why this image could not print the template, and says nothing of the
kind for a template whose own case failed. Nothing here runs anything:
tests/test_live_scripts.py imports it on every platform.
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Collection, Iterable, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from voltry_mac import sudo_messages
from voltry_mac.sudo_messages import Class

# The tool's own prompt (the allow-list's S2 to S4), so sudo prompts on a terminal as it
# does for the tool.
PROMPT: Final = "Your Mac password, for the two steps above: "
PINNED: Final = tuple(text for _, text in sudo_messages.TEMPLATES)
KIND: Final = MappingProxyType({text: kind for kind, text in sudo_messages.TEMPLATES})

# --- sudo's version (change record 12) ------------------------------------------------------

Version = tuple[int, int, int, int]
# The first line of `sudo -V`, parsed strictly, as the live tests parse it.
VERSION: Final = re.compile(r"Sudo version ([0-9]+)\.([0-9]+)\.([0-9]+)(?:p([0-9]+))?")
# What each version-dependent expectation needs, from sudo's NEWS: the ssh hint when no
# terminal can read the password came in 1.9.17; use_pty became the default in 1.9.14, so
# from then on sudo runs a command on a terminal behind a monitor process; and the
# cmddenial_message option came in 1.9.16.
SSH_HINT_SINCE: Final = (1, 9, 17)
MONITOR_SINCE: Final = (1, 9, 14)
CMDDENIAL_SINCE: Final = (1, 9, 16)


def parse_version(first_line: str) -> Version | None:
    """sudo's version from the first line `sudo -V` prints, or None for a line in any other
    shape: the capture then cannot know what this sudo prints, and stops."""
    found = VERSION.fullmatch(first_line)
    if found is None:
        return None
    major, minor, patch, level = found.groups()
    return int(major), int(minor), int(patch), int(level or 0)


def spelled(version: Version) -> str:
    """A version as sudo prints it, such as 1.9.13p2."""
    major, minor, patch, level = version
    return f"{major}.{minor}.{patch}" + (f"p{level}" if level else "")


def expectations(version: Version) -> list[str]:
    """What this sudo does where versions differ, which the cases and checks expect."""
    shown = spelled(version)
    return [
        f"sudo {shown}: "
        + ("has" if version >= SSH_HINT_SINCE else "has no")
        + " ssh hint when no terminal can read the password (1.9.17 added it)",
        f"sudo {shown}: "
        + ("runs" if version >= MONITOR_SINCE else "runs no")
        + " monitor between itself and a command on a terminal by default (use_pty became"
        " the default in 1.9.14)",
        f"sudo {shown}: "
        + ("has" if version >= CMDDENIAL_SINCE else "has no")
        + " cmddenial_message (1.9.16 added it)",
    ]


# --- the templates ------------------------------------------------------------------------


def _pinned(text: str) -> str:
    """A template exactly as the pinned source writes it; one that is not fails at import."""
    if text not in KIND:
        raise ValueError(f"{text!r} is not a pinned template")
    return text


REFUSED_COMMAND: Final = _pinned("Sorry, user %s is not allowed to execute '...' as %s on %s.")
REFUSED_HOST: Final = _pinned("%s is not allowed to run sudo on %s.")
REFUSED_VALIDATE: Final = _pinned("Sorry, user %s may not run sudo on %s.")
NOT_LISTED: Final = _pinned("%s is not in the sudoers file.")
ATTEMPTS: Final = _pinned("sudo: %u incorrect password attempt")
REQUIRED: Final = _pinned("sudo: a password is required")
NO_TERMINAL: Final = _pinned(
    "sudo: a terminal is required to read the password; either use the -S option to read "
    "from standard input or configure an askpass helper"
)
NO_TERMINAL_SSH: Final = _pinned(
    "sudo: a terminal is required to read the password; either use ssh's -t option or "
    "configure an askpass helper"
)
TIMED_OUT: Final = _pinned("sudo: timed out reading password")
NO_PASSWORD: Final = _pinned("sudo: no password was provided")

# The sudo source file each template is pinned to, as the spec's table names it (Decision
# 2); tests/ci/test_voltry_mac_spec_sudo.py holds this to the table.
_PAM: Final = "plugins/sudoers/auth/pam.c"
_LOGGING: Final = "plugins/sudoers/logging.c"
_TGETPASS: Final = "src/tgetpass.c"
SOURCES: Final = MappingProxyType(
    {
        **{text: _PAM for text in PINNED if KIND[text] is Class.ACCOUNT_STATE},
        **{text: _LOGGING for text in PINNED if KIND[text] is Class.POLICY_REFUSAL},
        ATTEMPTS: _LOGGING,
        REQUIRED: _LOGGING,
        NO_TERMINAL: _TGETPASS,
        NO_TERMINAL_SSH: _TGETPASS,
        TIMED_OUT: _TGETPASS,
        NO_PASSWORD: _TGETPASS,
    }
)
# The sudo those files are from, and the test of the package's own suite that holds each
# template to its file's format strings (a fixture of the three files' strings, with each
# file's SHA-256). The capture names it for a template this image did not reproduce.
SOURCE_VERSION: Final = "1.9.17p2"
HELD_BY: Final = (
    "agents/voltry-mac/tests/test_sudo_sources.py::"
    "test_each_template_is_a_format_string_of_the_file_it_is_pinned_to"
)

# The drop-in's own lines (capture.py writes them into it): the denial message sudo prints
# after its refusal, and the rewritten authentication failure, which sudo prints after
# "sudo: " with the number of attempts in place of %d.
CMDDENIAL: Final = "Voltry capture: the drop-in denies this command."
AUTHFAIL: Final = "Voltry capture rewrote this message after %d attempt"
AUTHFAIL_LINE: Final = "sudo: " + AUTHFAIL.replace("%d", "1")
# What sudo prints when macOS has locked an account after failed attempts: its PAM module
# answers with a lock code of Apple's own, which sudo does not count as a wrong password,
# so it prints this and PAM's text for the code (plugins/sudoers/auth/pam.c), then
# "sudo: a password is required", an authentication line (change record 13).
LOCKOUT_LINE: Final = "sudo: PAM authentication error: "

# %s stands for the rest of a line (at least one character), %u for one or more digits,
# and ... for a quoted command, its quotes kept as literals (Decision 2).
_WILD: Final = MappingProxyType({"%s": ".+", "%u": "[0-9]+", "...": ".*"})
# Lines sudo prints unchanged, which the classifier's precedence ignores (Decision 2).
FIXED: Final = frozenset(
    {"Sorry, try again.", "This incident has been reported to the administrator."}
)
# sudo's own lecture, printed when no lecture file is set, the same in 1.9.13p2 and 1.9.17p2
# (plugins/sudoers/check.c). macOS's sudoers names a file of its own, which the capture
# reads from the image.
BUILT_IN_LECTURE: Final = (
    "We trust you have received the usual lecture from the local System",
    "Administrator. It usually boils down to these three things:",
    "    #1) Respect the privacy of others.",
    "    #2) Think before you type.",
    "    #3) With great power comes great responsibility.",
    "For security reasons, the password you type will not be visible.",
)


def _pattern(template: str) -> re.Pattern[str]:
    parts = re.split(r"(%s|%u|(?<=')\.\.\.(?='))", template)
    body = "".join(
        _WILD[part] if index % 2 else re.escape(part) for index, part in enumerate(parts)
    )
    plural = "s?" if template in sudo_messages.PLURAL else ""
    return re.compile(body + plural, re.DOTALL)


_PATTERNS: Final = MappingProxyType({text: _pattern(text) for text in PINNED})


def matching(line: str) -> tuple[str, ...]:
    """Every pinned template a line of stderr matches, its trailing whitespace dropped as
    the classifier drops it."""
    line = line.rstrip()
    return tuple(text for text in PINNED if _PATTERNS[text].fullmatch(line))


def problem(line: str, expected: str | None) -> str | None:
    """What is wrong with a line held to ``expected``: it must match that template and no
    other, or, when ``expected`` is None, no template at all. None when nothing is. The
    answer names templates only, never the line, which can name an account and a host."""
    found = matching(line)
    if expected is None:
        return None if not found else f"expected it to match no pinned template; it matches {found}"
    if found == (expected,):
        return None
    if not found:
        return f"expected it to match {expected!r}; it matches no pinned template"
    return f"expected it to match {expected!r} and no other; it matches {found}"


def ignorable(lecture: Iterable[str]) -> frozenset[str]:
    """The lines that match no template and say nothing of the outcome: a blank line, the
    two sudo prints unchanged, and the lecture, the image's file or sudo's own."""
    return frozenset({"", *FIXED, *BUILT_IN_LECTURE, *(line.rstrip() for line in lecture)})


# --- the cases ----------------------------------------------------------------------------


@dataclass(frozen=True)
class Case:
    """One situation the bullet names: the test account that runs sudo, and how (its argv,
    a pseudo-terminal as its controlling terminal or none, what -S reads from standard
    input, what is typed at each prompt in turn, and, when ``primed``, a wrong password
    through -S first, the failed attempt that locks the account); then what its stderr
    must hold: ``expects``, the templates that must be on it, ``extra``, a line the drop-in
    makes sudo print, ``prefix``, the start of a line of the case's own that sudo ends with
    text of its own, ``kind``, the class the classifier must give it, and ``allowed``, the
    classes its template lines may take (the kind's alone unless named). ``shows`` says when
    the image lets the case show what it tries for: always; once sudo printed an
    account-state line; or once sudo refused the right password. A case is judged only
    then. Where no account-state line can print, on stock macOS, ``stock`` says what change
    record 13 says macOS does instead, which the capture holds to what sudo did:
    "refused", sudo fails in the authentication class, as for a wrong password, or
    "accepted", sudo takes the password and exits 0."""

    name: str
    account: str
    argv: tuple[str, ...]
    kind: Class
    expects: tuple[str, ...] = ()
    terminal: bool = False
    stdin: str = "devnull"  # devnull, empty, password or wrong
    answers: tuple[str, ...] = ()  # password or wrong, typed at each prompt in turn
    ssh: bool = False  # SSH_CONNECTION set and SSH_TTY not, as over ssh without -t
    primed: bool = False
    extra: str | None = None
    prefix: str | None = None
    allowed: frozenset[Class] = frozenset()
    shows: str = "always"  # always, account_state or refused
    stock: str | None = None  # refused or accepted, on stock macOS (change record 13)

    @property
    def classes(self) -> frozenset[Class]:
        return self.allowed or frozenset({self.kind})

    @property
    def where_allowed(self) -> bool:
        """Whether the case is judged only where the image lets it show what it tries for."""
        return self.shows != "always"


_SUDO: Final = "/usr/bin/sudo"
_TRUE: Final = ("--", "/usr/bin/true")
_DENIED: Final = ("--", "/usr/bin/id")  # the drop-in lets these accounts run true alone
_PROMPTED: Final = (_SUDO, "-p", PROMPT)
# -S with no prompt text, so stderr holds sudo's own lines alone.
_FROM_STDIN: Final = (_SUDO, "-S", "-p", "")
_ACCOUNT_STATE: Final = frozenset({Class.ACCOUNT_STATE, Class.AUTHENTICATION})

CASES: Final[tuple[Case, ...]] = (
    Case(
        "-n with no cached authorization",
        "vmcap_plain",
        (_SUDO, "-n", *_TRUE),
        Class.AUTHENTICATION,
        (REQUIRED,),
    ),
    Case(
        "no terminal, without -S",
        "vmcap_plain",
        (*_PROMPTED, *_TRUE),
        Class.AUTHENTICATION,
        (NO_TERMINAL,),
    ),
    Case(
        "no terminal, without -S, over ssh without -t",
        "vmcap_plain",
        (*_PROMPTED, *_TRUE),
        Class.AUTHENTICATION,
        (NO_TERMINAL_SSH,),
        ssh=True,
    ),
    Case(
        "end of input through -S",
        "vmcap_plain",
        (*_FROM_STDIN, *_TRUE),
        Class.AUTHENTICATION,
        (NO_PASSWORD,),
        stdin="empty",
    ),
    Case(
        "a wrong password through -S",
        "vmcap_once",
        (*_FROM_STDIN, *_TRUE),
        Class.AUTHENTICATION,
        (ATTEMPTS,),
        stdin="wrong",
    ),
    Case(
        "three wrong passwords on a terminal",
        "vmcap_thrice",
        (*_PROMPTED, *_TRUE),
        Class.AUTHENTICATION,
        (ATTEMPTS,),
        terminal=True,
        answers=("wrong", "wrong", "wrong"),
    ),
    Case(
        "a password read that times out",
        "vmcap_timeout",
        (*_PROMPTED, *_TRUE),
        Class.AUTHENTICATION,
        (TIMED_OUT,),
        terminal=True,
    ),
    Case(
        "a command the drop-in denies",
        "vmcap_plain",
        (*_PROMPTED, *_DENIED),
        Class.POLICY_REFUSAL,
        (REFUSED_COMMAND,),
        terminal=True,
        answers=("password",),
    ),
    Case(
        "a command the drop-in denies, with a cmddenial_message",
        "vmcap_denial",
        (*_PROMPTED, *_DENIED),
        Class.POLICY_REFUSAL,
        (REFUSED_COMMAND,),
        terminal=True,
        answers=("password",),
        extra=CMDDENIAL,
    ),
    Case(
        "an account sudo does not list, running a command",
        "vmcap_unlisted",
        (*_PROMPTED, *_TRUE),
        Class.POLICY_REFUSAL,
        (NOT_LISTED,),
        terminal=True,
        answers=("password",),
    ),
    Case(
        "an account sudo does not list, asking sudo -v",
        "vmcap_unlisted",
        (_SUDO, "-v", "-p", PROMPT),
        Class.POLICY_REFUSAL,
        (REFUSED_VALIDATE,),
        terminal=True,
        answers=("password",),
    ),
    Case(
        "an account the drop-in lists for another host",
        "vmcap_elsewhere",
        (*_PROMPTED, *_TRUE),
        Class.POLICY_REFUSAL,
        (REFUSED_HOST,),
        terminal=True,
        answers=("password",),
    ),
    Case(
        "a rewritten authfail_message",
        "vmcap_authfail",
        (*_FROM_STDIN, *_TRUE),
        Class.OTHER_SUDO,
        stdin="wrong",
        extra=AUTHFAIL_LINE,
    ),
    Case(
        "a locked account, where the image allows it",
        "vmcap_locked",
        (*_FROM_STDIN, *_TRUE),
        Class.ACCOUNT_STATE,
        stdin="password",
        allowed=_ACCOUNT_STATE,
        shows="account_state",
        stock="refused",
    ),
    Case(
        "an expired password, where the image allows it",
        "vmcap_expired",
        (*_FROM_STDIN, *_TRUE),
        Class.ACCOUNT_STATE,
        stdin="password",
        allowed=_ACCOUNT_STATE,
        shows="account_state",
        stock="accepted",
    ),
    # The right password after one failed attempt, under a policy that locks the account
    # then: however macOS refuses it, sudo's lines must fall in the authentication class,
    # so the owner reads "administrator access was not granted" (change record 13).
    Case(
        "the right password once a failed attempt locked the account, where the image allows it",
        "vmcap_lockout",
        (*_FROM_STDIN, *_TRUE),
        Class.AUTHENTICATION,
        stdin="password",
        primed=True,
        prefix=LOCKOUT_LINE,
        shows="refused",
    ),
)


def plan(case: Case, version: Version) -> tuple[Case | None, str | None]:
    """The case as this image's sudo can show it, or None for one it cannot run at all; and
    why it differs from what sudo 1.9.17p2 shows, or None (change record 12)."""
    shown = spelled(version)
    if case.extra == CMDDENIAL and version < CMDDENIAL_SINCE:
        return None, (
            f"sudo 1.9.16 added cmddenial_message, and this image's sudo is {shown}: it has "
            "no such option, so nothing here can print one"
        )
    if NO_TERMINAL_SSH in case.expects and version < SSH_HINT_SINCE:
        expects = tuple(NO_TERMINAL if text == NO_TERMINAL_SSH else text for text in case.expects)
        return dataclasses.replace(case, expects=expects), (
            f"sudo 1.9.17 added the ssh hint, and this image's sudo is {shown}: over ssh it "
            "prints the -S line, so that is the line this case expects here"
        )
    return case, None


def _lines(text: str) -> list[str]:
    return [line.rstrip() for line in text.split("\n")]


def _own(case: Case, line: str) -> bool:
    """Whether a line is the case's own: its drop-in's line, or its prefix line."""
    return line == case.extra or (case.prefix is not None and line.startswith(case.prefix))


def reproduced(case: Case, stderr: str, code: int | None) -> bool:
    """Whether a case the image may not allow showed what it tries for: sudo refused the
    right password, or printed an account-state line. Every other case is judged whatever
    it printed."""
    if case.shows == "refused":
        return code not in (0, None)
    if case.shows == "account_state":
        lines = _lines(stderr)
        return any(
            KIND[template] is Class.ACCOUNT_STATE for line in lines for template in matching(line)
        )
    return True


# The stock account stack of /etc/pam.d/sudo (Apple's sudo-113 and sudo-114.100.11).
STOCK_ACCOUNT_STACK: Final = ("pam_permit.so",)


def _stock(account_modules: Sequence[str] | None) -> bool:
    """Whether an account stack is stock macOS's exactly, pam_permit.so and nothing else."""
    return account_modules is not None and tuple(account_modules) == STOCK_ACCOUNT_STACK


def not_reproduced(case: Case, account_modules: Sequence[str] | None, state: int | None) -> str:
    """Why a case the image may not allow left nothing to judge, from what the image shows:
    its account stack, None when /etc/pam.d/sudo could not be read, and ``state``, pwpolicy's
    exit when it set the case account's state (change record 13)."""
    if case.shows == "refused":
        if state != 0:
            return (
                f"not judged: pwpolicy could not set the lockout policy (exit {state}), so "
                "nothing here could lock the account, and sudo took the right password"
            )
        return (
            "not judged: pwpolicy set the lockout policy, yet sudo took the right password "
            "after the failed attempt, so this image did not lock the account"
        )
    if account_modules is None:
        return (
            "not judged: no account-state line, and this image's /etc/pam.d/sudo could not be read"
        )
    if not _stock(account_modules):
        shown = ", ".join(account_modules) or "no module"
        return (
            "not judged: no account-state line, and this image's /etc/pam.d/sudo checks "
            f"accounts with {shown}"
        )
    said = (
        "not judged: this image's /etc/pam.d/sudo checks accounts with pam_permit.so alone, "
        "as stock macOS does, so sudo's account check always passes and none of the five "
        "account-state lines can print (change record 13); "
    )
    if state != 0:
        return said + (
            f"pwpolicy could not set this account's state (exit {state}), so what that record "
            "says macOS does instead is not checked here"
        )
    return said + "what sudo did instead is held to that record below"


def stock_check(
    case: Case,
    code: int | None,
    stderr: str,
    *,
    account_modules: Sequence[str] | None,
    state: int | None,
) -> tuple[bool, str, str] | None:
    """What change record 13 says stock macOS does in a case that can print no account-state
    line, held to what sudo did: whether it holds, what it claims, and the exit and class
    seen. None unless the stack is stock macOS's and pwpolicy set the account's state."""
    if case.stock is None or not _stock(account_modules) or state != 0:
        return None
    kind = sudo_messages.classify(stderr)
    seen = f"exit {code}, class {kind.name}"
    if case.stock == "refused":
        return (
            code not in (0, None) and kind is Class.AUTHENTICATION,
            f"{case.name}: macOS refused the disabled account at the password, as it does a "
            "wrong one, so sudo failed in the authentication class (change record 13)",
            seen,
        )
    return (
        code == 0,
        f"{case.name}: macOS accepted the password that must change, so sudo succeeded "
        "(change record 13)",
        seen,
    )


def unjudged(case: Case, stderr: str, *, ignorable: Collection[str]) -> list[str]:
    """What is wrong with the stderr of a run no case judges, a case the image did not let
    show what it tries for or the failed attempt before one: each line must match one pinned
    template, or be blank, the case's own or one of ``ignorable``, so a new line sudo prints
    is never missed. The answer names templates and line numbers only."""
    found = []
    for number, line in enumerate(_lines(stderr), 1):
        templates = matching(line)
        if len(templates) > 1:
            found.append(f"stderr line {number} matches more than one template: {templates}")
        elif not templates and line and not _own(case, line) and line not in ignorable:
            found.append(f"stderr line {number} matches no template and is not one to ignore")
    return found


def judge(case: Case, stderr: str, *, ignorable: Collection[str]) -> list[str]:
    """Everything wrong with one case's stderr, as the bullet asks: each line that matches
    a pinned template matches one and no other, of a class the case allows; each template
    the case expects is there, and its drop-in's line too; every other line is the case's
    own, blank or one of ``ignorable``, so a new line sudo prints is never missed; an
    account-state line is followed by an authentication line; and the classifier gives the
    whole of it the case's class. The answer names templates and line numbers only."""
    found: list[str] = []
    lines = _lines(stderr)
    seen: set[str] = set()
    state: int | None = None
    authentication: list[int] = []
    for number, line in enumerate(lines, 1):
        templates = matching(line)
        if len(templates) > 1:
            found.append(f"stderr line {number} matches more than one template: {templates}")
        elif templates:
            (template,) = templates
            seen.add(template)
            if KIND[template] is Class.ACCOUNT_STATE and state is None:
                state = number
            if KIND[template] is Class.AUTHENTICATION:
                authentication.append(number)
            if KIND[template] not in case.classes:
                found.append(
                    f"stderr line {number} is {template!r}, of class {KIND[template].name}, "
                    "which this case does not expect"
                )
        elif line.startswith("sudo:") and not _own(case, line):
            found.append(f"stderr line {number} starts with sudo: and matches no template")
        elif line and not _own(case, line) and line not in ignorable:
            found.append(
                f"stderr line {number} matches no template and is not a line sudo prints "
                "unchanged, the lecture or the case's own"
            )
    found += [
        f"expected {text!r} on stderr; it is not there" for text in case.expects if text not in seen
    ]
    if case.extra is not None and case.extra not in lines:
        found.append("expected the drop-in's own line on stderr; it is not there")
    if state is not None and not any(number > state for number in authentication):
        found.append(
            f"expected an authentication line after the account-state line {state}; "
            "there is none"
        )
    kind = sudo_messages.classify(stderr)
    if kind is not case.kind:
        found.append(f"expected the classifier to give {case.kind.name}; it gives {kind.name}")
    return found


def seen(stderr: str) -> set[str]:
    """The templates stderr reproduced: each that a line matches alone."""
    found = (matching(line) for line in _lines(stderr))
    return {templates[0] for templates in found if len(templates) == 1}


def labels(
    text: str, *, case: Case | None = None, ignorable: Collection[str] = frozenset()
) -> list[str]:
    """What each line of stderr or of the terminal is, in words that carry no name: the
    template it matches, a line sudo prints unchanged, the lecture, the case's own line,
    the prompt, or its length."""
    found = []
    for line in _lines(text):
        templates = matching(line)
        if len(templates) == 1:
            found.append(f"template {templates[0]!r}")
        elif templates:
            found.append(f"a line matching {len(templates)} templates")
        elif line == "":
            found.append("blank")
        elif line in FIXED:
            found.append(repr(line))
        elif case is not None and line == case.extra:
            found.append("the drop-in's line")
        elif case is not None and case.prefix is not None and line.startswith(case.prefix):
            found.append(f"{case.prefix.rstrip()!r} and {len(line) - len(case.prefix)} characters")
        elif line in ignorable:
            found.append("a line of the lecture")
        elif line.startswith(PROMPT.rstrip()):
            found.append("the prompt")
        else:
            found.append(f"another line of {len(line)} characters")
    while found and found[-1] == "blank":
        found.pop()
    return found


def outcomes(stderr: str) -> str:
    """What the classifier makes of stderr: its class, and S2's and a payload's outcome."""
    kind = sudo_messages.classify(stderr)
    s2, payload = sudo_messages.s2_outcome(stderr), sudo_messages.payload_ending(stderr)
    return f"{kind.name}, so S2 {s2} and a payload {payload}"


def _why_not(template: str, version: Version, account_modules: Sequence[str] | None) -> str | None:
    if template == NO_TERMINAL_SSH and version < SSH_HINT_SINCE:
        return f"this image's sudo {spelled(version)} has no ssh hint, which 1.9.17 added"
    if KIND[template] is Class.ACCOUNT_STATE and _stock(account_modules):
        return (
            "stock macOS's account check, pam_permit.so, never lets sudo print it (change "
            "record 13)"
        )
    return None


def pinned_lines(
    reproduced: Collection[str],
    failed: Collection[str],
    *,
    version: Version,
    account_modules: Sequence[str] | None,
) -> list[str]:
    """What the capture says of each pinned template: reproduced on this image; not
    reproduced because the case that asks for it failed, as that case says above, and
    nothing more; or held to its sudo source file by the package's own test, and why this
    image could not print it, where that is known."""
    said = []
    for template in PINNED:
        if template in reproduced:
            said.append(f"reproduced on this image: {template!r}")
        elif template in failed:
            said.append(f"not reproduced: {template!r}; the case that asks for it failed above")
        else:
            why = _why_not(template, version, account_modules)
            said.append(
                f"not reproduced on this image: {template!r}, held to sudo {SOURCE_VERSION}'s "
                f"{SOURCES[template]} by {HELD_BY}" + (f"; {why}" if why else "")
            )
    return said
