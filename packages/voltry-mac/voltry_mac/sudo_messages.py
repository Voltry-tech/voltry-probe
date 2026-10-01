"""How sudo's stderr is classified: the 15 pinned templates of sudo 1.9.17p2.

docs/VOLTRY_MAC_SPEC.md, Decision 2. Every child runs under the fixed LC_ALL=en_US.UTF-8,
and English is sudo's source language, so its messages arrive exactly as its source writes
them. The broker reads stderr only when sudo exited non-zero and nothing forced has latched.
Each line, with trailing whitespace dropped, is matched against the templates anchored at
both ends: %s is any text, '...' a quoted command, %u one or more digits. The match places
each template's literal pieces left to right, so it takes time linear in the line, however
hostile; a regular expression with four wildcards would backtrack. The first class
present decides, in the order account state, policy refusal, authentication, any other
line starting "sudo:", anything else. Account state comes first because an expired
password prints its own line and then fails the change with an authentication message.
Only the class is kept: some lines name the account and the host.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import IntEnum
from types import MappingProxyType
from typing import Final


class Class(IntEnum):
    """The five classes, in the order that decides."""

    ACCOUNT_STATE = 1
    POLICY_REFUSAL = 2
    AUTHENTICATION = 3
    OTHER_SUDO = 4
    OTHER = 5


# The spec's table, in its order: plugins/sudoers/auth/pam.c, plugins/sudoers/logging.c
# (the refusals carry no "sudo:" prefix) and src/tgetpass.c.
TEMPLATES: Final = (
    (Class.ACCOUNT_STATE, "sudo: account validation failure, is your account locked?"),
    (
        Class.ACCOUNT_STATE,
        "sudo: Account or password is expired, reset your password and try again",
    ),
    (Class.ACCOUNT_STATE, "sudo: unable to change expired password: %s"),
    (Class.ACCOUNT_STATE, "sudo: Password expired, contact your system administrator"),
    (
        Class.ACCOUNT_STATE,
        'sudo: Account expired or PAM config lacks an "account" section for sudo, contact '
        "your system administrator",
    ),
    (Class.POLICY_REFUSAL, "Sorry, user %s is not allowed to execute '...' as %s on %s."),
    (Class.POLICY_REFUSAL, "Sorry, user %s may not run sudo on %s."),
    (Class.POLICY_REFUSAL, "%s is not allowed to run sudo on %s."),
    (Class.POLICY_REFUSAL, "%s is not in the sudoers file."),
    (Class.AUTHENTICATION, "sudo: %u incorrect password attempt"),
    (Class.AUTHENTICATION, "sudo: a password is required"),
    (
        Class.AUTHENTICATION,
        "sudo: a terminal is required to read the password; either use the -S option to "
        "read from standard input or configure an askpass helper",
    ),
    (
        Class.AUTHENTICATION,
        "sudo: a terminal is required to read the password; either use ssh's -t option or "
        "configure an askpass helper",
    ),
    (Class.AUTHENTICATION, "sudo: timed out reading password"),
    (Class.AUTHENTICATION, "sudo: no password was provided"),
)
# The one template sudo prints with an optional plural s.
PLURAL: Final = frozenset({"sudo: %u incorrect password attempt"})

_S2: Final = MappingProxyType(
    {
        Class.ACCOUNT_STATE: "blocked",
        Class.POLICY_REFUSAL: "refused",
        Class.AUTHENTICATION: "denied",
        Class.OTHER_SUDO: "error",
        Class.OTHER: "error",
    }
)
_PAYLOAD: Final = MappingProxyType(
    {
        Class.ACCOUNT_STATE: "account_blocked",
        Class.POLICY_REFUSAL: "policy_refusal",
        Class.AUTHENTICATION: "auth_failed",
        Class.OTHER_SUDO: "sudo_error",
        Class.OTHER: "payload_error",
    }
)
_DIGITS: Final = re.compile(r"[0-9]+", re.ASCII)


@dataclass(frozen=True)
class _Gap:
    """What stands for a placeholder: at least ``least`` characters, digits only for %u."""

    least: int
    digits: bool = False

    def holds(self, text: str) -> bool:
        if len(text) < self.least:
            return False
        return _DIGITS.fullmatch(text) is not None if self.digits else True


# %s is at least one character; '...' is a quoted command, its quotes kept as literals.
_GAPS: Final = MappingProxyType({"%s": _Gap(1), "%u": _Gap(1, digits=True), "...": _Gap(0)})


@dataclass(frozen=True)
class _Template:
    """A template as its literal pieces and, between each two, the gap a placeholder fills."""

    kind: Class
    pieces: tuple[str, ...]
    gaps: tuple[_Gap, ...]

    def matches(self, line: str) -> bool:
        if not self.gaps:
            return line == self.pieces[0]
        first, last = self.pieces[0], self.pieces[-1]
        end = len(line) - len(last)
        if not (line.startswith(first) and line.endswith(last)) or end < len(first):
            return False
        position = len(first)
        for gap, piece in zip(self.gaps, self.pieces[1:-1], strict=False):
            found = line.find(piece, position + gap.least, end)
            if found < 0 or not gap.holds(line[position:found]):
                return False
            position = found + len(piece)
        return self.gaps[-1].holds(line[position:end])


def _template(kind: Class, template: str) -> _Template:
    parts = re.split(r"(%s|%u|(?<=')\.\.\.(?='))", template)
    return _Template(kind, tuple(parts[0::2]), tuple(_GAPS[part] for part in parts[1::2]))


_COMPILED: Final = tuple(
    _template(kind, variant)
    for kind, template in TEMPLATES
    for variant in ((template, template + "s") if template in PLURAL else (template,))
)


def _line(line: str) -> Class:
    for template in _COMPILED:
        if template.matches(line):
            return template.kind
    return Class.OTHER_SUDO if line.startswith("sudo:") else Class.OTHER


def classify(stderr: str) -> Class:
    """The class that decides: the first, in precedence order, of any line's class. Only
    a newline ends a line, so a line separator inside a name stays inside its line."""
    return min((_line(line.rstrip()) for line in stderr.split("\n")), default=Class.OTHER)


def s2_outcome(stderr: str) -> str:
    """S2's ``authenticate`` value for a non-zero exit: blocked, refused, denied or error."""
    return _S2[classify(stderr)]


def payload_ending(stderr: str) -> str:
    """A payload's ending for a non-zero exit before anything forced latched."""
    return _PAYLOAD[classify(stderr)]
