"""Availability and reasons, shared by the report model and the storage chain.

docs/VOLTRY_MAC_SPEC.md, Decision 6's reason codes and Decision 8's command records. A
value or surface that could not be read is unavailable with one reason code. When a user
command fails, every surface it feeds is unavailable with the reason for how it failed:
``tool_error`` for a non-zero exit or a failed start, ``timeout`` for its deadline,
``source_changed`` for the output cap, ``source_absent`` for a missing executable. C13's
exit 1 with Gatekeeper off is a read, not a failure (change record 11). A field a parser
could not read is ``source_changed`` on that value. C28 has its own outcome table
(``smart.outcome``), and the elevated surfaces have Decision 2's.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from voltry_mac import registry, spawn
from voltry_mac.parsers import UNREAD

# What spctl --status prints with Gatekeeper off, before it exits 1 (change record 11: the
# review of MAC 4.1, M2, read Apple's spctl.cpp and the M5's binary).
_GATEKEEPER_OFF: Final = "assessments disabled\n"


@dataclass(frozen=True)
class Unavailable:
    """A value or surface that was not read, and why."""

    reason: str

    def __post_init__(self) -> None:
        if self.reason not in registry.REASONS:
            raise ValueError("not a reason code")


def command_reason(result: spawn.Result) -> str | None:
    """How a user command failed, as a reason code; ``None`` when it read."""
    if result.ok or _gatekeeper_off(result):
        return None
    if result.ending is spawn.Ending.NOT_STARTED:
        return "source_absent" if result.missing_executable else "tool_error"
    if result.ending is spawn.Ending.DEADLINE:
        return "timeout"
    if result.ending is spawn.Ending.OUTPUT_CAP:
        return "source_changed"
    return "tool_error"  # a non-zero exit, a signal it was not sent, or a cancellation


def _gatekeeper_off(result: spawn.Result) -> bool:
    """C13 read Gatekeeper switched off: spctl prints exactly that one line and exits 1,
    with nothing on stderr. Any other non-zero exit is still a failure."""
    return (
        result.command_id == "C13"
        and result.ending is spawn.Ending.EXITED
        and result.returncode == 1
        and result.stdout == _GATEKEEPER_OFF
        and result.stderr == ""
    )


def read(value: object) -> object:
    """A parsed value, or ``source_changed`` for a field the parser could not read."""
    return Unavailable("source_changed") if value is UNREAD else value
