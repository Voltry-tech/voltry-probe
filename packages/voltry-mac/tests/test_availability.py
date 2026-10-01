"""Availability and reasons (docs/VOLTRY_MAC_SPEC.md, Decision 6's reason codes and
Decision 8's command records).

When a user command fails, every surface it feeds is unavailable with the reason for how
it failed: tool_error for a non-zero exit or a failed start, timeout for its deadline,
source_changed for the output cap, source_absent for a missing executable. C13's exit 1
with Gatekeeper off is a read, not a failure (change record 11). A field a parser could
not read is source_changed on that value.
"""

from __future__ import annotations

import pytest

from voltry_mac import availability, parsers, registry, spawn

Unavailable = availability.Unavailable


def result(ending: spawn.Ending, code: int | None, *, missing: bool = False) -> spawn.Result:
    return spawn.Result("C1", ending, code, "", "", 10, missing, True)


@pytest.mark.parametrize(
    ("run", "reason"),
    [
        (result(spawn.Ending.EXITED, 0), None),
        (result(spawn.Ending.EXITED, 1), "tool_error"),
        (result(spawn.Ending.EXITED, 64), "tool_error"),
        (result(spawn.Ending.NOT_STARTED, None, missing=True), "source_absent"),
        (result(spawn.Ending.NOT_STARTED, None), "tool_error"),
        (result(spawn.Ending.DEADLINE, -15), "timeout"),
        (result(spawn.Ending.OUTPUT_CAP, -15), "source_changed"),
        (result(spawn.Ending.SIGNALED, -11), "tool_error"),
        (result(spawn.Ending.CANCELLED, -15), "tool_error"),
    ],
    ids=[
        "exit 0",
        "exit 1",
        "exit 64",
        "missing executable",
        "failed start",
        "deadline",
        "output cap",
        "a signal it was not sent",
        "cancelled",
    ],
)
def test_the_user_command_mapping(run, reason):
    assert availability.command_reason(run) == reason


def c13(code: int | None, stdout: str, stderr: str = "") -> spawn.Result:
    ending = spawn.Ending.SIGNALED if code is not None and code < 0 else spawn.Ending.EXITED
    return spawn.Result("C13", ending, code, stdout, stderr, 10, False, True)


def test_gatekeeper_switched_off_is_a_read_not_a_failure():
    # Change record 11 (MAC 4.1's review, M2): with Gatekeeper off, spctl --status prints
    # this one line and exits 1, as Apple's spctl.cpp does, so the exit reads the setting.
    assert availability.command_reason(c13(1, "assessments disabled\n")) is None


@pytest.mark.parametrize(
    "run",
    [
        c13(1, "assessments disabled\n", "spctl: an error\n"),
        c13(1, "assessments enabled\n"),
        c13(1, "assessments disabled\nassessments disabled\n"),
        c13(1, "assessments disabled"),
        c13(1, " assessments disabled\n"),
        c13(1, ""),
        c13(2, "assessments disabled\n"),
        c13(-9, "assessments disabled\n"),
        spawn.Result("C12", spawn.Ending.EXITED, 1, "assessments disabled\n", "", 10, False, True),
    ],
    ids=[
        "with a line on stderr",
        "enabled",
        "the line twice",
        "no newline",
        "another line",
        "no output",
        "exit 2",
        "a signal",
        "another command",
    ],
)
def test_every_other_non_zero_exit_stays_a_failure(run):
    assert availability.command_reason(run) == "tool_error"


def test_every_ending_has_a_reason():
    for ending in spawn.Ending:
        for code in (None, 0, 1, -15):
            reason = availability.command_reason(result(ending, code))
            assert reason is None or reason in registry.REASONS


def test_an_unavailable_value_carries_a_registry_reason():
    assert Unavailable("source_changed").reason == "source_changed"
    assert Unavailable("timeout") == Unavailable("timeout") != Unavailable("tool_error")
    with pytest.raises(ValueError):
        Unavailable("broken")


def test_a_field_the_parser_could_not_read_is_source_changed():
    assert availability.read(parsers.UNREAD) == Unavailable("source_changed")
    assert availability.read(0) == 0
    assert availability.read(False) is False
    assert availability.read("disk0") == "disk0"
