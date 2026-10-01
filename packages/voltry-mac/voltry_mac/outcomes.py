"""The elevated path's decisions: consent, the outcome tables and the skip rule.

docs/VOLTRY_MAC_SPEC.md, Decision 2. The question is asked only after a yes is possible:
--no-root, a non-administrator account and a run with no terminal and no --yes skip it,
in that order, and --yes answers it without a prompt. Each elevated surface then takes its
reason and detail from the first step that stopped it, in the order R5, X1, P1, S1, S2,
then its own ending, a later failure applying only to the surfaces still active. A power
sample skipped after the count takes the skip rule, where an unverified stop of the count
comes first, because that is what makes starting a second payload unsafe. This module is
written from the spec, apart from the validator, which checks the same tables on its own.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import Final

LEDGER: Final = "memory_error_ledger"
POWER: Final = "power_and_thermal_samples"
Outcome = tuple[str, str] | None  # (reason, detail), or None when the payload parsed

_YES: Final = frozenset({"y", "yes"})
_SKIPPED: Final = MappingProxyType(
    {
        "no_root_flag": ("declined", "not_attempted"),
        "not_admin": ("no_admin", "not_attempted"),
        "no_terminal": ("no_terminal", "not_attempted"),
    }
)
_SERVICE: Final = MappingProxyType(
    {
        "missing": ("unsupported", "service_account_missing"),
        "error": ("tool_error", "service_account_error"),
    }
)
_AUTHENTICATE: Final = MappingProxyType(
    {
        "blocked": ("not_granted", "account_blocked"),
        "refused": ("not_granted", "policy_refusal"),
        "denied": ("not_granted", "auth_failed"),
        "error": ("tool_error", "sudo_error"),
    }
)
ENDINGS: Final[Mapping[str, Outcome]] = MappingProxyType(
    {
        "spawn_failed": ("tool_error", "spawn_failed"),
        "parsed": None,
        "unparsed": ("source_changed", "parse_failed"),
        "payload_error": ("tool_error", "payload_failed"),
        "policy_refusal": ("not_granted", "policy_refusal"),
        "account_blocked": ("not_granted", "account_blocked"),
        "auth_failed": ("not_granted", "auth_failed"),
        "sudo_error": ("tool_error", "sudo_error"),
        "runtime_deadline": ("timeout", "runtime_deadline"),
        "output_cap": ("source_changed", "output_cap"),
        "launch_deadline": ("tool_error", "launch_deadline"),
        "tracking_failed": ("tool_error", "tracking_failed"),
    }
)
ORDINARY: Final = frozenset(
    {"spawn_failed", "parsed", "unparsed", "payload_error", "policy_refusal"}
)
UNVERIFIED: Final = frozenset({"survivor", "listing_failed"})


def consent(
    *, yes: bool, no_root: bool, admin: bool, terminal: bool, ask: Callable[[], str | None]
) -> tuple[str, str | None, str]:
    """The record's ``consent``, ``skip_cause`` and ``mode``; ``ask`` puts the question."""
    if yes and no_root:
        raise ValueError("--yes and --no-root are refused before anything is read")
    if no_root:
        return "skipped", "no_root_flag", "none"
    if not admin:
        return "skipped", "not_admin", "none"
    if yes:
        return "flag", None, "interactive" if terminal else "noninteractive"
    if not terminal:
        return "skipped", "no_terminal", "none"
    answer = ask()
    if answer is not None and answer.strip().lower() in _YES:
        return "yes", None, "interactive"
    return "no", None, "none"


def power_runs(
    authenticate: str, service_account: str, count_ending: str, count_cleanup: str
) -> bool:
    """Whether the power sample may start after authentication and the count."""
    if authenticate != "ok":
        return False
    if service_account != "present":
        return True  # the count was skipped for the service account
    return count_ending in ORDINARY and count_cleanup == "verified"


def _skipped_power(count_ending: str, count_cleanup: str) -> tuple[str, str]:
    if count_cleanup in UNVERIFIED:
        return "tool_error", "skipped_after_unsafe_stop"
    if count_ending in ("auth_failed", "account_blocked"):
        return "not_granted", count_ending
    if count_ending == "sudo_error":
        return "tool_error", "skipped_after_sudo_error"
    return "tool_error", "skipped_after_unsafe_stop"


def surfaces(record: Mapping[str, object]) -> dict[str, Outcome]:
    """Each elevated surface's reason and detail for this record, or None if it parsed."""
    if record["consent"] == "no":
        return dict.fromkeys((LEDGER, POWER), ("declined", "not_attempted"))
    if record["consent"] == "skipped":
        cause = record["skip_cause"]
        assert isinstance(cause, str)  # noqa: S101 - a skipped record names its cause
        return dict.fromkeys((LEDGER, POWER), _SKIPPED[cause])
    checks = record["checks"]
    assert isinstance(checks, Mapping)  # noqa: S101 - the record's checks are a mapping
    found: dict[str, Outcome] = {}
    if checks["service_account"] in _SERVICE:
        found[LEDGER] = _SERVICE[checks["service_account"]]
    stopped: Outcome = None
    if checks["sandbox_probe"] == "failed":
        stopped = ("unsupported", "sandbox_probe_failed")
    elif checks["listing"] == "failed":
        stopped = ("tool_error", "listing_unavailable")
    elif record["prepare"] == "failed":
        stopped = ("tool_error", "prepare_failed")
    elif record["authenticate"] in _AUTHENTICATE:
        stopped = _AUTHENTICATE[str(record["authenticate"])]
    if stopped is not None:
        return {LEDGER: found.get(LEDGER, stopped), POWER: stopped}
    count, power = record["count"], record["power"]
    assert isinstance(count, Mapping) and isinstance(power, Mapping)  # noqa: S101
    if LEDGER not in found:
        found[LEDGER] = ENDINGS[count["ending"]]
    if power["ending"] == "not_run":
        found[POWER] = _skipped_power(count["ending"], count["cleanup"])
    else:
        found[POWER] = ENDINGS[power["ending"]]
    return {LEDGER: found[LEDGER], POWER: found[POWER]}
