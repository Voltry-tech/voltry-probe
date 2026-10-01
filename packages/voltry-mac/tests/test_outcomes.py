"""The elevated path's decisions (docs/VOLTRY_MAC_SPEC.md, Decision 2: the sequence's
consent step, the outcome tables, the cleanup table and the skip rule; Test strategy part
3, "Consent and checks").

Each elevated surface takes its reason and detail from the first step that stopped it, in
the order R5, X1, P1, S1, S2, then its own ending; a later failure applies only to the
surfaces still active. A power sample skipped after the count takes the skip rule, where
an unverified stop of the count comes first. This module is written from the spec, apart
from the validator, and the last test checks the two against each other on every legal
history.
"""

from __future__ import annotations

import copy

import pytest
import voltry_mac_test_reports as r

from voltry_mac import outcomes
from voltry_mac import validate as v

LEDGER, POWER = "memory_error_ledger", "power_and_thermal_samples"
ORDINARY = ("spawn_failed", "parsed", "unparsed", "payload_error", "policy_refusal")
STOPS = ("account_blocked", "auth_failed", "sudo_error")
FORCED = ("runtime_deadline", "output_cap", "launch_deadline", "tracking_failed")
RAN = ORDINARY + STOPS + FORCED
ENDING = {
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


def both(outcome: tuple[str, str] | None) -> dict:
    return {LEDGER: outcome, POWER: outcome}


# --- consent ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("flags", "answer", "expected"),
    [
        (
            {"yes": False, "no_root": False, "admin": True, "terminal": True},
            "y",
            ("yes", None, "interactive"),
        ),
        (
            {"yes": False, "no_root": False, "admin": True, "terminal": True},
            "YES",
            ("yes", None, "interactive"),
        ),
        (
            {"yes": False, "no_root": False, "admin": True, "terminal": True},
            "",
            ("no", None, "none"),
        ),
        (
            {"yes": False, "no_root": False, "admin": True, "terminal": True},
            "n",
            ("no", None, "none"),
        ),
        (
            {"yes": False, "no_root": False, "admin": True, "terminal": True},
            None,
            ("no", None, "none"),
        ),
        (
            {"yes": True, "no_root": False, "admin": True, "terminal": True},
            "unused",
            ("flag", None, "interactive"),
        ),
        (
            {"yes": True, "no_root": False, "admin": True, "terminal": False},
            "unused",
            ("flag", None, "noninteractive"),
        ),
        (
            {"yes": False, "no_root": True, "admin": True, "terminal": True},
            "unused",
            ("skipped", "no_root_flag", "none"),
        ),
        (
            {"yes": False, "no_root": False, "admin": False, "terminal": True},
            "unused",
            ("skipped", "not_admin", "none"),
        ),
        (
            {"yes": True, "no_root": False, "admin": False, "terminal": False},
            "unused",
            ("skipped", "not_admin", "none"),
        ),
        (
            {"yes": False, "no_root": False, "admin": True, "terminal": False},
            "unused",
            ("skipped", "no_terminal", "none"),
        ),
        (
            {"yes": False, "no_root": True, "admin": False, "terminal": False},
            "unused",
            ("skipped", "no_root_flag", "none"),
        ),
    ],
    ids=[
        "answered y",
        "answered YES",
        "Enter",
        "answered n",
        "end of input",
        "--yes with a terminal",
        "--yes without a terminal",
        "--no-root",
        "not an administrator",
        "not an administrator, --yes",
        "no terminal",
        "--no-root before the rest",
    ],
)
def test_consent(flags, answer, expected):
    asked = []

    def ask() -> str | None:
        asked.append(True)
        return answer

    assert outcomes.consent(ask=ask, **flags) == expected
    assert bool(asked) == (expected[0] in ("yes", "no")), "only an answered question asks"


def test_yes_with_no_root_never_reaches_consent():
    with pytest.raises(ValueError):
        outcomes.consent(yes=True, no_root=True, admin=True, terminal=True, ask=lambda: "y")


# --- the steps before the payloads -------------------------------------------------------------


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        (r.declined_record(), both(("declined", "not_attempted"))),
        (r.declined_record("skipped", "no_root_flag"), both(("declined", "not_attempted"))),
        (r.declined_record("skipped", "not_admin"), both(("no_admin", "not_attempted"))),
        (r.declined_record("skipped", "no_terminal"), both(("no_terminal", "not_attempted"))),
        (
            r.record(service_account="missing", count=r.NOT_RUN),
            {LEDGER: ("unsupported", "service_account_missing"), POWER: None},
        ),
        (
            r.record(service_account="error", count=r.NOT_RUN),
            {LEDGER: ("tool_error", "service_account_error"), POWER: None},
        ),
        (
            r.record(
                service_account="missing",
                sandbox_probe="failed",
                listing="not_run",
                prepare="not_run",
                authenticate="not_run",
                count=r.NOT_RUN,
                power=r.NOT_RUN,
                cleared="not_attempted",
            ),
            {
                LEDGER: ("unsupported", "service_account_missing"),
                POWER: ("unsupported", "sandbox_probe_failed"),
            },
        ),
        (
            r.record(
                service_account="error",
                listing="failed",
                prepare="not_run",
                authenticate="not_run",
                count=r.NOT_RUN,
                power=r.NOT_RUN,
                cleared="not_attempted",
            ),
            {
                LEDGER: ("tool_error", "service_account_error"),
                POWER: ("tool_error", "listing_unavailable"),
            },
        ),
        (
            r.record(
                sandbox_probe="failed",
                listing="not_run",
                prepare="not_run",
                authenticate="not_run",
                count=r.NOT_RUN,
                power=r.NOT_RUN,
                cleared="not_attempted",
            ),
            both(("unsupported", "sandbox_probe_failed")),
        ),
        (
            r.record(prepare="failed", authenticate="not_run", count=r.NOT_RUN, power=r.NOT_RUN),
            both(("tool_error", "prepare_failed")),
        ),
        (
            r.record(authenticate="blocked", count=r.NOT_RUN, power=r.NOT_RUN),
            both(("not_granted", "account_blocked")),
        ),
        (
            r.record(authenticate="refused", count=r.NOT_RUN, power=r.NOT_RUN),
            both(("not_granted", "policy_refusal")),
        ),
        (
            r.record(authenticate="denied", count=r.NOT_RUN, power=r.NOT_RUN),
            both(("not_granted", "auth_failed")),
        ),
        (
            r.record(authenticate="error", count=r.NOT_RUN, power=r.NOT_RUN),
            both(("tool_error", "sudo_error")),
        ),
    ],
    ids=[
        "declined",
        "--no-root",
        "not an administrator",
        "no terminal",
        "no service account",
        "service account lookup failed",
        "missing account, then the probe",
        "account error, then the listing",
        "the sandbox probe",
        "sudo -k",
        "an account-state message",
        "a policy refusal",
        "an authentication message",
        "any other sudo failure",
    ],
)
def test_each_step_before_the_payloads(record, expected):
    assert outcomes.surfaces(record) == expected


# --- the payloads and the skip rule ---------------------------------------------------------


@pytest.mark.parametrize("ending", RAN)
def test_each_count_ending(ending):
    cleanup = "verified"
    power = ("parsed", "verified") if ending in ORDINARY else r.NOT_RUN
    found = outcomes.surfaces(r.record(count=(ending, cleanup), power=power))
    assert found[LEDGER] == ENDING[ending]


@pytest.mark.parametrize("ending", RAN)
def test_each_power_ending(ending):
    found = outcomes.surfaces(r.record(power=(ending, "verified")))
    assert found == {LEDGER: None, POWER: ENDING[ending]}


@pytest.mark.parametrize(
    ("count", "power"),
    [
        (("parsed", "survivor"), ("tool_error", "skipped_after_unsafe_stop")),
        (("parsed", "listing_failed"), ("tool_error", "skipped_after_unsafe_stop")),
        (("auth_failed", "listing_failed"), ("tool_error", "skipped_after_unsafe_stop")),
        (("account_blocked", "survivor"), ("tool_error", "skipped_after_unsafe_stop")),
        (("sudo_error", "survivor"), ("tool_error", "skipped_after_unsafe_stop")),
        (("auth_failed", "verified"), ("not_granted", "auth_failed")),
        (("account_blocked", "verified"), ("not_granted", "account_blocked")),
        (("sudo_error", "verified"), ("tool_error", "skipped_after_sudo_error")),
        (("runtime_deadline", "verified"), ("tool_error", "skipped_after_unsafe_stop")),
        (("output_cap", "verified"), ("tool_error", "skipped_after_unsafe_stop")),
        (("launch_deadline", "verified"), ("tool_error", "skipped_after_unsafe_stop")),
        (("tracking_failed", "verified"), ("tool_error", "skipped_after_unsafe_stop")),
    ],
    ids=lambda x: "+".join(x) if isinstance(x, tuple) else x,
)
def test_the_skip_rule(count, power):
    found = outcomes.surfaces(r.record(count=count, power=r.NOT_RUN))
    assert found[POWER] == power
    assert found[LEDGER] == ENDING[count[0]], "a cleanup never changes its own surface"


@pytest.mark.parametrize(
    ("authenticate", "service", "count", "runs"),
    [
        ("ok", "present", ("parsed", "verified"), True),
        ("ok", "present", ("policy_refusal", "verified"), True),
        ("ok", "present", ("spawn_failed", "verified"), True),
        ("ok", "present", ("parsed", "survivor"), False),
        ("ok", "present", ("unparsed", "listing_failed"), False),
        ("ok", "present", ("auth_failed", "verified"), False),
        ("ok", "present", ("runtime_deadline", "verified"), False),
        ("ok", "missing", r.NOT_RUN, True),
        ("ok", "error", r.NOT_RUN, True),
        ("denied", "present", r.NOT_RUN, False),
        ("not_run", "present", r.NOT_RUN, False),
    ],
)
def test_the_power_sample_runs_only_when_the_tables_allow(authenticate, service, count, runs):
    assert outcomes.power_runs(authenticate, service, *count) is runs


# --- every legal history, against the validator ------------------------------------------------

CLEANUPS = ("verified", "survivor", "listing_failed")


def _payload_runs(ending_set: tuple[str, ...]):
    for ending in ending_set:
        for cleanup in CLEANUPS:
            if ending == "spawn_failed" and cleanup == "survivor":
                continue
            yield (ending, cleanup)


def _histories():
    for consent, cause in (
        ("no", None),
        ("skipped", "no_root_flag"),
        ("skipped", "not_admin"),
        ("skipped", "no_terminal"),
    ):
        yield r.declined_record(consent, cause)
    for consent, mode in (
        ("yes", "interactive"),
        ("flag", "interactive"),
        ("flag", "noninteractive"),
    ):
        for service in ("present", "missing", "error"):
            base = {"consent": consent, "mode": mode, "service_account": service}
            yield r.record(
                **base,
                sandbox_probe="failed",
                listing="not_run",
                prepare="not_run",
                authenticate="not_run",
                count=r.NOT_RUN,
                power=r.NOT_RUN,
                cleared="not_attempted",
            )
            yield r.record(
                **base,
                listing="failed",
                prepare="not_run",
                authenticate="not_run",
                count=r.NOT_RUN,
                power=r.NOT_RUN,
                cleared="not_attempted",
            )
            for cleared in (("cleared", None), ("failed", "nonzero_exit")):
                done = {"cleared": cleared[0], "clear_error": cleared[1]}
                yield r.record(
                    **base,
                    **done,
                    prepare="failed",
                    authenticate="not_run",
                    count=r.NOT_RUN,
                    power=r.NOT_RUN,
                )
                for auth in ("blocked", "refused", "denied", "error"):
                    yield r.record(
                        **base, **done, authenticate=auth, count=r.NOT_RUN, power=r.NOT_RUN
                    )
                counts = list(_payload_runs(RAN)) if service == "present" else [r.NOT_RUN]
                for count in counts:
                    runs = outcomes.power_runs("ok", service, *count)
                    for power in (list(_payload_runs(RAN)) if runs else [r.NOT_RUN]):
                        yield r.record(**base, **done, count=count, power=power)


HISTORIES = list(_histories())


def test_the_histories_cover_the_tables():
    assert len(HISTORIES) > 1500
    endings = {h["count"]["ending"] for h in HISTORIES} | {h["power"]["ending"] for h in HISTORIES}
    assert endings == set(RAN) | {"not_run"}


def test_every_legal_history_validates_with_these_outcomes():
    fixture = r.load("m5-laptop")
    for history in HISTORIES:
        document = copy.deepcopy(fixture)
        found = outcomes.surfaces(history)
        r.elevate(document, history, count=found[LEDGER], power=found[POWER])
        v.validate(r.finish(document))
