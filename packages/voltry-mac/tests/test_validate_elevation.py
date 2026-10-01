"""render's validator: the elevation record, its command records and the two elevated surfaces.

docs/VOLTRY_MAC_SPEC.md, Decision 2 (the outcome tables and the skip rule) and Decision 8
(the state machine and the command records). Every legal history below is built from the
m5-laptop fixture with the reason and detail each elevated surface must carry written out
by hand from the tables; every illegal one breaks exactly one rule.
"""

from __future__ import annotations

import pytest
import voltry_mac_test_reports as r

from voltry_mac import registry
from voltry_mac import validate as v
from voltry_mac.canonical import Invalid

M = "m5-laptop"
NOT_RUN = r.NOT_RUN
LEDGER = f"surfaces[{[s.key for s in registry.SURFACES].index('memory_error_ledger')}]"
POWER = f"surfaces[{[s.key for s in registry.SURFACES].index('power_and_thermal_samples')}]"
UNSAFE = ("tool_error", "skipped_after_unsafe_stop")


def _history(record: dict, count, power, **options) -> dict:
    document = r.load(M)
    r.elevate(document, record, count=count, power=power, **options)
    return r.finish(document)


def _refused(document: dict) -> Invalid:
    with pytest.raises(Invalid) as problem:
        v.validate(document)
    return problem.value


_before_payloads = r.before_payloads
LEGAL = r.LEGAL


@pytest.mark.parametrize(("record", "count", "power"), list(LEGAL.values()), ids=list(LEGAL))
def test_every_legal_history_validates(record, count, power):
    v.validate(_history(record, count, power))


def test_a_tracking_failure_allows_any_listing_failure_count():
    record = r.record(count=("tracking_failed", "verified"), power=NOT_RUN)
    v.validate(_history(record, ("tool_error", "tracking_failed"), UNSAFE, p1_failed=3))


def test_a_declined_run_has_exactly_the_27_user_records():
    document = _history(
        r.declined_record("no"), ("declined", "not_attempted"), ("declined", "not_attempted")
    )
    assert [c["id"] for c in document["commands"]] == r.USER_IDS
    assert document["collection"]["skipped"] == 2 and document["collection"]["status"] == "partial"


# --- illegal histories -----------------------------------------------------------------------

GRANTED = (r.record(), None, None)


def _case(record, count, power, path, edit=None, **options):
    return (record, count, power, path, edit, options)


def _drop(command_id: str):
    def edit(document: dict) -> None:
        document["commands"] = [c for c in document["commands"] if c["id"] != command_id]

    return edit


def _rename(old: str, new: str):
    def edit(document: dict) -> None:
        r.command(document, old)["id"] = new
        document["commands"].sort(key=lambda c: r.ORDER.index(c["id"]))

    return edit


def _add(command_id: str, failed: int = 0):
    def edit(document: dict) -> None:
        record = {"id": command_id, "runs": 1, "failed_runs": failed, "duration_ms": 20}
        document["commands"].append(record)
        document["commands"].sort(key=lambda c: r.ORDER.index(c["id"]))

    return edit


def _set(command_id: str, field: str, value: int):
    def edit(document: dict) -> None:
        r.command(document, command_id)[field] = value

    return edit


def _surface(key: str, reason: str, detail: str):
    def edit(document: dict) -> None:
        r.unavailable(document, key, reason, detail)

    return edit


def _record_field(path: str, value: object):
    def edit(document: dict) -> None:
        *head, last = path.split(".")
        node = document["elevation"]
        for part in head:
            node = node[part]
        node[last] = value

    return edit


def _cmd(document: dict, command_id: str) -> str:
    return f"commands[{r.command_index(document, command_id)}]"


DECLINED = ("declined", "not_attempted")
PROBE_FAILED = _before_payloads(
    sandbox_probe="failed",
    listing="not_run",
    prepare="not_run",
    authenticate="not_run",
    cleared="not_attempted",
)

ILLEGAL = {
    # The state machine, rule by rule.
    "declined with an interactive mode": _case(
        r.declined_record("no"),
        DECLINED,
        DECLINED,
        "elevation.mode",
        _record_field("mode", "interactive"),
    ),
    "a skip cause without a skip": _case(
        r.record(skip_cause="not_admin"), None, None, "elevation.skip_cause"
    ),
    "a skip without its cause": _case(
        r.declined_record("skipped", None), DECLINED, DECLINED, "elevation.skip_cause"
    ),
    "an answered prompt in the -n mode": _case(
        r.record(mode="noninteractive"), None, None, "elevation.mode"
    ),
    "--yes with no mode": _case(
        _before_payloads(
            consent="flag",
            mode="none",
            service_account="not_run",
            sandbox_probe="not_run",
            listing="not_run",
            prepare="not_run",
            authenticate="not_run",
            cleared="not_attempted",
        ),
        DECLINED,
        DECLINED,
        "elevation.mode",
    ),
    "a check run after a no": _case(
        r.declined_record("no"),
        DECLINED,
        DECLINED,
        "elevation.checks.service_account",
        _record_field("checks.service_account", "present"),
    ),
    "sudo -k after a no": _case(
        r.declined_record("no"),
        DECLINED,
        DECLINED,
        "elevation.prepare",
        _record_field("prepare", "ok"),
    ),
    "a count after a no": _case(
        r.declined_record("no"),
        DECLINED,
        DECLINED,
        "elevation.count.ending",
        _record_field("count.ending", "parsed"),
    ),
    "consent with no sandbox probe": _case(
        r.record(sandbox_probe="not_run"), None, None, "elevation.checks.sandbox_probe"
    ),
    "consent with the account never looked up": _case(
        r.record(service_account="not_run", count=NOT_RUN),
        None,
        None,
        "elevation.checks.service_account",
    ),
    "a probe that passed with no listing": _case(
        r.record(listing="not_run"), None, None, "elevation.checks.listing"
    ),
    "a listing after a failed probe": _case(
        PROBE_FAILED,
        ("unsupported", "sandbox_probe_failed"),
        ("unsupported", "sandbox_probe_failed"),
        "elevation.checks.listing",
        _record_field("checks.listing", "ok"),
    ),
    "sudo -k after a failed listing": _case(
        r.record(listing="failed"), None, None, "elevation.prepare"
    ),
    "S2 after a failed S1": _case(r.record(prepare="failed"), None, None, "elevation.authenticate"),
    "a count with no service account": _case(
        r.record(service_account="missing"), None, None, "elevation.count.ending"
    ),
    "a grant with no count ending": _case(
        r.record(count=NOT_RUN), None, None, "elevation.count.ending"
    ),
    "a power sample after authentication failed at the count": _case(
        r.record(count=("auth_failed", "verified")),
        ("not_granted", "auth_failed"),
        None,
        "elevation.power.ending",
    ),
    "a power sample after a survivor": _case(
        r.record(count=("parsed", "survivor")), None, None, "elevation.power.ending"
    ),
    "no power sample after a clean count": _case(
        r.record(power=NOT_RUN), None, UNSAFE, "elevation.power.ending"
    ),
    "a cleanup on a step that never ran": _case(
        r.declined_record("no"),
        DECLINED,
        DECLINED,
        "elevation.count.cleanup",
        _record_field("count.cleanup", "verified"),
    ),
    "no cleanup on a step that ran": _case(
        r.record(count=("parsed", "not_applicable"), power=NOT_RUN),
        None,
        UNSAFE,
        "elevation.count.cleanup",
    ),
    "a survivor after sudo could not start": _case(
        r.record(count=("spawn_failed", "survivor"), power=NOT_RUN),
        ("tool_error", "spawn_failed"),
        UNSAFE,
        "elevation.count.cleanup",
    ),
    "a clear with nothing prepared": _case(
        r.declined_record("no"),
        DECLINED,
        DECLINED,
        "elevation.cleared",
        _record_field("cleared", "cleared"),
    ),
    "no clear after sudo -k ran": _case(
        r.record(cleared="not_attempted"), None, None, "elevation.cleared"
    ),
    "a clear error after a clean clear": _case(
        r.record(clear_error="nonzero_exit"), None, None, "elevation.clear_error"
    ),
    "a failed clear with no error code": _case(
        r.record(cleared="failed"), None, None, "elevation.clear_error"
    ),
    # The command records against the record.
    "a sudo record after a failed probe": _case(
        PROBE_FAILED,
        ("unsupported", "sandbox_probe_failed"),
        ("unsupported", "sandbox_probe_failed"),
        lambda d: f"{_cmd(d, 'S1')}.id",
        _add("S1"),
    ),
    # A run with no service account holds 33 records, so a 34th fits the array's bound.
    "both S2 and S2n": _case(
        r.record(service_account="missing", count=NOT_RUN),
        ("unsupported", "service_account_missing"),
        None,
        lambda d: f"{_cmd(d, 'S2n')}.id",
        _add("S2n"),
    ),
    "an -n record in an interactive run": _case(
        *GRANTED, lambda d: f"{_cmd(d, 'S2n')}.id", _rename("S2", "S2n")
    ),
    "an interactive record in an -n run": _case(
        r.record(consent="flag", mode="noninteractive"),
        None,
        None,
        lambda d: f"{_cmd(d, 'S3')}.id",
        _rename("S3n", "S3"),
    ),
    "a cleared record without S5": _case(*GRANTED, "commands", _drop("S5")),
    "no X1 though the probe ran": _case(*GRANTED, "commands", _drop("X1")),
    "a payload whose failures disagree with its ending": _case(
        *GRANTED, lambda d: f"{_cmd(d, 'S3')}.failed_runs", _set("S3", "failed_runs", 1)
    ),
    "a probe that failed with no failed run": _case(
        PROBE_FAILED,
        ("unsupported", "sandbox_probe_failed"),
        ("unsupported", "sandbox_probe_failed"),
        lambda d: f"{_cmd(d, 'X1')}.failed_runs",
        _set("X1", "failed_runs", 0),
    ),
    "an unverified stop with no failed listing": _case(
        r.record(count=("parsed", "listing_failed"), power=NOT_RUN),
        None,
        UNSAFE,
        lambda d: f"{_cmd(d, 'P1')}.failed_runs",
        p1_failed=0,
    ),
    "a failed listing where nothing failed": _case(
        *GRANTED, lambda d: f"{_cmd(d, 'P1')}.failed_runs", p1_failed=1
    ),
    "more than one listing when the check failed": _case(
        _before_payloads(
            listing="failed", prepare="not_run", authenticate="not_run", cleared="not_attempted"
        ),
        ("tool_error", "listing_unavailable"),
        ("tool_error", "listing_unavailable"),
        lambda d: f"{_cmd(d, 'P1')}.runs",
        _set("P1", "runs", 2),
    ),
    "a failed check with no failed listing": _case(
        _before_payloads(
            listing="failed", prepare="not_run", authenticate="not_run", cleared="not_attempted"
        ),
        ("tool_error", "listing_unavailable"),
        ("tool_error", "listing_unavailable"),
        lambda d: f"{_cmd(d, 'P1')}.failed_runs",
        _set("P1", "failed_runs", 0),
    ),
    "a failed S1 after a clean prepare": _case(
        *GRANTED, lambda d: f"{_cmd(d, 'S1')}.failed_runs", _set("S1", "failed_runs", 1)
    ),
    "a clean S5 after a failed clear": _case(
        r.record(cleared="failed", clear_error="deadline"),
        None,
        None,
        lambda d: f"{_cmd(d, 'S5')}.failed_runs",
        _set("S5", "failed_runs", 0),
    ),
    "a clean S2 after authentication was denied": _case(
        _before_payloads(authenticate="denied"),
        ("not_granted", "auth_failed"),
        ("not_granted", "auth_failed"),
        lambda d: f"{_cmd(d, 'S2')}.failed_runs",
        _set("S2", "failed_runs", 0),
    ),
    # The elevated surfaces against the record.
    "a parsed count with an unavailable ledger": _case(
        *GRANTED,
        f"{LEDGER}.availability",
        _surface("memory_error_ledger", "source_changed", "parse_failed"),
    ),
    "an unparsed count with an available ledger": _case(
        r.record(count=("unparsed", "verified")), None, None, f"{LEDGER}.availability"
    ),
    "a declined run with another detail": _case(
        r.declined_record("no"), ("declined", "auth_failed"), DECLINED, f"{LEDGER}.detail"
    ),
    "a declined run with another reason": _case(
        r.declined_record("no"), ("no_admin", "not_attempted"), DECLINED, f"{LEDGER}.reason"
    ),
    "the skip rule's detail swapped": _case(
        r.record(count=("sudo_error", "verified"), power=NOT_RUN),
        ("tool_error", "sudo_error"),
        UNSAFE,
        f"{POWER}.detail",
    ),
    "the power sample without the unverified stop first": _case(
        r.record(count=("auth_failed", "survivor"), power=NOT_RUN),
        ("not_granted", "auth_failed"),
        ("not_granted", "auth_failed"),
        f"{POWER}.reason",
    ),
}


@pytest.mark.parametrize(
    ("record", "count", "power", "path", "edit", "options"),
    list(ILLEGAL.values()),
    ids=list(ILLEGAL),
)
def test_every_illegal_history_is_refused(record, count, power, path, edit, options):
    document = r.load(M)
    r.elevate(document, record, count=count, power=power, **options)
    if edit is not None:
        edit(document)
    document = r.finish(document)
    problem = _refused(document)
    assert problem.path == (path(document) if callable(path) else path)


@pytest.mark.parametrize("which", ["count", "power"])
def test_a_listing_that_failed_in_the_pass_the_output_cap_latched_is_counted(which):
    # Change record 3: the cap outranks the tracking failure in the latch, so the ending is
    # output_cap while P1's failed_runs still counts that listing.
    capped = ("source_changed", "output_cap")
    if which == "count":
        document = _history(
            r.record(count=("output_cap", "verified"), power=NOT_RUN), capped, UNSAFE, p1_failed=1
        )
    else:
        document = _history(r.record(power=("output_cap", "verified")), None, capped, p1_failed=1)
    v.validate(document)


@pytest.mark.parametrize(
    ("ending", "reason"),
    [
        ("runtime_deadline", ("timeout", "runtime_deadline")),
        ("launch_deadline", ("tool_error", "launch_deadline")),
    ],
)
def test_a_failed_listing_beside_another_forced_ending_is_still_refused(ending, reason):
    # Round 2: change record 3 excuses the output cap only, never another forced ending.
    document = _history(
        r.record(count=(ending, "verified"), power=NOT_RUN), reason, UNSAFE, p1_failed=1
    )
    assert _refused(document).path.endswith("failed_runs")


def test_a_failed_listing_with_no_ending_to_explain_it_is_still_refused():
    document = _history(r.record(), None, None, p1_failed=1)
    assert _refused(document).path.endswith("failed_runs")
