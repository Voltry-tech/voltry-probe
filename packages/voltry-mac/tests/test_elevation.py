"""The elevation broker's flow (docs/VOLTRY_MAC_SPEC.md, Decision 2: the sequence's steps
4 to 10, --yes and runs without a terminal, how a no degrades, the outcome tables and the
skip rule; Decision 8's elevation record and command records; Test strategy part 3,
"Modes", "Consent and checks" and "Payload endings times cleanups").

The broker drives the real chokepoint here, with its engine scripted per command, and a
fake payload runner stands in for MAC 3.8's tracked one. The expected reasons are written
out below from the spec's tables, not taken from the broker's own module, and every
scenario also becomes a whole report that the validator must accept.
"""

from __future__ import annotations

import dataclasses
import inspect
import json
import re
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest
import voltry_mac_test_reports as r

from voltry_mac import assemble, elevation, model, parsers, payloads, spawn, tracking
from voltry_mac import validate as v

TESTS = Path(__file__).resolve().parent
M5 = TESTS / "fixtures" / "commands" / "m5-laptop"
SAMPLE_E = (TESTS / "fixtures" / "payloads" / "m5-sample-e3.powermetrics").read_text()
LOG_HEX = (TESTS / "fixtures" / "smart" / "m5-laptop-2026-09-26.hex").read_text().strip()
LEDGER_E = (
    '[{"class":"correctable","event_rows":0,"reported_count":0},'
    '{"class":"uncorrectable","event_rows":0,"reported_count":0}]\n'
)
LISTING = (
    "  PID  PPID   UID STARTED                      COMM\n"
    "    1     0     0 Fri Aug 28 08:00:54 2026     /sbin/launchd\n"
)
ACCOUNT_STATE = "sudo: account validation failure, is your account locked?\n"
REFUSAL = "Sorry, user owner may not run sudo on host.\n"
WRONG_PASSWORD = "sudo: 3 incorrect password attempts\n"
UNKNOWN_SUDO = "sudo: unable to read password: Input/output error\n"
SQLITE_ERROR = "Error: unable to open database file\n"
SERVICE_UID = 283  # _mmaintenanced on the M5
LEDGER = "memory_error_ledger"
POWER = "power_and_thermal_samples"

MODES = [
    pytest.param({}, id="interactive"),
    pytest.param({"yes": True, "terminal": False}, id="the -n forms"),
]


def result(
    command_id: str,
    code: int | None = 0,
    ending: spawn.Ending = spawn.Ending.EXITED,
    *,
    stdout: str = "",
    stderr: str = "",
    reaped: bool = True,
) -> spawn.Result:
    return spawn.Result(command_id, ending, code, stdout, stderr, 10, False, reaped)


SURVIVOR = tracking.Survivor(pid=4242, uid=0, started="Sat Sep 26 12:00:00 2026", name="sudo")


def run_of(stdout: str = "", code: int | None = 0, **changes: object) -> spawn.PayloadRun:
    fields: dict[str, object] = {
        "command_id": "S3",
        "started": True,
        "forced": None,
        "returncode": code,
        "stdout": stdout,
        "stderr": "",
        "cleanup": "verified",
        "duration_ms": 200,
    }
    fields.update(changes)
    if fields["cleanup"] == "survivor":
        fields.setdefault("survivors", (SURVIVOR,))
    return spawn.PayloadRun(**fields)  # type: ignore[arg-type]


class Scene:
    """One broker run: the steps in the order they happened, and what the broker returned
    (``found``) or the cancellation it raised (``cancelled``).

    ``results`` scripts the chokepoint and ``runs`` the payload runner, each keyed by the
    interactive ID; a run with the -n forms gets the same scripts under its own IDs.
    """

    def __init__(
        self,
        monkeypatch: pytest.MonkeyPatch,
        *,
        yes: bool = False,
        no_root: bool = False,
        admin: bool = True,
        terminal: bool = True,
        answer: str | None = "y",
        results: dict[str, list[spawn.Result]] | None = None,
        runs: dict[str, spawn.PayloadRun] | None = None,
        lookup: Callable[[str], object] | None = None,
        cancel_after: str | None = None,
        steps: list[str] | None = None,
    ) -> None:
        self.steps: list[str] = [] if steps is None else steps
        self.uids: dict[str, int] = {}
        queues = {cid: list(items) for cid, items in (results or {}).items()}
        flag = {"cancelled": False, "quiet": False}

        def after(step: str) -> None:
            if step == cancel_after:
                flag["cancelled"] = True

        def fake_execute(argv, **kwargs):
            command_id = kwargs["command_id"]
            if not flag["quiet"]:
                self.steps.append(command_id)
            queue = queues.get(command_id.rstrip("n"))
            found = queue.pop(0) if queue else None
            if found is None:
                found = result(command_id, stdout=LISTING if command_id == "P1" else "")
            after(command_id)
            return dataclasses.replace(found, command_id=command_id)

        def payload(command_id: str, uid: int) -> spawn.PayloadRun:
            self.steps.append(command_id)
            self.uids[command_id] = uid
            base = command_id.rstrip("n")
            found = (runs or {}).get(base) or run_of(LEDGER_E if base == "S3" else SAMPLE_E)
            if found.cleanup == "listing_failed":
                # The listing after the payload failed: a failed P1 in its record.
                flag["quiet"] = True
                queues.setdefault("P1", []).insert(0, result("P1", 1))
                self.runner.run("P1", failed=lambda _found: True)
                flag["quiet"] = False
            after(command_id)
            return dataclasses.replace(found, command_id=command_id)

        def look(name: str) -> object:
            self.steps.append("R5")
            assert name == "_mmaintenanced"
            try:
                return (lookup or (lambda _name: SERVICE_UID))(name)
            finally:
                after("R5")

        def ask() -> str | None:
            after("ask")
            return answer

        monkeypatch.setattr(spawn, "_execute", fake_execute)
        self.runner = spawn.Runner(cancelled=lambda: flag["cancelled"])
        self.found: elevation.Elevation | None = None
        self.cancelled: elevation.Cancelled | None = None
        try:
            self.found = elevation.run(
                yes=yes,
                no_root=no_root,
                admin=admin,
                terminal=terminal,
                ask=ask,
                runner=self.runner,
                lookup=look,
                payload=payload,
                cancelled=lambda: flag["cancelled"],
                lookup_bound_s=0.3,
            )
        except elevation.Cancelled as stop:
            self.cancelled = stop

    @property
    def record(self) -> dict:
        assert self.found is not None
        return dict(self.found.record)

    @property
    def records(self) -> list[dict]:
        return [dataclasses.asdict(x) for x in self.runner.records()]

    def outcomes(self) -> tuple[object, object]:
        assert self.found is not None

        def one(found: assemble.Elevated) -> object:
            return "parsed" if found.values is not None else (found.reason, found.detail)

        return one(self.found.ledger), one(self.found.power)

    def report(self) -> dict:
        """The whole report this run makes on the M5's user reads; it must validate."""
        assert self.found is not None
        results = {
            cid: result(cid, stdout=(M5 / f"{cid}.out").read_text()) for cid in parsers.PARSERS
        }
        controller = {"location": "Internal", "media": ["disk0"], "status": "ok"}
        smart = {
            "schema": "voltry-mac-smart/0",
            "controllers": [controller | {"smart_hex": LOG_HEX}],
        }
        results["C28"] = result("C28", stdout=json.dumps(smart))
        collected = assemble.Collected(
            results=results,
            panic=0,
            ledger=self.found.ledger,
            power=self.found.power,
            collected_at=datetime(2026, 9, 26, 12, 0, 0, tzinfo=UTC),
        )
        user = [
            {
                "id": cid,
                "runs": 1,
                "failed_runs": int(assemble.failed_run(cid, results[cid])),
                "duration_ms": 20,
            }
            for cid in r.USER_IDS
        ]
        document = model.document(
            tool=r.load("m5-laptop")["tool"],
            collected_at=collected.collected_at,
            time_zone="America/Los_Angeles",
            validated=True,
            elevation=self.found.record,
            surfaces=assemble.surfaces(collected),
            commands=user + self.records,
            paper="letter",
        )
        v.validate(document)
        return document

    def exit_code(self) -> int:
        assert self.found is not None
        document = self.report()
        return model.exit_code(
            clear_failed=self.found.clear_failed, unexpected=model.unexpected(document)
        )


def ids(mode: dict, *bases: str) -> list[str]:
    """The IDs a mode runs: S2 to S4 become S2n to S4n in a run with the -n forms."""
    suffix = "n" if mode.get("terminal") is False else ""
    return [f"{base}{suffix}" if base in ("S2", "S3", "S4") else base for base in bases]


# --- the spec's tables, written out for the tests ----------------------------------------------

REASONS: dict[str, object] = {
    "spawn_failed": ("tool_error", "spawn_failed"),
    "parsed": "parsed",
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
ORDINARY = {"spawn_failed", "parsed", "unparsed", "payload_error", "policy_refusal"}
UNVERIFIED = {"survivor", "listing_failed"}


def skipped_power(ending: str, cleanup: str) -> tuple[str, str]:
    """The skip rule: an unverified stop first, then the count's own stopping ending."""
    if cleanup in UNVERIFIED:
        return "tool_error", "skipped_after_unsafe_stop"
    if ending in ("auth_failed", "account_blocked"):
        return "not_granted", ending
    if ending == "sudo_error":
        return "tool_error", "skipped_after_sudo_error"
    return "tool_error", "skipped_after_unsafe_stop"


def ending_run(case: str, base: str, cleanup: str) -> spawn.PayloadRun:
    """A payload run that ends as ``case``; "auth clock" is auth_failed by its clock."""
    good = LEDGER_E if base == "S3" else SAMPLE_E
    shapes: dict[str, dict[str, object]] = {
        "spawn_failed": {"started": False, "returncode": None},
        "parsed": {"stdout": good},
        "unparsed": {"stdout": "not the payload's output"},
        "payload_error": {"returncode": 1, "stderr": SQLITE_ERROR},
        "policy_refusal": {"returncode": 1, "stderr": REFUSAL},
        "account_blocked": {"returncode": 1, "stderr": ACCOUNT_STATE},
        "auth_failed": {"returncode": 1, "stderr": WRONG_PASSWORD},
        "auth clock": {"forced": "auth_failed", "returncode": -15, "stderr": REFUSAL},
        "sudo_error": {"returncode": 1, "stderr": UNKNOWN_SUDO},
    }
    fields = shapes.get(case, {"forced": case, "returncode": None, "stderr": ACCOUNT_STATE})
    return run_of(**{"cleanup": cleanup, **fields})  # type: ignore[arg-type]


ENDING_CASES = [*REASONS, "auth clock"]
CASES = [
    pytest.param(case, cleanup, id=f"{case}, {cleanup}")
    for case in ENDING_CASES
    for cleanup in ("verified", "survivor", "listing_failed")
    if not (case == "spawn_failed" and cleanup == "survivor")
]


def ending_of(case: str) -> str:
    return "auth_failed" if case == "auth clock" else case


# --- consent -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("flags", "record"),
    [
        ({"answer": "n"}, r.declined_record()),
        ({"answer": ""}, r.declined_record()),
        ({"answer": None}, r.declined_record()),
        ({"no_root": True}, r.declined_record("skipped", "no_root_flag")),
        ({"admin": False}, r.declined_record("skipped", "not_admin")),
        ({"admin": False, "yes": True}, r.declined_record("skipped", "not_admin")),
        ({"terminal": False}, r.declined_record("skipped", "no_terminal")),
    ],
    ids=[
        "answered n",
        "Enter",
        "no answer",
        "--no-root",
        "not an administrator",
        "not an administrator, --yes",
        "no terminal",
    ],
)
def test_without_consent_nothing_elevated_runs(monkeypatch, flags, record):
    scene = Scene(monkeypatch, **flags)
    assert scene.steps == [] and scene.records == []
    assert scene.record == record
    assert scene.found is not None and not scene.found.clear_failed
    assert scene.exit_code() == 0


def test_a_granted_run_is_the_full_sequence(monkeypatch):
    scene = Scene(monkeypatch)
    assert scene.steps == ["R5", "X1", "P1", "S1", "S2", "S3", "S4", "S5"]
    assert scene.record == r.record()
    assert scene.outcomes() == ("parsed", "parsed")
    document = scene.report()
    assert document["collection"]["status"] == "complete"
    power = r.values(document, POWER)
    assert power["cpu_power_mw_mean"]["value"] == "1612.28"
    assert r.values(document, LEDGER)["uncorrectable_reported_count"]["value"] == 0
    assert [x["id"] for x in scene.records] == ["X1", "P1", "S1", "S2", "S3", "S4", "S5"]
    assert all(x["failed_runs"] == 0 for x in scene.records)
    assert scene.exit_code() == 0


def test_yes_without_a_terminal_runs_the_n_forms_in_order(monkeypatch):
    scene = Scene(monkeypatch, yes=True, terminal=False)
    assert scene.steps == ["R5", "X1", "P1", "S1", "S2n", "S3n", "S4n", "S5"]
    assert scene.record == r.record(consent="flag", mode="noninteractive")
    assert scene.exit_code() == 0


def test_yes_with_a_terminal_is_interactive(monkeypatch):
    scene = Scene(monkeypatch, yes=True)
    assert scene.steps == ["R5", "X1", "P1", "S1", "S2", "S3", "S4", "S5"]
    assert scene.record == r.record(consent="flag")
    assert scene.exit_code() == 0


def test_yes_is_accepted_in_any_case(monkeypatch):
    assert Scene(monkeypatch, answer=" YES ").record == r.record()


def test_yes_and_no_root_together_are_refused_before_anything_runs(monkeypatch):
    with pytest.raises(ValueError):
        Scene(monkeypatch, yes=True, no_root=True)


# --- the capability checks -------------------------------------------------------------------


def test_the_service_account_is_looked_up_by_name_within_five_seconds():
    assert elevation.SERVICE_ACCOUNT == "_mmaintenanced"
    assert elevation.LOOKUP_BOUND_S == 5.0


def missing(_name: str) -> object:
    raise KeyError("no such account")


def broken(_name: str) -> object:
    raise OSError("directory services")


def hangs(_name: str) -> object:
    time.sleep(3)
    return SERVICE_UID


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    ("lookup", "state", "count", "code"),
    [
        (missing, "missing", ("unsupported", "service_account_missing"), 0),
        (broken, "error", ("tool_error", "service_account_error"), 1),
        (hangs, "error", ("tool_error", "service_account_error"), 1),
    ],
    ids=["no such account", "the lookup fails", "the lookup hangs"],
)
def test_the_service_account_stops_the_count_only(monkeypatch, mode, lookup, state, count, code):
    started = time.monotonic()
    scene = Scene(monkeypatch, lookup=lookup, **mode)
    assert time.monotonic() - started < 2, "a lookup that hangs is abandoned at its bound"
    assert scene.record["checks"]["service_account"] == state
    assert scene.steps == ids(mode, "R5", "X1", "P1", "S1", "S2", "S4", "S5"), "no S3"
    assert scene.record["count"] == {"ending": "not_run", "cleanup": "not_applicable"}
    assert scene.outcomes() == (count, "parsed")
    assert scene.exit_code() == code


@pytest.mark.parametrize("mode", MODES)
def test_a_failed_sandbox_probe_runs_no_listing_and_no_sudo(monkeypatch, mode):
    scene = Scene(monkeypatch, results={"X1": [result("X1", 1)]}, **mode)
    assert scene.steps == ["R5", "X1"]
    assert scene.record["checks"] == {
        "service_account": "present",
        "sandbox_probe": "failed",
        "listing": "not_run",
    }
    assert scene.outcomes() == (("unsupported", "sandbox_probe_failed"),) * 2
    assert scene.records == [{"id": "X1", "runs": 1, "failed_runs": 1, "duration_ms": 10}]
    assert scene.exit_code() == 0


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    "listing",
    [
        result("P1", 1),
        result("P1", stdout="not the listing\n"),
        result("P1", -9, spawn.Ending.DEADLINE),
    ],
    ids=["exit 1", "not ps's listing", "its deadline"],
)
def test_a_failed_listing_runs_no_sudo(monkeypatch, mode, listing):
    scene = Scene(monkeypatch, results={"P1": [listing]}, **mode)
    assert scene.steps == ["R5", "X1", "P1"]
    assert scene.record["checks"]["listing"] == "failed"
    assert scene.outcomes() == (("tool_error", "listing_unavailable"),) * 2
    assert scene.records[-1] == {"id": "P1", "runs": 1, "failed_runs": 1, "duration_ms": 10}
    assert scene.exit_code() == 1


@pytest.mark.parametrize(
    ("lookup", "results", "outcomes"),
    [
        (
            missing,
            {"X1": [result("X1", 1)]},
            (("unsupported", "service_account_missing"), ("unsupported", "sandbox_probe_failed")),
        ),
        (
            broken,
            {"P1": [result("P1", 1)]},
            (("tool_error", "service_account_error"), ("tool_error", "listing_unavailable")),
        ),
        (
            missing,
            {"S1": [result("S1", 1)]},
            (("unsupported", "service_account_missing"), ("tool_error", "prepare_failed")),
        ),
        (
            missing,
            {"S2": [result("S2", 1, stderr=WRONG_PASSWORD)]},
            (("unsupported", "service_account_missing"), ("not_granted", "auth_failed")),
        ),
    ],
    ids=[
        "no account, then no sandbox",
        "a lookup error, then no listing",
        "no account, then sudo -k fails",
        "no account, then wrong passwords",
    ],
)
def test_the_first_step_that_stopped_a_surface_names_it(monkeypatch, lookup, results, outcomes):
    scene = Scene(monkeypatch, lookup=lookup, results=results)
    assert scene.outcomes() == outcomes
    scene.report()


# --- sudo control ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    "s1",
    [result("S1", 1), result("S1", None, spawn.Ending.NOT_STARTED)],
    ids=["exit 1", "sudo could not start"],
)
def test_a_failed_sudo_k_runs_no_prompt_but_still_clears(monkeypatch, mode, s1):
    scene = Scene(monkeypatch, results={"S1": [s1]}, **mode)
    assert scene.steps == ["R5", "X1", "P1", "S1", "S5"]
    assert (scene.record["prepare"], scene.record["authenticate"]) == ("failed", "not_run")
    assert scene.record["cleared"] == "cleared"
    assert scene.outcomes() == (("tool_error", "prepare_failed"),) * 2
    assert scene.exit_code() == 1


PROMPT_ENDINGS = [
    pytest.param(result("S2", 1, stderr=ACCOUNT_STATE), "blocked", id="an account-state message"),
    pytest.param(result("S2", 1, stderr=REFUSAL), "refused", id="a policy refusal"),
    pytest.param(result("S2", 1, stderr=WRONG_PASSWORD), "denied", id="wrong passwords"),
    pytest.param(
        result("S2", 1, stderr="sudo: a password is required\n"), "denied", id="a password needed"
    ),
    pytest.param(result("S2", -15, spawn.Ending.DEADLINE), "denied", id="the authentication clock"),
    pytest.param(result("S2", 1, stderr=UNKNOWN_SUDO), "error", id="another sudo line"),
    pytest.param(result("S2", 1), "error", id="a silent failure"),
    pytest.param(result("S2", None, spawn.Ending.NOT_STARTED), "error", id="sudo could not start"),
    pytest.param(result("S2", -15, spawn.Ending.OUTPUT_CAP), "error", id="the output cap"),
    pytest.param(result("S2", -11, spawn.Ending.SIGNALED), "error", id="a signal"),
]
AUTHENTICATION = {
    "blocked": (("not_granted", "account_blocked"), 0),
    "refused": (("not_granted", "policy_refusal"), 0),
    "denied": (("not_granted", "auth_failed"), 0),
    "error": (("tool_error", "sudo_error"), 1),
}


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(("s2", "state"), PROMPT_ENDINGS)
def test_each_way_the_prompt_can_end(monkeypatch, mode, s2, state):
    scene = Scene(monkeypatch, results={"S2": [s2]}, **mode)
    assert scene.steps == ids(mode, "R5", "X1", "P1", "S1", "S2", "S5")
    assert scene.record["authenticate"] == state
    outcome, code = AUTHENTICATION[state]
    assert scene.outcomes() == (outcome, outcome)
    s2_record = next(x for x in scene.records if x["id"].startswith("S2"))
    assert s2_record["failed_runs"] == 1
    assert scene.exit_code() == code


@pytest.mark.parametrize(
    ("s5", "code"),
    [
        (result("S5", 1), "nonzero_exit"),
        (result("S5", -9, spawn.Ending.SIGNALED), "nonzero_exit"),
        (result("S5", -15, spawn.Ending.DEADLINE), "deadline"),
        (result("S5", -15, spawn.Ending.OUTPUT_CAP), "output_cap"),
        (result("S5", None, spawn.Ending.NOT_STARTED), "spawn_error"),
        (result("S5", None, spawn.Ending.DEADLINE, reaped=False), "not_reaped"),
    ],
    ids=["exit 1", "a signal", "its deadline", "the output cap", "could not start", "not reaped"],
)
def test_a_failed_clear_is_named_by_one_of_five_codes(monkeypatch, s5, code):
    scene = Scene(monkeypatch, results={"S5": [s5]})
    assert (scene.record["cleared"], scene.record["clear_error"]) == ("failed", code)
    assert scene.found is not None and scene.found.clear_failed
    assert scene.records[-1]["failed_runs"] == 1
    assert scene.exit_code() == 6


def test_a_failed_clear_after_a_failed_sudo_k_is_still_named(monkeypatch):
    scene = Scene(monkeypatch, results={"S1": [result("S1", 1)], "S5": [result("S5", 1)]})
    assert scene.record["cleared"] == "failed"
    assert scene.exit_code() == 6


# --- the payloads ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(("case", "cleanup"), CASES)
def test_every_count_ending_with_every_cleanup(monkeypatch, mode, case, cleanup):
    ending = ending_of(case)
    scene = Scene(monkeypatch, runs={"S3": ending_run(case, "S3", cleanup)}, **mode)
    assert scene.record["count"] == {"ending": ending, "cleanup": cleanup}
    power_runs = ending in ORDINARY and cleanup == "verified"
    s3, s4 = ids(mode, "S3", "S4")
    assert (s4 in scene.steps) == power_runs
    assert scene.steps[-1] == "S5"
    expected_power = "parsed" if power_runs else skipped_power(ending, cleanup)
    assert scene.outcomes() == (REASONS[ending], expected_power)
    if not power_runs:
        assert scene.record["power"] == {"ending": "not_run", "cleanup": "not_applicable"}
    by_id = {x["id"]: x for x in scene.records}
    assert by_id[s3]["failed_runs"] == int(ending not in ("parsed", "unparsed"))
    assert by_id["P1"]["failed_runs"] == int(cleanup == "listing_failed")
    reasons = {REASONS[ending], expected_power}
    unexpected = cleanup in UNVERIFIED or any(
        isinstance(x, tuple) and x[0] in r.UNEXPECTED for x in reasons
    )
    assert scene.exit_code() == int(unexpected)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(("case", "cleanup"), CASES)
def test_every_power_ending_with_every_cleanup(monkeypatch, mode, case, cleanup):
    ending = ending_of(case)
    scene = Scene(monkeypatch, runs={"S4": ending_run(case, "S4", cleanup)}, **mode)
    assert scene.record["count"] == {"ending": "parsed", "cleanup": "verified"}
    assert scene.record["power"] == {"ending": ending, "cleanup": cleanup}
    assert scene.outcomes() == ("parsed", REASONS[ending]), "the power never changes the count"
    by_id = {x["id"]: x for x in scene.records}
    assert by_id[ids(mode, "S4")[0]]["failed_runs"] == int(ending not in ("parsed", "unparsed"))
    unexpected = cleanup in UNVERIFIED or REASONS[ending][0] in r.UNEXPECTED
    assert scene.exit_code() == int(unexpected)


@pytest.mark.parametrize(("base", "key"), [("S3", "count"), ("S4", "power")])
def test_a_payload_killed_by_a_signal_it_was_not_sent_failed_on_its_own(monkeypatch, base, key):
    # Nothing latched, so the exit status and stderr decide: a signal is a non-zero exit.
    scene = Scene(monkeypatch, runs={base: run_of(code=-9)})
    assert scene.record[key] == {"ending": "payload_error", "cleanup": "verified"}


def _out_of_range_power() -> str:
    text = re.sub(r"(<key>elapsed_ns</key>\s*<integer>)[0-9]+", r"\g<1>1", SAMPLE_E)
    text = re.sub(r"(<key>thermal_pressure</key>\s*<string>)[^<]+", r"\g<1>Hot", text)
    return re.sub(
        r"(<key>(?:cpu|gpu|ane|combined)_power</key>\s*<real>)[^<]+", r"\g<1>2000000", text
    )


OUT_OF_RANGE_LEDGER = (
    '[{"class":"correctable","event_rows":1000000001,"reported_count":1000000001},'
    '{"class":"uncorrectable","event_rows":1000000001,"reported_count":1000000001}]\n'
)


@pytest.mark.parametrize(
    ("base", "stdout"),
    [("S3", OUT_OF_RANGE_LEDGER), ("S4", _out_of_range_power())],
    ids=["the count", "the power sample"],
)
def test_an_output_with_no_value_in_its_range_is_unparsed(monkeypatch, base, stdout):
    # Every value read, but none inside its registry range: the spec's unparsed, which only
    # the report model's ranges can tell.
    scene = Scene(monkeypatch, runs={base: run_of(stdout)})
    key, index = ("count", 0) if base == "S3" else ("power", 1)
    assert scene.record[key] == {"ending": "unparsed", "cleanup": "verified"}
    assert scene.outcomes()[index] == ("source_changed", "parse_failed")
    assert scene.exit_code() == 1


def test_one_value_in_its_range_keeps_the_output_parsed(monkeypatch):
    one = OUT_OF_RANGE_LEDGER.replace('"event_rows":1000000001', '"event_rows":0', 1)
    scene = Scene(monkeypatch, runs={"S3": run_of(one)})
    assert scene.record["count"] == {"ending": "parsed", "cleanup": "verified"}
    scene.report()


def test_a_payload_is_parsed_only_after_the_final_clear(monkeypatch):
    steps: list[str] = []
    ledger, power = payloads.ledger, payloads.power

    def read_ledger(text: str) -> object:
        steps.append("read S3")
        return ledger(text)

    def read_power(text: str) -> object:
        steps.append("read S4")
        return power(text)

    monkeypatch.setattr(payloads, "ledger", read_ledger)
    monkeypatch.setattr(payloads, "power", read_power)
    scene = Scene(monkeypatch, steps=steps)
    assert steps == ["R5", "X1", "P1", "S1", "S2", "S3", "S4", "S5", "read S3", "read S4"]
    assert scene.outcomes() == ("parsed", "parsed")


def test_a_count_that_parsed_and_left_a_survivor_keeps_its_records(monkeypatch):
    scene = Scene(monkeypatch, runs={"S3": run_of(LEDGER_E, cleanup="survivor")})
    assert scene.outcomes() == ("parsed", ("tool_error", "skipped_after_unsafe_stop"))
    assert scene.exit_code() == 1, "an unverified stop exits 1"


def test_a_payload_run_for_another_command_is_refused(monkeypatch):
    def elsewhere(command_id: str, uid: int) -> spawn.PayloadRun:
        return run_of(LEDGER_E, command_id="S4")

    monkeypatch.setattr(
        spawn, "_execute", lambda argv, **kwargs: result(kwargs["command_id"], stdout=LISTING)
    )
    with pytest.raises(elevation.Interrupted) as problem:
        elevation.run(
            yes=True,
            no_root=False,
            admin=True,
            terminal=True,
            ask=lambda: None,
            runner=spawn.Runner(),
            payload=elsewhere,
            cancelled=lambda: False,
            lookup=lambda _name: SERVICE_UID,
        )
    assert isinstance(problem.value.__cause__, ValueError)


# --- cancellation -----------------------------------------------------------------------------


@pytest.mark.parametrize("mode", MODES)
def test_ctrl_c_at_the_prompt_clears_and_cancels(monkeypatch, mode):
    scene = Scene(monkeypatch, results={"S2": [result("S2", -15, spawn.Ending.CANCELLED)]}, **mode)
    assert scene.cancelled is not None and scene.found is None
    assert scene.steps == ids(mode, "R5", "X1", "P1", "S1", "S2", "S5")
    assert not scene.cancelled.clear_failed


def test_a_failed_clear_on_the_cancellation_path_is_still_reported(monkeypatch):
    scene = Scene(
        monkeypatch,
        results={"S2": [result("S2", -15, spawn.Ending.CANCELLED)], "S5": [result("S5", 1)]},
    )
    assert scene.cancelled is not None and scene.cancelled.clear_failed, "the warning prints"


@pytest.mark.parametrize(
    ("step", "steps"),
    [
        ("ask", []),
        ("R5", ["R5"]),
        ("X1", ["R5", "X1"]),
        ("P1", ["R5", "X1", "P1"]),
        ("S1", ["R5", "X1", "P1", "S1", "S5"]),
        ("S2", ["R5", "X1", "P1", "S1", "S2", "S5"]),
        ("S3", ["R5", "X1", "P1", "S1", "S2", "S3", "S5"]),
        ("S4", ["R5", "X1", "P1", "S1", "S2", "S3", "S4", "S5"]),
    ],
)
def test_a_cancellation_stops_the_path_and_clears_once_sudo_k_was_attempted(
    monkeypatch, step, steps
):
    scene = Scene(monkeypatch, cancel_after=step)
    assert scene.cancelled is not None and scene.found is None
    assert scene.steps == steps
    assert not scene.cancelled.clear_failed


# --- the #346 review ----------------------------------------------------------------------------


class Crash(Exception):
    pass


def _raises(error: BaseException):
    def payload(command_id: str, uid: int) -> spawn.PayloadRun:
        raise error

    return payload


def _flow(monkeypatch, payload, s5=None, s5_raises=None) -> list[str]:
    steps: list[str] = []

    def fake_execute(argv, **kwargs):
        command_id = kwargs["command_id"]
        steps.append(command_id)
        if command_id == "S5" and s5_raises is not None:
            raise s5_raises
        if command_id == "S5" and s5 is not None:
            return dataclasses.replace(s5, command_id="S5")
        return result(command_id, stdout=LISTING if command_id == "P1" else "")

    monkeypatch.setattr(spawn, "_execute", fake_execute)
    elevation.run(
        yes=True,
        no_root=False,
        admin=True,
        terminal=True,
        ask=lambda: None,
        runner=spawn.Runner(),
        payload=payload,
        cancelled=lambda: False,
        lookup=lambda _name: SERVICE_UID,
    )
    return steps


@pytest.mark.parametrize(
    "s5", [None, result("S5", 1)], ids=["the clear worked", "the clear failed"]
)
def test_an_error_on_the_sudo_path_still_clears_and_says_how_the_clear_went(monkeypatch, s5):
    with pytest.raises(elevation.Interrupted) as problem:
        _flow(monkeypatch, _raises(Crash("a bug")), s5)
    assert isinstance(problem.value.__cause__, Crash), "the error it stopped on is kept"
    assert problem.value.clear_failed is (s5 is not None)


@pytest.mark.parametrize(
    "s5", [None, result("S5", 1)], ids=["the clear worked", "the clear failed"]
)
def test_an_interrupt_on_the_sudo_path_is_a_cancellation_that_clears(monkeypatch, s5):
    try:
        with pytest.raises(elevation.Cancelled) as problem:
            _flow(monkeypatch, _raises(KeyboardInterrupt()), s5)
    except KeyboardInterrupt:
        pytest.fail("the interrupt escaped the broker")
    assert problem.value.clear_failed is (s5 is not None)


def test_the_real_lookup_tells_a_missing_account_from_a_failed_directory(monkeypatch):
    def no_account(name: str) -> object:
        raise KeyError(name)

    monkeypatch.setattr(elevation.pwd, "getpwnam", no_account)
    monkeypatch.setattr(elevation.pwd, "getpwuid", lambda uid: object())
    with pytest.raises(KeyError):
        elevation._lookup("_mmaintenanced")
    assert elevation._service_account(elevation._lookup, 1.0)[0] == "missing"
    # CPython turns every failed getpwnam_r into KeyError; root's entry tells them apart.
    monkeypatch.setattr(elevation.pwd, "getpwuid", no_account)
    assert elevation._service_account(elevation._lookup, 1.0)[0] == "error"


def test_the_lookup_is_the_real_one_by_default():
    assert inspect.signature(elevation.run).parameters["lookup"].default is elevation._lookup


def test_the_lookup_runs_on_a_daemon_thread(monkeypatch):
    seen = []

    def lookup(name: str) -> object:
        seen.append(threading.current_thread().daemon)
        return SERVICE_UID

    assert elevation._service_account(lookup, 1.0)[0] == "present"
    assert seen == [True], "a lookup that never returns cannot keep the tool from exiting"


def test_a_lookup_that_returns_after_its_bound_is_an_error(monkeypatch):
    # The worker finishes after the bound but before the result is read.
    real_join = threading.Thread.join

    def late_join(self, timeout=None):
        real_join(self, timeout)
        real_join(self)  # let the late lookup finish before the broker reads it

    monkeypatch.setattr(threading.Thread, "join", late_join)

    def slow(name: str) -> object:
        time.sleep(0.3)
        return SERVICE_UID

    assert elevation._service_account(slow, 0.1)[0] == "error"


def test_a_listing_that_failed_after_printing_a_whole_listing_still_failed(monkeypatch):
    for listing_result in (
        result("P1", 1, stdout=LISTING),
        result("P1", -9, spawn.Ending.DEADLINE, stdout=LISTING),
    ):
        scene = Scene(monkeypatch, results={"P1": [listing_result]})
        assert scene.record["checks"]["listing"] == "failed"


@pytest.mark.parametrize(
    ("s2", "state"),
    [
        (result("S2", -15, spawn.Ending.OUTPUT_CAP, stderr=WRONG_PASSWORD), "error"),
        (result("S2", None, spawn.Ending.NOT_STARTED, stderr=WRONG_PASSWORD), "error"),
        (result("S2", -11, spawn.Ending.SIGNALED, stderr=ACCOUNT_STATE), "blocked"),
        (result("S2", -11, spawn.Ending.SIGNALED, stderr=""), "error"),
    ],
    ids=[
        "the cap, then an authentication line",
        "never started",
        "a signal, then an account line",
        "a silent signal",
    ],
)
def test_s2s_stderr_is_read_only_after_an_exit_or_a_signal_it_ended_on(monkeypatch, s2, state):
    # A signal death is read like a payload's: by the lines sudo printed before it.
    assert Scene(monkeypatch, results={"S2": [s2]}).record["authenticate"] == state


def test_a_cancellation_before_the_broker_starts_asks_nothing(monkeypatch):
    asked = []
    monkeypatch.setattr(spawn, "_execute", lambda argv, **kwargs: result(kwargs["command_id"]))
    with pytest.raises(elevation.Cancelled):
        elevation.run(
            yes=False,
            no_root=False,
            admin=True,
            terminal=True,
            ask=lambda: asked.append(True) or "y",
            runner=spawn.Runner(),
            payload=_raises(Crash("never reached")),
            cancelled=lambda: True,
            lookup=lambda _name: object(),
        )
    assert asked == []


def test_the_power_samples_stderr_is_read_only_after_the_final_clear(monkeypatch):
    steps: list[str] = []
    real = elevation.sudo_messages.payload_ending

    def classify(stderr: str) -> str:
        steps.append("classify")
        return real(stderr)

    monkeypatch.setattr(elevation.sudo_messages, "payload_ending", classify)
    scene = Scene(
        monkeypatch,
        runs={"S3": run_of(code=1, stderr=SQLITE_ERROR), "S4": run_of(code=1, stderr=SQLITE_ERROR)},
        steps=steps,
    )
    assert steps == ["R5", "X1", "P1", "S1", "S2", "S3", "classify", "S4", "S5", "classify"]
    assert scene.record["power"]["ending"] == "payload_error"


# --- the tracked payloads (MAC 3.8) --------------------------------------------------------------


@pytest.mark.parametrize("mode", MODES)
def test_each_payload_is_run_as_its_own_account(monkeypatch, mode):
    scene = Scene(monkeypatch, **mode)
    s3, s4 = ids(mode, "S3", "S4")
    assert scene.uids == {s3: SERVICE_UID, s4: 0}, "the looked-up account, and root"


@pytest.mark.parametrize(
    "found",
    [object(), "283", True, None],
    ids=["an entry", "text", "a bool", "nothing"],
)
def test_a_lookup_that_does_not_give_a_user_id_is_an_error(monkeypatch, found):
    scene = Scene(monkeypatch, lookup=lambda _name: found)
    assert scene.record["checks"]["service_account"] == "error"
    assert "S3" not in scene.steps


# The GPT audit, pass 2, G2-04: R5 took any whole number, so a service account the account
# database gave user ID 0 would have run the count's sqlite3 as root under the account's name.
NOT_THE_SERVICE_ACCOUNT = [0, -1, -2, 2**31, 4294967294, 2**32]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("uid", NOT_THE_SERVICE_ACCOUNT, ids=str)
def test_a_user_id_of_root_or_of_no_account_is_r5s_error(monkeypatch, mode, uid):
    # 0 is root; a negative ID names no account (the lookup gives -1 for (uid_t)-1); ps
    # prints 2^31 and above as negative numbers, so tracking could never find the payload.
    # R5's error then does what the outcome table says: no count, the power sample, exit 1.
    scene = Scene(monkeypatch, lookup=lambda _name: uid, **mode)
    assert scene.record["checks"]["service_account"] == "error"
    assert scene.steps == ids(mode, "R5", "X1", "P1", "S1", "S2", "S4", "S5"), "no S3"
    assert scene.uids == dict.fromkeys(ids(mode, "S4"), 0), "root only for the power sample"
    assert scene.record["count"] == {"ending": "not_run", "cleanup": "not_applicable"}
    assert scene.outcomes() == (("tool_error", "service_account_error"), "parsed")
    assert scene.exit_code() == 1


@pytest.mark.parametrize("uid", [1, SERVICE_UID, 499, 2**31 - 1], ids=str)
def test_a_user_id_from_1_to_2_31_less_1_is_the_service_accounts(monkeypatch, uid):
    scene = Scene(monkeypatch, lookup=lambda _name: uid)
    assert scene.record["checks"]["service_account"] == "present"
    assert scene.uids == {"S3": uid, "S4": 0}


@pytest.mark.parametrize("uid", NOT_THE_SERVICE_ACCOUNT, ids=str)
def test_the_lookup_gives_no_user_id_it_would_not_run_the_count_as(uid):
    assert elevation._service_account(lambda _name: uid, 1.0) == ("error", None)


def test_the_real_lookup_gives_the_accounts_user_id(monkeypatch):
    class Entry:
        pw_uid = SERVICE_UID

    monkeypatch.setattr(elevation.pwd, "getpwnam", lambda name: Entry())
    assert elevation._lookup("_mmaintenanced") == SERVICE_UID


SURVIVOR_S3 = tracking.Survivor(
    pid=701, uid=SERVICE_UID, started="Sat Sep 26 12:00:01 2026", name="sqlite3"
)
SURVIVOR_S4 = tracking.Survivor(
    pid=702, uid=0, started="Sat Sep 26 12:00:05 2026", name="powermetrics"
)


def test_the_survivors_of_both_payloads_reach_the_caller(monkeypatch):
    runs = {
        "S3": run_of(
            LEDGER_E,
            forced="runtime_deadline",
            returncode=None,
            cleanup="survivor",
            survivors=(SURVIVOR_S3,),
        ),
    }
    scene = Scene(monkeypatch, runs=runs)
    assert scene.found is not None and scene.found.survivors == (SURVIVOR_S3,)
    power = run_of(SAMPLE_E, cleanup="survivor", survivors=(SURVIVOR_S4,))
    scene = Scene(monkeypatch, runs={"S4": power})
    assert scene.found is not None and scene.found.survivors == (SURVIVOR_S4,)


def test_a_payload_the_cancellation_stopped_ends_the_path_with_its_survivors(monkeypatch):
    stopped = run_of(
        "", returncode=None, cancelled=True, cleanup="survivor", survivors=(SURVIVOR_S3,)
    )
    scene = Scene(monkeypatch, runs={"S3": stopped})
    assert scene.cancelled is not None and scene.found is None
    assert scene.steps == ["R5", "X1", "P1", "S1", "S2", "S3", "S5"]
    assert scene.cancelled.survivors == (SURVIVOR_S3,)
    assert not scene.cancelled.unverified


def test_an_unverified_stop_on_the_cancellation_path_is_reported(monkeypatch):
    stopped = run_of("", returncode=None, cancelled=True, cleanup="listing_failed")
    scene = Scene(monkeypatch, runs={"S4": stopped})
    assert scene.cancelled is not None and scene.cancelled.unverified


def test_the_default_payload_runner_is_the_chokepoints(monkeypatch):
    calls = []

    def tracked(self, command_id, *, uid):
        calls.append((command_id, uid))
        stdout = LEDGER_E if command_id == "S3" else SAMPLE_E
        return run_of(stdout, command_id=command_id)

    monkeypatch.setattr(spawn.Runner, "payload", tracked)
    monkeypatch.setattr(
        spawn, "_execute", lambda argv, **kwargs: result(kwargs["command_id"], stdout=LISTING)
    )
    found = elevation.run(
        yes=True,
        no_root=False,
        admin=True,
        terminal=True,
        ask=lambda: None,
        runner=spawn.Runner(),
        cancelled=lambda: False,
        lookup=lambda _name: SERVICE_UID,
    )
    assert calls == [("S3", SERVICE_UID), ("S4", 0)]
    assert found.record["count"] == {"ending": "parsed", "cleanup": "verified"}


# --- the review of #348 ------------------------------------------------------------------------


def test_an_error_inside_a_payload_names_what_its_final_listing_found(monkeypatch):
    left = run_of(code=None, cleanup="survivor", cancelled=True)

    def payload(command_id: str, uid: int) -> spawn.PayloadRun:
        run = dataclasses.replace(left, command_id=command_id)
        raise spawn.PayloadInterrupted(run) from Crash("a bug in the tracking")

    with pytest.raises(elevation.Interrupted) as problem:
        _flow(monkeypatch, payload)
    assert isinstance(problem.value.__cause__, Crash), "the error it stopped on is kept"
    assert problem.value.survivors == (SURVIVOR,)
    assert problem.value.unverified is False


# --- the review of #348, round 2: S5 and the steps after it -------------------------------------


def _left_a_survivor(command_id: str, uid: int) -> spawn.PayloadRun:
    run = dataclasses.replace(
        run_of(code=None, cleanup="survivor", cancelled=True), command_id=command_id
    )
    raise spawn.PayloadInterrupted(run) from Crash("a bug in the tracking")


def test_a_ctrl_c_in_the_final_clear_keeps_the_first_error_and_the_survivors(monkeypatch):
    try:
        with pytest.raises(elevation.Interrupted) as problem:
            _flow(monkeypatch, _left_a_survivor, s5_raises=KeyboardInterrupt())
    except KeyboardInterrupt:
        pytest.fail("the interrupt in the final clear escaped the broker")
    assert isinstance(problem.value.__cause__, Crash), "the first error is kept"
    assert problem.value.survivors == (SURVIVOR,)
    assert problem.value.clear_failed, "a clear that did not finish is not a clear"


def test_a_bug_in_the_final_clear_after_a_survivor_is_interrupted_with_it(monkeypatch):
    left = run_of(code=None, forced="runtime_deadline", cleanup="survivor")

    def payload(command_id: str, uid: int) -> spawn.PayloadRun:
        return dataclasses.replace(left, command_id=command_id)

    bug = Crash("a bug in the clear")
    with pytest.raises(elevation.Interrupted) as problem:
        _flow(monkeypatch, payload, s5_raises=bug)
    assert problem.value.__cause__ is bug
    assert problem.value.survivors == (SURVIVOR,) and problem.value.clear_failed


def test_a_ctrl_c_in_the_final_clear_of_a_clean_run_is_a_cancellation(monkeypatch):
    def payload(command_id: str, uid: int) -> spawn.PayloadRun:
        return dataclasses.replace(
            run_of(LEDGER_E if command_id.startswith("S3") else SAMPLE_E), command_id=command_id
        )

    try:
        with pytest.raises(elevation.Cancelled) as problem:
            _flow(monkeypatch, payload, s5_raises=KeyboardInterrupt())
    except KeyboardInterrupt:
        pytest.fail("the interrupt in the final clear escaped the broker")
    assert problem.value.clear_failed


def test_a_ctrl_c_after_the_clear_is_a_cancellation_with_the_survivors(monkeypatch):
    left = run_of(SAMPLE_E, code=0, cleanup="survivor")

    def payload(command_id: str, uid: int) -> spawn.PayloadRun:
        found = left if command_id.startswith("S4") else run_of(LEDGER_E)
        return dataclasses.replace(found, command_id=command_id)

    def interrupted(*_args: object, **_kwargs: object) -> object:
        raise KeyboardInterrupt

    monkeypatch.setattr(elevation, "_read", interrupted)
    try:
        with pytest.raises(elevation.Cancelled) as problem:
            _flow(monkeypatch, payload)
    except KeyboardInterrupt:
        pytest.fail("the interrupt after the clear escaped the broker")
    assert problem.value.survivors == (SURVIVOR,)


@pytest.mark.parametrize("where", ["note", "read"])
def test_a_bug_after_the_clear_is_interrupted_with_the_survivors(monkeypatch, where):
    left = run_of(SAMPLE_E, code=0, cleanup="survivor")

    def payload(command_id: str, uid: int) -> spawn.PayloadRun:
        base = command_id.rstrip("n")
        found = left if base == "S4" else run_of(LEDGER_E)
        return dataclasses.replace(found, command_id=command_id)

    bug = Crash(f"a bug in the {where}")

    def broken(*_args: object, **_kwargs: object) -> object:
        raise bug

    if where == "note":
        # Only the power sample's note, which the broker takes after the final clear.
        real = spawn.Runner.note_payload

        def note(self: spawn.Runner, command_id: str, **options: object) -> None:
            if command_id.startswith("S4"):
                raise bug
            real(self, command_id, **options)  # type: ignore[arg-type]

        monkeypatch.setattr(spawn.Runner, "note_payload", note)
    else:
        monkeypatch.setattr(elevation, "_read", broken)
    with pytest.raises(elevation.Interrupted) as problem:
        _flow(monkeypatch, payload)
    assert problem.value.__cause__ is bug
    assert problem.value.survivors == (SURVIVOR,)
    assert not problem.value.clear_failed


def test_an_error_that_left_a_payload_unchecked_is_an_unverified_stop(monkeypatch):
    with pytest.raises(elevation.Interrupted) as problem:
        _flow(monkeypatch, _raises(Crash("a bug")))
    assert (problem.value.survivors, problem.value.unverified) == ((), True)


def test_a_ctrl_c_that_left_a_payload_unchecked_is_an_unverified_cancellation(monkeypatch):
    try:
        with pytest.raises(elevation.Cancelled) as problem:
            _flow(monkeypatch, _raises(KeyboardInterrupt()))
    except KeyboardInterrupt:
        pytest.fail("the interrupt escaped the broker")
    assert problem.value.unverified is True


def test_an_error_before_any_payload_leaves_nothing_unverified(monkeypatch):
    def fake_execute(argv, **kwargs):
        command_id = kwargs["command_id"]
        if command_id.startswith("S2"):
            raise Crash("a bug at the prompt")
        return result(command_id, stdout=LISTING if command_id == "P1" else "")

    monkeypatch.setattr(spawn, "_execute", fake_execute)
    with pytest.raises(elevation.Interrupted) as problem:
        elevation.run(
            yes=True,
            no_root=False,
            admin=True,
            terminal=True,
            ask=lambda: None,
            runner=spawn.Runner(),
            payload=_raises(AssertionError("no payload runs")),
            cancelled=lambda: False,
            lookup=lambda _name: SERVICE_UID,
        )
    assert (problem.value.survivors, problem.value.unverified) == ((), False)


def test_a_cancellation_before_sudo_is_not_an_unverified_stop(monkeypatch):
    scene = Scene(monkeypatch, cancel_after="S1")
    assert scene.cancelled is not None and scene.cancelled.unverified is False
    assert elevation.Cancelled(clear_failed=False).unverified is False


@pytest.mark.parametrize("base", ["S3", "S4"])
def test_the_output_cap_in_the_pass_a_listing_failed_makes_a_valid_report(monkeypatch, base):
    # The latch gives the cap first, and P1's record still counts the listing that failed
    # in that pass (change record 3).
    def track(engine, *, payload, runtime_s, cancelled):
        return tracking.Tracked(
            started=True,
            forced="output_cap" if payload.name == tracking.PAYLOAD_NAMES[base] else None,
            returncode=None if payload.name == tracking.PAYLOAD_NAMES[base] else 0,
            stdout=LEDGER_E if payload.name == "sqlite3" else SAMPLE_E,
            stderr="",
            cleanup="verified",
            survivors=(),
            records=(),
            cancelled=False,
            stop="terminated" if payload.name == tracking.PAYLOAD_NAMES[base] else None,
            duration_s=0.5,
            listings=(
                ((0.05, True), (0.05, False))
                if payload.name == tracking.PAYLOAD_NAMES[base]
                else ((0.05, False),)
            ),
        )

    monkeypatch.setattr(tracking, "track", track)
    monkeypatch.setattr(
        spawn, "_execute", lambda argv, **kwargs: result(kwargs["command_id"], stdout=LISTING)
    )
    runner = spawn.Runner()
    found = elevation.run(
        yes=False,
        no_root=False,
        admin=True,
        terminal=True,
        ask=lambda: "y",
        runner=runner,
        cancelled=lambda: False,
        lookup=lambda _name: SERVICE_UID,
    )
    record = found.record["count" if base == "S3" else "power"]
    assert record == {"ending": "output_cap", "cleanup": "verified"}
    p1 = next(x for x in runner.records() if x.id == "P1")
    assert p1.failed_runs == 1
    scene = Scene.__new__(Scene)
    scene.found, scene.runner = found, runner
    scene.report()  # the validator accepts it


# --- the review of #326, round 1 -----------------------------------------------------------------


@pytest.mark.parametrize("base", ["S3", "S4"])
def test_a_payload_the_flag_kept_from_starting_is_not_an_unverified_stop(monkeypatch, base):
    # M6: the flag set as the payload runner is asked for the payload, after the broker's
    # own look. Tracking starts nothing and lists nothing, which is no stop to verify: no
    # unverified-stop note, no survivor, and the final clear still runs. The real runner and
    # tracking run here; no process starts.
    flag = {"set": False}
    steps: list[str] = []

    def execute(argv, **kwargs):  # type: ignore[no-untyped-def]
        command_id = kwargs["command_id"]
        if kwargs.get("cancelled") is not None and kwargs["cancelled"]():
            return spawn.Result(command_id, spawn.Ending.CANCELLED, None, "", "", 0, False, True)
        steps.append(command_id)
        return result(command_id, stdout=LISTING if command_id == "P1" else "")

    def payload(command_id: str, uid: int) -> spawn.PayloadRun:
        if command_id.rstrip("n") == base:
            flag["set"] = True
        else:
            steps.append(command_id)
            return run_of(LEDGER_E, command_id=command_id)
        return runner.payload(command_id, uid=uid)

    def no_start(argv):  # type: ignore[no-untyped-def]
        raise AssertionError("a process was started")

    monkeypatch.setattr(spawn, "_execute", execute)
    monkeypatch.setattr(spawn, "_popen", no_start)
    runner = spawn.Runner(cancelled=lambda: flag["set"])
    with pytest.raises(elevation.Cancelled) as stopped:
        elevation.run(
            yes=False,
            no_root=False,
            admin=True,
            terminal=True,
            ask=lambda: "y",
            runner=runner,
            payload=payload,
            cancelled=lambda: flag["set"],
            lookup=lambda _name: SERVICE_UID,
        )
    assert (stopped.value.unverified, stopped.value.survivors) == (False, ())
    assert steps[-1] == "S5" and base not in steps


# --- authorization clearing, with a fake sudo ------------------------------------------------

# Test strategy part 5: the runner's passwordless sudo cannot show that the final sudo -k
# clears the authorization, so this fake sudo keeps one. It stands for a Mac whose sudoers
# has no NOPASSWD rule, where the owner types the password at the one prompt: -v with a
# prompt makes the authorization, -k removes it, and -n succeeds only while it is kept.
# A "clear-fails" file beside it makes -k fail while an authorization is kept.
FAKE_SUDO = """\
import pathlib
import sys

state = pathlib.Path(sys.argv[1])
kept, log = state / "authorization", state / "log"
args = sys.argv[2:]


def note(line):
    with log.open("a") as out:
        out.write(line + "\\n")


if args == ["-k"]:
    if (state / "clear-fails").exists() and kept.exists():
        note("-k failed")
        sys.exit(1)
    note("-k removed" if kept.exists() else "-k found none")
    kept.unlink(missing_ok=True)
elif args[:2] == ["-v", "-p"]:
    kept.touch()
    note("-v made")
elif args[:1] == ["-n"] and kept.exists():
    note("-n used")
else:
    sys.stderr.write("sudo: a password is required\\n")
    sys.exit(1)
"""


class FakeSudo:
    """The fake sudo in a folder of its own: its program, its authorization, its log."""

    def __init__(self, folder: Path) -> None:
        self.folder = folder
        self.program = folder / "sudo.py"
        self.program.write_text(FAKE_SUDO, encoding="utf-8")
        self.kept = folder / "authorization"

    def argv(self, *args: str) -> list[str]:
        return [sys.executable, str(self.program), str(self.folder), *args]

    def run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(self.argv(*args), capture_output=True, text=True, timeout=30)

    def log(self) -> list[str]:
        found = self.folder / "log"
        return found.read_text(encoding="utf-8").splitlines() if found.exists() else []

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Each sudo argv the broker starts runs the fake instead, with the same options,
        once the allow-list has checked the real argv; X1 and P1 get stand-ins that pass on
        any platform."""
        real = spawn.Runner._checked_argv

        def checked(runner, command_id, *, broker=False):  # type: ignore[no-untyped-def]
            argv = real(runner, command_id, broker=broker)
            if argv[0] == "/usr/bin/sudo":
                return self.argv(*argv[1:])
            if command_id == "X1":
                return [sys.executable, "-c", ""]
            if command_id == "P1":
                return [sys.executable, "-c", f"print({LISTING!r}, end='')"]
            return argv

        monkeypatch.setattr(spawn.Runner, "_checked_argv", checked)


def _clearing_run(sudo: FakeSudo, monkeypatch, payload=None) -> elevation.Elevation:
    sudo.install(monkeypatch)

    def ran(command_id: str, uid: int) -> spawn.PayloadRun:
        return run_of(LEDGER_E if command_id == "S3" else SAMPLE_E, command_id=command_id)

    return elevation.run(
        yes=False,
        no_root=False,
        admin=True,
        terminal=True,
        ask=lambda: "y",
        runner=spawn.Runner(),
        payload=payload or ran,
        cancelled=lambda: False,
        lookup=lambda _name: SERVICE_UID,
    )


def test_the_final_sudo_k_leaves_no_authorization_behind(monkeypatch, tmp_path):
    # Acceptance criteria, Privilege: right after a run, sudo -n true fails, because the
    # authorization was cleared. S1 clears one kept from before, so the prompt is fresh
    # consent; both payloads run inside the one it makes; S5 removes that one.
    sudo = FakeSudo(tmp_path)
    sudo.kept.touch()
    inside: list[tuple[str, bool]] = []

    def payload(command_id: str, uid: int) -> spawn.PayloadRun:
        inside.append((command_id, sudo.kept.exists()))
        return run_of(LEDGER_E if command_id == "S3" else SAMPLE_E, command_id=command_id)

    found = _clearing_run(sudo, monkeypatch, payload)
    assert [found.record[step] for step in ("prepare", "authenticate", "cleared")] == [
        "ok",
        "ok",
        "cleared",
    ]
    assert inside == [("S3", True), ("S4", True)]
    assert sudo.log() == ["-k removed", "-v made", "-k removed"]
    assert not sudo.kept.exists()
    after = sudo.run("-n", "/usr/bin/true")
    assert (after.returncode, after.stderr) == (1, "sudo: a password is required\n")


def test_a_final_sudo_k_that_fails_leaves_the_authorization_the_warning_names(
    monkeypatch, tmp_path
):
    # When the final clear fails, the authorization outlives the run: the JSON records
    # cleared failed, and the run warns and exits 6 (test_run.py's
    # test_a_failed_clear_warns_at_once_and_at_the_end_and_exits_6). The sudo -k the
    # warning names clears it.
    sudo = FakeSudo(tmp_path)
    (tmp_path / "clear-fails").touch()
    found = _clearing_run(sudo, monkeypatch)
    assert found.clear_failed
    assert (found.record["cleared"], found.record["clear_error"]) == ("failed", "nonzero_exit")
    assert sudo.log() == ["-k found none", "-v made", "-k failed"]
    assert sudo.run("-n", "/usr/bin/true").returncode == 0, "the authorization is still kept"
    (tmp_path / "clear-fails").unlink()
    assert sudo.run("-k").returncode == 0
    assert sudo.run("-n", "/usr/bin/true").returncode == 1
