"""render's validator, third pass: the elevation record and what it implies.

docs/VOLTRY_MAC_SPEC.md, Decision 8 (the eight rules of the state machine and the command
records they imply) and Decision 2 (the outcome tables and the skip rule, which give each
elevated surface its reason and detail). ``check`` runs after the shapes and the report's
relations have passed; it raises ``canonical.Invalid`` naming the field path.
"""

from __future__ import annotations

from typing import Final

from voltry_mac import allowlist, registry
from voltry_mac.canonical import Invalid
from voltry_mac.validate_relations import Report

# The elevation record's values (Decision 8) and Decision 2's thirteen endings.
CONSENT: Final = ("yes", "no", "flag", "skipped")
SKIP_CAUSE: Final = ("no_root_flag", "not_admin", "no_terminal")
MODE: Final = ("interactive", "noninteractive", "none")
SERVICE_ACCOUNT: Final = ("present", "missing", "error", "not_run")
CHECK_RESULT: Final = ("ok", "failed", "not_run")
AUTHENTICATE: Final = ("ok", "blocked", "refused", "denied", "error", "not_run")
ENDINGS: Final = (
    "not_run",
    "spawn_failed",
    "parsed",
    "unparsed",
    "payload_error",
    "policy_refusal",
    "account_blocked",
    "auth_failed",
    "sudo_error",
    "runtime_deadline",
    "output_cap",
    "launch_deadline",
    "tracking_failed",
)
CLEANUP: Final = ("verified", "survivor", "listing_failed", "not_applicable")
CLEARED: Final = ("cleared", "failed", "not_attempted")
CLEAR_ERROR: Final = ("nonzero_exit", "deadline", "output_cap", "spawn_error", "not_reaped")
_ORDINARY: Final = frozenset(
    {"spawn_failed", "parsed", "unparsed", "payload_error", "policy_refusal"}
)

# Decision 2's outcome tables: what stops an elevated surface, and with which reason and
# detail. AVAILABLE marks a payload that parsed.
AVAILABLE: Final = ("available", "")
_SKIPPED_AT_QUESTION: Final = {
    "no_root_flag": ("declined", "not_attempted"),
    "not_admin": ("no_admin", "not_attempted"),
    "no_terminal": ("no_terminal", "not_attempted"),
}
_AUTHENTICATE_STOPS: Final = {
    "blocked": ("not_granted", "account_blocked"),
    "refused": ("not_granted", "policy_refusal"),
    "denied": ("not_granted", "auth_failed"),
    "error": ("tool_error", "sudo_error"),
}
_ENDING_OUTCOMES: Final = {
    "spawn_failed": ("tool_error", "spawn_failed"),
    "parsed": AVAILABLE,
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
_UNSAFE_STOP: Final = ("tool_error", "skipped_after_unsafe_stop")


def check(report: Report) -> None:
    """Raise ``Invalid`` at the first rule the elevation record or what it implies breaks."""
    elevation = report.document["elevation"]
    assert isinstance(elevation, dict)  # noqa: S101
    _state_machine(elevation)
    _elevated_records(report, elevation)
    _elevated_surfaces(report, elevation)


def _state_machine(elevation: dict) -> None:
    """The eight rules of Decision 8; only their legal histories pass."""
    consent, mode, cause = elevation["consent"], elevation["mode"], elevation["skip_cause"]
    checks = elevation["checks"]
    count, power = elevation["count"], elevation["power"]
    declined = consent in ("no", "skipped")
    # 1. No consent, no mode, nothing run.
    if declined != (mode == "none"):
        raise Invalid("mode is none exactly when consent is no or skipped", "elevation.mode")
    if (cause is not None) != (consent == "skipped"):
        raise Invalid(
            "a skip cause is present exactly when consent is skipped", "elevation.skip_cause"
        )
    if consent == "yes" and mode != "interactive":
        raise Invalid("an answered prompt runs the interactive forms", "elevation.mode")
    if declined:
        for name in ("service_account", "sandbox_probe", "listing"):
            if checks[name] != "not_run":
                raise Invalid("nothing runs without consent", f"elevation.checks.{name}")
        for name in ("prepare", "authenticate"):
            if elevation[name] != "not_run":
                raise Invalid("nothing runs without consent", f"elevation.{name}")
        for name in ("count", "power"):
            if elevation[name]["ending"] != "not_run":
                raise Invalid("nothing runs without consent", f"elevation.{name}.ending")
        if elevation["cleared"] != "not_attempted":
            raise Invalid("nothing runs without consent", "elevation.cleared")
    else:
        # 2. With consent, the three checks in order.
        if checks["service_account"] == "not_run":
            raise Invalid(
                "the account is looked up once consent is given", "elevation.checks.service_account"
            )
        if checks["sandbox_probe"] == "not_run":
            raise Invalid(
                "the sandbox probe runs once consent is given", "elevation.checks.sandbox_probe"
            )
        if (checks["listing"] == "not_run") != (checks["sandbox_probe"] == "failed"):
            raise Invalid(
                "the listing runs exactly when the probe succeeded", "elevation.checks.listing"
            )
    # 3. to 8.
    stopped = declined or "failed" in (checks["sandbox_probe"], checks["listing"])
    if (elevation["prepare"] == "not_run") != stopped:
        raise Invalid(
            "sudo -k runs exactly when consent was given and both checks succeeded",
            "elevation.prepare",
        )
    if (elevation["authenticate"] == "not_run") != (elevation["prepare"] != "ok"):
        raise Invalid("sudo asks exactly when sudo -k succeeded", "elevation.authenticate")
    granted = elevation["authenticate"] == "ok"
    count_runs = granted and checks["service_account"] == "present"
    if (count["ending"] == "not_run") == count_runs:
        raise Invalid(
            "the count runs exactly when access was granted and the account exists",
            "elevation.count.ending",
        )
    count_stops = count["ending"] != "not_run" and (
        count["ending"] not in _ORDINARY or count["cleanup"] != "verified"
    )
    if (power["ending"] == "not_run") == (granted and not count_stops):
        raise Invalid(
            "the power sample runs exactly when access was granted and the count ended safely",
            "elevation.power.ending",
        )
    for name, payload in (("count", count), ("power", power)):
        if (payload["cleanup"] == "not_applicable") != (payload["ending"] == "not_run"):
            raise Invalid(
                "a cleanup is not applicable exactly when its step did not run",
                f"elevation.{name}.cleanup",
            )
        if payload["ending"] == "spawn_failed" and payload["cleanup"] == "survivor":
            raise Invalid(
                "a payload that never started leaves no survivor", f"elevation.{name}.cleanup"
            )
    if (elevation["cleared"] == "not_attempted") != (elevation["prepare"] == "not_run"):
        raise Invalid("the final clear runs exactly when sudo -k ran", "elevation.cleared")
    if (elevation["clear_error"] is not None) != (elevation["cleared"] == "failed"):
        raise Invalid(
            "an error code is present exactly when the final clear failed", "elevation.clear_error"
        )


def _elevated_records(report: Report, elevation: dict) -> None:
    """The records the elevation record implies, and their failed runs."""
    checks = elevation["checks"]
    count, power = elevation["count"]["ending"], elevation["power"]["ending"]
    suffix = "n" if elevation["mode"] == "noninteractive" else ""
    expected: dict[str, int | None] = {}
    if checks["sandbox_probe"] != "not_run":
        expected["X1"] = int(checks["sandbox_probe"] == "failed")
    if checks["listing"] != "not_run":
        expected["P1"] = None
    if elevation["prepare"] != "not_run":
        expected["S1"] = int(elevation["prepare"] == "failed")
        expected["S5"] = int(elevation["cleared"] == "failed")
    if elevation["authenticate"] != "not_run":
        expected["S2" + suffix] = int(elevation["authenticate"] != "ok")
    if count != "not_run":
        expected["S3" + suffix] = int(count not in ("parsed", "unparsed"))
    if power != "not_run":
        expected["S4" + suffix] = int(power not in ("parsed", "unparsed"))
    for command_id in report.commands:
        if command_id not in allowlist.USER_COMMAND_IDS and command_id not in expected:
            raise Invalid(
                "the elevation record says this command did not run",
                report.command_path(command_id, "id"),
            )
    for command_id in expected:
        if command_id not in report.commands:
            raise Invalid(
                f"the elevation record says {command_id} ran, and it has no record", "commands"
            )
    for command_id, failed in expected.items():
        record = report.commands[command_id]
        if failed is not None and record["failed_runs"] != failed:
            raise Invalid(
                "disagrees with the elevation record",
                report.command_path(command_id, "failed_runs"),
            )
    if "P1" in expected:
        _listings(report, elevation)


def _listings(report: Report, elevation: dict) -> None:
    record = report.commands["P1"]
    cleanups = (elevation["count"]["cleanup"], elevation["power"]["cleanup"])
    endings = (elevation["count"]["ending"], elevation["power"]["ending"])
    if elevation["checks"]["listing"] == "failed":
        if record["runs"] != 1:
            raise Invalid("one listing, the check that failed", report.command_path("P1", "runs"))
        if record["failed_runs"] != 1:
            raise Invalid(
                "the check failed, so one listing failed", report.command_path("P1", "failed_runs")
            )
    elif "listing_failed" in cleanups:
        if record["failed_runs"] < 1:
            raise Invalid(
                "a cleanup listing failed, so one listing failed",
                report.command_path("P1", "failed_runs"),
            )
    elif not {"tracking_failed", "output_cap"} & set(endings) and record["failed_runs"] != 0:
        # A listing can fail in the pass the output cap latches, and the cap outranks the
        # tracking failure, so an output_cap ending may carry one (change record 3).
        raise Invalid("no listing failed", report.command_path("P1", "failed_runs"))


def _expected_elevated(elevation: dict) -> tuple[tuple[str, str], tuple[str, str]]:
    """What the outcome tables give each elevated surface for this record."""
    consent = elevation["consent"]
    if consent == "no":
        return ("declined", "not_attempted"), ("declined", "not_attempted")
    if consent == "skipped":
        outcome = _SKIPPED_AT_QUESTION[elevation["skip_cause"]]
        return outcome, outcome
    checks = elevation["checks"]
    count: tuple[str, str] | None = None
    if checks["service_account"] == "missing":
        count = ("unsupported", "service_account_missing")
    elif checks["service_account"] == "error":
        count = ("tool_error", "service_account_error")
    for stopped, outcome in (
        (checks["sandbox_probe"] == "failed", ("unsupported", "sandbox_probe_failed")),
        (checks["listing"] == "failed", ("tool_error", "listing_unavailable")),
        (elevation["prepare"] == "failed", ("tool_error", "prepare_failed")),
        (
            elevation["authenticate"] in _AUTHENTICATE_STOPS,
            _AUTHENTICATE_STOPS.get(elevation["authenticate"], AVAILABLE),
        ),
    ):
        if stopped:
            return count or outcome, outcome
    ending, cleanup = elevation["count"]["ending"], elevation["count"]["cleanup"]
    if count is None:
        count = _ENDING_OUTCOMES[ending]
    power_ending = elevation["power"]["ending"]
    if power_ending != "not_run":
        return count, _ENDING_OUTCOMES[power_ending]
    # The skip rule: an unverified stop of the count comes first.
    if cleanup in ("survivor", "listing_failed"):
        return count, _UNSAFE_STOP
    if ending in ("auth_failed", "account_blocked"):
        return count, ("not_granted", ending)
    if ending == "sudo_error":
        return count, ("tool_error", "skipped_after_sudo_error")
    return count, _UNSAFE_STOP


def _elevated_surfaces(report: Report, elevation: dict) -> None:
    for key, expected in zip(
        registry.ELEVATED_SURFACES, _expected_elevated(elevation), strict=True
    ):
        surface = report.by_key[key]
        if expected == AVAILABLE:
            if surface["availability"] != "available":
                raise Invalid(
                    "the record says this payload parsed, so this surface is available",
                    report.path(key, field="availability"),
                )
            continue
        reason, detail = expected
        if surface["availability"] != "unavailable":
            raise Invalid(
                "the record says this surface was not read", report.path(key, field="availability")
            )
        if surface["reason"] != reason:
            raise Invalid(
                "not the reason the outcome tables give for this record",
                report.path(key, field="reason"),
            )
        if surface["detail"] != detail:
            raise Invalid(
                "not the detail the outcome tables give for this record",
                report.path(key, field="detail"),
            )
