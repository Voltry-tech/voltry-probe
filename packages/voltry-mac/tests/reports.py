"""The complete report fixtures, and the edits the validator tests make to them.

``fixtures/reports`` holds the two complete documents the spec names: ``m5-laptop``
(transcript 1, the M5's values with a made-up serial) and ``concerning-desktop``
(transcript 7 and the JSON example in Decision 8, synthetic). A test loads one, breaks
exactly one rule, keeps everything else consistent with ``finish`` (which recounts the
collection block and recomputes the report ID), and expects the validator to name the
field. The helpers here restate the spec's rules for building consistent documents; they
are written from the spec, not from the validator.
"""

from __future__ import annotations

import copy
from pathlib import Path

from voltry_mac import canonical

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "reports"
NAMES = ("m5-laptop", "concerning-desktop")

SKIPPED = frozenset({"declined", "not_granted", "no_admin", "no_terminal"})
UNEXPECTED = frozenset({"source_absent", "source_changed", "timeout", "tool_error"})
USER_IDS = [f"C{n}" for n in range(1, 10)] + [f"C{n}" for n in range(11, 29)]
ORDER = [*USER_IDS, "X1", "P1", "S1", "S2", "S3", "S4", "S5", "S2n", "S3n", "S4n"]
ORDINARY = frozenset({"spawn_failed", "parsed", "unparsed", "payload_error", "policy_refusal"})


def load(name: str) -> dict:
    return canonical.load((FIXTURES / f"{name}.json").read_bytes())


def surface(document: dict, key: str) -> dict:
    return next(entry for entry in document["surfaces"] if entry["key"] == key)


def index(document: dict, key: str) -> int:
    return next(i for i, entry in enumerate(document["surfaces"]) if entry["key"] == key)


def values(document: dict, key: str) -> dict:
    return surface(document, key)["values"]


def command(document: dict, command_id: str) -> dict:
    return next(record for record in document["commands"] if record["id"] == command_id)


def command_index(document: dict, command_id: str) -> int:
    return next(i for i, record in enumerate(document["commands"]) if record["id"] == command_id)


def unavailable(document: dict, key: str, reason: str, detail: str | None = None) -> None:
    """Make a whole surface unavailable, with its values dropped."""
    entry = surface(document, key)
    entry["availability"] = "unavailable"
    entry["reason"] = reason
    entry["values"] = {}
    entry.pop("detail", None)
    if detail is not None:
        entry["detail"] = detail


def value_unavailable(document: dict, key: str, name: str, reason: str) -> None:
    values(document, key)[name] = {"availability": "unavailable", "reason": reason}


def set_value(document: dict, key: str, name: str, value: object) -> None:
    values(document, key)[name]["value"] = value


def fail(document: dict, command_id: str) -> None:
    command(document, command_id)["failed_runs"] = 1


def retally(document: dict) -> None:
    """The collection block from the surfaces, as Decision 6 defines it."""
    surfaces = document["surfaces"]
    available = [s for s in surfaces if s["availability"] == "available"]
    missing = [s for s in surfaces if s["availability"] == "unavailable"]
    skipped = [s for s in missing if s.get("reason") in SKIPPED]
    value_reasons = {
        entry.get("reason")
        for s in available
        for entry in s["values"].values()
        if isinstance(entry, dict) and entry.get("availability") == "unavailable"
    }
    codes = {s.get("reason") for s in missing} | value_reasons
    complete = (
        not skipped and all(s.get("reason") == "unsupported" for s in missing) and not value_reasons
    )
    document["collection"] = {
        "status": "complete" if complete else "partial",
        "read": len(available),
        "skipped": len(skipped),
        "unavailable": len(missing) - len(skipped),
        "not_applicable": sum(s["availability"] == "not_applicable" for s in surfaces),
        "unexpected_reasons": sorted(code for code in codes if code in UNEXPECTED),
    }


def rehash(document: dict) -> dict:
    return canonical.with_report_id(document)


def finish(document: dict) -> dict:
    """Recount the collection block and recompute the report ID."""
    retally(document)
    return rehash(document)


def elevate(
    document: dict,
    record: dict,
    *,
    count: tuple[str, str] | None,
    power: tuple[str, str] | None,
    p1_failed: int | None = None,
) -> None:
    """Give the document another elevation record, with its surfaces and command records.

    ``count`` and ``power`` are the (reason, detail) each elevated surface must carry, or
    None to keep the fixture's available surface; each case states them by hand from the
    outcome tables. The command records follow the record by the rules in Decision 8.
    """
    for key, outcome in (("memory_error_ledger", count), ("power_and_thermal_samples", power)):
        if outcome is not None:
            unavailable(document, key, *outcome)
    record = copy.deepcopy(record)  # the tables share their records between cases
    document["elevation"] = record
    by_id = {r["id"]: r for r in document["commands"]}
    noninteractive = record["mode"] == "noninteractive"
    suffix = "n" if noninteractive else ""
    checks = record["checks"]
    endings = (record["count"]["ending"], record["power"]["ending"])
    cleanups = (record["count"]["cleanup"], record["power"]["cleanup"])
    records = [by_id[cid] for cid in USER_IDS]

    def add(command_id: str, failed: bool, runs: int = 1) -> None:
        base = by_id.get(command_id.rstrip("n"), {"duration_ms": 25})
        records.append(
            {
                "id": command_id,
                "runs": runs,
                "failed_runs": int(failed),
                "duration_ms": base["duration_ms"],
            }
        )

    if checks["sandbox_probe"] != "not_run":
        add("X1", checks["sandbox_probe"] == "failed")
    if checks["listing"] != "not_run":
        if checks["listing"] == "failed":
            add("P1", True)
        else:
            failed = 1 if "listing_failed" in cleanups else 0
            add("P1", False, runs=by_id["P1"]["runs"])
            records[-1]["failed_runs"] = failed if p1_failed is None else p1_failed
    if record["prepare"] != "not_run":
        add("S1", record["prepare"] == "failed")
    if record["authenticate"] != "not_run":
        add("S2" + suffix, record["authenticate"] != "ok")
    if endings[0] != "not_run":
        add("S3" + suffix, endings[0] not in ("parsed", "unparsed"))
    if endings[1] != "not_run":
        add("S4" + suffix, endings[1] not in ("parsed", "unparsed"))
    if record["prepare"] != "not_run":
        add("S5", record["cleared"] == "failed")
    records.sort(key=lambda r: ORDER.index(r["id"]))
    document["commands"] = records


def record(**changes: object) -> dict:
    """An elevation record: the fixtures' granted run, with the named fields changed."""
    base: dict = {
        "consent": "yes",
        "skip_cause": None,
        "mode": "interactive",
        "checks": {"service_account": "present", "sandbox_probe": "ok", "listing": "ok"},
        "prepare": "ok",
        "authenticate": "ok",
        "count": {"ending": "parsed", "cleanup": "verified"},
        "power": {"ending": "parsed", "cleanup": "verified"},
        "cleared": "cleared",
        "clear_error": None,
    }
    for name, value in changes.items():
        if name in ("service_account", "sandbox_probe", "listing"):
            base["checks"][name] = value
        elif name in ("count", "power"):
            ending, cleanup = value  # type: ignore[misc]
            base[name] = {"ending": ending, "cleanup": cleanup}
        else:
            base[name] = value
    return base


NOT_RUN = ("not_run", "not_applicable")
UNSAFE_STOP = ("tool_error", "skipped_after_unsafe_stop")


def declined_record(consent: str = "no", skip_cause: str | None = None) -> dict:
    return record(
        consent=consent,
        skip_cause=skip_cause,
        mode="none",
        service_account="not_run",
        sandbox_probe="not_run",
        listing="not_run",
        prepare="not_run",
        authenticate="not_run",
        count=NOT_RUN,
        power=NOT_RUN,
        cleared="not_attempted",
    )


def history(name: str, elevation: dict, count, power, **options) -> dict:
    """A fixture with another elevation history, recounted and rehashed."""
    document = load(name)
    elevate(document, elevation, count=count, power=power, **options)
    return finish(document)


def before_payloads(**changes) -> dict:
    """A record stopped before any payload ran: no endings, cleared once prepared."""
    base = {"count": NOT_RUN, "power": NOT_RUN}
    base.update(changes)
    return record(**base)


# (record, count surface, power surface); None keeps the fixture's available surface.
LEGAL = {
    "declined at the question": (
        declined_record("no"),
        ("declined", "not_attempted"),
        ("declined", "not_attempted"),
    ),
    "--no-root": (
        declined_record("skipped", "no_root_flag"),
        ("declined", "not_attempted"),
        ("declined", "not_attempted"),
    ),
    "not an administrator": (
        declined_record("skipped", "not_admin"),
        ("no_admin", "not_attempted"),
        ("no_admin", "not_attempted"),
    ),
    "no terminal": (
        declined_record("skipped", "no_terminal"),
        ("no_terminal", "not_attempted"),
        ("no_terminal", "not_attempted"),
    ),
    "no service account": (
        record(service_account="missing", count=NOT_RUN),
        ("unsupported", "service_account_missing"),
        None,
    ),
    "the account lookup failed": (
        record(service_account="error", count=NOT_RUN),
        ("tool_error", "service_account_error"),
        None,
    ),
    "the sandbox probe failed": (
        before_payloads(
            sandbox_probe="failed",
            listing="not_run",
            prepare="not_run",
            authenticate="not_run",
            cleared="not_attempted",
        ),
        ("unsupported", "sandbox_probe_failed"),
        ("unsupported", "sandbox_probe_failed"),
    ),
    "the listing failed": (
        before_payloads(
            listing="failed", prepare="not_run", authenticate="not_run", cleared="not_attempted"
        ),
        ("tool_error", "listing_unavailable"),
        ("tool_error", "listing_unavailable"),
    ),
    "sudo -k failed": (
        before_payloads(prepare="failed", authenticate="not_run"),
        ("tool_error", "prepare_failed"),
        ("tool_error", "prepare_failed"),
    ),
    "an account-state message at S2": (
        before_payloads(authenticate="blocked"),
        ("not_granted", "account_blocked"),
        ("not_granted", "account_blocked"),
    ),
    "a policy refusal at S2": (
        before_payloads(authenticate="refused"),
        ("not_granted", "policy_refusal"),
        ("not_granted", "policy_refusal"),
    ),
    "authentication denied at S2": (
        before_payloads(authenticate="denied"),
        ("not_granted", "auth_failed"),
        ("not_granted", "auth_failed"),
    ),
    "an unexplained sudo error at S2": (
        before_payloads(authenticate="error"),
        ("tool_error", "sudo_error"),
        ("tool_error", "sudo_error"),
    ),
    # The count's endings, with the power sample by the skip rule.
    "count: could not start sudo": (
        record(count=("spawn_failed", "verified")),
        ("tool_error", "spawn_failed"),
        None,
    ),
    "count: unparsed": (
        record(count=("unparsed", "verified")),
        ("source_changed", "parse_failed"),
        None,
    ),
    "count: a SQLite error": (
        record(count=("payload_error", "verified")),
        ("tool_error", "payload_failed"),
        None,
    ),
    "count: refused by policy": (
        record(count=("policy_refusal", "verified")),
        ("not_granted", "policy_refusal"),
        None,
    ),
    "count: account blocked": (
        record(count=("account_blocked", "verified"), power=NOT_RUN),
        ("not_granted", "account_blocked"),
        ("not_granted", "account_blocked"),
    ),
    "count: authentication failed": (
        record(count=("auth_failed", "verified"), power=NOT_RUN),
        ("not_granted", "auth_failed"),
        ("not_granted", "auth_failed"),
    ),
    "count: an unexplained sudo error": (
        record(count=("sudo_error", "verified"), power=NOT_RUN),
        ("tool_error", "sudo_error"),
        ("tool_error", "skipped_after_sudo_error"),
    ),
    "count: its runtime deadline": (
        record(count=("runtime_deadline", "verified"), power=NOT_RUN),
        ("timeout", "runtime_deadline"),
        UNSAFE_STOP,
    ),
    "count: the output cap": (
        record(count=("output_cap", "verified"), power=NOT_RUN),
        ("source_changed", "output_cap"),
        UNSAFE_STOP,
    ),
    "count: its launch deadline": (
        record(count=("launch_deadline", "verified"), power=NOT_RUN),
        ("tool_error", "launch_deadline"),
        UNSAFE_STOP,
    ),
    "count: a tracking failure": (
        record(count=("tracking_failed", "verified"), power=NOT_RUN),
        ("tool_error", "tracking_failed"),
        UNSAFE_STOP,
    ),
    "count: parsed, then a survivor": (
        record(count=("parsed", "survivor"), power=NOT_RUN),
        None,
        UNSAFE_STOP,
    ),
    "count: parsed, then the listing failed": (
        record(count=("parsed", "listing_failed"), power=NOT_RUN),
        None,
        UNSAFE_STOP,
    ),
    "count: a runtime deadline, then a survivor": (
        record(count=("runtime_deadline", "survivor"), power=NOT_RUN),
        ("timeout", "runtime_deadline"),
        UNSAFE_STOP,
    ),
    "count: authentication failed, then a survivor": (
        record(count=("auth_failed", "survivor"), power=NOT_RUN),
        ("not_granted", "auth_failed"),
        UNSAFE_STOP,
    ),
    "count: could not start, the listing failed": (
        record(count=("spawn_failed", "listing_failed"), power=NOT_RUN),
        ("tool_error", "spawn_failed"),
        UNSAFE_STOP,
    ),
    # The power sample's endings after a clean count.
    "power: could not start sudo": (
        record(power=("spawn_failed", "verified")),
        None,
        ("tool_error", "spawn_failed"),
    ),
    "power: unparsed": (
        record(power=("unparsed", "verified")),
        None,
        ("source_changed", "parse_failed"),
    ),
    "power: a payload error": (
        record(power=("payload_error", "verified")),
        None,
        ("tool_error", "payload_failed"),
    ),
    "power: refused by policy": (
        record(power=("policy_refusal", "verified")),
        None,
        ("not_granted", "policy_refusal"),
    ),
    "power: account blocked": (
        record(power=("account_blocked", "verified")),
        None,
        ("not_granted", "account_blocked"),
    ),
    "power: authentication failed": (
        record(power=("auth_failed", "verified")),
        None,
        ("not_granted", "auth_failed"),
    ),
    "power: an unexplained sudo error": (
        record(power=("sudo_error", "verified")),
        None,
        ("tool_error", "sudo_error"),
    ),
    "power: its runtime deadline, then a survivor": (
        record(power=("runtime_deadline", "survivor")),
        None,
        ("timeout", "runtime_deadline"),
    ),
    "power: the output cap": (
        record(power=("output_cap", "verified")),
        None,
        ("source_changed", "output_cap"),
    ),
    "power: its launch deadline": (
        record(power=("launch_deadline", "verified")),
        None,
        ("tool_error", "launch_deadline"),
    ),
    "power: a tracking failure, then the listing failed": (
        record(power=("tracking_failed", "listing_failed")),
        None,
        ("tool_error", "tracking_failed"),
    ),
    # Modes, the final clear, and the compound histories of Test strategy part 3.
    "--yes without a terminal (-n forms)": (
        record(consent="flag", mode="noninteractive"),
        None,
        None,
    ),
    "--yes with a terminal": (record(consent="flag"), None, None),
    "-n forms, authentication denied": (
        before_payloads(consent="flag", mode="noninteractive", authenticate="denied"),
        ("not_granted", "auth_failed"),
        ("not_granted", "auth_failed"),
    ),
    **{
        f"the final clear failed ({code})": (
            record(cleared="failed", clear_error=code),
            None,
            None,
        )
        for code in ("nonzero_exit", "deadline", "output_cap", "spawn_error", "not_reaped")
    },
    "no account, then the probe failed": (
        before_payloads(
            service_account="missing",
            sandbox_probe="failed",
            listing="not_run",
            prepare="not_run",
            authenticate="not_run",
            cleared="not_attempted",
        ),
        ("unsupported", "service_account_missing"),
        ("unsupported", "sandbox_probe_failed"),
    ),
    "an account error, then the listing failed": (
        before_payloads(
            service_account="error",
            listing="failed",
            prepare="not_run",
            authenticate="not_run",
            cleared="not_attempted",
        ),
        ("tool_error", "service_account_error"),
        ("tool_error", "listing_unavailable"),
    ),
    "no account, then authentication denied": (
        before_payloads(service_account="missing", authenticate="denied"),
        ("unsupported", "service_account_missing"),
        ("not_granted", "auth_failed"),
    ),
}
