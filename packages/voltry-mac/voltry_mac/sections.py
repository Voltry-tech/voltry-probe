"""A report's opening as data, before any layout: the title block's parts, At a glance and
what the report cannot tell you. The detail sections are details.py's.

docs/VOLTRY_MAC_SPEC.md, Decision 6 (the section order, the two labels, the collection
status), Decision 7, "How a no degrades", the field inventory and transcripts 1, 2 and 7.
Pure.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from voltry_mac import phrases


def _shown(report: phrases.Report, key: str, name: str) -> str | None:
    """A text value the identity line can name: read, and not empty."""
    found = report.text(key, name)
    return None if found == phrases.EMPTY else found


def model(report: phrases.Report) -> str:
    """The Mac's name and model identifier, as the identity line and the PDF's running
    header name it: the hardware overview's own names only, since sysctl's model and CPU
    brand are Appendix A's (the field inventory)."""
    name = _shown(report, "hardware_overview", "machine_name") or "Mac"
    identifier = _shown(report, "hardware_overview", "machine_model")
    return f"{name} ({identifier})" if identifier else name


def identity(report: phrases.Report) -> list[str]:
    """The identity line's units: the Mac, its chip, the local date and time, and the
    report ID's first 12 digits, always last. The names part at their spaces (U+0020)
    alone, since the PDF joins the units with one: any other space is a character of its
    own, which the PDF prints or counts (Decision 4)."""
    chip = _shown(report, "hardware_overview", "chip_type")
    who = f"{model(report)}, {chip}." if chip else f"{model(report)}."
    local = phrases.Local.parse(str(report.document["collected_at_local"]))
    report_id = str(report.document["report_id"]).removeprefix("sha256:")[:12]
    units = [
        *(unit for unit in who.split(" ") if unit),
        f"{phrases.date(local.year, local.month, local.day)},",
        f"{local.hour:02d}:{local.minute:02d} ({phrases.offset(local.offset)}).",
        f"ID {report_id}",
    ]
    return units


_SKIPS: Final = ("declined", "not_granted", "no_admin", "no_terminal")
_UNAVAILABLE: Final = "unavailable"
NOT_APPLICABLE: Final = "not_applicable"


def _skipped_because(report: phrases.Report) -> str:
    reasons = {
        str(surface["reason"])
        for surface in report.surfaces.values()
        if surface["availability"] == "unavailable" and surface["reason"] in _SKIPS
    }
    said = []
    for reason in (skip for skip in _SKIPS if skip in reasons):
        if reason == "declined":
            flag = report.elevation["skip_cause"] == "no_root_flag"
            said.append(
                "administrator reads skipped with --no-root"
                if flag
                else "administrator reads declined"
            )
        elif reason == "no_admin" and report.elevation["skip_cause"] != "not_admin":
            # Only the crash reports: the account is an administrator for all Voltry knows.
            said.append("the crash report folder is readable by administrator accounts only")
        else:
            said.append(
                {
                    "not_granted": "administrator access not granted",
                    "no_admin": "this account is not an administrator",
                    "no_terminal": "no terminal to ask for a password",
                }[reason]
            )
    return "; ".join(said)


def collection(report: phrases.Report) -> list[str]:
    counts = report.document["collection"]
    assert isinstance(counts, Mapping)  # noqa: S101 - a validated document
    read, skipped = int(counts["read"]), int(counts["skipped"])
    unavailable, not_applicable = int(counts["unavailable"]), int(counts["not_applicable"])
    units = ["Collection:", f"{counts['status']}.", f"{read} read,"]
    last = not_applicable == 0
    if skipped:
        units.append(f"{skipped} skipped")
        units += f"({_skipped_because(report)}),".split()
    else:
        units.append(f"{skipped} skipped,")
    missing = [
        key for key, surface in report.surfaces.items() if surface["availability"] == "unavailable"
    ]
    only_ecc = unavailable and not skipped and missing == ["ecc_ras_telemetry"]
    end = "." if last else ","
    if only_ecc:
        units += [f"{unavailable} unavailable", "(no", "public", "interface", "on", f"Macs){end}"]
    else:
        units.append(f"{unavailable} unavailable{end}")
    if not last:
        units.append(f"{not_applicable} not applicable.")
    return units


# A payload's own sudo ending after S2 granted access, by the outcome tables.
_STOPPED: Final = {
    "auth_failed": "not granted",
    "account_blocked": "macOS reported a problem with this account",
    "policy_refusal": "refused by sudo's policy",
    "sudo_error": "sudo reported an error",
}
_STEPS: Final = (("count", "the memory-error step"), ("power", "the power and thermal step"))


def elevation(report: phrases.Report) -> str:
    e = report.elevation
    consent, cause = e["consent"], e["skip_cause"]
    if consent == "skipped":
        return {
            "no_root_flag": "not asked; skipped with --no-root.",
            "not_admin": "not asked; this account is not an administrator on this Mac.",
            "no_terminal": "not asked; no terminal to ask for a password.",
        }[str(cause)]
    if consent == "no":
        return "asked; you chose not to allow them."
    asked = "asked" if consent == "yes" else "allowed with --yes"
    checks = e["checks"]
    assert isinstance(checks, Mapping)  # noqa: S101 - a validated document
    if checks["sandbox_probe"] == "failed":
        return f"{asked}; not run: this Mac cannot run them safely (no working sandbox)."
    if checks["listing"] == "failed":
        return f"{asked}; not run: this Mac cannot run them safely (process listing unavailable)."
    parts = [asked]
    if e["prepare"] == "failed":
        parts[0] = f"{asked}; not prepared (sudo -k failed)"
    else:
        parts.append(
            {
                "ok": "granted",
                "denied": "not granted",
                "refused": "refused by sudo's policy for this account",
                "blocked": "macOS reported a problem with this account",
                "error": "sudo reported an error",
            }.get(str(e["authenticate"]), "not used")
        )
        # Granted at S2 is not granted throughout: a payload's own sudo can still refuse.
        for name, step in _STEPS:
            stop = e[name]
            if isinstance(stop, Mapping) and stop["ending"] in _STOPPED:
                parts.append(f"then {_STOPPED[str(stop['ending'])]} at {step}")
    # Past the checks, S1 was attempted, so the final clear was too.
    parts.append("cleared" if e["cleared"] == "cleared" else "not cleared: run sudo -k")
    line = ", ".join(parts)
    stops = [e["count"], e["power"]]
    if any(
        isinstance(stop, Mapping) and stop["cleanup"] in ("survivor", "listing_failed")
        for stop in stops
    ):
        line += "; a stop could not be verified"
    return line + "."


@dataclass(frozen=True)
class Entry:
    """One At a glance line: its topic, its text, and its provenance chip when what it names
    is available, or its availability (unavailable, not_applicable) when it is not."""

    topic: str
    text: str
    chip: str | None = None
    availability: str = "available"


def _storage_entries(report: phrases.Report, stated: set[str]) -> list[Entry]:
    gap = report.gap("smart_health_snapshot")
    if gap is not None:
        stated.add(phrases.gap_name(gap))
        why = phrases.words(report, gap).phrase
        return [Entry("Storage", f"SSD health log not read: {why}.", availability=_UNAVAILABLE)]
    entries = []
    byte = report.number("smart_health_snapshot", "critical_warning_byte")
    if byte:
        said = phrases.warnings(byte, phrases.WARNINGS)
        entries.append(Entry("Storage", f"SSD reports a critical warning: {said}.", "reported"))
    else:
        # An available health log always decodes its endurance: only its temperature and
        # spare fields can fall outside their bounds (Decision 8).
        used = report.number("smart_wear_attributes", "percentage_used")
        assert used is not None  # noqa: S101 - a validated document
        entries.append(
            Entry("Storage", f"SSD reports {used}% of its rated endurance used.", "reported")
        )
    errors = report.number("smart_wear_attributes", "media_errors")
    if errors:
        entries.append(
            Entry(
                "Storage",
                phrases.plural(errors, "media error", "media errors")
                + " on the controller's counter.",
                "measured",
            )
        )
    return entries


def _battery_entries(report: phrases.Report, stated: set[str]) -> list[Entry]:
    if report.state("battery_health") == "not_applicable":
        return []
    # The gauge's permanent-failure flag leads whatever the power report says.
    failure = (
        [Entry("Battery", "The battery reports a permanent failure.", "reported")]
        if report.flag("battery_gauge", "permanent_failure")
        else []
    )
    gap = report.gap("battery_health")
    if gap is not None:
        stated.add(phrases.gap_name(gap))
        why = phrases.words(report, gap).phrase
        return [
            *failure,
            Entry("Battery", f"Power report not read: {why}.", availability=_UNAVAILABLE),
        ]
    condition = report.text("battery_health", "condition")
    capacity = report.number("battery_health", "maximum_capacity_percent")
    said = [
        f"condition {condition}" if condition else "",
        f"capacity {capacity}%" if capacity is not None else "",
    ]
    said = [part for part in said if part]
    if said:
        entries = [Entry("Battery", f"macOS reports {', '.join(said)}.", "reported")]
    else:
        stated.update(("Battery condition", "Maximum capacity"))
        entries = [
            Entry(
                "Battery",
                f"Battery condition and capacity {phrases.NOT_REPORTED}.",
                availability=_UNAVAILABLE,
            )
        ]
    return [*failure, *entries]


def _memory_entry(report: phrases.Report, stated: set[str]) -> list[Entry]:
    gap = report.gap("memory_error_ledger")
    if gap is not None:
        stated.add(phrases.gap_name(gap))
        said = phrases.words(report, gap).phrase
        return [
            Entry("Memory", f"Memory error records not read: {said}.", availability=_UNAVAILABLE)
        ]
    key = "memory_error_ledger"
    rows = {kind: report.number(key, f"{kind}_event_rows") for kind in phrases.KINDS}
    own = {kind: report.number(key, f"{kind}_reported_count") for kind in phrases.KINDS}
    correctable, uncorrectable = rows["correctable"], rows["uncorrectable"]
    if correctable is None or uncorrectable is None:
        return [_counted_entry(rows, own, stated)]
    if correctable == uncorrectable == 0:
        return [
            Entry(
                "Memory",
                "0 records in macOS's private memory error log. That does not prove the "
                "memory never had errors.",
                "measured",
            )
        ]
    return [
        Entry(
            "Memory",
            f"{phrases.thousands(correctable)} correctable and {phrases.thousands(uncorrectable)} "
            f"uncorrectable records in macOS's private memory error log.{_REACH}",
            "measured",
        )
    ]


# A count above zero on the line says the log holds records and how little that proves;
# only a line where every count is zero says what a zero does not prove.
_REACH: Final = " Records exist; how far back the log reaches is unknown."
_ZERO: Final = " Zero does not prove the memory never had errors."


def _counted_entry(
    rows: dict[str, int | None], own: dict[str, int | None], stated: set[str]
) -> Entry:
    """At a glance when a record count is unread: a record count read prints, and the log's
    own count stands in for one that is not, so a count the log gave is never said to be
    missing and a missing one is never a zero (Decision 6)."""
    key = "memory_error_ledger"
    for kind in phrases.KINDS:
        if rows[kind] is None:
            stated.add(phrases.value_name(key, f"{kind}_event_rows"))
            if own[kind] is None:
                stated.add(phrases.value_name(key, f"{kind}_reported_count"))
    read = [kind for kind in phrases.KINDS if rows[kind] is not None]
    if read:
        kind = read[0]
        (other,) = [each for each in phrases.KINDS if each != kind]
        count, stand_in = rows[kind] or 0, own[other]
        records = phrases.plural(count, f"{kind} record", f"{kind} records")
        if stand_in is None:
            said, counted = f"the {other} count was {phrases.NOT_REPORTED}", [count]
        else:
            said = (
                f"the {other} records were {phrases.NOT_REPORTED}, and the log's own {other} "
                f"count is {phrases.thousands(stand_in)}"
            )
            counted = [count, stand_in]
        tail = _REACH if any(counted) else _ZERO
        return Entry(
            "Memory", f"{records} in macOS's private memory error log; {said}.{tail}", "measured"
        )
    counts = [(kind, own[kind]) for kind in phrases.KINDS if own[kind] is not None]
    # An available surface has a value read, so a log with no record count has its own.
    assert counts  # noqa: S101 - a validated document
    listed = phrases.joined([f"{phrases.thousands(count or 0)} {kind}" for kind, count in counts])
    unread = [kind for kind in phrases.KINDS if own[kind] is None]
    what = f"its records, and the {unread[0]} count," if unread else "its records"
    tail = _REACH if any(count for _, count in counts) else _ZERO
    # The counts as the detail row gives them, with no noun after them: "0 uncorrectable
    # errors" is the clean claim zero records never make (Acceptance, "Zero memory error
    # records never produce healthy, no errors or any clean claim"; the pass-3 pre-audit,
    # P3-output-02).
    return Entry(
        "Memory",
        f"macOS's private memory error log counts {listed}; {what} were "
        f"{phrases.NOT_REPORTED}.{tail}",
        "measured",
    )


def states(report: phrases.Report) -> str | None:
    counts = [
        (state, report.number("power_and_thermal_samples", f"thermal_{state}_count"))
        for state in phrases.STATES
    ]
    if any(count is None for _, count in counts):
        return None
    total = report.number("power_and_thermal_samples", "sample_count") or 5
    said = [(state.capitalize(), count) for state, count in counts if count]
    first, *rest = said
    text = f"{first[0]} in {first[1]} of {total} samples"
    return "".join([text, *[f", {state} in {count}" for state, count in rest]])


def _thermal_entry(report: phrases.Report, stated: set[str]) -> list[Entry]:
    counted = states(report)
    if counted is not None:
        return [Entry("Thermal", f"{counted}.", "derived")]
    gap = report.gap("power_and_thermal_samples")
    said = warning_level(report)
    # The field inventory shows macOS's own warning level only when administrator reads
    # were skipped, never in place of a power sample that ran and failed.
    if said is not None and gap is not None and gap.reason in _SKIPS:
        recorded = report.flag("thermal_warning_level", "thermal_warning_recorded")
        if recorded and report.number("thermal_warning_level", "thermal_warning_level") is None:
            stated.add("Thermal warning level")  # the line says the level was not reported
        return [Entry("Thermal", f"macOS thermal warning level now: {said}.", "reported")]
    if gap is None:
        stated.add("Thermal pressure")
        return [
            Entry("Thermal", f"Thermal pressure {phrases.NOT_REPORTED}.", availability=_UNAVAILABLE)
        ]
    stated.add(phrases.gap_name(gap))
    why = phrases.words(report, gap).phrase
    return [Entry("Thermal", f"Thermal pressure not read: {why}.", availability=_UNAVAILABLE)]


def warning_level(report: phrases.Report) -> str | None:
    """macOS's own thermal warning level in the report's words; None when it was not read."""
    recorded = report.flag("thermal_warning_level", "thermal_warning_recorded")
    if recorded is None:
        return None
    if not recorded:
        return "none recorded"
    level = report.number("thermal_warning_level", "thermal_warning_level")
    if level is None:
        return f"recorded, the level itself {phrases.NOT_REPORTED}"
    return phrases.thousands(level)


SECURITY: Final = (
    ("sip_status", "enabled", "SIP", "System Integrity Protection"),
    ("gatekeeper_status", "assessments_enabled", "Gatekeeper", "Gatekeeper"),
    ("filevault_status", "enabled", "FileVault", "FileVault"),
    ("hardware_overview", "activation_lock_enabled", "Activation Lock", "Activation Lock"),
)


def _security_entry(report: phrases.Report, stated: set[str]) -> list[Entry]:
    on, off = [], []
    unread: dict[str, list[str]] = {}
    for key, name, short, full in SECURITY:
        state = report.flag(key, name)
        if state is None:
            gap = report.gap(key, name)
            said = (
                phrases.Words("", phrases.NOT_REPORTED)
                if gap is None
                else phrases.words(report, gap)
            )
            # "not read: <why>", or for a value macOS left out, "not reported by macOS".
            why = f"not read: {said.phrase}" if said.lead else said.phrase
            unread.setdefault(why, []).append(full)
            stated.add(full)
        elif state:
            on.append(short)
        else:
            off.append(full)
    reasons = [f"{phrases.joined(names)} {why}" for why, names in unread.items()]
    if not on and not off:
        return [Entry("Security", f"{'; '.join(reasons)}.", availability=_UNAVAILABLE)]
    text = (
        f"{phrases.joined(off)} {'is' if len(off) == 1 else 'are'} off"
        if off
        else f"{phrases.joined(on)} on"
    )
    return [Entry("Security", f"{'; '.join([text, *reasons])}.", "reported")]


def glance(report: phrases.Report) -> list[Entry]:
    stated: set[str] = set()
    entries = []
    if report.flag("virtualization_state", "vmm_present"):
        entries.append(
            Entry(
                "Machine",
                "This is a virtual machine. Hardware readings describe the virtual machine, not "
                "a physical Mac.",
                "measured",
            )
        )
    entries += _storage_entries(report, stated)
    entries += _battery_entries(report, stated)
    entries += _memory_entry(report, stated)
    entries += _thermal_entry(report, stated)
    entries += _security_entry(report, stated)
    if report.state("battery_health") == "not_applicable":
        entries.append(
            Entry(
                "Battery", "Not applicable: this Mac has no battery.", availability=NOT_APPLICABLE
            )
        )
    listed = _not_read(report, stated)
    if listed:
        entries.append(Entry("Not read", listed, availability=_UNAVAILABLE))
    return entries


def _not_read(report: phrases.Report, stated: set[str]) -> str:
    """Every gap no topic states, once, in registry order; the parts of one row that share
    a reason are named together: "Charge now (charge level and fully charged): ..."."""
    said: dict[tuple[str, str | None], tuple[str, list[str]]] = {}
    for gap in report.gaps():
        name = phrases.gap_name(gap)
        if name in stated:
            continue
        phrase = phrases.listed(report, gap).split(": ", 1)[1]
        label, _, part = name.partition(" (")
        if not part:
            said.setdefault((name, None), (phrase, []))  # a name is said once
            continue
        said.setdefault((label, phrase), (phrase, []))[1].append(part[:-1])
    return " ".join(
        f"{label} ({phrases.joined(parts)}): {phrase}" if parts else f"{label}: {phrase}"
        for (label, _), (phrase, parts) in said.items()
    )


def limits(report: phrases.Report) -> list[str]:
    bullets = []
    warning = report.number("smart_health_snapshot", "critical_warning_byte")
    if warning or report.plain("nvme_devices", "smart_status") == "Failing":
        bullets.append(
            "Why the SSD reports a warning, or whether it will fail. It shows what the "
            "controller reports now."
        )
    # Any count the log gave, its records' or its own, chooses the memory bullet.
    counts = [
        report.number("memory_error_ledger", f"{kind}_{column}")
        for kind in phrases.KINDS
        for column in ("event_rows", "reported_count")
    ]
    if any(counts):
        bullets.append(
            "Whether the memory errors are ongoing. The log holds records, not a rate, and its "
            "retention is unknown."
        )
    else:
        bullets.append(
            "Whether the memory has ever had errors. Apple offers no public memory error "
            "counter, and its private log has unknown retention."
        )
    bullets += [
        "Its complete prior use. Controller counters give limited device-reported history "
        "(power-on hours, data written); nothing here shows how it was used, or how long it "
        "will last.",
        "Repair history. System Settings, General, About, Parts and Service shows Apple's own "
        "view.",
        "Value or price. Voltry does not assess either.",
    ]
    return bullets


def validated(report: phrases.Report) -> str:
    """Whether this configuration is on the validated list, in Decision 7's words."""
    platform = report.document["platform"]
    assert isinstance(platform, Mapping)  # noqa: S101 - a validated document
    if platform["validated"]:
        return "Validated configuration: yes."
    return (
        "Validated configuration: no. This configuration has not been validated by Voltry yet; "
        "more items than usual may be unavailable."
    )
