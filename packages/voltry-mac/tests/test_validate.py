"""render's validator: the schema, the registry and the report's own relations.

docs/VOLTRY_MAC_SPEC.md, Decision 8 ("JSON schema, normative", "Surface registry,
normative") and Test strategy part 3 ("render validation", "Registry relations, value
reasons and storage", "Complete fixtures"). Each case starts from a complete fixture,
breaks exactly one rule, keeps everything else consistent, and expects ``validate`` to
refuse the document, naming the field path in ASCII and never the value. The elevation
record's state machine and its command records are in test_validate_elevation.py.
"""

from __future__ import annotations

import copy
import json
import random
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal

import pytest
import voltry_mac_test_reports as r

from voltry_mac import canonical, numbers, registry
from voltry_mac import validate as v
from voltry_mac.canonical import Invalid

SI = {surface.key: index for index, surface in enumerate(registry.SURFACES)}
CI = {
    cid: index for index, cid in enumerate([*r.USER_IDS, "X1", "P1", "S1", "S2", "S3", "S4", "S5"])
}
_PART = re.compile(r"\[(\d+)\]|\.?([A-Za-z_][A-Za-z0-9_]*)")


def sv(key: str, name: str | None = None, field: str | None = None) -> str:
    """The path of a surface, one of its values, or a field of that value."""
    path = f"surfaces[{SI[key]}]"
    if name is not None:
        path += f".values.{name}"
        if field is not None:
            path += f".{field}"
    elif field is not None:
        path += f".{field}"
    return path


def _parts(path: str) -> list[str | int]:
    return [int(index) if index else name for index, name in _PART.findall(path)]


def _parent(document: dict, path: str) -> tuple[object, str | int]:
    *head, last = _parts(path)
    node: object = document
    for part in head:
        node = node[part]  # type: ignore[index]
    return node, last


Edit = Callable[[dict], None]


def put(path: str, value: object) -> Edit:
    def edit(document: dict) -> None:
        node, last = _parent(document, path)
        node[last] = copy.deepcopy(value)  # type: ignore[index]

    return edit


def drop(path: str) -> Edit:
    def edit(document: dict) -> None:
        node, last = _parent(document, path)
        del node[last]  # type: ignore[union-attr, arg-type]

    return edit


def both(*edits: Edit) -> Edit:
    def edit(document: dict) -> None:
        for one in edits:
            one(document)

    return edit


def av(value: object, provenance: str) -> dict:
    return {"availability": "available", "value": value, "provenance": provenance}


def un(reason: str) -> dict:
    return {"availability": "unavailable", "reason": reason}


def unavailable(key: str, reason: str) -> Edit:
    return lambda document: r.unavailable(document, key, reason)


def value_unavailable(key: str, name: str, reason: str) -> Edit:
    return lambda document: r.value_unavailable(document, key, name, reason)


def fail(command_id: str) -> Edit:
    return lambda document: r.fail(document, command_id)


def swap(path: str, first: int, second: int) -> Edit:
    def edit(document: dict) -> None:
        node, last = _parent(document, path)
        items = node[last]  # type: ignore[index]
        items[first], items[second] = items[second], items[first]

    return edit


@dataclass(frozen=True)
class Case:
    edit: Edit
    path: str
    fixture: str = "m5-laptop"
    # "finish" recounts the collection block and recomputes the ID; "rehash" only
    # recomputes the ID; "raw" leaves the document as edited.
    mode: str = "finish"
    # The refusal's message. Several rules can name one path, so the path alone does not
    # show which rule fired.
    says: str = ""


def _apply(case: Case) -> dict:
    document = r.load(case.fixture)
    case.edit(document)
    if case.mode == "finish":
        return r.finish(document)
    if case.mode == "rehash":
        return r.rehash(document)
    return document


def _refused(document: dict) -> Invalid:
    with pytest.raises(Invalid) as problem:
        v.validate(document)
    return problem.value


# --- the complete fixtures -------------------------------------------------------------------


@pytest.mark.parametrize("name", r.NAMES)
def test_the_complete_fixtures_validate(name):
    v.validate(r.load(name))


@pytest.mark.parametrize("name", r.NAMES)
def test_each_fixture_holds_27_user_records_and_passes_the_save_gate(name):
    document = r.load(name)
    user = [c for c in document["commands"] if c["id"] in r.USER_IDS]
    assert [c["id"] for c in user] == r.USER_IDS and all(c["runs"] == 1 for c in user)
    assert document["collection"]["read"] >= 8


def test_the_concerning_fixture_is_the_decision_8_example():
    document = r.load("concerning-desktop")
    assert document["collection"] == {
        "status": "partial",
        "read": 19,
        "skipped": 0,
        "unavailable": 2,
        "not_applicable": 2,
        "unexpected_reasons": ["source_changed"],
    }
    power = r.values(document, "power_and_thermal_samples")
    assert power["cpu_power_mw_mean"]["value"] == "21804.6"
    assert power["gpu_power_mw_mean"] == un("source_changed")
    assert r.surface(document, "memory_pressure")["reason"] == "source_changed"
    assert r.command(document, "C2")["duration_ms"] == 127
    assert r.command(document, "P1") == {
        "id": "P1",
        "runs": 38,
        "failed_runs": 0,
        "duration_ms": 412,
    }


def test_the_m5_fixture_carries_the_discovery_logs_means():
    power = r.values(r.load("m5-laptop"), "power_and_thermal_samples")
    means = {
        kind: power[f"{kind}_power_mw_mean"]["value"] for kind in ("cpu", "gpu", "ane", "combined")
    }
    assert means == {"cpu": "1612.28", "gpu": "54.25", "ane": "0.0", "combined": "1666.53"}


def test_key_order_changes_neither_the_form_nor_the_id():
    document = r.load("m5-laptop")

    def reversed_keys(node: object) -> object:
        if isinstance(node, dict):
            return {key: reversed_keys(node[key]) for key in reversed(list(node))}
        if isinstance(node, list):
            return [reversed_keys(item) for item in node]
        return node

    shuffled = reversed_keys(document)
    assert canonical.canonical_json(shuffled) == canonical.canonical_json(document)
    assert canonical.report_id(shuffled) == document["report_id"]
    v.validate(shuffled)


@pytest.mark.parametrize("name", r.NAMES)
def test_read_takes_the_saved_bytes(name):
    data = (r.FIXTURES / f"{name}.json").read_bytes()
    assert v.read(data) == r.load(name)


def test_read_refuses_a_control_character_before_validating():
    data = (r.FIXTURES / "m5-laptop.json").read_bytes().replace(b'"Micron"', b'"Mic\\u0007ron"')
    with pytest.raises(Invalid) as problem:
        v.read(data)
    assert problem.value.path == sv("memory_configuration", "manufacturer", "value")


# --- one rule broken at a time ---------------------------------------------------------------

M = "m5-laptop"
D = "concerning-desktop"
REPORTED = "reported"


def _surfaces_order(document: dict) -> None:
    document["surfaces"][0], document["surfaces"][1] = (
        document["surfaces"][1],
        document["surfaces"][0],
    )


def _garbled_store(document: dict, smart: str = "source_changed") -> None:
    """A store the source garbled: the trunk closes with source_changed."""
    r.value_unavailable(document, "startup_disk", "physical_store", "source_changed")
    r.value_unavailable(document, "startup_disk", "whole_disk", "source_changed")
    for name in ("bsd_name", "device_model", "device_revision", "size_text", "size_bytes"):
        r.value_unavailable(document, "nvme_devices", name, "source_changed")
    for name in ("smart_status", "trim_support"):
        r.value_unavailable(document, "nvme_devices", name, "source_changed")
    r.unavailable(document, "smart_health_snapshot", smart)
    r.unavailable(document, "smart_wear_attributes", smart)


def _two_stores(document: dict) -> None:
    r.set_value(document, "startup_disk", "physical_store_count", 2)
    r.value_unavailable(document, "startup_disk", "physical_store", "unsupported")
    r.value_unavailable(document, "startup_disk", "whole_disk", "unsupported")
    for name in (
        "bsd_name",
        "device_model",
        "device_revision",
        "size_text",
        "size_bytes",
        "smart_status",
        "trim_support",
    ):
        r.value_unavailable(document, "nvme_devices", name, "unsupported")
    r.unavailable(document, "smart_health_snapshot", "unsupported")
    r.unavailable(document, "smart_wear_attributes", "unsupported")


def _below_gate(document: dict) -> None:
    for key in (
        "os_version",
        "firmware_and_boot",
        "nvme_devices",
        "gpu_configuration",
        "memory_configuration",
        "battery_health",
        "battery_gauge",
        "thermal_warning_level",
        "memory_pressure",
        "sip_status",
        "gatekeeper_status",
        "filevault_status",
        "virtualization_state",
        "boot_time",
    ):
        r.unavailable(document, key, "source_changed")
    r.unavailable(document, "panic_report_count", "no_admin")


def _no_identity(document: dict) -> None:
    r.unavailable(document, "hardware_overview", "source_changed")
    r.unavailable(document, "kernel_and_platform", "source_changed")


def _bytes_written_off(document: dict) -> None:
    wear = r.values(document, "smart_wear_attributes")
    wear["bytes_written"]["value"] = str(int(wear["bytes_written"]["value"]) + 512_000)


def _boot_plus_one(document: dict) -> None:
    boot = r.values(document, "boot_time")
    boot["boot_time_utc"]["value"] = "2026-08-28T16:12:10Z"


def _boot_after_collection(document: dict) -> None:
    collected = datetime.strptime(document["collected_at_utc"], "%Y-%m-%dT%H:%M:%SZ")
    boot = r.values(document, "boot_time")
    boot["boot_epoch_seconds"]["value"] = int(collected.replace(tzinfo=UTC).timestamp()) + 100


def _thermal_tally_off(document: dict) -> None:
    power = r.values(document, "power_and_thermal_samples")
    power["thermal_nominal_count"]["value"] = 4
    power["thermal_moderate_count"]["value"] = 1


def _one_level(document: dict) -> None:
    kernel = r.values(document, "kernel_and_platform")
    kernel["perf_level_count"]["value"] = 1
    kernel["perf_level_names"]["value"] = ["Performance"]
    kernel["perf_level_physical_cpus"]["value"] = [10]
    r.fail(document, "C24")
    r.fail(document, "C25")


def _three_levels(document: dict) -> None:
    for name in ("perf_level_count", "perf_level_names", "perf_level_physical_cpus"):
        r.value_unavailable(document, "kernel_and_platform", name, "source_changed")


def _recorded_warning(level: dict | None) -> Edit:
    def edit(document: dict) -> None:
        thermal = r.values(document, "thermal_warning_level")
        thermal["thermal_warning_recorded"]["value"] = True
        if level is not None:
            thermal["thermal_warning_level"] = level

    return edit


def _whole_disk_elsewhere(document: dict) -> None:
    r.set_value(document, "startup_disk", "whole_disk", "disk1")
    r.set_value(document, "nvme_devices", "bsd_name", "disk1")


def _whole_disk_reason_off(document: dict) -> None:
    r.value_unavailable(document, "startup_disk", "physical_store", "source_changed")
    r.value_unavailable(document, "startup_disk", "whole_disk", "unsupported")
    for name in (
        "bsd_name",
        "device_model",
        "device_revision",
        "size_text",
        "size_bytes",
        "smart_status",
        "trim_support",
    ):
        r.value_unavailable(document, "nvme_devices", name, "unsupported")
    r.unavailable(document, "smart_health_snapshot", "unsupported")
    r.unavailable(document, "smart_wear_attributes", "unsupported")


def _one_store_unsupported(document: dict) -> None:
    _two_stores(document)
    r.set_value(document, "startup_disk", "physical_store_count", 1)


def _startup_disk_failed(document: dict) -> None:
    r.fail(document, "C11")
    r.unavailable(document, "startup_disk", "tool_error")
    for name in (
        "bsd_name",
        "device_model",
        "device_revision",
        "size_text",
        "size_bytes",
        "smart_status",
        "trim_support",
    ):
        r.value_unavailable(document, "nvme_devices", name, "tool_error")
    r.unavailable(document, "smart_health_snapshot", "tool_error")
    r.unavailable(document, "smart_wear_attributes", "tool_error")


def _entry_reason_off(document: dict) -> None:
    _garbled_store(document)
    r.value_unavailable(document, "nvme_devices", "device_model", "unsupported")


def _entry_available_without_whole_disk(document: dict) -> None:
    _garbled_store(document)
    entry = r.values(r.load(M), "nvme_devices")
    r.values(document, "nvme_devices").update(entry)


def _smart_available_without_whole_disk(document: dict) -> None:
    _garbled_store(document)
    fresh = r.load(M)
    for key in ("smart_health_snapshot", "smart_wear_attributes"):
        document["surfaces"][SI[key]] = r.surface(fresh, key)


def _no_entry_without_whole_disk(document: dict) -> None:
    _garbled_store(document)
    r.unavailable(document, "nvme_devices", "source_absent")


W = "smart_wear_attributes"
H = "smart_health_snapshot"
P = "power_and_thermal_samples"
SMART_BOUNDS = (
    "only the temperature and spare fields can fail their bounds on an available SMART surface"
)
COMPUTED = "a computed value is unavailable when an input is"
BELOW_GATE = (
    "below the save gate: at least 8 surfaces must be available, including "
    "hardware_overview or kernel_and_platform"
)


def _lost(key: str, *names: str) -> Edit:
    return both(*(value_unavailable(key, name, "source_changed") for name in names))


def _bytes_read_off(document: dict) -> None:
    wear = r.values(document, W)
    wear["bytes_read"]["value"] = str(int(wear["bytes_read"]["value"]) + 512_000)


def _eight_read(document: dict) -> None:
    """The save gate's edge: the gate's own list less the boot time, so eight surfaces read."""
    _below_gate(document)
    fresh = r.load(M)
    document["surfaces"][SI["boot_time"]] = r.surface(fresh, "boot_time")


CASES: dict[str, Case] = {
    # The top level and the metadata.
    "an unknown top-level field": Case(put("extra", 1), "extra", says="an unknown field"),
    "a missing top-level field": Case(
        drop("platform"), "platform", says="a required field is missing"
    ),
    "another schema": Case(
        put("schema", "voltry-mac-report/1"), "schema", says="must be voltry-mac-report/0"
    ),
    "no evidence-bundle disclaimer": Case(
        put("not_an_evidence_bundle", False), "not_an_evidence_bundle", says="must be true"
    ),
    "another tool": Case(put("tool.name", "voltry"), "tool.name", says="must be voltry-mac"),
    "a version that is not PEP 440": Case(
        put("tool.version", "v0.1.0"),
        "tool.version",
        says="must be a PEP 440 version of at most 32 characters",
    ),
    "a version over 32 characters": Case(
        put("tool.version", "0.1.0.dev" + "1" * 24),
        "tool.version",
        says="must be a PEP 440 version of at most 32 characters",
    ),
    "a renderer version of five digits": Case(
        put("tool.renderer_version", "12345"), "tool.renderer_version", says="must be 1 to 4 digits"
    ),
    "a renderer version as a number": Case(
        put("tool.renderer_version", 1), "tool.renderer_version", says="must be 1 to 4 digits"
    ),
    "a Python version without its micro": Case(
        put("tool.python", "3.12"), "tool.python", says="must be a Python version such as 3.12.11"
    ),
    "another architecture": Case(
        put("tool.architecture", "arm64e"), "tool.architecture", says="must be one of arm64, x86_64"
    ),
    "Rosetta as text": Case(
        put("tool.rosetta", "no"), "tool.rosetta", says="must be true or false"
    ),
    "an unknown tool field": Case(put("tool.extra", 1), "tool.extra", says="an unknown field"),
    "a date that does not exist": Case(
        put("collected_at_utc", "2026-02-30T21:05:31Z"),
        "collected_at_utc",
        says="not a real calendar instant",
    ),
    "a leap second": Case(
        put("collected_at_utc", "2026-09-23T23:59:60Z"),
        "collected_at_utc",
        says="not a real calendar instant",
    ),
    "a time outside the grammar": Case(
        put("collected_at_utc", "2026-09-23 21:05:31Z"),
        "collected_at_utc",
        says="must be a UTC time in the form YYYY-MM-DDTHH:MM:SSZ",
    ),
    "a local time for another instant": Case(
        put("collected_at_local", "2026-09-23T14:05:31-06:00"),
        "collected_at_local",
        says="must denote the same instant as collected_at_utc",
    ),
    "a local offset of 24 hours": Case(
        put("collected_at_local", "2026-09-24T21:05:31+24:00"),
        "collected_at_local",
        says="not a real UTC offset",
    ),
    "a time zone with a space": Case(
        put("time_zone", "America/Los Angeles"),
        "time_zone",
        says="must be an IANA identifier or unknown",
    ),
    "a time zone over 64 characters": Case(
        put("time_zone", "A" * 65), "time_zone", says="must be an IANA identifier or unknown"
    ),
    "a time zone that is a path (change record 6)": Case(
        put("time_zone", "/Users/CANARY"), "time_zone", says="must be an IANA identifier or unknown"
    ),
    "a time zone that is a parent step": Case(
        put("time_zone", ".."), "time_zone", says="must be an IANA identifier or unknown"
    ),
    "a time zone that is a current step": Case(
        put("time_zone", "."), "time_zone", says="must be an IANA identifier or unknown"
    ),
    "a time zone with a current step": Case(
        put("time_zone", "./x"), "time_zone", says="must be an IANA identifier or unknown"
    ),
    "a time zone with a parent step inside": Case(
        put("time_zone", "a/../b"), "time_zone", says="must be an IANA identifier or unknown"
    ),
    "a time zone with an empty step": Case(
        put("time_zone", "a//b"), "time_zone", says="must be an IANA identifier or unknown"
    ),
    "a time zone ending in a slash": Case(
        put("time_zone", "Europe/"), "time_zone", says="must be an IANA identifier or unknown"
    ),
    "a time zone that is a slash": Case(
        put("time_zone", "/"), "time_zone", says="must be an IANA identifier or unknown"
    ),
    "validated as text": Case(
        put("platform.validated", "yes"), "platform.validated", says="must be true or false"
    ),
    "an unknown platform field": Case(
        put("platform.chip", "M5"), "platform.chip", says="an unknown field"
    ),
    "another consent": Case(
        put("elevation.consent", "maybe"),
        "elevation.consent",
        says="must be one of yes, no, flag, skipped",
    ),
    "free text in clear_error": Case(
        put("elevation.clear_error", "sudo: unable to clear"),
        "elevation.clear_error",
        says="must be one of nonzero_exit, deadline, output_cap, spawn_error, not_reaped",
    ),
    "another ending": Case(
        put("elevation.count.ending", "crashed"),
        "elevation.count.ending",
        says=(
            "must be one of not_run, spawn_failed, parsed, unparsed, payload_error, "
            "policy_refusal, account_blocked, auth_failed, sudo_error, runtime_deadline, "
            "output_cap, launch_deadline, tracking_failed"
        ),
    ),
    "another cleanup": Case(
        put("elevation.power.cleanup", "gone"),
        "elevation.power.cleanup",
        says="must be one of verified, survivor, listing_failed, not_applicable",
    ),
    "another listing result": Case(
        put("elevation.checks.listing", "maybe"),
        "elevation.checks.listing",
        says="must be one of ok, failed, not_run",
    ),
    "an unknown elevation field": Case(
        put("elevation.extra", 1), "elevation.extra", says="an unknown field"
    ),
    "an unknown checks field": Case(
        put("elevation.checks.extra", "ok"), "elevation.checks.extra", says="an unknown field"
    ),
    "a status outside the two": Case(
        put("collection.status", "done"),
        "collection.status",
        mode="rehash",
        says="must be one of complete, partial",
    ),
    "a negative count": Case(
        put("collection.read", -1), "collection.read", mode="rehash", says="must be from 0 to 23"
    ),
    "counts that do not sum to 23": Case(
        put("collection.read", 21),
        "collection",
        mode="rehash",
        says="the four counts must sum to 23",
    ),
    "unexpected reasons out of order": Case(
        put("collection.unexpected_reasons", ["timeout", "source_changed"]),
        "collection.unexpected_reasons",
        D,
        "rehash",
        says="must hold distinct reason codes in ascending order",
    ),
    "a repeated unexpected reason": Case(
        put("collection.unexpected_reasons", ["source_changed", "source_changed"]),
        "collection.unexpected_reasons",
        D,
        "rehash",
        says="must hold distinct reason codes in ascending order",
    ),
    "an unknown reason code": Case(
        put("collection.unexpected_reasons", ["broken"]),
        "collection.unexpected_reasons[0]",
        D,
        "rehash",
        says=(
            "must be one of declined, not_granted, no_admin, no_terminal, unsupported, "
            "source_absent, source_changed, timeout, tool_error"
        ),
    ),
    "another paper": Case(
        put("render.paper", "legal"), "render.paper", says="must be one of letter, a4"
    ),
    "22 surfaces": Case(
        drop("surfaces[22]"),
        "surfaces",
        mode="rehash",
        says="must be an array of the 23 registry surfaces, in order",
    ),
    "a report ID outside its grammar": Case(
        put("report_id", "sha256:XYZ"),
        "report_id",
        mode="raw",
        says="must be sha256: and 64 lowercase hex digits",
    ),
    "a report ID that does not recompute": Case(
        put(sv("memory_pressure", "free_percent", "value"), 39),
        "report_id",
        mode="raw",
        says="the report ID does not recompute from this document",
    ),
    "a local time outside the grammar": Case(
        put("collected_at_local", "2026-09-23 14:05:31-07:00"),
        "collected_at_local",
        says="must be a local time in the form YYYY-MM-DDTHH:MM:SS+HH:MM",
    ),
    "a local date that does not exist": Case(
        put("collected_at_local", "2026-02-30T14:05:31-07:00"),
        "collected_at_local",
        says="not a real calendar instant",
    ),
    "unexpected reasons that are not an array": Case(
        put("collection.unexpected_reasons", "source_changed"),
        "collection.unexpected_reasons",
        D,
        "rehash",
        says="must be an array of at most 9 reason codes",
    ),
    "ten unexpected reasons": Case(
        put("collection.unexpected_reasons", ["source_changed"] * 10),
        "collection.unexpected_reasons",
        D,
        "rehash",
        says="must be an array of at most 9 reason codes",
    ),
    # The command records' shapes.
    "no record for a user command": Case(
        drop("commands[0]"), "commands", says="has no record for C1"
    ),
    "fewer than 27 records": Case(
        lambda d: d["commands"].__delitem__(slice(0, 8)),
        "commands",
        says="must be an array of 27 to 34 command records",
    ),
    "a duplicate command ID": Case(
        lambda d: d["commands"].__setitem__(1, copy.deepcopy(d["commands"][0])),
        "commands[1].id",
        says="a second record for one ID",
    ),
    "an O1 record": Case(
        put(f"commands[{CI['S1']}]", {"id": "O1", "runs": 1, "failed_runs": 0, "duration_ms": 30}),
        f"commands[{CI['S1']}].id",
        says="O1 runs after the files are published and never has a record",
    ),
    "an ID not on the list": Case(
        put("commands[0].id", "C10"), "commands[0].id", says="not an allow-list ID"
    ),
    "an ID outside the grammar": Case(
        put("commands[0].id", "Z1"), "commands[0].id", says="not an allow-list ID"
    ),
    "a user command run twice": Case(
        put("commands[0].runs", 2), "commands[0].runs", says="must be from 1 to 1"
    ),
    "4001 listings": Case(
        put(f"commands[{CI['P1']}].runs", 4001),
        f"commands[{CI['P1']}].runs",
        says="must be from 1 to 4000",
    ),
    "more failures than runs": Case(
        put("commands[0].failed_runs", 2), "commands[0].failed_runs", says="must be from 0 to 1"
    ),
    "a negative duration": Case(
        put("commands[0].duration_ms", -1),
        "commands[0].duration_ms",
        says="must be from 0 to 9223372036854775807",
    ),
    "a duration past 64 bits": Case(
        put("commands[0].duration_ms", 2**63),
        "commands[0].duration_ms",
        says="must be a 64-bit integer",
    ),
    "records out of order": Case(
        swap("commands", 0, 1), "commands[1].id", says="out of allow-list order"
    ),
    "an unknown record field": Case(
        put("commands[0].extra", 1), "commands[0].extra", says="an unknown field"
    ),
    # The surfaces' shapes.
    "a surface out of order": Case(
        _surfaces_order, "surfaces[0].key", says="must be the registry's surface 1, os_version"
    ),
    "a key not in the registry": Case(
        put("surfaces[0].key", "os"),
        "surfaces[0].key",
        says="must be the registry's surface 1, os_version",
    ),
    "another interface": Case(
        put("surfaces[0].interface", "sw_vers"),
        "surfaces[0].interface",
        says="must be the registry's interface for os_version",
    ),
    "another privilege": Case(
        put("surfaces[0].privilege", "admin"),
        "surfaces[0].privilege",
        says="must be the registry's privilege for os_version",
    ),
    "another temporal class": Case(
        put("surfaces[0].temporal_class", "instant"),
        "surfaces[0].temporal_class",
        says="must be the registry's temporal_class for os_version",
    ),
    "an availability outside the three": Case(
        put("surfaces[0].availability", "partial"),
        "surfaces[0].availability",
        mode="rehash",
        says="must be one of available, unavailable, not_applicable",
    ),
    "not applicable on a surface that is no battery": Case(
        both(
            put(sv("memory_pressure", field="availability"), "not_applicable"),
            put(sv("memory_pressure", field="values"), {}),
        ),
        sv("memory_pressure", field="availability"),
        says="only the two battery surfaces can be not applicable",
    ),
    "reason null on an available surface": Case(
        put(sv("memory_pressure", field="reason"), None),
        sv("memory_pressure", field="reason"),
        says="present only on an unavailable surface",
    ),
    "an unavailable surface without a reason": Case(
        drop(sv("memory_pressure", field="reason")),
        sv("memory_pressure", field="reason"),
        D,
        says="a required field is missing",
    ),
    "a detail on a surface that is not elevated": Case(
        put(sv("memory_pressure", field="detail"), "parse_failed"),
        sv("memory_pressure", field="detail"),
        D,
        says="present only on an unavailable elevated surface",
    ),
    "a surface reason outside its domain": Case(
        unavailable("memory_pressure", "declined"),
        sv("memory_pressure", field="reason"),
        says="not a reason this surface's availability domain allows",
    ),
    "a surface reason that is an object": Case(
        put(sv("memory_pressure", field="reason"), {}),
        sv("memory_pressure", field="reason"),
        D,
        "rehash",
        says="not a reason this surface's availability domain allows",
    ),
    "a value reason that is an object": Case(
        put(sv("power_and_thermal_samples", "gpu_power_mw_mean", "reason"), {}),
        sv("power_and_thermal_samples", "gpu_power_mw_mean", "reason"),
        D,
        "rehash",
        says="not a reason this value may carry",
    ),
    "values on an unavailable surface": Case(
        put(sv("memory_pressure", field="values"), {"free_percent": av(38, "measured")}),
        sv("memory_pressure", field="values"),
        D,
        says="must be empty unless the surface is available",
    ),
    "an available surface missing a required key": Case(
        drop(sv("os_version", "build_version")),
        sv("os_version", "build_version"),
        says="a required value key is missing",
    ),
    "an unknown value key": Case(
        put(sv("os_version", "kernel"), av("x", REPORTED)),
        sv("os_version", "kernel"),
        says="not a value key of this surface",
    ),
    "the optional level without a recorded warning": Case(
        put(sv("thermal_warning_level", "thermal_warning_level"), av(70, REPORTED)),
        sv("thermal_warning_level", "thermal_warning_level"),
        says="present exactly when a thermal warning is recorded",
    ),
    "a recorded warning without its level": Case(
        _recorded_warning(None),
        sv("thermal_warning_level", "thermal_warning_level"),
        says="present exactly when a thermal warning is recorded",
    ),
    "a value that is not applicable": Case(
        put(sv("memory_pressure", "free_percent"), {"availability": "not_applicable"}),
        sv("memory_pressure", "free_percent", "availability"),
        says="must be available or unavailable; no value is not applicable",
    ),
    "reason null on an available value": Case(
        put(sv("memory_pressure", "free_percent", "reason"), None),
        sv("memory_pressure", "free_percent", "reason"),
        says="present only on an unavailable value",
    ),
    "an unavailable value without a reason": Case(
        put(sv("memory_pressure", "free_percent"), {"availability": "unavailable"}),
        sv("memory_pressure", "free_percent", "reason"),
        says="a required field is missing",
    ),
    "another provenance": Case(
        put(sv("memory_pressure", "free_percent", "provenance"), REPORTED),
        sv("memory_pressure", "free_percent", "provenance"),
        says="must be measured, as the registry assigns",
    ),
    "an integer as text": Case(
        put(sv("memory_pressure", "free_percent", "value"), "38"),
        sv("memory_pressure", "free_percent", "value"),
        says="must be a 64-bit integer",
    ),
    "a boolean as a number": Case(
        put(sv("sip_status", "enabled", "value"), 1),
        sv("sip_status", "enabled", "value"),
        says="must be true or false",
    ),
    "a float": Case(
        put(sv("memory_pressure", "free_percent", "value"), 38.0),
        sv("memory_pressure", "free_percent", "value"),
        mode="raw",  # a float has no canonical form, so no report ID can be computed
        says="must be a 64-bit integer",
    ),
    "a negative panic count": Case(
        put(sv("panic_report_count", "count", "value"), -1),
        sv("panic_report_count", "count", "value"),
        says="must be from 0 to 100000",
    ),
    "a percentage of 101": Case(
        put(sv("memory_pressure", "free_percent", "value"), 101),
        sv("memory_pressure", "free_percent", "value"),
        says="must be from 0 to 100",
    ),
    "a sample count of 4": Case(
        put(sv("power_and_thermal_samples", "sample_count", "value"), 4),
        sv("power_and_thermal_samples", "sample_count", "value"),
        says="must be from 5 to 5",
    ),
    "a series of 6": Case(
        lambda d: r.values(d, "power_and_thermal_samples")["sample_cpu_power_mw"]["value"].append(
            "566.227"
        ),
        sv("power_and_thermal_samples", "sample_cpu_power_mw", "value"),
        says="must have exactly 5 elements",
    ),
    "a non-canonical decimal": Case(
        put(sv("power_and_thermal_samples", "cpu_power_mw_mean", "value"), "1612.280"),
        sv("power_and_thermal_samples", "cpu_power_mw_mean", "value"),
        says="must be a canonical decimal string",
    ),
    "a decimal as an integer": Case(
        put(sv("power_and_thermal_samples", "cpu_power_mw_mean", "value"), 1612),
        sv("power_and_thermal_samples", "cpu_power_mw_mean", "value"),
        says="must be a canonical decimal string",
    ),
    "an integer past 64 bits": Case(
        put(sv("nvme_devices", "size_bytes", "value"), 2**63),
        sv("nvme_devices", "size_bytes", "value"),
        says="must be a 64-bit integer",
    ),
    "a 128-bit counter with a leading zero": Case(
        put(sv("smart_wear_attributes", "power_on_hours", "value"), "0427"),
        sv("smart_wear_attributes", "power_on_hours", "value"),
        says="must be a digit string no greater than 2^128-1",
    ),
    "a 128-bit counter past 2^128-1": Case(
        put(sv("smart_wear_attributes", "power_on_hours", "value"), str(2**128)),
        sv("smart_wear_attributes", "power_on_hours", "value"),
        says="must be a digit string no greater than 2^128-1",
    ),
    "a byte total past its cap": Case(
        put(
            sv("smart_wear_attributes", "bytes_written", "value"),
            str(numbers.BYTES128_MAX + 1),
        ),
        sv("smart_wear_attributes", "bytes_written", "value"),
        says="must be a digit string no greater than (2^128-1) x 512,000",
    ),
    "a byte total unequal to its units": Case(
        _bytes_written_off,
        sv("smart_wear_attributes", "bytes_written", "value"),
        says="disagrees with data_units_written",
    ),
    "a thermal state outside the five": Case(
        put(sv("power_and_thermal_samples", "sample_thermal_pressure", "value") + "[0]", "Hot"),
        sv("power_and_thermal_samples", "sample_thermal_pressure", "value") + "[0]",
        says="must be one of Nominal, Moderate, Heavy, Trapping, Sleeping",
    ),
    "state counts that disagree with the samples": Case(
        _thermal_tally_off,
        sv("power_and_thermal_samples", "thermal_nominal_count", "value"),
        says="disagrees with the samples",
    ),
    "a string over 256 characters": Case(
        put(sv("hardware_overview", "machine_name", "value"), "x" * 257),
        sv("hardware_overview", "machine_name", "value"),
        says="longer than 256 characters",
    ),
    "a store outside its grammar": Case(
        put(sv("startup_disk", "physical_store", "value"), "disk0"),
        sv("startup_disk", "physical_store", "value"),
        says="not in the form this key takes",
    ),
    "a whole disk outside its grammar": Case(
        put(sv("startup_disk", "whole_disk", "value"), "disk0s2"),
        sv("startup_disk", "whole_disk", "value"),
        says="not in the form this key takes",
    ),
    "a BSD name outside its grammar": Case(
        put(sv("nvme_devices", "bsd_name", "value"), "sda"),
        sv("nvme_devices", "bsd_name", "value"),
        says="not in the form this key takes",
    ),
    "a whole disk that is not its store without the suffix": Case(
        _whole_disk_elsewhere,
        sv("startup_disk", "whole_disk", "value"),
        says="must be physical_store without its final s and digits",
    ),
    "an NVMe entry for another disk": Case(
        put(sv("nvme_devices", "bsd_name", "value"), "disk1"),
        sv("nvme_devices", "bsd_name", "value"),
        says="must be the startup disk's whole-disk name",
    ),
    "a serial ending of three characters": Case(
        put(sv("hardware_overview", "serial_last4", "value"), "K7Q"),
        sv("hardware_overview", "serial_last4", "value"),
        says="must be exactly four characters",
    ),
    "a full serial that does not end with it": Case(
        put(sv("hardware_overview", "serial_number"), av("C02XK1ZQMD6T", REPORTED)),
        sv("hardware_overview", "serial_number", "value"),
        says="the full serial must end with serial_last4",
    ),
    "a value reason outside the value reasons": Case(
        value_unavailable("os_version", "build_version", "declined"),
        sv("os_version", "build_version", "reason"),
        says="not a reason this value may carry",
    ),
    "timeout on a value with no command of its own": Case(
        value_unavailable("os_version", "build_version", "timeout"),
        sv("os_version", "build_version", "reason"),
        says="not a reason this value may carry",
    ),
    "a surface that is not an object": Case(
        put("surfaces[0]", "os_version"), "surfaces[0]", mode="rehash", says="must be an object"
    ),
    "values that are not an object": Case(
        put(sv("os_version", field="values"), []),
        sv("os_version", field="values"),
        mode="rehash",
        says="must be an object",
    ),
    "a value that is not an object": Case(
        put(sv("memory_pressure", "free_percent"), 38),
        sv("memory_pressure", "free_percent"),
        says="must be an object",
    ),
    "an array value that is not an array": Case(
        put(sv("kernel_and_platform", "perf_level_names", "value"), "Super"),
        sv("kernel_and_platform", "perf_level_names", "value"),
        says="must be an array",
    ),
    "three perf-level names": Case(
        put(sv("kernel_and_platform", "perf_level_names", "value"), ["a", "b", "c"]),
        sv("kernel_and_platform", "perf_level_names", "value"),
        says="must have one or two elements",
    ),
    "a boot epoch as text": Case(
        put(sv("boot_time", "boot_epoch_seconds", "value"), "1787940729"),
        sv("boot_time", "boot_epoch_seconds", "value"),
        says="must be a 64-bit integer",
    ),
    "a string value that is not a string": Case(
        put(sv("os_version", "product_name", "value"), 26),
        sv("os_version", "product_name", "value"),
        says="must be a string",
    ),
    # The registry's relations.
    "a boot date that disagrees": Case(
        _boot_plus_one,
        sv("boot_time", "boot_time_utc", "value"),
        says="disagrees with boot_epoch_seconds",
    ),
    "a day count that disagrees": Case(
        put(sv("boot_time", "days_since_boot", "value"), 27),
        sv("boot_time", "days_since_boot", "value"),
        says="disagrees with the boot and the collection instant",
    ),
    "a boot after the collection": Case(
        _boot_after_collection,
        sv("boot_time", "boot_epoch_seconds", "value"),
        says="must be from 2000-01-01 to the collection instant",
    ),
    "a boot date outside its grammar": Case(
        put(sv("boot_time", "boot_time_utc", "value"), "2026-08-28 15:00:57Z"),
        sv("boot_time", "boot_time_utc", "value"),
        says="must be a UTC time in the form YYYY-MM-DDTHH:MM:SSZ",
    ),
    "a boot before 2000": Case(
        put(sv("boot_time", "boot_epoch_seconds", "value"), 946684799),
        sv("boot_time", "boot_epoch_seconds", "value"),
        says="must be from 2000-01-01 to the collection instant",
    ),
    "a zero warning byte with a warning flag": Case(
        put(sv("smart_health_snapshot", "spare_below_threshold", "value"), True),
        sv("smart_health_snapshot", "spare_below_threshold", "value"),
        says="disagrees with critical_warning_byte",
    ),
    "an unknown bit without its flag": Case(
        put(sv("smart_health_snapshot", "critical_warning_byte", "value"), 32),
        sv("smart_health_snapshot", "unknown_warning_bits", "value"),
        says="disagrees with critical_warning_byte",
    ),
    "a Celsius reading that disagrees": Case(
        put(sv("smart_health_snapshot", "composite_temperature_c", "value"), 34),
        sv("smart_health_snapshot", "composite_temperature_c", "value"),
        says="disagrees with composite_temperature_k",
    ),
    "a battery temperature that disagrees": Case(
        put(sv("battery_gauge", "temperature_c", "value"), "30.5"),
        sv("battery_gauge", "temperature_c", "value"),
        says="disagrees with temperature_centi_c",
    ),
    "a minimum that disagrees": Case(
        put(sv("power_and_thermal_samples", "cpu_power_mw_min", "value"), "566.228"),
        sv("power_and_thermal_samples", "cpu_power_mw_min", "value"),
        says="disagrees with its series",
    ),
    "a maximum that disagrees": Case(
        put(sv("power_and_thermal_samples", "cpu_power_mw_max", "value"), "2675.48"),
        sv("power_and_thermal_samples", "cpu_power_mw_max", "value"),
        says="disagrees with its series",
    ),
    "a mean that disagrees": Case(
        put(sv("power_and_thermal_samples", "cpu_power_mw_mean", "value"), "1612.29"),
        sv("power_and_thermal_samples", "cpu_power_mw_mean", "value"),
        says="disagrees with its series",
    ),
    "perf-level arrays shorter than the count": Case(
        put(sv("kernel_and_platform", "perf_level_names", "value"), ["Super"]),
        sv("kernel_and_platform", "perf_level_names", "value"),
        says="must have perf_level_count elements",
    ),
    # A SMART unit count cannot be missing at all (C28's row 12), so the computed-values
    # rule is shown on the power series and the battery's temperature.
    "a computed value beside an unavailable input": Case(
        value_unavailable("power_and_thermal_samples", "sample_cpu_power_mw", "source_changed"),
        sv("power_and_thermal_samples", "cpu_power_mw_min"),
        says="a computed value is unavailable when an input is",
    ),
    "a computed value missing beside an available input": Case(
        value_unavailable("battery_gauge", "temperature_c", "source_changed"),
        sv("battery_gauge", "temperature_c"),
        says="a computed value is available when its inputs are",
    ),
    "a computed value with another reason than its input": Case(
        _whole_disk_reason_off,
        sv("startup_disk", "whole_disk", "reason"),
        says="must carry the reason of its first unavailable input",
    ),
    "an NVMe entry key with another reason than the whole disk": Case(
        _entry_reason_off,
        sv("nvme_devices", "device_model", "reason"),
        says="must carry the reason of its first unavailable input",
    ),
    "an available surface whose values are all unavailable": Case(
        value_unavailable("memory_pressure", "free_percent", "source_changed"),
        sv("memory_pressure", field="availability"),
        says="an available surface needs at least one available value",
    ),
    "the ECC statement available": Case(
        both(
            put(sv("ecc_ras_telemetry", field="availability"), "available"),
            drop(sv("ecc_ras_telemetry", field="reason")),
        ),
        sv("ecc_ras_telemetry", field="availability"),
        says="an available surface needs at least one available value",
    ),
    "one battery surface not applicable": Case(
        both(
            put(sv("battery_health", field="availability"), "not_applicable"),
            put(sv("battery_health", field="values"), {}),
        ),
        sv("battery_gauge", field="availability"),
        says="the two battery surfaces are not applicable together or not at all",
    ),
    # The storage chain and C28.
    "the SMART surfaces apart": Case(
        unavailable("smart_wear_attributes", "tool_error"),
        sv("smart_wear_attributes", field="availability"),
        says="the two SMART surfaces come from one log and share one availability",
    ),
    "the SMART surfaces with two reasons": Case(
        both(
            unavailable("smart_health_snapshot", "tool_error"),
            unavailable("smart_wear_attributes", "source_absent"),
        ),
        sv("smart_wear_attributes", field="reason"),
        says="the two SMART surfaces come from one log and share one reason",
    ),
    "SMART available while C28 failed": Case(
        fail("C28"),
        f"commands[{CI['C28']}].failed_runs",
        says="C28's table needs no failed run here",
    ),
    "SMART source_absent while C28 failed": Case(
        both(
            unavailable("smart_health_snapshot", "source_absent"),
            unavailable("smart_wear_attributes", "source_absent"),
            fail("C28"),
        ),
        f"commands[{CI['C28']}].failed_runs",
        says="C28's table needs no failed run here",
    ),
    "SMART timeout while C28 did not fail": Case(
        both(
            unavailable("smart_health_snapshot", "timeout"),
            unavailable("smart_wear_attributes", "timeout"),
        ),
        f"commands[{CI['C28']}].failed_runs",
        says="C28's table needs a failed run here",
    ),
    "an unavailable store count beside an available store": Case(
        value_unavailable("startup_disk", "physical_store_count", "source_changed"),
        sv("startup_disk", "physical_store"),
        says="a computed value is unavailable when an input is",
    ),
    "two stores beside an available store": Case(
        put(sv("startup_disk", "physical_store_count", "value"), 2),
        sv("startup_disk", "physical_store"),
        says="a computed value is unavailable when an input is",
    ),
    "SMART available while the whole disk is not": Case(
        _smart_available_without_whole_disk,
        sv("smart_health_snapshot", field="availability"),
        says="the SMART surfaces are unavailable while the whole disk is",
    ),
    "SMART with another reason than the whole disk": Case(
        lambda d: _garbled_store(d, smart="unsupported"),
        sv("smart_health_snapshot", field="reason"),
        says="must carry the whole disk's reason",
    ),
    "an NVMe entry available while the whole disk is not": Case(
        _entry_available_without_whole_disk,
        sv("nvme_devices", "bsd_name"),
        says="a computed value is unavailable when an input is",
    ),
    "no NVMe entry while the whole disk is unavailable": Case(
        _no_entry_without_whole_disk,
        sv("nvme_devices", field="reason"),
        says="not a reason the storage chain gives while C3 ran",
    ),
    "one store marked unsupported": Case(
        _one_store_unsupported,
        sv("startup_disk", "physical_store", "reason"),
        says="with one physical store, a store that did not read is source_changed",
    ),
    "an NVMe entry key marked unsupported with the whole disk known": Case(
        value_unavailable("nvme_devices", "device_model", "unsupported"),
        sv("nvme_devices", "device_model", "reason"),
        says="with the whole disk known, an entry field that did not read is source_changed",
    ),
    "a kernel surface's tool_error with C15 fine": Case(
        unavailable("kernel_and_platform", "tool_error"),
        sv("kernel_and_platform", field="reason"),
        says="its first value's command did not fail",
    ),
    # User commands and the surfaces they feed.
    "a failed command beside its available surface": Case(
        fail("C1"),
        sv("os_version", field="availability"),
        says="C1 failed, so this surface is unavailable",
    ),
    "tool_error on a surface whose command did not fail": Case(
        unavailable("os_version", "tool_error"),
        sv("os_version", field="reason"),
        says="C1 did not fail",
    ),
    "a failed C6 beside a battery that is not applicable": Case(
        fail("C6"),
        sv("battery_health", field="availability"),
        D,
        says="C6 failed, so this surface is unavailable",
    ),
    "a failed C2 with one of its surfaces available": Case(
        both(fail("C2"), unavailable("hardware_overview", "tool_error")),
        sv("firmware_and_boot", field="availability"),
        says="C2 failed, so this surface is unavailable",
    ),
    "a kernel value beside its failed OID": Case(
        fail("C17"),
        sv("kernel_and_platform", "memory_bytes"),
        says="its sysctl call failed, so this value is unavailable",
    ),
    "a kernel value's timeout while its OID ran": Case(
        value_unavailable("kernel_and_platform", "memory_bytes", "timeout"),
        sv("kernel_and_platform", "memory_bytes", "reason"),
        says="its sysctl call did not fail",
    ),
    "perf-level names available while C22 failed": Case(
        fail("C22"),
        sv("kernel_and_platform", "perf_level_names"),
        says="its sysctl call failed, so this value is unavailable",
    ),
    "C24 counts when there are two levels": Case(
        fail("C24"),
        sv("kernel_and_platform", "perf_level_names"),
        says="its sysctl call failed, so this value is unavailable",
    ),
    # The collection block and the save gate.
    "counts that do not match the surfaces": Case(
        both(put("collection.read", 21), put("collection.unavailable", 2)),
        "collection.read",
        mode="rehash",
        says="does not match the surfaces",
    ),
    "a status that does not follow": Case(
        put("collection.status", "partial"),
        "collection.status",
        mode="rehash",
        says="does not follow from the surfaces",
    ),
    "unexpected reasons that do not match": Case(
        put("collection.unexpected_reasons", ["timeout"]),
        "collection.unexpected_reasons",
        mode="rehash",
        says="must be the unexpected reasons present on the surfaces and values",
    ),
    "below the save gate": Case(
        _below_gate,
        "surfaces",
        says=BELOW_GATE,
    ),
    "no identity surface": Case(
        _no_identity,
        "surfaces",
        says=BELOW_GATE,
    ),
    # Found by the #342 review.
    "another schema carrying a field it adds": Case(
        both(put("schema", "voltry-mac-report/1"), put("new_field", 1)),
        "schema",
        says="must be voltry-mac-report/0",
    ),
    "a panic count reason outside its domain": Case(
        unavailable("panic_report_count", "timeout"),
        sv("panic_report_count", field="reason"),
        says="not a reason this surface's availability domain allows",
    ),
    "source_absent on a value whose command read": Case(
        value_unavailable("os_version", "product_name", "source_absent"),
        sv("os_version", "product_name", "reason"),
        says="not a reason this value may carry",
    ),
    "the gauge not applicable beside a battery that reads": Case(
        both(
            put(sv("battery_gauge", field="availability"), "not_applicable"),
            put(sv("battery_gauge", field="values"), {}),
        ),
        sv("battery_gauge", field="availability"),
        says="the two battery surfaces are not applicable together or not at all",
    ),
    "a failed C2 whose two surfaces carry two reasons": Case(
        both(
            fail("C2"),
            unavailable("hardware_overview", "tool_error"),
            unavailable("firmware_and_boot", "timeout"),
        ),
        sv("firmware_and_boot", field="reason"),
        says="C2 failed once, so every surface it feeds carries the same reason",
    ),
    "an SMART counter lost from an available surface": Case(
        _lost(W, "power_cycles"), sv(W, "power_cycles"), says=SMART_BOUNDS
    ),
    "the endurance lost from an available surface": Case(
        _lost(W, "percentage_used"), sv(W, "percentage_used"), says=SMART_BOUNDS
    ),
    "the media errors lost from an available surface": Case(
        _lost(W, "media_errors"), sv(W, "media_errors"), says=SMART_BOUNDS
    ),
    "a unit count lost with its byte total": Case(
        _lost(W, "data_units_read", "bytes_read"), sv(W, "data_units_read"), says=SMART_BOUNDS
    ),
    "the warning byte lost with its flags": Case(
        _lost(
            H,
            "critical_warning_byte",
            "spare_below_threshold",
            "temperature_warning",
            "reliability_degraded",
            "read_only_mode",
            "volatile_backup_failed",
            "unknown_warning_bits",
        ),
        sv(H, "critical_warning_byte"),
        says=SMART_BOUNDS,
    ),
    "a warning flag lost beside its byte": Case(
        _lost(H, "read_only_mode"), sv(H, "read_only_mode"), says=SMART_BOUNDS
    ),
    "a byte total unequal to its read units": Case(
        _bytes_read_off, sv(W, "bytes_read", "value"), says="disagrees with data_units_read"
    ),
    **{
        f"a {kind} {stat} that disagrees": Case(
            put(sv(P, f"{kind}_power_mw_{stat}", "value"), "1.0"),
            sv(P, f"{kind}_power_mw_{stat}", "value"),
            says="disagrees with its series",
        )
        for kind in ("gpu", "ane", "combined")
        for stat in ("min", "max", "mean")
    },
    "perf-level arrays beside an unavailable count": Case(
        _lost("kernel_and_platform", "perf_level_count"),
        sv("kernel_and_platform", "perf_level_names"),
        says=COMPUTED,
    ),
    "a battery temperature beside an unavailable reading": Case(
        _lost("battery_gauge", "temperature_centi_c"),
        sv("battery_gauge", "temperature_c"),
        says=COMPUTED,
    ),
    "a boot date beside an unavailable epoch": Case(
        _lost("boot_time", "boot_epoch_seconds"), sv("boot_time", "boot_time_utc"), says=COMPUTED
    ),
    "a day count beside an unavailable epoch": Case(
        _lost("boot_time", "boot_epoch_seconds", "boot_time_utc"),
        sv("boot_time", "days_since_boot"),
        says=COMPUTED,
    ),
    "a Celsius reading beside an unavailable Kelvin reading": Case(
        _lost(H, "composite_temperature_k"), sv(H, "composite_temperature_c"), says=COMPUTED
    ),
    "thermal counts beside an unavailable series": Case(
        _lost(P, "sample_thermal_pressure"), sv(P, "thermal_nominal_count"), says=COMPUTED
    ),
    "the sample count lost from an available power surface": Case(
        _lost(P, "sample_count"),
        sv(P, "sample_count"),
        says="always 5 while the surface is available",
    ),
    "every series lost from an available power surface": Case(
        _lost(
            P, *(value.name for value in registry.BY_KEY[P].values if value.name != "sample_count")
        ),
        sv(P, "sample_elapsed_ns"),
        says="an available power surface keeps at least one of its samples",
    ),
    "SMART unsupported while C28 failed": Case(
        both(unavailable(H, "unsupported"), unavailable(W, "unsupported"), fail("C28")),
        f"commands[{CI['C28']}].failed_runs",
        says="C28's table needs no failed run here",
    ),
    "SMART source_changed while C28 did not fail": Case(
        both(unavailable(H, "source_changed"), unavailable(W, "source_changed")),
        f"commands[{CI['C28']}].failed_runs",
        says="C28's table needs a failed run here",
    ),
}


@pytest.mark.parametrize("case", list(CASES.values()), ids=list(CASES))
def test_each_rule_is_enforced(case):
    problem = _refused(_apply(case))
    assert problem.path == case.path
    assert str(problem) == (f"{case.path}: {case.says}" if case.path else case.says)
    assert str(problem).isascii()


def test_every_rule_case_names_its_message():
    assert [name for name, case in CASES.items() if not case.says] == []


VALID: dict[str, Case] = {
    "a failed C3 beside available SMART surfaces": Case(
        both(fail("C3"), unavailable("nvme_devices", "tool_error")), ""
    ),
    "a failed C28 beside an available NVMe entry": Case(
        both(
            fail("C28"),
            unavailable("smart_health_snapshot", "timeout"),
            unavailable("smart_wear_attributes", "timeout"),
        ),
        "",
    ),
    "C28 tool_error either way": Case(
        both(
            unavailable("smart_health_snapshot", "tool_error"),
            unavailable("smart_wear_attributes", "tool_error"),
        ),
        "",
    ),
    "a garbled store": Case(_garbled_store, ""),
    "a startup disk that could not be read": Case(_startup_disk_failed, ""),
    "two physical stores": Case(_two_stores, ""),
    "a user command stopped at the output cap": Case(
        both(fail("C9"), unavailable("memory_pressure", "source_changed")), ""
    ),
    "a missing executable": Case(both(fail("C12"), unavailable("sip_status", "source_absent")), ""),
    "a parse failure with the command fine": Case(
        unavailable("gpu_configuration", "source_changed"), ""
    ),
    "a sysctl OID that timed out": Case(
        both(fail("C17"), value_unavailable("kernel_and_platform", "memory_bytes", "timeout")), ""
    ),
    "a missing sysctl for one OID": Case(
        both(fail("C18"), value_unavailable("kernel_and_platform", "cpu_count", "source_absent")),
        "",
    ),
    "a failed C22 with an available count": Case(
        both(
            fail("C22"),
            value_unavailable("kernel_and_platform", "perf_level_names", "tool_error"),
        ),
        "",
    ),
    "one performance level": Case(_one_level, ""),
    "three performance levels": Case(_three_levels, ""),
    "a recorded thermal warning with its level": Case(_recorded_warning(av(70, REPORTED)), ""),
    "the full serial with --show-serial": Case(
        put(sv("hardware_overview", "serial_number"), av("C02XK1ZQK7Q2", REPORTED)), ""
    ),
    "a missing GPU series": Case(
        lambda d: [
            r.value_unavailable(d, "power_and_thermal_samples", name, "source_changed")
            for name in (
                "sample_gpu_power_mw",
                "gpu_power_mw_min",
                "gpu_power_mw_max",
                "gpu_power_mw_mean",
            )
        ]
        and None,
        "",
    ),
    "a missing thermal series": Case(
        lambda d: [
            r.value_unavailable(d, "power_and_thermal_samples", name, "source_changed")
            for name in (
                "sample_thermal_pressure",
                *(f"thermal_{s.lower()}_count" for s in registry.THERMAL_STATES),
            )
        ]
        and None,
        "",
    ),
    "a non-administrator's panic count": Case(unavailable("panic_report_count", "no_admin"), ""),
    "a desktop's batteries": Case(
        both(
            put(sv("battery_health", field="availability"), "not_applicable"),
            put(sv("battery_health", field="values"), {}),
            put(sv("battery_gauge", field="availability"), "not_applicable"),
            put(sv("battery_gauge", field="values"), {}),
        ),
        "",
    ),
    "an unknown time zone": Case(put("time_zone", "unknown"), ""),
    "a time zone of three steps": Case(put("time_zone", "America/Argentina/Buenos_Aires"), ""),
    "a time zone with a sign and digits": Case(put("time_zone", "Etc/GMT+5"), ""),
    "a time zone of 64 characters in steps": Case(
        put("time_zone", "A" * 31 + "/" + "A" * 30 + "/B"), ""
    ),
    "a durations far past every bound": Case(
        lambda d: [record.__setitem__("duration_ms", 2**62) for record in d["commands"]] and None,
        "",
    ),
    "a pre-release Python": Case(put("tool.python", "3.14.0rc1"), ""),
    # Found by the #342 review.
    "the temperature and spare fields outside their bounds": Case(
        _lost(
            H,
            "composite_temperature_k",
            "composite_temperature_c",
            "available_spare_percent",
            "available_spare_threshold_percent",
        ),
        "",
    ),
    "no NVMe entry carries the startup disk's name": Case(
        unavailable("nvme_devices", "source_absent"), ""
    ),
    "two NVMe entries carry the startup disk's name": Case(
        unavailable("nvme_devices", "source_changed"), ""
    ),
    "a failed C2 with one reason on both surfaces": Case(
        both(
            fail("C2"),
            unavailable("hardware_overview", "timeout"),
            unavailable("firmware_and_boot", "timeout"),
        ),
        "",
    ),
    "exactly eight surfaces read": Case(_eight_read, ""),
    "only kernel_and_platform names the Mac": Case(
        unavailable("hardware_overview", "source_changed"), ""
    ),
    "only hardware_overview names the Mac": Case(
        unavailable("kernel_and_platform", "source_changed"), ""
    ),
}


@pytest.mark.parametrize("case", list(VALID.values()), ids=list(VALID))
def test_consistent_variants_validate(case):
    v.validate(_apply(case))


def test_exactly_eight_is_the_gate_and_seven_is_below_it():
    eight = _apply(VALID["exactly eight surfaces read"])
    assert sum(surface["availability"] == "available" for surface in eight["surfaces"]) == 8
    below = _apply(CASES["below the save gate"])
    assert sum(surface["availability"] == "available" for surface in below["surfaces"]) == 7


@pytest.mark.parametrize("name", r.NAMES)
def test_the_fixtures_canonical_bytes_read_and_validate(name):
    # The fixtures are indented for review; --json writes the canonical form, which reads
    # to the same document.
    document = r.load(name)
    assert v.read(canonical.canonical_json(document).encode()) == document


def test_the_m5_fixture_carries_sample_es_own_timings():
    power = r.values(r.load("m5-laptop"), "power_and_thermal_samples")
    assert power["sample_elapsed_ns"]["value"] == [
        1006543000,
        1011719875,
        1008502124,
        1011962250,
        1011879791,
    ]


# --- every range, at each end ----------------------------------------------------------------


def _range_cases() -> list[tuple[str, str, object, str, str]]:
    document = r.load(M)
    cases = []
    for surface in document["surfaces"]:
        if surface["availability"] != "available":
            continue
        for name, entry in surface["values"].items():
            array = "[0]" if isinstance(entry["value"], list) else ""
            if name in registry.INT_RANGES:
                low, high = registry.INT_RANGES[name]
                for bad in (low - 1, high + 1):
                    cases.append(
                        (surface["key"], name, bad, array, f"must be from {low} to {high}")
                    )
            elif name in registry.DEC_RANGES:
                low, high = registry.DEC_RANGES[name]
                for bad in (low - Decimal("0.01"), high + Decimal("0.01")):
                    says = f"must be from {low} to {high}"
                    cases.append((surface["key"], name, numbers.canonical(bad), array, says))
    return cases


RANGE_CASES = _range_cases()


@pytest.mark.parametrize(
    ("key", "name", "bad", "element", "says"),
    RANGE_CASES,
    ids=[f"{key}.{name}={bad}" for key, name, bad, _, _ in RANGE_CASES],
)
def test_every_range_is_enforced_at_both_ends(key, name, bad, element, says):
    # The message too: a relation on the same key would refuse the same path otherwise.
    document = r.load(M)
    entry = r.values(document, key)[name]
    if element:
        entry["value"][0] = bad
    else:
        entry["value"] = bad
    problem = _refused(r.finish(document))
    assert problem.path == sv(key, name, "value") + element
    assert str(problem) == f"{problem.path}: {says}"


def test_the_range_cases_cover_every_ranged_key():
    covered = {name for _, name, _, _, _ in RANGE_CASES}
    assert covered | {"thermal_warning_level"} == set(registry.INT_RANGES) | set(
        registry.DEC_RANGES
    )


@pytest.mark.parametrize("level", [-1, 101])
def test_the_thermal_warning_level_range(level):
    document = r.load(M)
    _recorded_warning(av(level, REPORTED))(document)
    problem = _refused(r.finish(document))
    assert problem.path == sv("thermal_warning_level", "thermal_warning_level", "value")


# --- diagnostics -----------------------------------------------------------------------------


def test_a_refusal_never_echoes_the_value():
    document = r.load(M)
    canary = "CANARY" + "x" * 300
    r.set_value(document, "hardware_overview", "machine_name", canary)
    problem = _refused(r.finish(document))
    assert "CANARY" not in str(problem) and "CANARY" not in problem.path


def test_an_odd_key_is_named_in_escaped_ascii():
    document = r.load(M)
    r.values(document, "os_version")["we ird\u00e9\u202e"] = av("x", REPORTED)
    problem = _refused(r.finish(document))
    assert problem.path == "surfaces[0].values['we ird\\xe9\\u202e']"
    assert problem.path.isascii() and str(problem).isascii()


def test_the_serial_canary_never_reaches_a_message():
    document = r.load(M)
    r.values(document, "hardware_overview")["serial_number"] = av("C02CANARYQ7K", REPORTED)
    problem = _refused(r.finish(document))
    assert "CANARY" not in str(problem)


@pytest.mark.parametrize("document", [[], None, 5, "schema", ["schema"]])
def test_a_document_that_is_not_an_object_is_refused(document):
    with pytest.raises(Invalid) as problem:
        v.validate(document)  # type: ignore[arg-type]
    assert problem.value.path == "(top level)"


def test_validate_takes_the_parsed_document_and_changes_nothing():
    document = r.load(M)
    before = json.dumps(document, sort_keys=True)
    v.validate(document)
    assert json.dumps(document, sort_keys=True) == before


# --- hostile edits ----------------------------------------------------------------------------

_POOL = (
    None,
    True,
    0,
    -1,
    2**63,
    "",
    "available",
    "unavailable",
    "not_applicable",
    "source_changed",
    "parsed",
    "not_run",
    "S3",
    "disk0",
    "0.0",
    [],
    ["a"],
    {},
    {"availability": "available"},
    {"availability": "unavailable", "reason": "timeout"},
)


def _paths(node: object, prefix: tuple = ()) -> list[tuple]:
    found = [prefix] if prefix else []
    if isinstance(node, dict):
        for key, value in node.items():
            found.extend(_paths(value, (*prefix, key)))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            found.extend(_paths(value, (*prefix, index)))
    return found


@pytest.mark.parametrize("name", r.NAMES)
def test_hostile_edits_raise_only_invalid(name):
    # render must refuse any document with a named field, never crash on one: 1,500 seeded
    # documents per fixture, each with one to three fields replaced or removed.
    rng = random.Random(f"{name}-20260926")  # noqa: S311 - a seeded test, not a secret
    base = r.load(name)
    paths = _paths(base)
    for _ in range(1500):
        document = copy.deepcopy(base)
        for _ in range(rng.choice((1, 2, 3))):
            *head, last = rng.choice(paths)
            node = document
            try:
                for part in head:
                    node = node[part]
                if rng.random() < 0.8:
                    node[last] = copy.deepcopy(rng.choice(_POOL))
                else:
                    del node[last]
            except (KeyError, IndexError, TypeError):
                continue
        try:
            v.validate(document)
        except Invalid as problem:
            assert str(problem).isascii()
