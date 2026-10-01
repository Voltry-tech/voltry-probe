"""render's validator: the normative JSON schema, the registry and the elevation record.

docs/VOLTRY_MAC_SPEC.md, Decision 8 ("JSON schema, normative", "Surface registry,
normative", the command records and the state machine) and Decision 2 (the outcome
tables and the skip rule). ``validate`` checks a document as ``canonical.load`` parsed it
and raises ``canonical.Invalid`` at the first rule the document breaks, naming the field
path in ASCII and never the value. It runs in four passes, so a broken shape is named
before any relation that depends on it: every shape (types, grammars, enumerations,
ranges); the report's own relations (the registry's, the storage chain and C28's table,
the user commands against the surfaces they feed, the collection block, the save gate);
the elevation record, its command records and the two elevated surfaces; and last the
report ID, which must recompute.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from typing import Final

from voltry_mac import (
    allowlist,
    canonical,
    numbers,
    registry,
    validate_elevation,
    validate_relations,
    versions,
)
from voltry_mac.canonical import TOP_LEVEL, Invalid, child_path
from voltry_mac.validate_elevation import (
    AUTHENTICATE,
    CHECK_RESULT,
    CLEANUP,
    CLEAR_ERROR,
    CLEARED,
    CONSENT,
    ENDINGS,
    MODE,
    SERVICE_ACCOUNT,
    SKIP_CAUSE,
)
from voltry_mac.validate_relations import COMMAND_REASONS, COUNTS, NVME_ENTRY

SCHEMA: Final = "voltry-mac-report/0"
TOOL_NAME: Final = "voltry-mac"

_TOP: Final = frozenset(
    {
        "schema",
        "not_an_evidence_bundle",
        "tool",
        "collected_at_utc",
        "collected_at_local",
        "time_zone",
        "platform",
        "elevation",
        "collection",
        "render",
        "surfaces",
        "commands",
        "report_id",
    }
)
_TOOL: Final = frozenset(
    {"name", "version", "renderer_version", "python", "architecture", "rosetta"}
)
_ELEVATION: Final = frozenset(
    {
        "consent",
        "skip_cause",
        "mode",
        "checks",
        "prepare",
        "authenticate",
        "count",
        "power",
        "cleared",
        "clear_error",
    }
)
_CHECKS: Final = frozenset({"service_account", "sandbox_probe", "listing"})
_PAYLOAD: Final = frozenset({"ending", "cleanup"})
_COLLECTION: Final = frozenset(
    {"status", "read", "skipped", "unavailable", "not_applicable", "unexpected_reasons"}
)
_SURFACE: Final = frozenset(
    {"key", "interface", "privilege", "temporal_class", "availability", "values"}
)
_RECORD: Final = frozenset({"id", "runs", "failed_runs", "duration_ms"})

# Grammars, used with fullmatch. The version's is versions.VERSION, PEP 440's canonical
# public form.
_RENDERER: Final = re.compile(r"[0-9]{1,4}", re.ASCII)
_PYTHON: Final = re.compile(r"[0-9]{1,2}\.[0-9]{1,3}\.[0-9]{1,3}([a-z]{1,2}[0-9]{1,3})?", re.ASCII)
_UTC: Final = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z", re.ASCII
)
_LOCAL: Final = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})([+-])([0-9]{2}):([0-9]{2})",
    re.ASCII,
)
# Change record 6: one to 64 characters of steps as R2 reads them, joined by single slashes:
# letters, digits and _ + - ., never . or .. alone, so no path passes.
_ZONE_STEP: Final = r"(?!\.\.?(?:/|\Z))[A-Za-z0-9_+.-]+"
_TIME_ZONE: Final = re.compile(rf"(?=.{{1,64}}\Z){_ZONE_STEP}(?:/{_ZONE_STEP})*", re.ASCII)
_REPORT_ID: Final = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)
_COMMAND_ID: Final = re.compile(r"[CSPXO][0-9]{1,2}n?", re.ASCII)

_USER_IDS: Final = allowlist.USER_COMMAND_IDS
_ORDER: Final = {command.id: index for index, command in enumerate(allowlist.COMMANDS)}


def read(data: bytes) -> dict[str, object]:
    """Read a saved report strictly and validate it; ``render`` starts here."""
    document = canonical.load(data)
    validate(document)
    return document


def validate(document: Mapping[str, object]) -> None:
    """Raise ``Invalid`` at the first rule the document breaks."""
    instant = _shapes(document)
    report = validate_relations.Report(document, instant)
    validate_relations.check(report)
    validate_elevation.check(report)
    if canonical.report_id(document) != document["report_id"]:
        raise Invalid("the report ID does not recompute from this document", "report_id")


# --- the first pass: shapes ------------------------------------------------------------------


def _object(value: object, path: str, keys: frozenset[str]) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise Invalid("must be an object", path or TOP_LEVEL)
    missing = sorted(keys - value.keys())
    if missing:
        raise Invalid("a required field is missing", child_path(path, missing[0]))
    unknown = sorted(value.keys() - keys)
    if unknown:
        raise Invalid("an unknown field", child_path(path, unknown[0]))
    return value


def _member(value: object, allowed: frozenset[str]) -> bool:
    """Set membership for a string; any other JSON value, a list or an object, is not one."""
    return isinstance(value, str) and value in allowed


def _one_of(value: object, path: str, allowed: tuple[str, ...]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise Invalid(f"must be one of {', '.join(allowed)}", path)
    return value


def _nullable(value: object, path: str, allowed: tuple[str, ...]) -> str | None:
    return None if value is None else _one_of(value, path, allowed)


def _integer(value: object, path: str, low: int, high: int) -> int:
    if not numbers.is_int64(value):
        raise Invalid("must be a 64-bit integer", path)
    assert isinstance(value, int)  # noqa: S101 - is_int64 admits only int
    if not low <= value <= high:
        raise Invalid(f"must be from {low} to {high}", path)
    return value


def _text(value: object, path: str, grammar: re.Pattern[str], what: str) -> str:
    if not isinstance(value, str) or not grammar.fullmatch(value):
        raise Invalid(f"must be {what}", path)
    return value


def _bool(value: object, path: str) -> bool:
    if type(value) is not bool:
        raise Invalid("must be true or false", path)
    return value


def _utc(value: object, path: str) -> datetime:
    match = _UTC.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise Invalid("must be a UTC time in the form YYYY-MM-DDTHH:MM:SSZ", path)
    try:
        return datetime(*(int(part) for part in match.groups()), tzinfo=UTC)  # type: ignore[misc]
    except ValueError:
        raise Invalid("not a real calendar instant", path) from None


def _local(value: object, path: str) -> datetime:
    match = _LOCAL.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise Invalid("must be a local time in the form YYYY-MM-DDTHH:MM:SS+HH:MM", path)
    *fields, sign, hours, minutes = match.groups()
    if int(hours) > 23 or int(minutes) > 59:
        raise Invalid("not a real UTC offset", path)
    offset = timedelta(hours=int(hours), minutes=int(minutes))
    zone = timezone(-offset if sign == "-" else offset)
    try:
        return datetime(*(int(part) for part in fields), tzinfo=zone)  # type: ignore[misc]
    except ValueError:
        raise Invalid("not a real calendar instant", path) from None


def _shapes(document: Mapping[str, object]) -> int:
    """Check every shape; return the collection instant as seconds since the epoch."""
    if not isinstance(document, Mapping):
        raise Invalid("must be an object", TOP_LEVEL)
    # The schema first: a later schema adds fields, and is named as a schema, not as one.
    if "schema" in document and document["schema"] != SCHEMA:
        raise Invalid(f"must be {SCHEMA}", "schema")
    _object(document, "", _TOP)
    if document["not_an_evidence_bundle"] is not True:
        raise Invalid("must be true", "not_an_evidence_bundle")
    _tool(document["tool"])
    collected = _utc(document["collected_at_utc"], "collected_at_utc")
    if _local(document["collected_at_local"], "collected_at_local") != collected:
        raise Invalid("must denote the same instant as collected_at_utc", "collected_at_local")
    _text(document["time_zone"], "time_zone", _TIME_ZONE, "an IANA identifier or unknown")
    platform = _object(document["platform"], "platform", frozenset({"validated"}))
    _bool(platform["validated"], "platform.validated")
    _elevation_shape(document["elevation"])
    _collection_shape(document["collection"])
    paper = _object(document["render"], "render", frozenset({"paper"}))
    _one_of(paper["paper"], "render.paper", ("letter", "a4"))
    instant = int(collected.timestamp())
    _surfaces_shape(document["surfaces"], instant)
    _commands_shape(document["commands"])
    _text(document["report_id"], "report_id", _REPORT_ID, "sha256: and 64 lowercase hex digits")
    return instant


def _tool(value: object) -> None:
    tool = _object(value, "tool", _TOOL)
    if tool["name"] != TOOL_NAME:
        raise Invalid(f"must be {TOOL_NAME}", "tool.name")
    if not versions.is_version(tool["version"]):
        raise Invalid("must be a PEP 440 version of at most 32 characters", "tool.version")
    _text(tool["renderer_version"], "tool.renderer_version", _RENDERER, "1 to 4 digits")
    _text(tool["python"], "tool.python", _PYTHON, "a Python version such as 3.12.11")
    _one_of(tool["architecture"], "tool.architecture", ("arm64", "x86_64"))
    _bool(tool["rosetta"], "tool.rosetta")


def _elevation_shape(value: object) -> None:
    elevation = _object(value, "elevation", _ELEVATION)
    _one_of(elevation["consent"], "elevation.consent", CONSENT)
    _nullable(elevation["skip_cause"], "elevation.skip_cause", SKIP_CAUSE)
    _one_of(elevation["mode"], "elevation.mode", MODE)
    checks = _object(elevation["checks"], "elevation.checks", _CHECKS)
    _one_of(checks["service_account"], "elevation.checks.service_account", SERVICE_ACCOUNT)
    _one_of(checks["sandbox_probe"], "elevation.checks.sandbox_probe", CHECK_RESULT)
    _one_of(checks["listing"], "elevation.checks.listing", CHECK_RESULT)
    _one_of(elevation["prepare"], "elevation.prepare", CHECK_RESULT)
    _one_of(elevation["authenticate"], "elevation.authenticate", AUTHENTICATE)
    for payload in ("count", "power"):
        record = _object(elevation[payload], f"elevation.{payload}", _PAYLOAD)
        _one_of(record["ending"], f"elevation.{payload}.ending", ENDINGS)
        _one_of(record["cleanup"], f"elevation.{payload}.cleanup", CLEANUP)
    _one_of(elevation["cleared"], "elevation.cleared", CLEARED)
    _nullable(elevation["clear_error"], "elevation.clear_error", CLEAR_ERROR)


def _collection_shape(value: object) -> None:
    collection = _object(value, "collection", _COLLECTION)
    _one_of(collection["status"], "collection.status", ("complete", "partial"))
    counts = [_integer(collection[name], f"collection.{name}", 0, 23) for name in COUNTS]
    if sum(counts) != len(registry.SURFACES):
        raise Invalid("the four counts must sum to 23", "collection")
    reasons = collection["unexpected_reasons"]
    if not isinstance(reasons, list) or len(reasons) > len(registry.REASONS):
        raise Invalid("must be an array of at most 9 reason codes", "collection.unexpected_reasons")
    for index, reason in enumerate(reasons):
        _one_of(reason, f"collection.unexpected_reasons[{index}]", registry.REASONS)
    if reasons != sorted(set(reasons)):
        raise Invalid(
            "must hold distinct reason codes in ascending order", "collection.unexpected_reasons"
        )


def _surfaces_shape(value: object, instant: int) -> None:
    if not isinstance(value, list) or len(value) != len(registry.SURFACES):
        raise Invalid("must be an array of the 23 registry surfaces, in order", "surfaces")
    for index, (surface, spec) in enumerate(zip(value, registry.SURFACES, strict=True)):
        _surface_shape(surface, spec, f"surfaces[{index}]", instant)


def _surface_shape(surface: object, spec: registry.Surface, path: str, instant: int) -> None:
    if not isinstance(surface, dict):
        raise Invalid("must be an object", path)
    if surface.get("key") != spec.key:
        raise Invalid(f"must be the registry's surface {spec.number}, {spec.key}", f"{path}.key")
    availability = surface.get("availability")
    _one_of(availability, f"{path}.availability", ("available", "unavailable", "not_applicable"))
    if availability == "not_applicable" and not spec.not_applicable:
        raise Invalid("only the two battery surfaces can be not applicable", f"{path}.availability")
    unavailable = availability == "unavailable"
    elevated = spec.key in registry.ELEVATED_SURFACES
    if "reason" in surface and not unavailable:
        raise Invalid("present only on an unavailable surface", f"{path}.reason")
    if "detail" in surface and not (unavailable and elevated):
        raise Invalid("present only on an unavailable elevated surface", f"{path}.detail")
    keys = _SURFACE | ({"reason"} if unavailable else set())
    keys |= {"detail"} if unavailable and elevated else set()
    _object(surface, path, frozenset(keys))
    for field in ("interface", "privilege", "temporal_class"):
        if surface[field] != getattr(spec, field):
            raise Invalid(f"must be the registry's {field} for {spec.key}", f"{path}.{field}")
    if unavailable:
        if not _member(surface["reason"], spec.reasons):
            raise Invalid(
                "not a reason this surface's availability domain allows", f"{path}.reason"
            )
        if elevated:
            _one_of(surface["detail"], f"{path}.detail", registry.DETAILS)
    values = surface["values"]
    values_path = f"{path}.values"
    if not isinstance(values, dict):
        raise Invalid("must be an object", values_path)
    if availability != "available":
        if values:
            raise Invalid("must be empty unless the surface is available", values_path)
        return
    names = {value.name for value in spec.values}
    for value_spec in spec.values:
        if not value_spec.optional and value_spec.name not in values:
            raise Invalid(
                "a required value key is missing", child_path(values_path, value_spec.name)
            )
    for name in values:
        if name not in names:
            raise Invalid("not a value key of this surface", child_path(values_path, name))
    for value_spec in spec.values:
        if value_spec.name in values:
            _value_shape(
                values[value_spec.name],
                value_spec,
                spec.key,
                child_path(values_path, value_spec.name),
                instant,
            )


def _value_reasons(surface_key: str, name: str) -> frozenset[str]:
    if surface_key == "kernel_and_platform":
        return COMMAND_REASONS
    if surface_key == "startup_disk" and name in ("physical_store", "whole_disk"):
        return frozenset({"source_changed", "unsupported"})
    if surface_key == "nvme_devices" and name in NVME_ENTRY:
        return COMMAND_REASONS | {"unsupported"}
    return frozenset({"source_changed"})


def _value_shape(
    entry: object, spec: registry.ValueKey, surface_key: str, path: str, instant: int
) -> None:
    if not isinstance(entry, dict):
        raise Invalid("must be an object", path)
    availability = entry.get("availability")
    if availability not in ("available", "unavailable"):
        raise Invalid(
            "must be available or unavailable; no value is not applicable", f"{path}.availability"
        )
    if availability == "available":
        if "reason" in entry:
            raise Invalid("present only on an unavailable value", f"{path}.reason")
        _object(entry, path, frozenset({"availability", "value", "provenance"}))
        if entry["provenance"] != spec.provenance:
            raise Invalid(
                f"must be {spec.provenance}, as the registry assigns", f"{path}.provenance"
            )
        _shape(entry["value"], spec, f"{path}.value", instant)
        return
    _object(entry, path, frozenset({"availability", "reason"}))
    if not _member(entry["reason"], _value_reasons(surface_key, spec.name)):
        raise Invalid("not a reason this value may carry", f"{path}.reason")


def _shape(value: object, spec: registry.ValueKey, path: str, instant: int) -> None:
    if not spec.shape.startswith("array of "):
        _scalar(value, spec.shape, spec.name, path, instant)
        return
    if not isinstance(value, list):
        raise Invalid("must be an array", path)
    if spec.name.startswith("sample_"):
        if len(value) != registry.SAMPLE_COUNT:
            raise Invalid(f"must have exactly {registry.SAMPLE_COUNT} elements", path)
    elif not 1 <= len(value) <= max(registry.INT_RANGES["perf_level_count"]):
        raise Invalid("must have one or two elements", path)
    element_shape = spec.shape.removeprefix("array of ")
    for index, element in enumerate(value):
        _scalar(element, element_shape, spec.name, child_path(path, index), instant)


def _scalar(value: object, shape: str, name: str, path: str, instant: int) -> None:
    if shape == "int":
        if name == "boot_epoch_seconds":
            if not numbers.is_int64(value):
                raise Invalid("must be a 64-bit integer", path)
            assert isinstance(value, int)  # noqa: S101 - is_int64 admits only int
            if not registry.BOOT_EPOCH_MIN <= value <= instant:
                raise Invalid("must be from 2000-01-01 to the collection instant", path)
            return
        _integer(value, path, *registry.INT_RANGES[name])
    elif shape == "dec":
        if not isinstance(value, str) or not numbers.is_canonical(value):
            raise Invalid("must be a canonical decimal string", path)
        low, high = registry.DEC_RANGES[name]
        if not low <= Decimal(value) <= high:
            raise Invalid(f"must be from {low} to {high}", path)
    elif shape == "u128":
        if not isinstance(value, str) or not numbers.is_u128(value):
            raise Invalid("must be a digit string no greater than 2^128-1", path)
    elif shape == "bytes128":
        if not isinstance(value, str) or not numbers.is_bytes128(value):
            raise Invalid("must be a digit string no greater than (2^128-1) x 512,000", path)
    elif shape == "bool":
        _bool(value, path)
    else:
        _string(value, name, path)


def _string(value: object, name: str, path: str) -> None:
    if not isinstance(value, str):
        raise Invalid("must be a string", path)
    if len(value) > registry.MAX_STRING:
        raise Invalid(f"longer than {registry.MAX_STRING} characters", path)
    canonical.check_text(value, path)
    grammar = registry.GRAMMARS.get(name)
    if grammar is not None and not grammar.fullmatch(value):
        raise Invalid("not in the form this key takes", path)
    if name == "boot_time_utc":
        _utc(value, path)
    elif name == "serial_last4" and len(value) != 4:
        raise Invalid("must be exactly four characters", path)
    elif name == "sample_thermal_pressure" and value not in registry.THERMAL_STATES:
        raise Invalid(f"must be one of {', '.join(registry.THERMAL_STATES)}", path)


def _commands_shape(value: object) -> None:
    if not isinstance(value, list) or not 27 <= len(value) <= 34:
        raise Invalid("must be an array of 27 to 34 command records", "commands")
    seen: set[str] = set()
    last = -1
    for index, record in enumerate(value):
        path = f"commands[{index}]"
        _object(record, path, _RECORD)
        command_id = record["id"]
        if (
            not isinstance(command_id, str)
            or not _COMMAND_ID.fullmatch(command_id)
            or command_id not in _ORDER
        ):
            raise Invalid("not an allow-list ID", f"{path}.id")
        if command_id == "O1":
            raise Invalid(
                "O1 runs after the files are published and never has a record", f"{path}.id"
            )
        if command_id in seen:
            raise Invalid("a second record for one ID", f"{path}.id")
        if _ORDER[command_id] < last:
            raise Invalid("out of allow-list order", f"{path}.id")
        seen.add(command_id)
        last = _ORDER[command_id]
        runs = _integer(record["runs"], f"{path}.runs", 1, 4000 if command_id == "P1" else 1)
        _integer(record["failed_runs"], f"{path}.failed_runs", 0, runs)
        _integer(record["duration_ms"], f"{path}.duration_ms", 0, numbers.INT64_MAX)
    for command_id in _USER_IDS:
        if command_id not in seen:
            raise Invalid(f"has no record for {command_id}", "commands")
