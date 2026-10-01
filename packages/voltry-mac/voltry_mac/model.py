"""The report model's core: the JSON's value and surface objects, the collection block,
the save gate, the exit code and the document.

docs/VOLTRY_MAC_SPEC.md, Decision 6 (the two labels on every observation, the collection
status), Decision 8 (the value and surface objects, the collapse rule, the report ID) and
Failure modes (the save gate, and the exit codes with their precedence). An available
value carries the provenance the registry assigns it, an unavailable one only its reason,
and no value is ever not applicable. A surface is available when at least one of its
values is; when none is, it is unavailable with the reason of its first value in registry
order. The model is pure: it reads no clock, file or process, and takes what the run
collected as arguments.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from typing import Final

from voltry_mac import canonical, numbers, registry
from voltry_mac.availability import Unavailable
from voltry_mac.parsers import NOT_APPLICABLE

SCHEMA: Final = "voltry-mac-report/0"
SAVE_GATE: Final = 8
_IDENTITY: Final = ("hardware_overview", "kernel_and_platform")
_UNVERIFIED_STOPS: Final = frozenset({"survivor", "listing_failed"})

# Failure modes: when more than one applies, the code is the first in this order.
_EXIT_ORDER: Final = (
    ("root", 5),
    ("unsupported", 3),
    ("usage", 2),
    ("interrupted", 130),
    ("not_saved", 4),
    ("clear_failed", 6),
    ("unexpected", 1),
)


def _decimal(value: object) -> Decimal:
    if not isinstance(value, Decimal):
        raise TypeError("a decimal value is a Decimal, never a float")
    return value


def _written(spec: registry.ValueKey, value: object) -> object:
    if spec.shape == "dec":
        return numbers.canonical(_decimal(value))
    if spec.shape == "array of dec":
        assert isinstance(value, Sequence)  # noqa: S101 - an array key holds a sequence
        return [numbers.canonical(_decimal(element)) for element in value]
    if isinstance(value, list | tuple):
        return list(value)
    return value


def value_object(spec: registry.ValueKey, value: object) -> dict[str, object]:
    """One value as the JSON writes it: available with its provenance, or its reason."""
    if isinstance(value, Unavailable):
        return {"availability": "unavailable", "reason": value.reason}
    return {
        "availability": "available",
        "value": _written(spec, value),
        "provenance": spec.provenance,
    }


def surface_object(key: str, content: object, *, detail: str | None = None) -> dict[str, object]:
    """One surface as the JSON writes it.

    ``content`` is the surface's values by name (each a value or ``Unavailable``), an
    ``Unavailable`` for the surface as a whole, or ``NOT_APPLICABLE`` for a battery
    surface on a Mac without a battery. ``detail`` goes with an unavailable elevated
    surface, and only there.
    """
    spec = registry.BY_KEY[key]
    row: dict[str, object] = {
        "key": key,
        "interface": spec.interface,
        "privilege": spec.privilege,
        "temporal_class": spec.temporal_class,
    }
    if content is NOT_APPLICABLE:
        if not spec.not_applicable or detail is not None:
            raise ValueError(f"{key} cannot be not applicable")
        return {**row, "availability": "not_applicable", "values": {}}
    if isinstance(content, Mapping):
        content = _values(spec, content, detail)
        if isinstance(content, dict):
            return {**row, "availability": "available", "values": content}
    if not isinstance(content, Unavailable):
        raise TypeError("a surface's content is its values, Unavailable, or NOT_APPLICABLE")
    if content.reason not in spec.reasons:
        raise ValueError(f"{content.reason} is not in {key}'s availability domain")
    elevated = key in registry.ELEVATED_SURFACES
    if elevated != (detail is not None) or (detail is not None and detail not in registry.DETAILS):
        raise ValueError("an unavailable elevated surface, and only one, carries a detail")
    unavailable: dict[str, object] = {
        **row,
        "availability": "unavailable",
        "reason": content.reason,
        "values": {},
    }
    if detail is not None:
        unavailable["detail"] = detail
    return unavailable


def _values(
    spec: registry.Surface, content: Mapping[str, object], detail: str | None
) -> dict[str, object] | Unavailable:
    """The value objects, or the first value's reason when none is available."""
    names = {value.name for value in spec.values}
    required = {value.name for value in spec.values if not value.optional}
    if not content.keys() <= names or not required <= content.keys():
        raise ValueError(f"not the registry's value keys for {spec.key}")
    given = [(value, content[value.name]) for value in spec.values if value.name in content]
    if not given:
        raise ValueError(f"{spec.key} has no values to be available with")
    if all(isinstance(value, Unavailable) for _, value in given):
        first = given[0][1]
        assert isinstance(first, Unavailable)  # noqa: S101 - every value is unavailable
        return first
    if detail is not None:
        raise ValueError("an available surface carries no detail")
    return {value.name: value_object(value, item) for value, item in given}


def collection(surfaces: Sequence[Mapping[str, object]]) -> dict[str, object]:
    """Decision 6's collection block: the counts, the status, the unexpected reasons."""
    counts = {"read": 0, "skipped": 0, "unavailable": 0, "not_applicable": 0}
    codes: set[str] = set()
    missing_value = False
    only_unsupported = True
    for surface in surfaces:
        availability = surface["availability"]
        if availability == "available":
            counts["read"] += 1
            values = surface["values"]
            assert isinstance(values, Mapping)  # noqa: S101 - a surface's values are a mapping
            for entry in values.values():
                if entry["availability"] == "unavailable":
                    missing_value = True
                    codes.add(entry["reason"])
        elif availability == "not_applicable":
            counts["not_applicable"] += 1
        else:
            reason = surface["reason"]
            assert isinstance(reason, str)  # noqa: S101 - an unavailable surface has a reason
            codes.add(reason)
            if reason in registry.SKIPPED_REASONS:
                counts["skipped"] += 1
            else:
                counts["unavailable"] += 1
                only_unsupported = only_unsupported and reason == "unsupported"
    complete = counts["skipped"] == 0 and only_unsupported and not missing_value
    return {
        "status": "complete" if complete else "partial",
        **counts,
        "unexpected_reasons": sorted(codes & registry.UNEXPECTED_REASONS),
    }


def save_gate(surfaces: Sequence[Mapping[str, object]]) -> bool:
    """At least 8 surfaces available, including hardware_overview or kernel_and_platform."""
    available = {surface["key"] for surface in surfaces if surface["availability"] == "available"}
    return len(available) >= SAVE_GATE and any(key in available for key in _IDENTITY)


def unexpected(document: Mapping[str, object]) -> bool:
    """Exit 1's cause: an unexpected reason anywhere, or a stop that was not verified."""
    block = document["collection"]
    elevation = document["elevation"]
    assert isinstance(block, Mapping) and isinstance(elevation, Mapping)  # noqa: S101
    return bool(block["unexpected_reasons"]) or any(
        elevation[payload]["cleanup"] in _UNVERIFIED_STOPS for payload in ("count", "power")
    )


def exit_code(
    *,
    root: bool = False,
    unsupported: bool = False,
    usage: bool = False,
    interrupted: bool = False,
    not_saved: bool = False,
    clear_failed: bool = False,
    unexpected: bool = False,
) -> int:
    """The first code that applies, in the order 5, 3, 2, 130, 4, 6, 1, 0."""
    applies = {
        "root": root,
        "unsupported": unsupported,
        "usage": usage,
        "interrupted": interrupted,
        "not_saved": not_saved,
        "clear_failed": clear_failed,
        "unexpected": unexpected,
    }
    return next((code for name, code in _EXIT_ORDER if applies[name]), 0)


def document(
    *,
    tool: Mapping[str, object],
    collected_at: datetime,
    time_zone: str,
    validated: bool,
    elevation: Mapping[str, object],
    surfaces: Sequence[Mapping[str, object]],
    commands: Sequence[Mapping[str, object]],
    paper: str,
) -> dict[str, object]:
    """The complete report, with its collection block and its report ID.

    ``collected_at`` is the collection instant in local time with its UTC offset; both
    times are written in whole seconds and denote the same instant.
    """
    offset = collected_at.utcoffset()
    if offset is None:
        raise ValueError("the collection time needs its UTC offset")
    utc = collected_at.astimezone(UTC).replace(microsecond=0)
    local = utc.astimezone(timezone(timedelta(minutes=offset // timedelta(minutes=1))))
    body: dict[str, object] = {
        "schema": SCHEMA,
        "not_an_evidence_bundle": True,
        "tool": dict(tool),
        "collected_at_utc": utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "collected_at_local": local.isoformat(),
        "time_zone": time_zone,
        "platform": {"validated": validated},
        "elevation": copy.deepcopy(dict(elevation)),
        "collection": collection(surfaces),
        "render": {"paper": paper},
        "surfaces": [dict(surface) for surface in surfaces],
        "commands": [dict(record) for record in commands],
    }
    return canonical.with_report_id(body)
