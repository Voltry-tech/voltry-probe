"""Assembling the 23 surfaces from what a run collected.

docs/VOLTRY_MAC_SPEC.md, Decision 8: the surface registry, the availability domains, the
value reasons, the ranges and grammars, the computed-values rule and the command records'
reason mapping; Decision 6's rounding. Each user command's output is read through its
parser; a failed command gives every surface it feeds the reason for how it failed, a
sysctl OID only its own value, and C28 its outcome table through the storage chain. A
value a parser could not read, or one outside its range or grammar, is ``source_changed``
on that value alone; a value of another shape than the registry's is a bug upstream and
raises ValueError. A value Voltry computes is available exactly when its inputs are, and
otherwise carries the reason of its first unavailable input. The elevated surfaces take
what the broker gives them: their parsed values, or the reason and detail its outcome
tables chose. Parsed values of which none survives are the broker's ``unparsed`` ending,
not a surface (``Unreadable``, and ``readable`` for the broker to ask first).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Final, cast

from voltry_mac import canonical, model, numbers, parsers, registry, smart, spawn, storage
from voltry_mac.availability import Unavailable, command_reason, read
from voltry_mac.parsers import NOT_APPLICABLE, UNREAD

_CHANGED: Final = Unavailable("source_changed")
# The schema's own bound on every integer, for a key the registry gives no narrower range.
_INT64: Final = (-(2**63), 2**63 - 1)


def _shapes() -> dict[str, str]:
    """Each value name's shape, an array's being its elements'. A name several surfaces
    share (``size_text``, ``cycle_count``, ``enabled``) must have one shape on all of them."""
    found: dict[str, str] = {}
    for surface in registry.SURFACES:
        for value in surface.values:
            shape = value.shape.removeprefix("array of ")
            if found.setdefault(value.name, shape) != shape:
                raise ValueError(f"{value.name} has two shapes in the registry")
    return found


_SHAPES: Final = _shapes()
_KERNEL_OIDS: Final = {
    "hw_model": "C15",
    "hw_target": "C16",
    "memory_bytes": "C17",
    "cpu_count": "C18",
    "cpu_brand": "C19",
    "arm64": "C20",
    "perf_level_count": "C21",
}
_PERF_OIDS: Final = {
    "perf_level_names": ("C22", "C24"),
    "perf_level_physical_cpus": ("C23", "C25"),
}
_POWER_KINDS: Final = ("cpu", "gpu", "ane", "combined")

# What a surface holds before it is written: its values by name, an Unavailable for the
# surface as a whole, or NOT_APPLICABLE.
Content = object


class Unreadable(ValueError):
    """A payload's parsed values of which none survives its registry range: the broker's
    ending is ``unparsed``, and the surface is not built from them."""


@dataclass(frozen=True)
class Elevated:
    """What the broker gives one elevated surface: its parsed values when the payload's
    ending is ``parsed``, or the reason and detail its outcome tables chose."""

    values: Mapping[str, object] | None = None
    reason: str | None = None
    detail: str | None = None

    def __post_init__(self) -> None:
        if (self.values is None) == (self.reason is None) or (self.reason is None) != (
            self.detail is None
        ):
            raise ValueError("an elevated surface has its values, or a reason and a detail")


@dataclass(frozen=True)
class Collected:
    """What a run gathered: the 27 user commands' results (C1 to C9 and C11 to C28), the
    panic count (R1) or why it was not read, the two elevated surfaces, the collection
    instant, and whether the owner asked for the full serial."""

    results: Mapping[str, spawn.Result]
    panic: int | Unavailable
    ledger: Elevated
    power: Elevated
    collected_at: datetime
    show_serial: bool = False

    def __post_init__(self) -> None:
        if self.collected_at.utcoffset() is None:
            raise ValueError("the collection instant carries its UTC offset")


def failed_run(command_id: str, result: spawn.Result) -> bool:
    """Whether a user command's run counts as failed in its record: C28 by its outcome
    table's rows 1 to 7, every other command by how it ended."""
    if command_id == "C28":
        return smart.failed_run(result)
    return command_reason(result) is not None


# --- fitting one value to the registry ---------------------------------------------------------


def _clean(text: str) -> bool:
    try:
        canonical.check_text(text, "")
    except canonical.Invalid:
        return False
    return True


def _spelled(value: Decimal) -> bool:
    """Whether the JSON's decimal grammar can spell the value: finite, with at most 15
    integer and 12 fractional digits (numbers.source_decimal never gives another)."""
    if not value.is_finite():
        return False
    try:
        numbers.canonical(value)
    except ValueError:
        return False
    return True


def _shaped(name: str, shape: str, fits: bool) -> None:
    if not fits:
        raise ValueError(f"{name} does not hold the registry's {shape}")


def _fit(name: str, value: object) -> object:
    """A read value within its registry range and grammar, or ``source_changed``."""
    if value is UNREAD or isinstance(value, Unavailable):
        return read(value)
    shape = _SHAPES.get(name)
    if shape is None:
        raise ValueError(f"{name} is not a registry value")
    if shape == "bool":
        _shaped(name, shape, isinstance(value, bool))
        return value
    if shape == "int":
        _shaped(name, shape, type(value) is int)
        assert isinstance(value, int)  # noqa: S101 - checked just above
        low, high = registry.INT_RANGES.get(name, _INT64)
        return value if low <= value <= high else _CHANGED
    if shape == "dec":
        _shaped(name, shape, isinstance(value, Decimal) and _spelled(value))
        assert isinstance(value, Decimal)  # noqa: S101 - checked just above
        low_dec, high_dec = registry.DEC_RANGES[name]
        return value if low_dec <= value <= high_dec else _CHANGED
    if shape == "u128":
        _shaped(name, shape, numbers.is_u128(value))
    elif shape == "bytes128":
        _shaped(name, shape, numbers.is_bytes128(value))
    else:
        _shaped(name, shape, isinstance(value, str))
    assert isinstance(value, str)  # noqa: S101 - checked just above
    grammar = registry.GRAMMARS.get(name)
    fits = 0 < len(value) <= registry.MAX_STRING and _clean(value)
    return value if fits and (grammar is None or grammar.fullmatch(value)) else _CHANGED


def _first_failing(*inputs: object) -> Unavailable | None:
    return next((item for item in inputs if isinstance(item, Unavailable)), None)


# --- user reads --------------------------------------------------------------------------------


def _parsed(
    results: Mapping[str, spawn.Result], command_id: str, parse: Callable[[str], object]
) -> object:
    """A user command's parsed output, or why it has none."""
    result = results[command_id]
    reason = command_reason(result)
    if reason is not None:
        return Unavailable(reason)
    try:
        return parse(result.stdout)
    except parsers.SourceChanged:
        return _CHANGED


def _fields(parsed: object, names: Sequence[str]) -> Content:
    if isinstance(parsed, Unavailable):
        return parsed
    assert isinstance(parsed, Mapping)  # noqa: S101 - a parser returns its fields
    return {name: _fit(name, parsed[name]) for name in names}


def _keys(surface: str, *skip: str) -> list[str]:
    return [value.name for value in registry.BY_KEY[surface].values if value.name not in skip]


def _hardware(parsed: object, show_serial: bool) -> Content:
    fields = _fields(parsed, _keys("hardware_overview", "serial_last4", "serial_number"))
    if not isinstance(fields, dict):
        return fields
    assert isinstance(parsed, Mapping)  # noqa: S101 - fields came from it
    serial = _fit("serial_number", parsed["serial_number"])
    if not isinstance(serial, str) or len(serial) < 4:
        serial = _CHANGED
    fields["serial_last4"] = serial[-4:] if isinstance(serial, str) else serial
    if show_serial:
        fields["serial_number"] = serial
    return fields


def _batteries(results: Mapping[str, spawn.Result]) -> tuple[Content, Content]:
    """C6 and C7. The pair is not applicable only together (the domains table), so one
    that found no battery beside one that did not say so reads as source_changed."""
    health = _parsed(results, "C6", parsers.battery_health)
    gauge = _parsed(results, "C7", parsers.battery_gauge)
    if health is NOT_APPLICABLE and gauge is NOT_APPLICABLE:
        return NOT_APPLICABLE, NOT_APPLICABLE
    if health is NOT_APPLICABLE:
        health = _CHANGED
    if gauge is NOT_APPLICABLE:
        gauge = _CHANGED
    gauge_fields = _fields(gauge, _keys("battery_gauge", "temperature_c"))
    if isinstance(gauge_fields, dict):
        centi = gauge_fields["temperature_centi_c"]
        gauge_fields["temperature_c"] = (
            _fit("temperature_c", numbers.centi_to_degrees(centi))
            if isinstance(centi, int)
            else centi
        )
    return _fields(health, _keys("battery_health")), gauge_fields


def _thermal(parsed: object) -> Content:
    if isinstance(parsed, Unavailable):
        return parsed
    assert isinstance(parsed, Mapping)  # noqa: S101 - a parser returns its fields
    recorded = _fit("thermal_warning_recorded", parsed["thermal_warning_recorded"])
    fields = {"thermal_warning_recorded": recorded}
    if "thermal_warning_level" in parsed:
        fields["thermal_warning_level"] = _fit(
            "thermal_warning_level", parsed["thermal_warning_level"]
        )
    return fields


def _oid(results: Mapping[str, spawn.Result], command_id: str, name: str) -> object:
    """One sysctl value: its command's own reason, or its value fitted to the registry."""
    result = results[command_id]
    reason = command_reason(result)
    if reason is not None:
        return Unavailable(reason)
    return _fit(name, parsers.sysctl(command_id, result.stdout))


def _kernel(results: Mapping[str, spawn.Result]) -> Content:
    values = {name: _oid(results, cid, name) for name, cid in _KERNEL_OIDS.items()}
    count = values["perf_level_count"]
    for name, oids in _PERF_OIDS.items():
        if isinstance(count, Unavailable):
            values[name] = count
            continue
        assert isinstance(count, int)  # noqa: S101 - a fitted count is 1 or 2
        elements = [_oid(results, cid, name) for cid in oids[:count]]
        values[name] = _first_failing(*elements) or elements
    return values


def _boot(parsed: object, instant: int) -> Content:
    if isinstance(parsed, Unavailable):
        return parsed
    assert isinstance(parsed, Mapping)  # noqa: S101 - a parser returns its fields
    epoch = _fit("boot_epoch_seconds", parsed["boot_epoch_seconds"])
    if not isinstance(epoch, int) or not registry.BOOT_EPOCH_MIN <= epoch <= instant:
        return dict.fromkeys(_keys("boot_time"), _CHANGED)
    days = _fit("days_since_boot", (instant - epoch) // 86400)
    if isinstance(days, Unavailable):  # a clock a century past the boot: no date to trust
        return dict.fromkeys(_keys("boot_time"), _CHANGED)
    return {
        "boot_epoch_seconds": epoch,
        "boot_time_utc": datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "days_since_boot": days,
    }


# --- storage and SMART -------------------------------------------------------------------------


def _fitted(surface: object) -> Content:
    if not isinstance(surface, Mapping):
        return surface
    return {name: _fit(name, value) for name, value in surface.items()}


def _smart(chain: storage.Chain) -> tuple[Content, Content]:
    health, wear = _fitted(chain.smart_health_snapshot), _fitted(chain.smart_wear_attributes)
    if isinstance(health, dict) and isinstance(wear, dict):
        kelvin = health["composite_temperature_k"]
        health["composite_temperature_c"] = (
            _fit("composite_temperature_c", numbers.kelvin_to_celsius(kelvin))
            if isinstance(kelvin, int)
            else kelvin
        )
        for units, total in (
            ("data_units_read", "bytes_read"),
            ("data_units_written", "bytes_written"),
        ):
            count = wear[units]
            wear[total] = (
                str(numbers.data_units_to_bytes(int(count))) if isinstance(count, str) else count
            )
    return health, wear


# --- the panic count and the elevated surfaces -------------------------------------------------


def _panic(panic: int | Unavailable) -> Content:
    if isinstance(panic, Unavailable):
        return panic
    fitted = _fit("count", panic)
    return {"count": panic} if fitted == panic else Unavailable("tool_error")


def _broker(name: str, value: object) -> object:
    """A value the broker parsed: ``UNREAD`` when it could not be read, never a reason."""
    if isinstance(value, Unavailable):
        raise ValueError(f"{name}: a payload's value is read, or UNREAD, never a reason")
    return value


def _exact(key: str, values: Mapping[str, object], names: Sequence[str]) -> None:
    if set(values) != set(names):
        raise ValueError(f"not the registry's keys for {key}'s parsed values")


def _elevated_values(key: str, values: Mapping[str, object]) -> dict[str, object]:
    """A payload's parsed values as its surface's content, or Unreadable when none survives."""
    if key == "memory_error_ledger":
        names = _keys(key)
        _exact(key, values, names)
        fitted = {name: _fit(name, _broker(name, values[name])) for name in names}
        if all(isinstance(value, Unavailable) for value in fitted.values()):
            raise Unreadable("every ledger count failed: the broker's ending is unparsed")
        return fitted
    _exact(key, values, [name for name in _keys(key) if name in _SERIES])
    return _power(values)


def readable(key: str, values: Mapping[str, object]) -> bool:
    """Whether a payload's parsed values leave its surface anything to show. The spec's
    ``unparsed`` covers an output in which every value would be unavailable, a value
    outside its range included, and only this module applies the ranges, so the broker
    asks here before it records ``parsed``."""
    if key not in registry.ELEVATED_SURFACES:
        raise ValueError(f"{key} is not an elevated surface")
    try:
        _elevated_values(key, values)
    except Unreadable:
        return False
    return True


def _elevated(key: str, elevated: Elevated) -> tuple[Content, str | None]:
    if elevated.values is None:
        assert elevated.reason is not None  # noqa: S101 - Elevated holds one or the other
        return Unavailable(elevated.reason), elevated.detail
    return _elevated_values(key, elevated.values), None


def _series(name: str, elements: object) -> object:
    if not isinstance(elements, list | tuple) or len(elements) != registry.SAMPLE_COUNT:
        raise ValueError("a power series is a list of exactly five samples")
    fitted = [_fit(name, _broker(name, element)) for element in elements]
    if name == "sample_thermal_pressure" and not all(
        state in registry.THERMAL_STATES for state in fitted if isinstance(state, str)
    ):
        return _CHANGED
    return _first_failing(*fitted) or fitted


_SERIES: Final = frozenset(
    value.name
    for value in registry.BY_KEY["power_and_thermal_samples"].values
    if value.name.startswith("sample_") and value.name != "sample_count"
)


def _power(parsed: Mapping[str, object]) -> dict[str, object]:
    series = {
        name: _series(name, parsed[name])
        for name in _keys("power_and_thermal_samples")
        if name in _SERIES
    }
    if all(isinstance(samples, Unavailable) for samples in series.values()):
        raise Unreadable("every power series failed: the broker's ending is unparsed")
    values: dict[str, object] = {"sample_count": registry.SAMPLE_COUNT, **series}
    states = series["sample_thermal_pressure"]
    for state in registry.THERMAL_STATES:
        name = f"thermal_{state.lower()}_count"
        values[name] = states.count(state) if isinstance(states, list) else states
    for kind in _POWER_KINDS:
        samples = series[f"sample_{kind}_power_mw"]
        stats: dict[str, object]
        if isinstance(samples, list):
            exact = cast(list[Decimal], samples)
            stats = {"min": min(exact), "max": max(exact), "mean": numbers.mean(exact)}
        else:
            stats = dict.fromkeys(("min", "max", "mean"), samples)
        for stat, value in stats.items():
            values[f"{kind}_power_mw_{stat}"] = value
    return values


# --- the surfaces --------------------------------------------------------------------------------


def surfaces(collected: Collected) -> list[dict[str, object]]:
    """The 23 surface objects, in registry order."""
    results = collected.results
    instant = int(collected.collected_at.timestamp())
    hardware = _parsed(results, "C2", parsers.hardware)
    health, gauge = _batteries(results)
    chain = storage.chain(results["C11"], results["C3"], results["C28"])
    smart_health, smart_wear = _smart(chain)
    ledger, ledger_detail = _elevated("memory_error_ledger", collected.ledger)
    power, power_detail = _elevated("power_and_thermal_samples", collected.power)

    def user(command_id: str, parse: Callable[[str], object], key: str) -> Content:
        return _fields(_parsed(results, command_id, parse), _keys(key))

    contents: dict[str, tuple[object, str | None]] = {
        "os_version": (user("C1", parsers.os_version, "os_version"), None),
        "hardware_overview": (_hardware(hardware, collected.show_serial), None),
        "firmware_and_boot": (_fields(hardware, _keys("firmware_and_boot")), None),
        "nvme_devices": (_fitted(chain.nvme_devices), None),
        "gpu_configuration": (user("C4", parsers.gpu, "gpu_configuration"), None),
        "memory_configuration": (user("C5", parsers.memory, "memory_configuration"), None),
        "battery_health": (health, None),
        "battery_gauge": (gauge, None),
        "thermal_warning_level": (_thermal(_parsed(results, "C8", parsers.thermal)), None),
        "memory_pressure": (user("C9", parsers.memory_pressure, "memory_pressure"), None),
        "startup_disk": (_fitted(chain.startup_disk), None),
        "sip_status": (user("C12", parsers.sip, "sip_status"), None),
        "gatekeeper_status": (user("C13", parsers.gatekeeper, "gatekeeper_status"), None),
        "filevault_status": (user("C14", parsers.filevault, "filevault_status"), None),
        "kernel_and_platform": (_kernel(results), None),
        "virtualization_state": ({"vmm_present": _oid(results, "C26", "vmm_present")}, None),
        "boot_time": (_boot(_parsed(results, "C27", parsers.boot_time), instant), None),
        "smart_health_snapshot": (smart_health, None),
        "smart_wear_attributes": (smart_wear, None),
        "panic_report_count": (_panic(collected.panic), None),
        "memory_error_ledger": (ledger, ledger_detail),
        "power_and_thermal_samples": (power, power_detail),
        "ecc_ras_telemetry": (Unavailable("unsupported"), None),
    }
    return [
        model.surface_object(spec.key, contents[spec.key][0], detail=contents[spec.key][1])
        for spec in registry.SURFACES
    ]


def document(
    collected: Collected,
    *,
    tool: Mapping[str, object],
    time_zone: str,
    validated: bool,
    elevation: Mapping[str, object],
    commands: Sequence[Mapping[str, object]],
    paper: str,
) -> dict[str, object]:
    """The whole report from what a run collected, so its surfaces and its two times come
    from one instant."""
    return model.document(
        tool=tool,
        collected_at=collected.collected_at,
        time_zone=time_zone,
        validated=validated,
        elevation=elevation,
        surfaces=surfaces(collected),
        commands=commands,
        paper=paper,
    )
