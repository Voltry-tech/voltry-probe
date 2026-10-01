"""The storage identity chain: one trunk and two exact branches.

docs/VOLTRY_MAC_SPEC.md, Decision 8's storage dependency table and the identity chain in
the component table. C11 names the startup volume's physical stores; with exactly one,
its whole disk is that store without its final ``s`` and digits (``disk0s2`` gives
``disk0``). The chain forks there: C3's one entry carrying the whole disk's name is the
NVMe profile, and C28's one controller listing it is the SMART log, by C28's outcome
table. Every storage fact in the report comes from that one device; any other count
fails closed only the branch where it occurs, and an unavailable whole disk passes its
reason to both branches. The values Voltry computes from these (the Celsius reading and
the byte totals) are the report model's.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from voltry_mac import parsers, registry, smart, spawn
from voltry_mac.availability import Unavailable, command_reason, read

_COMPUTED: Final = frozenset({"composite_temperature_c", "bytes_read", "bytes_written"})


def _read_keys(surface: str, *also_computed: str) -> tuple[str, ...]:
    skip = _COMPUTED | set(also_computed)
    return tuple(key.name for key in registry.BY_KEY[surface].values if key.name not in skip)


HEALTH_KEYS: Final = _read_keys("smart_health_snapshot")
WEAR_KEYS: Final = _read_keys("smart_wear_attributes")
ENTRY_KEYS: Final = _read_keys("nvme_devices", "entry_count")

_STORE: Final = re.compile(r"disk[0-9]{1,3}s[0-9]{1,3}", re.ASCII)
_STORE_COUNT: Final = registry.INT_RANGES["physical_store_count"]
_ENTRY_COUNT: Final = registry.INT_RANGES["entry_count"]

Surface = Unavailable | dict[str, object]


@dataclass(frozen=True)
class Chain:
    """The four storage surfaces, each unavailable as a whole or holding its read values
    (a value itself ``Unavailable`` when it was not read), and C28's failed run."""

    startup_disk: Surface
    nvme_devices: Surface
    smart_health_snapshot: Surface
    smart_wear_attributes: Surface
    c28_failed_run: bool


def _parsed(
    result: spawn.Result, parse: Callable[[str], dict[str, object]]
) -> dict[str, object] | Unavailable:
    """A user command's parsed output, or the reason it has none."""
    reason = command_reason(result)
    if reason is not None:
        return Unavailable(reason)
    try:
        return parse(result.stdout)
    except parsers.SourceChanged:
        return Unavailable("source_changed")


def _count(count: int, bounds: tuple[int, int]) -> int | Unavailable:
    low, high = bounds
    return count if low <= count <= high else Unavailable("source_changed")


def _store(stores: object) -> tuple[int | Unavailable, str | Unavailable]:
    """The store count and the one store, or why there is no single store."""
    if not isinstance(stores, tuple):
        return Unavailable("source_changed"), Unavailable("source_changed")
    count = _count(len(stores), _STORE_COUNT)
    if isinstance(count, Unavailable):
        return count, count
    if count != 1:
        return count, Unavailable("unsupported")
    (name,) = stores
    if isinstance(name, str) and _STORE.fullmatch(name):
        return count, name
    return count, Unavailable("source_changed")


def _trunk(c11: spawn.Result) -> tuple[Surface, str | Unavailable]:
    """``startup_disk`` and the whole disk: its name, or why there is none."""
    disk = _parsed(c11, parsers.startup_disk)
    if isinstance(disk, Unavailable):
        return disk, disk
    count, store = _store(disk["physical_stores"])
    whole = store if isinstance(store, Unavailable) else store.rsplit("s", 1)[0]
    surface = {
        "physical_store_count": count,
        "physical_store": store,
        "whole_disk": whole,
        "internal": read(disk["internal"]),
        "solid_state": read(disk["solid_state"]),
    }
    return surface, whole


def _nvme(c3: spawn.Result, whole: str | Unavailable) -> Surface:
    """The NVMe branch: C3 itself decides first, then exactly one entry by name."""
    found = _parsed(c3, parsers.nvme)
    if isinstance(found, Unavailable):
        return found
    entries = found["entries"]
    assert isinstance(entries, tuple)  # noqa: S101 - parsers.nvme returns a tuple
    count = _count(len(entries), _ENTRY_COUNT)
    if isinstance(whole, Unavailable):
        return {"entry_count": count, **dict.fromkeys(ENTRY_KEYS, whole)}
    names = [entry["bsd_name"] for entry in entries]
    if parsers.UNREAD in names:
        return Unavailable("source_changed")  # a garbled name could be the startup disk's
    matched = [entry for entry in entries if entry["bsd_name"] == whole]
    if not matched:
        return Unavailable("source_absent")
    if len(matched) > 1:
        return Unavailable("source_changed")
    (entry,) = matched
    return {"entry_count": count, **{key: read(entry[key]) for key in ENTRY_KEYS}}


def chain(c11: spawn.Result, c3: spawn.Result, c28: spawn.Result) -> Chain:
    """The storage surfaces from C11, C3 and C28, by the dependency table."""
    startup_disk, whole = _trunk(c11)
    nvme_devices = _nvme(c3, whole)
    health: Surface
    wear: Surface
    if isinstance(whole, Unavailable):
        health = wear = whole
    else:
        outcome = smart.outcome(c28, whole)
        if outcome.reason is not None:
            health = wear = Unavailable(outcome.reason)
        else:
            assert outcome.values is not None  # noqa: S101 - row 12 carries the decoded log
            values = {key: read(value) for key, value in outcome.values.items()}
            health = {key: values[key] for key in HEALTH_KEYS}
            wear = {key: values[key] for key in WEAR_KEYS}
    return Chain(startup_disk, nvme_devices, health, wear, smart.failed_run(c28))
