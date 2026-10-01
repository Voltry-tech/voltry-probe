"""Parsers for the user reads, C1 to C9 and C11 to C27.

docs/VOLTRY_MAC_SPEC.md, "Command allow-list" and the field inventory. Each parser takes
one command's stdout and returns only the fields the registry keeps, read by name through
a field allow-list, so nothing else in the output (a UUID, a volume or display name, a
scheduled event, a battery lot code) ever reaches the report model. A field the source
omitted or garbled comes back as ``UNREAD``, which the model turns into an unavailable
value with ``source_changed``; output that is not the command's shape at all raises
``SourceChanged``, and the surface is unavailable with that reason. So does a line, a
record or a key the parser reads that the source gives twice, with the same value or not:
taking the first or the last would be a guess (the GPT audit, pass 1, G1-02). The battery
reads return ``NOT_APPLICABLE`` on a Mac without a battery.

Numbers are read from their text or from the document's integers, never through a float.
Values Voltry computes from these (the whole disk, the battery's degrees, the boot date and
day count) are the report model's; C28 and the storage chain are the SMART child's. A
value's characters are checked by fixed code points (canonical.check_text) or by the
character table (characters.py), and a pattern's classes are ASCII, so every Python the
package supports reads a line alike (Decision 4; the pass-3 pre-audit, P3-output-04).
"""

from __future__ import annotations

import json
import plistlib
import re
from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import Final

from voltry_mac import canonical, characters

Parsed = dict[str, object]

_INT64: Final = (-(2**63), 2**63 - 1)
# More than a Mac has: a longer list is not a shape this version recognizes, and is never
# built up entry by entry (a 4 MiB list of empty entries would be a million of them).
_MAX_NVME_ENTRIES: Final = 16
_MAX_STORES: Final = 8
_STORE: Final = re.compile(r"disk[0-9]{1,3}s[0-9]{1,3}", re.ASCII)


class _Marker:
    def __init__(self, name: str) -> None:
        self._name = name

    def __repr__(self) -> str:
        return self._name


UNREAD: Final = _Marker("UNREAD")
NOT_APPLICABLE: Final = _Marker("NOT_APPLICABLE")


class SourceChanged(ValueError):
    """The output as a whole is not in a shape this version recognizes."""


# --- reading documents and fields --------------------------------------------------------------


class _Twice(Exception):
    """A key given twice in one object or dictionary."""


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    found: dict[str, object] = {}
    for key, value in pairs:
        if key in found:
            raise _Twice
        found[key] = value
    return found


class _UniqueDict(dict):  # type: ignore[type-arg]
    """plistlib's dictionaries: its readers set each key with ``d[key] = value``."""

    def __setitem__(self, key: object, value: object) -> None:
        if key in self:
            raise _Twice
        super().__setitem__(key, value)


def _json(text: str, top: str, *, empty: bool = False) -> list[object]:
    """The list system_profiler prints under its data type's key; ``empty`` allows none,
    as system_profiler prints for a data type with no devices."""
    try:
        document = json.loads(text, object_pairs_hook=_unique)
    except _Twice:
        raise SourceChanged(f"a key given twice in the JSON of {top}") from None
    except (ValueError, RecursionError):  # RecursionError: nested past the interpreter's limit
        raise SourceChanged(f"not the JSON of {top}") from None
    entries = document.get(top) if isinstance(document, dict) else None
    if not isinstance(entries, list) or not (entries or empty):
        raise SourceChanged(f"no {top} entries")
    return entries


def _only(entries: list[object], top: str) -> dict[str, object]:
    """The one entry of a data type a Mac has one of: the hardware overview, its GPU, its
    memory."""
    if len(entries) != 1:
        raise SourceChanged(f"more than one {top} entry")
    entry = entries[0]
    if not isinstance(entry, dict):
        raise SourceChanged(f"the {top} entry is not an object")
    return entry


def _plist(text: str) -> object:
    try:
        return plistlib.loads(text.encode("utf-8"), dict_type=_UniqueDict)
    except _Twice:
        raise SourceChanged("a key given twice in the property list") from None
    except Exception:  # noqa: BLE001 - plistlib raises many kinds on malformed input
        raise SourceChanged("not a property list") from None


def _clean(text: str) -> bool:
    """No control, separator, bidirectional or surrogate character: none belongs in a value."""
    try:
        canonical.check_text(text, "")
    except canonical.Invalid:
        return False
    return True


def _text(value: object) -> object:
    ok = isinstance(value, str) and 0 < len(value) <= 256 and _clean(value)
    return value if ok else UNREAD


def _string(mapping: object, key: str) -> object:
    return _text(mapping.get(key) if isinstance(mapping, dict) else None)


def _integer(mapping: object, key: str) -> object:
    value = mapping.get(key) if isinstance(mapping, dict) else None
    fits = type(value) is int and _INT64[0] <= value <= _INT64[1]
    return value if fits else UNREAD


def _choice(value: object, choices: Mapping[str, object]) -> object:
    return choices.get(value, UNREAD) if isinstance(value, str) else UNREAD


def _digits(value: object, suffix: str = "") -> object:
    """A whole number printed as text, such as "10" or "99%"."""
    if not isinstance(value, str) or not value.endswith(suffix):
        return UNREAD
    digits = value[: len(value) - len(suffix)] if suffix else value
    return int(digits) if re.fullmatch(r"[0-9]{1,18}", digits) else UNREAD


def _lines(text: str) -> list[str]:
    # Only a newline ends a line: str.splitlines() would also break inside a value at a
    # form feed, a record separator or a line separator, and cut the value short there.
    return [line.rstrip() for line in text.split("\n")]


def _one_line(text: str, pattern: str) -> re.Match[str]:
    """The one line in the expected form, the pattern's classes ASCII."""
    matches = (re.fullmatch(pattern, line, re.ASCII) for line in _lines(text))
    found = [m for m in matches if m is not None]
    if not found:
        raise SourceChanged("no line in the expected form")
    if len(found) > 1:
        raise SourceChanged("more than one line in the expected form")
    return found[0]


_YES_NO: Final = MappingProxyType({"Yes": True, "No": False})
_TRUE_FALSE: Final = MappingProxyType({"TRUE": True, "FALSE": False})


# --- C1 to C9 ----------------------------------------------------------------------------------

_SW_VERS: Final = (
    ("ProductName", "product_name"),
    ("ProductVersion", "product_version"),
    ("BuildVersion", "build_version"),
)


def os_version(text: str) -> Parsed:
    """C1, sw_vers: "Key:" then tabs then the value, one per line, each key once. A key
    counts whatever its value, so one given twice is refused even when its first value is
    missing or garbled (the review of #326, round 1, N1); that value is UNREAD."""
    found: dict[str, object] = {}
    for line in _lines(text):
        key = re.match(r"([A-Za-z]+):", line)
        if key is None:
            continue
        if key[1] in found:
            raise SourceChanged(f"sw_vers gave {key[1]} twice")
        match = re.fullmatch(r"[A-Za-z]+:\s+(\S.{0,255})", line, re.ASCII)
        found[key[1]] = UNREAD if match is None else match[1]
    if not any(isinstance(found.get(key), str) for key, _ in _SW_VERS):
        raise SourceChanged("no sw_vers keys")
    return {name: _text(found.get(key, UNREAD)) for key, name in _SW_VERS}


_ACTIVATION_LOCK: Final = MappingProxyType(
    {"activation_lock_enabled": True, "activation_lock_disabled": False}
)


def hardware(text: str) -> Parsed:
    """C2, SPHardwareDataType: the hardware overview and the firmware, from one run."""
    entry = _only(_json(text, "SPHardwareDataType"), "SPHardwareDataType")
    return {
        "machine_name": _string(entry, "machine_name"),
        "machine_model": _string(entry, "machine_model"),
        "model_number": _string(entry, "model_number"),
        "chip_type": _string(entry, "chip_type"),
        "physical_memory_text": _string(entry, "physical_memory"),
        "serial_number": _string(entry, "serial_number"),
        "activation_lock_enabled": _choice(
            entry.get("activation_lock_status") if isinstance(entry, dict) else None,
            _ACTIVATION_LOCK,
        ),
        "boot_rom_version": _string(entry, "boot_rom_version"),
        "os_loader_version": _string(entry, "os_loader_version"),
    }


def nvme(text: str) -> Parsed:
    """C3, SPNVMeDataType: every NVMe entry, keyed by its BSD name, in the order printed."""
    lists: list[list[object]] = []
    for controller in _json(text, "SPNVMeDataType", empty=True):
        items = controller.get("_items") if isinstance(controller, dict) else None
        if not isinstance(items, list):
            raise SourceChanged("an NVMe controller without its items")
        lists.append(items)
    if sum(len(items) for items in lists) > _MAX_NVME_ENTRIES:
        raise SourceChanged("more NVMe entries than a Mac has")
    entries = []
    for items in lists:
        for item in items:
            entries.append(
                {
                    "bsd_name": _string(item, "bsd_name"),
                    "device_model": _string(item, "device_model"),
                    "device_revision": _string(item, "device_revision"),
                    "size_text": _string(item, "size"),
                    "size_bytes": _integer(item, "size_in_bytes"),
                    "smart_status": _string(item, "smart_status"),
                    "trim_support": _choice(
                        item.get("spnvme_trim_support") if isinstance(item, dict) else None,
                        _YES_NO,
                    ),
                }
            )
    return {"entry_count": len(entries), "entries": tuple(entries)}


def gpu(text: str) -> Parsed:
    """C4, SPDisplaysDataType: the GPU's cores and Metal family, never a display."""
    entry = _only(_json(text, "SPDisplaysDataType"), "SPDisplaysDataType")
    family = entry.get("spdisplays_mtlgpufamilysupport") if isinstance(entry, dict) else None
    match = (
        re.fullmatch(r"spdisplays_metal([0-9]{1,2})", family) if isinstance(family, str) else None
    )
    return {
        "core_count": _digits(entry.get("sppci_cores") if isinstance(entry, dict) else None),
        "metal_family": f"Metal {match[1]}" if match is not None else UNREAD,
    }


def memory(text: str) -> Parsed:
    """C5, SPMemoryDataType."""
    entry = _only(_json(text, "SPMemoryDataType"), "SPMemoryDataType")
    return {
        "memory_type": _string(entry, "dimm_type"),
        "manufacturer": _string(entry, "dimm_manufacturer"),
        "size_text": _string(entry, "SPMemoryDataType"),
    }


def _named(entries: list[object], name: str) -> dict[str, object] | None:
    """The one entry of that name, or None when there is none."""
    found = [entry for entry in entries if isinstance(entry, dict) and entry.get("_name") == name]
    if len(found) > 1:
        raise SourceChanged(f"more than one {name} entry")
    return found[0] if found else None


def battery_health(text: str) -> Parsed | _Marker:
    """C6, SPPowerDataType: the battery as macOS reports it; not applicable without one."""
    entries = _json(text, "SPPowerDataType")
    names: list[str] = []
    for entry in entries:
        name = entry.get("_name") if isinstance(entry, dict) else None
        if not isinstance(name, str):
            raise SourceChanged("a power report entry without its name")
        names.append(name)
    if any(name.startswith("spbattery") and name != "spbattery_information" for name in names):
        raise SourceChanged("a battery entry under another name")
    battery = _named(entries, "spbattery_information")
    if battery is None:
        return NOT_APPLICABLE  # a power report that names no battery: a Mac without one
    charge = battery.get("sppower_battery_charge_info")
    health = battery.get("sppower_battery_health_info")
    model = battery.get("sppower_battery_model_info")
    charger = _named(entries, "sppower_ac_charger_information")
    return {
        "condition": _string(health, "sppower_battery_health"),
        "maximum_capacity_percent": _digits(
            (
                health.get("sppower_battery_health_maximum_capacity")
                if isinstance(health, dict)
                else None
            ),
            "%",
        ),
        "cycle_count": _integer(health, "sppower_battery_cycle_count"),
        "state_of_charge_percent": _integer(charge, "sppower_battery_state_of_charge"),
        "fully_charged": _choice(
            charge.get("sppower_battery_fully_charged") if isinstance(charge, dict) else None,
            _TRUE_FALSE,
        ),
        "is_charging": _choice(
            charge.get("sppower_battery_is_charging") if isinstance(charge, dict) else None,
            _TRUE_FALSE,
        ),
        "charger_connected": _choice(
            charger.get("sppower_battery_charger_connected") if charger is not None else None,
            _TRUE_FALSE,
        ),
        "gauge_device_name": _string(model, "sppower_battery_device_name"),
        "gauge_firmware_version": _string(model, "sppower_battery_firmware_version"),
        "gauge_hardware_revision": _string(model, "sppower_battery_hardware_revision"),
    }


def battery_gauge(text: str) -> Parsed | _Marker:
    """C7, ioreg's AppleSmartBattery: the gauge's own counters; not applicable without one."""
    if not text.strip():
        return NOT_APPLICABLE
    document = _plist(text)
    if isinstance(document, list) and not document:
        return NOT_APPLICABLE
    if not isinstance(document, list) or not isinstance(document[0], dict):
        raise SourceChanged("not the battery's registry entries")
    if len(document) > 1:
        raise SourceChanged("more than one battery registry entry")
    gauge = document[0]
    failure = _integer(gauge, "PermanentFailureStatus")
    return {
        "cycle_count": _integer(gauge, "CycleCount"),
        "design_cycle_count": _integer(gauge, "DesignCycleCount9C"),
        "design_capacity_mah": _integer(gauge, "DesignCapacity"),
        "full_charge_capacity_mah": _integer(gauge, "AppleRawMaxCapacity"),
        "temperature_centi_c": _integer(gauge, "Temperature"),
        "permanent_failure": UNREAD if failure is UNREAD else failure != 0,
    }


_NOT_RECORDED: Final = "Note: No thermal warning level has been recorded"
# pmset prints the date and the level on one line (pmset.m, show_thermal_warning_level).
_RECORDED: Final = re.compile(
    r"(?:[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} [+-][0-9]{4} )?"
    r"Thermal Warning Level = ([0-9]{1,3})"
)


def thermal(text: str) -> Parsed:
    """C8, pmset -g therm: whether a thermal warning level is recorded, and which, from
    the one line that says."""
    said: list[Parsed] = []
    for line in _lines(text):
        if line == _NOT_RECORDED:
            said.append({"thermal_warning_recorded": False})
        match = _RECORDED.fullmatch(line)
        if match is not None:
            said.append({"thermal_warning_recorded": True, "thermal_warning_level": int(match[1])})
    if len(said) != 1:
        raise SourceChanged("no thermal warning line" if not said else "two thermal warning lines")
    return said[0]


def memory_pressure(text: str) -> Parsed:
    """C9, memory_pressure -Q: the system-wide free percentage."""
    match = _one_line(text, r"System-wide memory free percentage: ([0-9]{1,3})%")
    return {"free_percent": int(match[1])}


# --- C11 to C14 ---------------------------------------------------------------------------------


def _store(store: object) -> object:
    name = _string(store, "APFSPhysicalStore")
    return name if isinstance(name, str) and _STORE.fullmatch(name) else UNREAD


def startup_disk(text: str) -> Parsed:
    """C11, diskutil info -plist /: the startup volume's physical stores and two flags.

    The stores come back as a tuple with one name per store, ``UNREAD`` for a store the
    source garbled or that is not in the store form (``disk0s2``, the spec's grammar), so a
    list that can be counted keeps its length; the whole list is ``UNREAD`` only when it
    cannot be counted, or holds more stores than a volume can have.
    """
    disk = _plist(text)
    if not isinstance(disk, dict):
        raise SourceChanged("not diskutil's volume record")
    stores = disk.get("APFSPhysicalStores")
    names: object = UNREAD
    if isinstance(stores, list) and 0 < len(stores) <= _MAX_STORES:
        names = tuple(_store(store) for store in stores)
        read = [name for name in names if name is not UNREAD]
        if len(set(read)) != len(read):
            # One store listed twice is not two stores (the review of #326, round 1, N1).
            raise SourceChanged("a physical store listed twice")
    internal, solid = disk.get("Internal"), disk.get("SolidState")
    return {
        "physical_stores": names,
        "internal": internal if isinstance(internal, bool) else UNREAD,
        "solid_state": solid if isinstance(solid, bool) else UNREAD,
    }


def sip(text: str) -> Parsed:
    """C12, csrutil status."""
    match = _one_line(text, r"System Integrity Protection status: (enabled|disabled)\.")
    return {"enabled": match[1] == "enabled"}


def gatekeeper(text: str) -> Parsed:
    """C13, spctl --status."""
    match = _one_line(text, r"assessments (enabled|disabled)")
    return {"assessments_enabled": match[1] == "enabled"}


def filevault(text: str) -> Parsed:
    """C14, fdesetup status: On or Off, whatever else it adds."""
    match = _one_line(text, r"FileVault is (On|Off)(?:[.,].*)?")
    return {"enabled": match[1] == "On"}


# --- C15 to C27 ---------------------------------------------------------------------------------

# Each sysctl read gives one value of kernel_and_platform, or virtualization_state's.
_SYSCTL_SHAPES: Final = MappingProxyType(
    {
        "C15": "str",  # hw.model
        "C16": "str",  # hw.target
        "C17": "int",  # hw.memsize
        "C18": "int",  # hw.ncpu
        "C19": "str",  # machdep.cpu.brand_string
        "C20": "bool",  # hw.optional.arm64
        "C21": "int",  # hw.nperflevels
        "C22": "str",  # hw.perflevel0.name
        "C23": "int",  # hw.perflevel0.physicalcpu
        "C24": "str",  # hw.perflevel1.name
        "C25": "int",  # hw.perflevel1.physicalcpu
        "C26": "bool",  # kern.hv_vmm_present
    }
)


# What str.isprintable() refuses: a control, format, surrogate, private-use or unassigned
# character, and a separator other than the space.
_UNPRINTABLE: Final = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp", "Zs"})


def _printable(text: str) -> bool:
    """str.isprintable() as Python 3.12 answers it, by the character table, on every
    Python: the method itself reads the running Python's Unicode database, so "Apple M5"
    and a mark Unicode 15.0.0 added was unread on 3.11 alone (the pass-3 pre-audit,
    P3-output-04)."""
    return all(c == " " or characters.category(c) not in _UNPRINTABLE for c in text)


def sysctl(command_id: str, text: str) -> object:
    """One sysctl -n value; anything but one line in the OID's shape is UNREAD."""
    lines = text.splitlines()
    if len(lines) != 1 or not lines[0].strip():
        return UNREAD
    value = lines[0].strip()
    shape = _SYSCTL_SHAPES[command_id]
    if shape == "int":
        return int(value) if re.fullmatch(r"[0-9]{1,18}", value) else UNREAD
    if shape == "bool":
        return {"1": True, "0": False}.get(value, UNREAD)
    return value if len(value) <= 256 and _printable(value) else UNREAD


def boot_time(text: str) -> Parsed:
    """C27, sysctl -n kern.boottime: "{ sec = N, usec = N } <date>"."""
    match = _one_line(text, r"\{ sec = ([0-9]{1,18}), usec = [0-9]{1,6} \}.*")
    return {"boot_epoch_seconds": int(match[1])}


def _sysctl_parser(command_id: str) -> Callable[[str], object]:
    def parse(text: str) -> object:
        return sysctl(command_id, text)

    return parse


PARSERS: Final[Mapping[str, Callable[[str], object]]] = MappingProxyType(
    {
        "C1": os_version,
        "C2": hardware,
        "C3": nvme,
        "C4": gpu,
        "C5": memory,
        "C6": battery_health,
        "C7": battery_gauge,
        "C8": thermal,
        "C9": memory_pressure,
        "C11": startup_disk,
        "C12": sip,
        "C13": gatekeeper,
        "C14": filevault,
        **{command_id: _sysctl_parser(command_id) for command_id in _SYSCTL_SHAPES},
        "C27": boot_time,
    }
)
