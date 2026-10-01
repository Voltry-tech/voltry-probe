"""The SMART child's output on the parent's side: the contract, the outcome table and the
log decode.

docs/VOLTRY_MAC_SPEC.md, the C28 layout table, pinned to NVMeSMARTLibExternal.h in the
MacOSX26.5 SDK and to the NVM Express SMART / Health Information log page (identifier
02h). Every multi-byte field is little-endian and every 128-bit counter is two 64-bit
words, low word first, so each field reads as one little-endian integer of its size. The
parent decodes by this table and never through ctypes; the child's ctypes struct is
tested against the same table. A raw field that fails its decoded bound comes back as
``UNREAD`` (source_changed on that value): the temperature outside 250 to 400 K, and a
spare above 100%. The host and busy-time counters are dropped from v0 and never read.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from voltry_mac import spawn
from voltry_mac.parsers import UNREAD

LOG_SIZE: Final = 512
# field: (offset, size) in bytes.
LAYOUT: Final = MappingProxyType(
    {
        "critical_warning": (0, 1),
        "composite_temperature": (1, 2),
        "available_spare": (3, 1),
        "available_spare_threshold": (4, 1),
        "percentage_used": (5, 1),
        "data_units_read": (32, 16),
        "data_units_written": (48, 16),
        "host_read_commands": (64, 16),
        "host_write_commands": (80, 16),
        "controller_busy_time": (96, 16),
        "power_cycles": (112, 16),
        "power_on_hours": (128, 16),
        "unsafe_shutdowns": (144, 16),
        "media_errors": (160, 16),
        "error_log_entries": (176, 16),
    }
)
KELVIN_BOUNDS: Final = (250, 400)
# The critical-warning byte's bits 0 to 4, in order; any of bits 5 to 7 is an unknown one.
WARNING_FLAGS: Final = (
    "spare_below_threshold",
    "temperature_warning",
    "reliability_degraded",
    "read_only_mode",
    "volatile_backup_failed",
)
_UNKNOWN_BITS: Final = 0b1110_0000
_COUNTERS: Final = (
    "data_units_read",
    "data_units_written",
    "power_cycles",
    "power_on_hours",
    "unsafe_shutdowns",
    "media_errors",
    "error_log_entries",
)


def _field(raw: bytes, name: str) -> int:
    offset, size = LAYOUT[name]
    return int.from_bytes(raw[offset : offset + size], "little")


def decode(raw: bytes) -> dict[str, object]:
    """The registry's source values for both SMART surfaces, from one 512-byte log."""
    if len(raw) != LOG_SIZE:
        raise ValueError(f"a SMART log is {LOG_SIZE} bytes")
    byte = _field(raw, "critical_warning")
    kelvin = _field(raw, "composite_temperature")
    spare = _field(raw, "available_spare")
    threshold = _field(raw, "available_spare_threshold")
    low, high = KELVIN_BOUNDS
    values: dict[str, object] = {"critical_warning_byte": byte}
    values.update({flag: bool(byte >> bit & 1) for bit, flag in enumerate(WARNING_FLAGS)})
    values.update(
        {
            "unknown_warning_bits": bool(byte & _UNKNOWN_BITS),
            "composite_temperature_k": kelvin if low <= kelvin <= high else UNREAD,
            "available_spare_percent": spare if spare <= 100 else UNREAD,
            "available_spare_threshold_percent": threshold if threshold <= 100 else UNREAD,
            "percentage_used": _field(raw, "percentage_used"),
        }
    )
    values.update({counter: str(_field(raw, counter)) for counter in _COUNTERS})
    return values


# --- the child's document and C28's outcomes ----------------------------------------------------

SCHEMA: Final = "voltry-mac-smart/0"
MAX_DOCUMENT: Final = 64 * 1024
MAX_CONTROLLERS: Final = 8
MAX_MEDIA: Final = 8
_MEDIUM: Final = re.compile(r"disk[0-9]{1,3}", re.ASCII)
_HEX: Final = re.compile(r"[0-9a-fA-F]{1024}", re.ASCII)
_LOCATIONS: Final = frozenset({"Internal", "External", "Unknown"})
_ERRORS: Final = frozenset({"interface_unavailable", "smart_read_failed"})


class ContractBroken(ValueError):
    """The child's stdout is not one valid document for its exit status."""


@dataclass(frozen=True)
class Controller:
    location: str
    media: tuple[str, ...]
    status: str
    smart_hex: str | None
    error: str | None


@dataclass(frozen=True)
class Outcome:
    """What C28's run gives the two SMART surfaces, and whether it counts as failed."""

    reason: str | None  # None: both surfaces are available
    values: dict[str, object] | None
    failed_run: bool


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    found: dict[str, object] = {}
    for key, value in pairs:
        if key in found:
            raise ContractBroken("a duplicate key")
        found[key] = value
    return found


def _exact(value: object, keys: frozenset[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ContractBroken("not the contract's fields")
    return value


def _controller(value: object) -> Controller:
    # Each check refuses a wrong type before it looks anything up, so no document, however
    # hostile, can raise anything but ContractBroken.
    if not isinstance(value, dict):
        raise ContractBroken("a record that is not an object")
    status = value.get("status")
    if status == "ok":
        extra = "smart_hex"
    elif status == "error":
        extra = "error"
    else:
        raise ContractBroken("a status that is neither ok nor error")
    record = _exact(value, frozenset({"location", "media", "status", extra}))
    location, media = record["location"], record["media"]
    if not isinstance(location, str) or location not in _LOCATIONS:
        raise ContractBroken("another location")
    if not isinstance(media, list) or len(media) > MAX_MEDIA:
        raise ContractBroken("media is not a list of at most 8 names")
    if not all(isinstance(name, str) and _MEDIUM.fullmatch(name) for name in media):
        raise ContractBroken("a medium name outside the grammar")
    if status == "ok":
        smart_hex = record["smart_hex"]
        if not isinstance(smart_hex, str) or not _HEX.fullmatch(smart_hex):
            raise ContractBroken("the log is not 1,024 hex characters")
        return Controller(location, tuple(media), "ok", smart_hex, None)
    error = record["error"]
    if not isinstance(error, str) or error not in _ERRORS:
        raise ContractBroken("another error")
    return Controller(location, tuple(media), "error", None, error)


def parse_document(stdout: str, returncode: int) -> tuple[Controller, ...]:
    """The child's controllers, once the whole contract holds for this exit status."""
    # ASCII first, so the length in characters is the length in bytes and nothing is encoded.
    if not stdout.isascii() or len(stdout) > MAX_DOCUMENT:
        raise ContractBroken("not ASCII, or larger than 64 KiB")
    try:
        document = json.loads(stdout, object_pairs_hook=_pairs)
    except (ValueError, RecursionError):
        raise ContractBroken("not one JSON document") from None
    top = _exact(document, frozenset({"schema", "controllers"}))
    listed = top["controllers"]
    if top["schema"] != SCHEMA or not isinstance(listed, list) or len(listed) > MAX_CONTROLLERS:
        raise ContractBroken("another schema, or more than 8 controllers")
    controllers = tuple(_controller(value) for value in listed)
    names = [name for controller in controllers for name in controller.media]
    if len(names) != len(set(names)):
        raise ContractBroken("a medium listed twice")
    read = any(controller.status == "ok" for controller in controllers)
    agrees = {0: read, 2: not read, 3: not controllers}.get(returncode, False)
    if not agrees:
        raise ContractBroken("the document disagrees with the exit status")
    return controllers


def _failed(result: spawn.Result) -> tuple[str, str | None]:
    """Rows 1 to 7: the reason, with the valid document's text when none matched."""
    if result.ending is spawn.Ending.NOT_STARTED:
        return "tool_error", None
    if result.ending is spawn.Ending.OUTPUT_CAP:
        return "source_changed", None
    if result.ending is spawn.Ending.DEADLINE:
        return "timeout", None
    if result.ending is not spawn.Ending.EXITED or result.returncode not in (0, 2, 3):
        return "tool_error", None  # a signal, a cancellation, or another exit status
    return "", result.stdout


def failed_run(result: spawn.Result) -> bool:
    """C28's failed_runs: 1 when rows 1 to 7 match, whether or not the whole disk is known.

    Rows 8 to 12 never fail the run, so matching no disk at all gives the same answer.
    """
    return outcome(result, whole_disk="").failed_run


def outcome(result: spawn.Result, whole_disk: str) -> Outcome:
    """The ordered outcome table, once the storage chain has found the whole disk."""
    reason, stdout = _failed(result)
    if reason:
        return Outcome(reason, None, True)
    assert stdout is not None and result.returncode is not None  # noqa: S101
    try:
        controllers = parse_document(stdout, result.returncode)
    except ContractBroken:
        return Outcome("source_changed", None, True)
    if result.returncode == 3:
        return Outcome("tool_error", None, True)
    matched = [controller for controller in controllers if whole_disk in controller.media]
    if not matched:
        return Outcome("source_absent", None, False)
    (controller,) = matched  # media names are unique across the document
    if len(controller.media) != 1:
        return Outcome("unsupported", None, False)
    if controller.status == "error":
        reason = "unsupported" if controller.error == "interface_unavailable" else "tool_error"
        return Outcome(reason, None, False)
    assert controller.smart_hex is not None  # noqa: S101 - an ok record carries its log
    return Outcome(None, decode(bytes.fromhex(controller.smart_hex)), False)
