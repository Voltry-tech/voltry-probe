"""The two elevated payloads' outputs: the memory error ledger (S3) and the power and
thermal samples (S4).

docs/VOLTRY_MAC_SPEC.md, Decision 2's parsed and unparsed endings and the aggregate query,
and Test strategy part 3, "Numbers as text". S3's sqlite3 -json output is two rows,
correctable then uncorrectable, each with its row count and its summed reported count.
S4's output is five plists separated by NUL bytes. They are read with the XML parser, not
plistlib, which would turn every <real> into a binary float first; each <real> is taken
from its text into decimal. A field missing inside an output that parsed costs that one
value (``UNREAD``); an output that does not parse into the registry's shape, or in which
every value would be unavailable, raises ``Unparsed``: the ending ``unparsed``.
"""

from __future__ import annotations

import json
import re
from decimal import Decimal
from typing import Final
from xml.parsers import expat

from voltry_mac import numbers, registry
from voltry_mac.parsers import UNREAD


class Unparsed(ValueError):
    """The output as a whole is not the payload's shape."""


# --- S3 ------------------------------------------------------------------------------------------

_CLASSES: Final = ("correctable", "uncorrectable")
_COLUMNS: Final = ("event_rows", "reported_count")
_ROW_KEYS: Final = frozenset({"class", *_COLUMNS})


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    found: dict[str, object] = {}
    for key, value in pairs:
        if key in found:
            raise Unparsed("a duplicate key")
        found[key] = value
    return found


def _count(value: object) -> object:
    ok = type(value) is int and 0 <= value <= numbers.INT64_MAX
    return value if ok else UNREAD


def ledger(stdout: str) -> dict[str, object]:
    """The four ledger values from S3's output."""
    try:
        document = json.loads(stdout, object_pairs_hook=_unique)
    except (ValueError, RecursionError):
        raise Unparsed("not the query's JSON") from None
    if not isinstance(document, list) or len(document) != len(_CLASSES):
        raise Unparsed("not two rows")
    values: dict[str, object] = {}
    for row, label in zip(document, _CLASSES, strict=True):
        if not isinstance(row, dict) or row.get("class") != label or not row.keys() <= _ROW_KEYS:
            raise Unparsed("not the query's rows, in its order")
        for column in _COLUMNS:
            values[f"{label}_{column}"] = _count(row.get(column))
    if all(value is UNREAD for value in values.values()):
        raise Unparsed("no count could be read")
    return values


# --- S4 ------------------------------------------------------------------------------------------

_POWER: Final = {
    "cpu_power": "sample_cpu_power_mw",
    "gpu_power": "sample_gpu_power_mw",
    "ane_power": "sample_ane_power_mw",
    "combined_power": "sample_combined_power_mw",
}
_INTEGER: Final = re.compile(r"-?[0-9]{1,19}", re.ASCII)
_SCALARS: Final = frozenset({"key", "string", "integer", "real", "date", "data"})
_EMPTY: Final = frozenset({"true", "false"})
_CONTAINERS: Final = frozenset({"plist", "dict", "array"})


class _Plist:
    """A plist's values from its XML: dicts, arrays, strings, integers, decimals for reals
    (``UNREAD`` for a real that is not a plain decimal), booleans; dates and data as text.

    Only what a plist writer produces is read: an element outside the plist set, an
    element inside a scalar, text between elements and a key twice in one dict are all
    ``Unparsed``.
    """

    def __init__(self) -> None:
        self.stack: list[list[object] | dict[str, object]] = [[]]
        self.keys: list[str | None] = [None]
        self.text: list[str] = []
        self.open: list[str] = []

    def start(self, name: str, _attributes: dict[str, str]) -> None:
        if name not in _SCALARS | _EMPTY | _CONTAINERS:
            raise Unparsed("an element a plist never holds")
        if self.open and self.open[-1] not in _CONTAINERS:
            raise Unparsed("an element inside a value")
        self.open.append(name)
        self.text = []
        if name == "dict":
            self.stack.append({})
            self.keys.append(None)
        elif name == "array":
            self.stack.append([])
            self.keys.append(None)

    def end(self, name: str) -> None:
        self.open.pop()
        text = "".join(self.text)
        self.text = []
        if name == "key":
            container = self.stack[-1]
            if isinstance(container, dict) and text in container:
                raise Unparsed("a key twice in one dict")
            self.keys[-1] = text
            return
        if name in ("dict", "array"):
            self.keys.pop()
            self._add(self.stack.pop())
        elif name in ("true", "false"):
            self._add(name == "true")
        elif name == "integer":
            self._add(int(text) if _INTEGER.fullmatch(text.strip()) else UNREAD)
        elif name == "real":
            self._add(_decimal(text.strip()))
        elif name in _SCALARS:
            self._add(text)

    def data(self, text: str) -> None:
        if (not self.open or self.open[-1] in _CONTAINERS) and text.strip():
            raise Unparsed("text between elements")
        self.text.append(text)

    def _add(self, value: object) -> None:
        container = self.stack[-1]
        if isinstance(container, dict):
            key = self.keys[-1]
            if key is not None:
                container[key] = value
                self.keys[-1] = None
        else:
            container.append(value)


def _decimal(text: str) -> object:
    try:
        return numbers.source_decimal(text)
    except ValueError:
        return UNREAD


def _refuse_entities(*_arguments: object) -> None:
    raise Unparsed("an XML entity declaration")


def _plist(text: str) -> object:
    reader = _Plist()
    parser = expat.ParserCreate()
    parser.StartElementHandler = reader.start
    parser.EndElementHandler = reader.end
    parser.CharacterDataHandler = reader.data
    parser.EntityDeclHandler = _refuse_entities
    # An entity the parser cannot expand would be skipped silently, joining the text around it.
    parser.SkippedEntityHandler = _refuse_entities
    try:
        parser.Parse(text.lstrip(), True)
    except expat.ExpatError:
        raise Unparsed("not a plist") from None
    (root,) = reader.stack[0] if len(reader.stack[0]) == 1 else (None,)
    return root


def _power_value(value: object) -> object:
    if isinstance(value, Decimal):
        return value
    return Decimal(value) if type(value) is int else UNREAD


def power(stdout: str) -> dict[str, list[object]]:
    """The six sample series from S4's output, one element per sample."""
    parts = stdout.split("\0")
    if len(parts) != registry.SAMPLE_COUNT:
        raise Unparsed("not five samples")
    series: dict[str, list[object]] = {
        "sample_elapsed_ns": [],
        "sample_thermal_pressure": [],
        **{name: [] for name in _POWER.values()},
    }
    for part in parts:
        sample = _plist(part)
        if not isinstance(sample, dict):
            raise Unparsed("a sample that is not a dictionary")
        elapsed = sample.get("elapsed_ns")
        series["sample_elapsed_ns"].append(elapsed if type(elapsed) is int else UNREAD)
        state = sample.get("thermal_pressure")
        series["sample_thermal_pressure"].append(state if isinstance(state, str) else UNREAD)
        processor = sample.get("processor")
        found = processor if isinstance(processor, dict) else {}
        for key, name in _POWER.items():
            series[name].append(_power_value(found.get(key)))
    if all(element is UNREAD for values in series.values() for element in values):
        raise Unparsed("no value could be read")
    return series
