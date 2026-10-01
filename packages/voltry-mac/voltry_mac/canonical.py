"""The canonical JSON form, the report ID and the strict reader that ``render`` uses.

docs/VOLTRY_MAC_SPEC.md, Decision 4. The canonical form, which the report ID is computed
over and which ``--json`` writes: keys sorted by Unicode code point, no whitespace, ASCII
only with every other character escaped as ``\\uXXXX`` (surrogate pairs outside the BMP),
integers as plain decimals, no floats, NaN or Infinity, and one trailing newline. The
report ID is ``sha256:`` and the SHA-256 of that form without the ``report_id`` field.

The reader takes a saved JSON as bytes: at most 4 MiB, UTF-8, nesting at most 32 deep
(checked before parsing, so a hostile file cannot exhaust the parser), no duplicate key,
no float or constant, no integer of more than 19 digits (no field holds more), no key
over 64 characters (every key the schema names is a short ASCII name), and no control,
separator, bidirectional or lone surrogate character in any key or string. A failure
raises ``Invalid`` with the field path in ASCII and never the value; with keys capped,
a path, and so a message, stays bounded however large the file.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Final

MAX_BYTES: Final = 4 * 1024 * 1024
MAX_DEPTH: Final = 32
REPORT_ID_KEY: Final = "report_id"

MAX_KEY: Final = 64
MAX_INTEGER_DIGITS: Final = 19
# The field a refusal names for the document itself, which has no path: one spelling for
# every place that names it (the copy pass's review, round 3, m1).
TOP_LEVEL: Final = "(top level)"

# What no key or string may hold: C0 controls, DEL and C1 controls (the Unicode category
# Cc, which the report model strips from system output too), the line and paragraph
# separators, the bidirectional controls, and a lone surrogate, which is no character
# and has no UTF-8 form.
_FORBIDDEN: Final = re.compile(
    "[\x00-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069\ud800-\udfff]"
)
_PLAIN_KEY: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_]*", re.ASCII)


class NotCanonical(ValueError):
    """A value that has no canonical form: a float, a non-JSON type, a non-string key."""


class Invalid(ValueError):
    """A saved JSON that ``render`` refuses; ``path`` names where, never what, and
    ``message`` says what is wrong there."""

    def __init__(self, message: str, path: str = "") -> None:
        self.path = path
        self.message = message
        super().__init__(f"{path}: {message}" if path else message)


def child_path(path: str, key: str | int) -> str:
    """The path one step down: ``a.b``, ``a[3]``, or ``a['odd key']`` escaped to ASCII."""
    if isinstance(key, int):
        return f"{path}[{key}]"
    if _PLAIN_KEY.fullmatch(key):
        return f"{path}.{key}" if path else key
    return f"{path}[{ascii(key)}]"


def _check_writable(value: object) -> None:
    if value is None or isinstance(value, bool | str):
        return
    if type(value) is int:
        return
    if isinstance(value, float):
        raise NotCanonical("a float has no canonical form; write a decimal string")
    if isinstance(value, list):
        for item in value:
            _check_writable(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise NotCanonical("every key must be a string")
            _check_writable(item)
        return
    raise NotCanonical(f"{type(value).__name__} is not a JSON type")


def canonical_json(document: Mapping[str, object]) -> str:
    """The canonical form of a document, with its trailing newline."""
    _check_writable(dict(document))
    return (
        json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        )
        + "\n"
    )


def report_id(document: Mapping[str, object]) -> str:
    """``sha256:`` and the hash of the canonical form without the ``report_id`` field."""
    body = {key: value for key, value in document.items() if key != REPORT_ID_KEY}
    return "sha256:" + hashlib.sha256(canonical_json(body).encode("ascii")).hexdigest()


def with_report_id(document: Mapping[str, object]) -> dict[str, object]:
    """A copy of the document carrying its own report ID."""
    body = {key: value for key, value in document.items() if key != REPORT_ID_KEY}
    return {**body, REPORT_ID_KEY: report_id(body)}


# --- reading --------------------------------------------------------------------------------


class _Pairs(list[tuple[str, object]]):
    """An object as parsed: its key and value pairs in order, duplicates included."""


class _Rejected:
    """A float or constant the parser met, kept as a marker so its path can be named."""

    def __init__(self, kind: str) -> None:
        self.kind = kind


def _reject_float(_text: str) -> _Rejected:
    return _Rejected("a float")


def _reject_constant(_text: str) -> _Rejected:
    return _Rejected("NaN or Infinity")


def _read_int(text: str) -> int | _Rejected:
    """An integer literal; one longer than any field can hold never reaches ``int``."""
    if len(text) - text.startswith("-") > MAX_INTEGER_DIGITS:
        return _Rejected(f"an integer of more than {MAX_INTEGER_DIGITS} digits")
    return int(text)


def _depth_exceeds(text: str, limit: int) -> bool:
    depth = 0
    in_string = escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > limit:
                return True
        elif char in "]}":
            depth -= 1
    return False


def check_text(text: str, path: str) -> None:
    """Refuse a control, separator, bidirectional or surrogate character, naming ``path``."""
    if _FORBIDDEN.search(text):
        raise Invalid("a control, separator, bidirectional or surrogate character", path)


def _build(node: object, path: str) -> object:
    if isinstance(node, _Rejected):
        raise Invalid(f"{node.kind} is not allowed", path)
    if isinstance(node, str):
        check_text(node, path)
        return node
    if isinstance(node, _Pairs):
        built: dict[str, object] = {}
        for key, value in node:
            if len(key) > MAX_KEY:
                raise Invalid(f"a key longer than {MAX_KEY} characters", path or TOP_LEVEL)
            check_text(key, path or TOP_LEVEL)
            key_path = child_path(path, key)
            if key in built:
                raise Invalid("a duplicate key", key_path)
            built[key] = _build(value, key_path)
        return built
    if isinstance(node, list):
        return [_build(item, child_path(path, index)) for index, item in enumerate(node)]
    return node


def load(data: bytes) -> dict[str, object]:
    """Read a saved report JSON strictly; ``Invalid`` names what failed and where."""
    if len(data) > MAX_BYTES:
        raise Invalid("larger than the 4 MiB limit")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Invalid("not UTF-8 text") from None
    if _depth_exceeds(text, MAX_DEPTH):
        raise Invalid(f"nested deeper than {MAX_DEPTH} levels")
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_Pairs,
            parse_float=_reject_float,
            parse_int=_read_int,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, RecursionError):
        raise Invalid("not well-formed JSON") from None
    if not isinstance(parsed, _Pairs):
        raise Invalid("the top level is not an object")
    document = _build(parsed, "")
    assert isinstance(document, dict)  # noqa: S101 - a _Pairs node builds to a dict
    return document
