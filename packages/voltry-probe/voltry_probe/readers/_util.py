"""Small helpers shared by the reader mappers."""

from __future__ import annotations

from typing import Any


def _d(obj: Any, *keys: str, default: Any = None) -> Any:
    """Walk nested dict keys, returning ``default`` if any level is missing.

    Payloads arrive as plain JSON dicts, so any level can be absent or the wrong
    type; a non-dict mid-walk returns ``default`` instead of raising.
    """
    cur = obj
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur
