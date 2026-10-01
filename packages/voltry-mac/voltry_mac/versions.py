"""The form of a voltry-mac version, as a report's tool.version holds it.

docs/VOLTRY_MAC_SPEC.md, Decision 8's schema: PEP 440's canonical public form, at most 32
characters. A leaf module, so the PDF's appendices can check a drawing version without
importing the validator's whole chain; the validator applies the same rule to tool.version.
"""

from __future__ import annotations

import re
from typing import Final

MAX_VERSION: Final = 32
VERSION: Final = re.compile(
    r"([1-9][0-9]*!)?(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))*((a|b|rc)(0|[1-9][0-9]*))?"
    r"(\.post(0|[1-9][0-9]*))?(\.dev(0|[1-9][0-9]*))?",
    re.ASCII,
)


def is_version(text: object) -> bool:
    """Whether text is a version a report's tool.version may hold."""
    return isinstance(text, str) and len(text) <= MAX_VERSION and bool(VERSION.fullmatch(text))
