"""Shared field types used across the evidence-bundle models.

Two concerns live here:

1. **Deterministic datetimes.** Every timestamp is stored timezone-aware and
   normalised to UTC, so its canonical (RFC 8785) serialization is byte-stable. A
   naive datetime is rejected loudly rather than silently assumed to be UTC.
2. **The safe-integer rule.** RFC 8785 canonicalizes JSON numbers as IEEE-754
   doubles, so any integer above 2**53 cannot round-trip. Bounded counters in the
   typed blocks stay well under that; anything that might be large (cumulative NVML
   counters, 64-bit identifiers) is captured **verbatim as a string** in
   ``RawReads`` instead of as a JSON number. ``SAFE_INTEGER_MAX`` documents the
   boundary; enforcement is the ``Count`` bound below plus the serializer itself:
   ``rfc8785.dumps`` raises on an out-of-domain integer, and
   :mod:`evidence_schema.canonicalize` wraps that into a typed
   ``CanonicalizationError``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from pydantic import AfterValidator, Field, PlainSerializer

#: Largest integer that survives RFC 8785 canonicalization losslessly (2**53).
SAFE_INTEGER_MAX: int = 9_007_199_254_740_992


def _ensure_utc(value: datetime) -> datetime:
    """Require a timezone-aware datetime and normalise it to UTC.

    Naive datetimes are ambiguous and would make canonical bytes depend on the
    producer's local clock, so they are rejected.
    """
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware (UTC); naive datetimes are rejected")
    return value.astimezone(timezone.utc)


#: A timezone-aware datetime, always stored in UTC and serialized with a fixed
#: ISO-8601 form so canonical bytes never depend on the producer's locale/clock.
UtcDateTime = Annotated[
    datetime,
    AfterValidator(_ensure_utc),
    PlainSerializer(lambda d: d.isoformat(), return_type=str, when_used="json"),
]

#: A non-negative counter bounded to the RFC 8785 safe-integer domain. Anything that
#: could exceed this (cumulative NVML counters, 64-bit ids) is captured verbatim as a
#: string in ``RawReads`` instead, so it never has to round-trip as a JSON number.
Count = Annotated[int, Field(ge=0, le=SAFE_INTEGER_MAX - 1)]


def utcnow() -> datetime:
    """Current time as a timezone-aware UTC datetime (single source for 'now')."""
    return datetime.now(timezone.utc)


__all__ = ["SAFE_INTEGER_MAX", "UtcDateTime", "Count", "utcnow"]
