"""Numbers as text: canonical decimals, the rounding rule and the counters' bounds.

docs/VOLTRY_MAC_SPEC.md, Decision 6 ("Rounding and spelling, normative") and Decision 8
(value shapes). Every number is read from its decimal text into ``decimal`` and never
through a float, since the standard plist reader turns 2675.49 into 2675.489999...; ties
round half away from zero (``ROUND_HALF_UP``). A decimal written to the JSON has exactly
one spelling: at least one fractional digit, no trailing zero after the first, no leading
``+``, and zero as ``0.0``, never signed. A source value keeps up to twelve fractional
digits, and one with more is rounded half up to twelve; a value Voltry computes (a mean, a
converted temperature) is rounded half up to two places first.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from decimal import ROUND_HALF_UP, Context, Decimal, InvalidOperation, localcontext
from typing import Final

MAX_FRACTION_DIGITS: Final = 12
MAX_INTEGER_DIGITS: Final = 15
INT64_MIN: Final = -(2**63)
INT64_MAX: Final = 2**63 - 1
U128_MAX: Final = 2**128 - 1
DATA_UNIT_BYTES: Final = 512_000
BYTES128_MAX: Final = U128_MAX * DATA_UNIT_BYTES

# Plain decimal text, with an optional exponent: what a plist <real> or a tool prints.
_SOURCE: Final = re.compile(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?", re.ASCII)
# The JSON's canonical decimal (spec, Decision 8): -0.0 is refused separately.
_CANONICAL: Final = re.compile(r"-?(?:0|[1-9][0-9]{0,14})\.(?:0|[0-9]{0,11}[1-9])", re.ASCII)
_U128: Final = re.compile(r"0|[1-9][0-9]{0,38}", re.ASCII)
_BYTES128: Final = re.compile(r"0|[1-9][0-9]{0,44}", re.ASCII)
_TWELVE: Final = Decimal(1).scaleb(-MAX_FRACTION_DIGITS)
_HUNDREDTH: Final = Decimal("0.01")
_WHOLE: Final = Decimal(1)
_KELVIN_OFFSET: Final = Decimal("273.15")
# Wide enough that no quantize here ever rounds by precision instead of by rule.
_EXACT: Final = Context(prec=120, rounding=ROUND_HALF_UP)


def source_decimal(text: str) -> Decimal:
    """A source value from its text, exactly, with at most twelve fractional digits.

    Accepts plain or exponent decimal text (``6.95445e-05``) with at most fifteen integer
    digits, the most the JSON's decimal grammar holds, before and after rounding, and
    nothing else: no NaN, no infinity, no whitespace, no float, no exponent beyond what
    the decimal module holds. Raises ``ValueError`` for anything else.
    """
    if not isinstance(text, str):
        raise TypeError("a source number is read from its text, never from a float")
    if not _SOURCE.fullmatch(text):
        raise ValueError("not a plain decimal")
    with localcontext(_EXACT):
        try:
            value = Decimal(text)
        except ArithmeticError:  # an exponent past the context's own limits
            raise ValueError("an exponent this version cannot hold") from None
        if not value.is_zero() and value.adjusted() >= MAX_INTEGER_DIGITS:
            raise ValueError(f"more than {MAX_INTEGER_DIGITS} integer digits")
        # Bounded above, rounding to twelve places needs at most 27 digits of the 120 the
        # context holds, so it cannot fail; a carry can still reach a sixteenth digit.
        exponent = value.as_tuple().exponent
        if isinstance(exponent, int) and exponent < -MAX_FRACTION_DIGITS:
            value = value.quantize(_TWELVE, rounding=ROUND_HALF_UP)
        if not value.is_zero() and value.adjusted() >= MAX_INTEGER_DIGITS:
            raise ValueError(f"more than {MAX_INTEGER_DIGITS} integer digits once rounded")
        return value


def computed(value: Decimal) -> Decimal:
    """A value Voltry computes, rounded half up to two decimal places."""
    with localcontext(_EXACT):
        return value.quantize(_HUNDREDTH, rounding=ROUND_HALF_UP)


def mean(values: Sequence[Decimal]) -> Decimal:
    """The arithmetic mean, rounded half up to two places."""
    if not values:
        raise ValueError("the mean of no values")
    with localcontext(_EXACT):
        return computed(sum(values, Decimal(0)) / Decimal(len(values)))


def kelvin_to_celsius(kelvin: int) -> int:
    """A whole Kelvin reading minus 273.15, rounded half up to a whole degree."""
    with localcontext(_EXACT):
        return int((Decimal(kelvin) - _KELVIN_OFFSET).quantize(_WHOLE, rounding=ROUND_HALF_UP))


def centi_to_degrees(centi: int) -> Decimal:
    """Hundredths of a degree as degrees (exact, then the computed-value rounding)."""
    with localcontext(_EXACT):
        return computed(Decimal(centi) / Decimal(100))


def data_units_to_bytes(units: int) -> int:
    """NVMe data units of 512,000 bytes as bytes."""
    return units * DATA_UNIT_BYTES


def _trailing_zeros(digits: tuple[int, ...]) -> int:
    text = "".join(map(str, digits))
    return len(text) - len(text.rstrip("0"))


def canonical(value: Decimal) -> str:
    """The one spelling of a decimal in the JSON; ``ValueError`` outside its grammar."""
    try:
        if not value.is_finite():
            raise ValueError("not a finite decimal")
    except (AttributeError, InvalidOperation) as problem:
        raise ValueError("not a decimal") from problem
    if value.is_zero():
        return "0.0"
    # Bounded before it is spelled: an exponent in the millions would otherwise be
    # written out digit by digit.
    if value.adjusted() >= MAX_INTEGER_DIGITS:
        raise ValueError(f"more than {MAX_INTEGER_DIGITS} integer digits")
    _, coefficient, exponent = value.as_tuple()
    assert isinstance(exponent, int)  # noqa: S101 - a finite decimal has an int exponent
    if exponent + _trailing_zeros(coefficient) < -MAX_FRACTION_DIGITS:
        raise ValueError(f"more than {MAX_FRACTION_DIGITS} fractional digits")
    text = format(value, "f")
    sign = "-" if text.startswith("-") else ""
    digits = text.lstrip("-")
    whole, _, fraction = digits.partition(".")
    fraction = fraction.rstrip("0") or "0"
    whole = whole.lstrip("0") or "0"
    spelled = f"{sign}{whole}.{fraction}"
    assert is_canonical(spelled)  # noqa: S101 - the two bounds above keep it in the grammar
    return spelled


def is_canonical(text: object) -> bool:
    """True for exactly the canonical decimal spellings the JSON allows."""
    return isinstance(text, str) and bool(_CANONICAL.fullmatch(text)) and text != "-0.0"


def is_int64(value: object) -> bool:
    """A JSON integer in the signed 64-bit range; booleans and floats never count."""
    return type(value) is int and INT64_MIN <= value <= INT64_MAX


def is_u128(text: object) -> bool:
    """A 128-bit counter as a digit string, compared numerically against 2**128 - 1."""
    return isinstance(text, str) and bool(_U128.fullmatch(text)) and int(text) <= U128_MAX


def is_bytes128(text: object) -> bool:
    """A derived byte total as a digit string, at most (2**128 - 1) x 512,000."""
    return isinstance(text, str) and bool(_BYTES128.fullmatch(text)) and int(text) <= BYTES128_MAX
