"""Numbers as text (docs/VOLTRY_MAC_SPEC.md, Decision 6 "Rounding and spelling, normative",
Decision 8's value shapes, and Test strategy part 3 "Numbers as text").

Every number is read from its decimal text into ``decimal`` and never through a float;
ties round half away from zero; a decimal in the JSON has exactly one spelling.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from voltry_mac import numbers

# --- reading source text ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "canonical"),
    [
        ("2675.49", "2675.49"),
        ("2675.490", "2675.49"),
        ("0", "0.0"),
        ("0.00", "0.0"),
        ("-0", "0.0"),
        ("6.95445e-05", "0.0000695445"),
        ("6.95445E-05", "0.0000695445"),
        ("0.000000000001", "0.000000000001"),
        ("566.227", "566.227"),
        ("1e3", "1000.0"),
        ("-12.5", "-12.5"),
        ("+3.25", "3.25"),
        (".5", "0.5"),
        ("7.", "7.0"),
    ],
)
def test_source_text_is_read_exactly_and_spelled_canonically(text, canonical):
    assert numbers.canonical(numbers.source_decimal(text)) == canonical


@pytest.mark.parametrize(
    ("text", "canonical"),
    [
        ("9.9999999999995", "10.0"),  # the carry crosses the decimal point
        ("-9.9999999999995", "-10.0"),
        ("-0.0000000000004", "0.0"),  # rounds to zero: never "-0.0"
        ("0.0000000000005", "0.000000000001"),  # a tie rounds half away from zero
        ("1.2345678901234", "1.234567890123"),
    ],
)
def test_a_thirteenth_fractional_digit_rounds_half_up_to_twelve(text, canonical):
    assert numbers.canonical(numbers.source_decimal(text)) == canonical


@pytest.mark.parametrize(
    "text",
    ["", " 1.0", "1.0 ", "nan", "NaN", "inf", "-Infinity", "1,5", "0x10", "1e", "--1", "1.2.3"],
)
def test_text_that_is_not_a_plain_decimal_is_refused(text):
    with pytest.raises(ValueError):
        numbers.source_decimal(text)


def test_a_source_value_never_passes_through_a_float():
    # The standard plist reader would give 2675.489999...; text into decimal does not.
    assert numbers.source_decimal("2675.49") == Decimal("2675.49")
    with pytest.raises(TypeError):
        numbers.source_decimal(2675.49)  # type: ignore[arg-type]


# --- canonical spelling --------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    ["0.0", "1.0", "2675.49", "0.000000000001", "-10.0", "123456789012345.5", "0.5"],
)
def test_the_validator_accepts_canonical_spellings(text):
    assert numbers.is_canonical(text)


@pytest.mark.parametrize(
    "text",
    [
        "1.00",
        "2675.490",
        "+1.0",
        "-0.0",
        "1.",
        "1",
        ".5",
        "0.0000000000001",  # a thirteenth fractional digit
        "1.0000000000001",
        "01.5",
        "1234567890123456.0",  # sixteen integer digits
        "1e3",
        " 1.0",
        "1.0\n",
    ],
)
def test_the_validator_refuses_every_other_spelling(text):
    assert not numbers.is_canonical(text)


def test_numerically_equal_values_have_one_spelling():
    spellings = {numbers.canonical(numbers.source_decimal(t)) for t in ("1", "1.0", "1.00", "1e0")}
    assert spellings == {"1.0"}


def test_a_value_too_large_for_the_grammar_is_refused():
    with pytest.raises(ValueError):
        numbers.canonical(Decimal("1234567890123456"))


@pytest.mark.parametrize("value", [Decimal("NaN"), Decimal("Infinity"), Decimal("-Infinity"), 1.5])
def test_only_a_finite_decimal_has_a_canonical_spelling(value):
    with pytest.raises(ValueError):
        numbers.canonical(value)


def test_the_mean_of_nothing_is_refused():
    with pytest.raises(ValueError):
        numbers.mean([])


# --- values Voltry computes ----------------------------------------------------------------


def test_a_computed_value_rounds_half_up_to_two_places():
    assert numbers.canonical(numbers.computed(Decimal("1612.2812"))) == "1612.28"
    assert numbers.canonical(numbers.computed(Decimal("1612.30"))) == "1612.3"
    assert numbers.canonical(numbers.computed(Decimal("0.005"))) == "0.01"
    assert numbers.canonical(numbers.computed(Decimal("-0.005"))) == "-0.01"


def test_the_means_of_the_real_capture_match_the_discovery_log():
    # Sample E part 3 (spec, Sources and discovery log): processor.cpu_power, gpu_power,
    # ane_power and combined_power across the five samples, in capture order.
    series = {
        "cpu": ["2675.49", "2513.54", "1641.05", "566.227", "665.099"],
        "gpu": ["50.6685", "50.4092", "60.4857", "55.338", "54.3543"],
        "ane": ["0", "0", "0", "0", "0"],
        "combined": ["2726.16", "2563.95", "1701.53", "621.565", "719.453"],
    }
    means = {
        kind: numbers.canonical(numbers.mean([numbers.source_decimal(t) for t in texts]))
        for kind, texts in series.items()
    }
    assert means == {"cpu": "1612.28", "gpu": "54.25", "ane": "0.0", "combined": "1666.53"}


def test_extremes_are_values_not_samples():
    values = [numbers.source_decimal(t) for t in ("2.50", "2.5", "1.0")]
    assert numbers.canonical(max(values)) == "2.5"
    assert numbers.canonical(min(values)) == "1.0"


@pytest.mark.parametrize(
    ("kelvin", "celsius"), [(330, 57), (300, 27), (273, 0), (250, -23), (400, 127)]
)
def test_kelvin_to_whole_degrees_rounds_half_up(kelvin, celsius):
    assert numbers.kelvin_to_celsius(kelvin) == celsius


@pytest.mark.parametrize(
    ("centi", "text"), [(3040, "30.4"), (-4000, "-40.0"), (10000, "100.0"), (5, "0.05")]
)
def test_hundredths_of_a_degree_are_divided_and_spelled_canonically(centi, text):
    assert numbers.canonical(numbers.centi_to_degrees(centi)) == text


# --- integers and the 128-bit counters -------------------------------------------------------


def test_int64_bounds_and_bools():
    assert numbers.is_int64(0) and numbers.is_int64(2**63 - 1) and numbers.is_int64(-(2**63))
    assert not numbers.is_int64(2**63) and not numbers.is_int64(-(2**63) - 1)
    assert not numbers.is_int64(True), "a JSON boolean is not an integer"
    assert not numbers.is_int64(1.0), "a float is never an integer here"


def test_u128_digit_strings():
    assert numbers.is_u128("0") and numbers.is_u128(str(2**128 - 1))
    assert not numbers.is_u128(str(2**128)), "compared numerically, not by length"
    for bad in ("", "00", "01", "-1", "1.0", "1e3", " 1", str(10**39)):
        assert not numbers.is_u128(bad), bad


def test_bytes128_digit_strings():
    cap = (2**128 - 1) * 512_000
    assert cap == numbers.BYTES128_MAX
    assert numbers.is_bytes128("0") and numbers.is_bytes128(str(cap))
    assert not numbers.is_bytes128(str(cap + 1))
    assert not numbers.is_bytes128("0" + str(cap)), "a leading zero is not canonical"


def test_data_units_convert_to_bytes_exactly():
    assert numbers.DATA_UNIT_BYTES == 512_000
    assert numbers.data_units_to_bytes(26_019_396) == 26_019_396 * 512_000
    assert numbers.data_units_to_bytes(2**128 - 1) == numbers.BYTES128_MAX


# --- the #342 review: sizes no source value or JSON decimal can have ---------------------------


@pytest.mark.parametrize(
    "text",
    [
        "1" * 200 + ".1234567890123",  # rounding it needs more digits than the context holds
        "1e30000000",
        "9" * 16,  # sixteen integer digits: more than the JSON's grammar holds
        "-" + "9" * 16,
    ],
    ids=["200 digits to round", "an exponent of 30 million", "16 digits", "16 digits, negative"],
)
def test_a_source_value_too_large_for_the_json_is_a_value_error(text):
    with pytest.raises(ValueError):
        numbers.source_decimal(text)


def test_fifteen_integer_digits_still_read():
    assert numbers.canonical(numbers.source_decimal("9" * 15 + ".5")) == "9" * 15 + ".5"


def test_a_zero_with_any_exponent_is_zero():
    for text in ("0e999999999", "-0e999999999", "0e-999999999"):
        assert numbers.canonical(numbers.source_decimal(text)) == "0.0"


@pytest.mark.parametrize("value", ["1e30000000", "-1e30000000", "1e-30000000"])
def test_spelling_an_extreme_decimal_allocates_nothing_large(value):
    import tracemalloc

    tracemalloc.start()
    try:
        with pytest.raises(ValueError):
            numbers.canonical(Decimal(value))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 1024 * 1024


def test_trailing_zeros_past_twelve_places_still_spell_canonically():
    assert numbers.canonical(Decimal("1.5" + "0" * 40)) == "1.5"
    assert numbers.canonical(Decimal("15" + "0" * 13 + "e-13")) == "15.0"


# --- the #342 review, round 2 ------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    ["1e" + "9" * 19, "1e-" + "9" * 19, "0e" + "9" * 20, "1e" + "9" * 30],
    ids=["19-digit exponent", "19-digit negative exponent", "zero, 20 digits", "30 digits"],
)
def test_an_exponent_past_the_decimal_modules_range_is_a_value_error(text):
    with pytest.raises(ValueError):
        numbers.source_decimal(text)


def test_rounding_that_carries_into_a_sixteenth_integer_digit_is_refused():
    with pytest.raises(ValueError):
        numbers.source_decimal("999999999999999.9999999999995")
    assert numbers.source_decimal("999999999999999.999999999999") == Decimal(
        "999999999999999.999999999999"
    )


def test_a_thirteenth_significant_fractional_digit_has_no_spelling():
    with pytest.raises(ValueError):
        numbers.canonical(Decimal("1E-13"))
    assert numbers.canonical(Decimal("1E-12")) == "0.000000000001"
