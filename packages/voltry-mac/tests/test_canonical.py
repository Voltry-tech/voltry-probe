"""The canonical JSON form, the report ID and the strict reader ``render`` uses.

docs/VOLTRY_MAC_SPEC.md, Decision 4: keys sorted by code point, no whitespace, ASCII only
with every other character escaped (surrogate pairs outside the BMP), integers as plain
decimals, no floats, NaN or Infinity, one trailing newline; the report ID is the SHA-256 of
that form without the ``report_id`` field. ``render`` reads a file with a 4 MiB cap, a
parser that rejects duplicate keys, a nesting cap of 32, and no control, separator or
bidirectional characters anywhere; a failure names the field path in escaped ASCII and
never echoes the value.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from voltry_mac import canonical as c

# --- the canonical form --------------------------------------------------------------------


def test_keys_sort_by_code_point_and_nothing_is_padded():
    text = c.canonical_json({"b": 1, "a": [3, {"z": True, "Z": None}], "\u00e9": "x"})
    assert text == '{"a":[3,{"Z":null,"z":true}],"b":1,"\\u00e9":"x"}\n'


def test_non_ascii_is_escaped_with_surrogate_pairs_outside_the_bmp():
    assert c.canonical_json({"k": "\U0001f600"}) == '{"k":"\\ud83d\\ude00"}\n'


def test_integers_are_plain_decimals():
    assert c.canonical_json({"n": 2**63 - 1, "m": -(2**63)}) == (
        '{"m":-9223372036854775808,"n":9223372036854775807}\n'
    )


@pytest.mark.parametrize("value", [1.5, float("nan"), float("inf"), -0.0])
def test_floats_are_refused_before_anything_is_written(value):
    with pytest.raises(c.NotCanonical):
        c.canonical_json({"v": [1, {"x": value}]})


def test_only_json_types_are_accepted():
    for value in ({1, 2}, (1, 2), b"x", object()):
        with pytest.raises(c.NotCanonical):
            c.canonical_json({"v": value})
    with pytest.raises(c.NotCanonical):
        c.canonical_json({1: "not a string key"})


def test_two_documents_differing_only_in_key_order_have_one_form_and_one_id():
    first = {"schema": "voltry-mac-report/0", "a": {"x": 1, "y": 2}}
    second = {"a": {"y": 2, "x": 1}, "schema": "voltry-mac-report/0"}
    assert c.canonical_json(first) == c.canonical_json(second)
    assert c.report_id(first) == c.report_id(second)


def test_the_report_id_is_the_hash_of_the_form_without_the_id():
    document = {"schema": "voltry-mac-report/0", "n": 1}
    expected = hashlib.sha256(b'{"n":1,"schema":"voltry-mac-report/0"}\n').hexdigest()
    assert c.report_id(document) == f"sha256:{expected}"
    with_id = {**document, "report_id": "sha256:" + "0" * 64}
    assert c.report_id(with_id) == f"sha256:{expected}", "the existing ID is left out"


def test_with_report_id_adds_the_id_and_the_result_recomputes():
    document = c.with_report_id({"n": 1})
    assert document["report_id"] == c.report_id(document)
    tail = '"report_id":"' + document["report_id"] + '"}\n'
    assert c.canonical_json(document).endswith(tail)


# --- the strict reader ---------------------------------------------------------------------


def _load(document) -> dict:
    return c.load(json.dumps(document).encode())


def test_a_canonical_document_reads_back_equal():
    document = c.with_report_id({"a": [1, 2, {"b": "text"}], "c": None, "d": False})
    assert c.load(c.canonical_json(document).encode()) == document


def test_the_size_cap_is_4_mib():
    assert c.MAX_BYTES == 4 * 1024 * 1024
    big = b'{"a":"' + b"x" * (4 * 1024 * 1024) + b'"}'
    with pytest.raises(c.Invalid) as problem:
        c.load(big)
    assert "4 MiB" in str(problem.value)


def test_duplicate_keys_are_refused_with_their_path():
    with pytest.raises(c.Invalid) as problem:
        c.load(b'{"a": {"b": 1, "b": 2}}')
    assert problem.value.path == "a.b"


@pytest.mark.parametrize("text", [b'{"a": 1.5}', b'{"a": 1e3}', b'{"a": NaN}', b'{"a": -Infinity}'])
def test_floats_and_constants_are_refused_while_reading(text):
    with pytest.raises(c.Invalid):
        c.load(text)


def test_nesting_deeper_than_32_is_refused_before_parsing():
    assert c.MAX_DEPTH == 32
    fine = b"[" * 32 + b"]" * 32
    c.load(b'{"a":' + fine[1:-1] + b"}")
    deep = b"[" * 100_000 + b"]" * 100_000
    with pytest.raises(c.Invalid) as problem:
        c.load(deep)
    assert "32" in str(problem.value)


def test_brackets_inside_strings_do_not_count_toward_depth():
    c.load(json.dumps({"a": "[" * 100 + "{" * 100}).encode())


@pytest.mark.parametrize(
    "char",
    [
        "\x00",
        "\x1f",
        "\x7f",
        "\x85",
        "\x9f",
        "\u2028",
        "\u2029",
        "\u202a",
        "\u202e",
        "\u2066",
        "\u2069",
    ],
)
def test_control_separator_and_bidi_characters_are_refused_in_values_and_keys(char):
    for document in ({"a": f"x{char}y"}, {f"k{char}": 1}, {"a": [{"b": char}]}):
        with pytest.raises(c.Invalid) as problem:
            _load(document)
        assert char not in str(problem.value) and char not in problem.value.path


def test_a_failure_names_the_path_in_ascii_and_never_the_value():
    secret = "C02XK1ZQMD6T\u202e"
    with pytest.raises(c.Invalid) as problem:
        _load({"surfaces": [{"values": {"serial_number": secret}}]})
    message = str(problem.value)
    assert problem.value.path == "surfaces[0].values.serial_number"
    assert "C02XK1ZQMD6T" not in message and message.isascii()


def test_an_odd_key_is_escaped_in_the_path():
    with pytest.raises(c.Invalid) as problem:
        c.load('{"a": {"we ird\u00e9": 1, "we ird\u00e9": 2}}'.encode())
    assert problem.value.path == "a['we ird\\xe9']"
    assert problem.value.path.isascii()


@pytest.mark.parametrize("data", [b"\xff\xfe", b"{", b"", b"[1] [2]", b'"just a string"'])
def test_malformed_input_is_refused(data):
    with pytest.raises(c.Invalid):
        c.load(data)


def test_the_top_level_must_be_an_object():
    with pytest.raises(c.Invalid):
        c.load(b"[1, 2]")


# --- the #342 review: the reader's edges and its cost ------------------------------------------


def _nested(levels: int) -> bytes:
    """A top-level object whose value nests arrays until ``levels`` containers deep."""
    return b'{"a":' + b"[" * (levels - 1) + b"]" * (levels - 1) + b"}"


def test_the_depth_cap_is_exact():
    c.load(_nested(32))
    with pytest.raises(c.Invalid) as problem:
        c.load(_nested(33))
    assert "32" in str(problem.value)


def test_the_size_cap_is_exact():
    exact = b'{"a":"' + b"x" * (c.MAX_BYTES - len(b'{"a":""}')) + b'"}'
    assert len(exact) == c.MAX_BYTES
    assert c.load(exact)["a"] == "x" * (c.MAX_BYTES - 8)
    with pytest.raises(c.Invalid):
        c.load(exact[:-2] + b'x"}')


def test_an_escaped_quote_does_not_end_a_string_for_the_depth_scan():
    # A scan that missed the escape would leave the string early and count 40 brackets.
    c.load(json.dumps({"a": '"' + "[" * 40}).encode())


def test_an_escaped_backslash_does_end_a_string_for_the_depth_scan():
    # A scan that read the quote after an escaped backslash as escaped would stay in the
    # string and miss the nesting after it.
    data = b'{"a": "x\\\\", "b": ' + _nested(33)[5:-1] + b"}"
    assert json.loads(data)["a"] == "x\\"
    with pytest.raises(c.Invalid) as problem:
        c.load(data)
    assert "32" in str(problem.value)


@pytest.mark.parametrize("digits", [20, 4300, 4301, 5000])
@pytest.mark.parametrize("sign", ["", "-"])
def test_an_integer_too_long_for_any_field_is_refused_at_its_path(digits, sign):
    # Python refuses to convert more than 4,300 digits with a bare ValueError; no field
    # holds more than 19 digits, so the reader refuses a longer integer itself.
    with pytest.raises(c.Invalid) as problem:
        c.load(f'{{"a": {{"b": [{sign}{"9" * digits}]}}}}'.encode())
    assert problem.value.path == "a.b[0]"
    assert "9" * 20 not in str(problem.value)


def test_a_nineteen_digit_integer_reads():
    top = 2**63 - 1
    assert c.load(f'{{"a": [{top}, {-top - 1}]}}'.encode()) == {"a": [top, -top - 1]}


def test_a_key_over_64_characters_is_refused_without_being_echoed():
    c.load(json.dumps({"a": {"k" * 64: 1}}).encode())
    for document, path in (({"a": {"k" * 65: 1}}, "a"), ({"k" * 65: 1}, "(top level)")):
        with pytest.raises(c.Invalid) as problem:
            _load(document)
        assert problem.value.path == path
        assert "k" * 65 not in str(problem.value)


def test_a_refusal_message_stays_short_whatever_the_document_holds():
    # With keys capped at 64 characters, the longest path a document can make is 32
    # levels of keys whose characters each escape to 10, so a refusal stays bounded and
    # spelling paths costs at most a fixed factor, however large the document.
    key = "\U0001f600" * 64
    document: object = "\u202e"
    for _ in range(31):
        document = {key: document}
    with pytest.raises(c.Invalid) as problem:
        _load(document)
    assert len(str(problem.value)) < 32 * (64 * 10 + 4) + 100


@pytest.mark.parametrize("escape", ["\\ud800", "\\udfff", "\\udc00\\ud800"])
def test_a_lone_surrogate_is_refused_in_values_and_keys(escape):
    # Not a character at all: it has no UTF-8 form, so no report can carry one.
    for text in (f'{{"a": "x{escape}"}}', f'{{"k{escape}": 1}}'):
        with pytest.raises(c.Invalid):
            c.load(text.encode())
    c.load(b'{"a": "\\ud83d\\ude00"}')  # a pair is a character
