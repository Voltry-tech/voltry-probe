"""The two elevated payloads' outputs (docs/VOLTRY_MAC_SPEC.md, Decision 2's endings
parsed and unparsed, the aggregate query, root sample E, and Test strategy part 3,
"Numbers as text").

S3's sqlite3 -json output is two rows, correctable then uncorrectable, each with its row
count and summed reported count. S4's output is five plists separated by NUL bytes, read
with the XML parser, never plistlib, every <real> taken from its text into decimal. A
field missing inside a parsed output costs that one value; an output that does not parse
into the registry's shape, or in which every value would be unavailable, is unparsed.
"""

from __future__ import annotations

import ast
import json
from decimal import Decimal
from pathlib import Path

import pytest

from voltry_mac import parsers, payloads

UNREAD = parsers.UNREAD
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "payloads"
SAMPLE_E = (FIXTURES / "m5-sample-e3.powermetrics").read_text(encoding="utf-8")

# --- S3, the memory error ledger ---------------------------------------------------------------

LEDGER_E = (
    '[{"class":"correctable","event_rows":0,"reported_count":0},'
    '{"class":"uncorrectable","event_rows":0,"reported_count":0}]\n'
)


def rows(*changes: dict) -> str:
    base = [
        {"class": "correctable", "event_rows": 14, "reported_count": 20},
        {"class": "uncorrectable", "event_rows": 2, "reported_count": 3},
    ]
    for row, change in zip(base, changes, strict=False):
        row.update(change)
    return json.dumps(base) + "\n"


def test_sample_es_ledger_output():
    assert payloads.ledger(LEDGER_E) == {
        "correctable_event_rows": 0,
        "correctable_reported_count": 0,
        "uncorrectable_event_rows": 0,
        "uncorrectable_reported_count": 0,
    }


def test_each_count_goes_to_its_own_key():
    assert payloads.ledger(rows()) == {
        "correctable_event_rows": 14,
        "correctable_reported_count": 20,
        "uncorrectable_event_rows": 2,
        "uncorrectable_reported_count": 3,
    }


@pytest.mark.parametrize("value", [None, "14", 14.0, True, -1, 2**63])
def test_a_count_of_another_shape_is_unread(value):
    found = payloads.ledger(rows({"event_rows": value}))
    assert found["correctable_event_rows"] is UNREAD
    assert found["uncorrectable_event_rows"] == 2


def test_a_missing_count_is_unread():
    text = json.dumps(
        [
            {"class": "correctable", "event_rows": 14},
            {"class": "uncorrectable", "event_rows": 2, "reported_count": 3},
        ]
    )
    assert payloads.ledger(text)["correctable_reported_count"] is UNREAD


LEDGER_UNPARSED = {
    "empty": "",
    "not JSON": "Error: no such table: ecc_errors_v2\n",
    "not a list": '{"class": "correctable"}',
    "one row": json.dumps([{"class": "correctable", "event_rows": 0, "reported_count": 0}]),
    "three rows": rows()[:-2] + ',{"class":"extra","event_rows":0,"reported_count":0}]',
    "rows out of order": json.dumps(list(reversed(json.loads(rows())))),
    "another class": rows({"class": "fatal"}),
    "a row that is not an object": '[5, {"class":"uncorrectable","event_rows":0,'
    '"reported_count":0}]',
    "an extra column": rows({"first_seen": 0}),
    "a duplicate key": '[{"class":"correctable","event_rows":1,"event_rows":2,"reported_count":0},'
    '{"class":"uncorrectable","event_rows":0,"reported_count":0}]',
    "every count unreadable": rows(
        {"event_rows": "x", "reported_count": "x"}, {"event_rows": "x", "reported_count": "x"}
    ),
    "nested past any limit": "[" * 100_000 + "]" * 100_000,
}


@pytest.mark.parametrize("text", list(LEDGER_UNPARSED.values()), ids=list(LEDGER_UNPARSED))
def test_a_ledger_output_not_in_the_querys_shape_is_unparsed(text):
    with pytest.raises(payloads.Unparsed):
        payloads.ledger(text)


# --- S4, the power and thermal samples -------------------------------------------------------


def test_sample_es_five_samples():
    # The spec's discovery log, part 3 of root sample E.
    assert payloads.power(SAMPLE_E) == {
        "sample_elapsed_ns": [1006543000, 1011719875, 1008502124, 1011962250, 1011879791],
        "sample_thermal_pressure": ["Nominal"] * 5,
        "sample_cpu_power_mw": [
            Decimal("2675.49"),
            Decimal("2513.54"),
            Decimal("1641.05"),
            Decimal("566.227"),
            Decimal("665.099"),
        ],
        "sample_gpu_power_mw": [
            Decimal("50.6685"),
            Decimal("50.4092"),
            Decimal("60.4857"),
            Decimal("55.338"),
            Decimal("54.3543"),
        ],
        "sample_ane_power_mw": [Decimal("0")] * 5,
        "sample_combined_power_mw": [
            Decimal("2726.16"),
            Decimal("2563.95"),
            Decimal("1701.53"),
            Decimal("621.565"),
            Decimal("719.453"),
        ],
    }


def _plists() -> list[str]:
    return SAMPLE_E.split("\0")


def _edit(index: int, old: str, new: str) -> str:
    parts = _plists()
    assert old in parts[index]
    parts[index] = parts[index].replace(old, new, 1)
    return "\0".join(parts)


def test_a_missing_power_value_costs_that_one_element():
    text = _edit(4, "<key>gpu_power</key>", "<key>gpu_power_was</key>")
    found = payloads.power(text)
    assert found["sample_gpu_power_mw"][4] is UNREAD
    assert found["sample_gpu_power_mw"][:4] == [
        Decimal("50.6685"),
        Decimal("50.4092"),
        Decimal("60.4857"),
        Decimal("55.338"),
    ]
    assert found["sample_cpu_power_mw"][4] == Decimal("665.099")


@pytest.mark.parametrize("real", ["NaN", "inf", "1,5", "", "1e400000000000000000000"])
def test_a_real_that_is_not_a_plain_decimal_is_unread(real):
    text = _edit(0, "<real>2675.49</real>", f"<real>{real}</real>")
    assert payloads.power(text)["sample_cpu_power_mw"][0] is UNREAD


def test_an_exponent_form_is_read_exactly():
    text = _edit(0, "<real>2675.49</real>", "<real>6.95445e-05</real>")
    assert payloads.power(text)["sample_cpu_power_mw"][0] == Decimal("6.95445e-05")


def test_an_integer_where_a_real_belongs_is_read_as_the_same_decimal():
    text = _edit(0, "<real>2675.49</real>", "<integer>2675</integer>")
    assert payloads.power(text)["sample_cpu_power_mw"][0] == Decimal("2675")


def test_only_the_processor_dicts_own_keys_are_read():
    # A cpu_power nested deeper, under clusters, is not the sample's.
    text = _edit(0, "<key>cpu_power</key>", "<key>cpu_power_moved</key>")
    text = text.replace("<key>name</key>", "<key>cpu_power</key><real>1</real><key>name</key>", 1)
    assert payloads.power(text)["sample_cpu_power_mw"][0] is UNREAD


POWER_UNPARSED = {
    "empty": "",
    "four samples": "\0".join(_plists()[:4]),
    "six samples": "\0".join([*_plists(), _plists()[0]]),
    "not XML": "powermetrics: must be invoked as the superuser\n",
    "an entity declaration": "\0".join(
        [
            _plists()[0].replace(
                '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
                '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
                '<!DOCTYPE plist [<!ENTITY e "boom">]>',
                1,
            ),
            *_plists()[1:],
        ]
    ),
    "a sample that is not XML": "\0".join([*_plists()[:4], "not a plist"]),
    "a sample that is not a dict": "\0".join(
        [*_plists()[:4], '<?xml version="1.0"?><plist version="1.0"><array/></plist>']
    ),
    "every value missing": "\0".join(
        ['<?xml version="1.0"?><plist version="1.0"><dict/></plist>'] * 5
    ),
}


@pytest.mark.parametrize("text", list(POWER_UNPARSED.values()), ids=list(POWER_UNPARSED))
def test_a_power_output_not_in_the_plists_shape_is_unparsed(text):
    with pytest.raises(payloads.Unparsed):
        payloads.power(text)


def test_nothing_else_in_a_sample_is_kept():
    found = payloads.power(SAMPLE_E)
    assert set(found) == {
        "sample_elapsed_ns",
        "sample_thermal_pressure",
        "sample_cpu_power_mw",
        "sample_gpu_power_mw",
        "sample_ane_power_mw",
        "sample_combined_power_mw",
    }
    assert "synthetic-bootargs" not in repr(found) and "Mac17,2" not in repr(found)


def test_the_power_reader_never_imports_plistlib():
    # plistlib turns <real> into a binary float first (Test strategy part 3).
    tree = ast.parse(Path(payloads.__file__).read_text(encoding="utf-8"))
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import | ast.ImportFrom)
        for alias in (
            node.names if isinstance(node, ast.Import) else [ast.alias(node.module or "")]
        )
    }
    assert "plistlib" not in imported


def test_a_value_without_its_key_is_passed_over():
    text = _edit(0, "<dict>", "<dict><string>stray</string>")
    assert payloads.power(text)["sample_elapsed_ns"][0] == 1006543000


# --- the #346 review ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text", ["5", '"rows"', "null", "true"], ids=["a number", "text", "null", "true"]
)
def test_a_ledger_that_is_a_bare_json_value_is_unparsed(text):
    with pytest.raises(payloads.Unparsed):
        payloads.ledger(text)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("</plist>", "</plist>trailing"),
        ("</dict>\n</plist>", "</dict>"),
        ("<key>cpu_power</key>", "<key>cpu_power</key><real>1</real><key>cpu_power</key>"),
        ("<real>2675.49</real>", "<real>26&foo;75.49</real>"),
        ("<real>2675.49</real>", "<real>26<b/>75.49</real>"),
        ("<key>cpu_power</key>", "<wrapper/><key>cpu_power</key>"),
        ("<real>2675.49</real>", "<real>26<real>1</real>75.49</real>"),
        ("<key>cpu_power</key>", "stray text<key>cpu_power</key>"),
    ],
    ids=[
        "text after the plist",
        "a sample cut off after its dict",
        "a key twice in one dict",
        "an entity it cannot expand",
        "an element inside a real",
        "an element a plist never holds",
        "a plist element inside a value",
        "text between elements",
    ],
)
def test_a_sample_a_plist_writer_could_not_produce_is_unparsed(old, new):
    with pytest.raises(payloads.Unparsed):
        payloads.power(_edit(0, old, new))
