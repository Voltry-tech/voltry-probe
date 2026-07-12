"""JSON Schema generation for cross-language consumers."""

from __future__ import annotations

import json

import evidence_schema as es
from evidence_schema.jsonschema import generate_json_schema, json_schema_str, main

_PRICE_TOKENS = (
    "price",
    "valuation",
    "appraisal",
    "resale",
    "asset_value",
    "dollar",
    "worth",
    "score",
    "grade",
)


def _all_property_names(schema: dict) -> set[str]:
    names: set[str] = set()

    def walk(node):
        if isinstance(node, dict):
            props = node.get("properties")
            if isinstance(props, dict):
                names.update(props.keys())
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(schema)
    return names


def test_schema_generates_with_blocks():
    schema = generate_json_schema()
    assert schema["x-schema-version"] == es.SCHEMA_VERSION
    props = schema["properties"]
    for block in ("identity", "measured", "raw_reads", "provenance", "signature", "agent"):
        assert block in props, f"missing top-level block: {block}"


def test_schema_has_no_price_or_score_property():
    names = _all_property_names(generate_json_schema())
    offenders = [n for n in names for tok in _PRICE_TOKENS if tok in n.lower()]
    assert not offenders, f"forbidden property names in schema: {offenders}"


def test_schema_str_is_valid_sorted_json():
    text = json_schema_str()
    parsed = json.loads(text)
    assert parsed["title"] == "Voltry Evidence Bundle"
    # Written with sort_keys=True, so re-dumping with sort_keys yields the same string.
    assert json.dumps(parsed, indent=2, sort_keys=True) == text


def test_main_writes_file(tmp_path):
    out = tmp_path / "schema" / "evidence_bundle.schema.json"
    rc = main(["-o", str(out)])
    assert rc == 0
    assert out.exists()
    assert json.loads(out.read_text())["x-schema-version"] == es.SCHEMA_VERSION


def test_main_stdout(capsys):
    rc = main([])
    assert rc == 0
    captured = capsys.readouterr()
    assert "Voltry Evidence Bundle" in captured.out
