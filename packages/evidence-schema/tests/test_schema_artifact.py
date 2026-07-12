"""The committed JSON Schema artifact must never drift from the models.

``schema/evidence_bundle.schema.json`` is the published cross-language contract. It is
generated from the pydantic models, so this test fails loudly if the two ever diverge
(regenerate with ``uv run evidence-schema-jsonschema -o schema/evidence_bundle.schema.json``).
"""

from __future__ import annotations

import json
from pathlib import Path

from evidence_schema.jsonschema import generate_json_schema

_ARTIFACT = Path(__file__).resolve().parent.parent / "schema" / "evidence_bundle.schema.json"


def test_committed_schema_artifact_exists():
    assert _ARTIFACT.exists(), f"missing published schema artifact: {_ARTIFACT}"


def test_committed_schema_matches_models():
    committed = json.loads(_ARTIFACT.read_text(encoding="utf-8"))
    assert committed == generate_json_schema(), (
        "committed schema artifact has drifted from the models; regenerate with "
        "`uv run evidence-schema-jsonschema -o schema/evidence_bundle.schema.json`"
    )
