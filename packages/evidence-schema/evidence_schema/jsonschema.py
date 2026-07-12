"""Emit the JSON Schema for the evidence bundle, for cross-language consumers.

The schema is derived from the pydantic models (the single source of truth) so it can
never drift from the contract. ``main`` writes it to a file (default
``schema/evidence_bundle.schema.json``) or stdout, and is exposed as the
``evidence-schema-jsonschema`` console script.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .models import EvidenceBundle
from .version import SCHEMA_VERSION


def generate_json_schema() -> dict:
    """Return the JSON Schema (draft 2020-12) for :class:`EvidenceBundle`."""
    schema = EvidenceBundle.model_json_schema()
    schema["$id"] = f"https://voltry.dev/schema/evidence_bundle/{SCHEMA_VERSION}.json"
    schema["title"] = "Voltry Evidence Bundle"
    schema["x-schema-version"] = SCHEMA_VERSION
    return schema


def json_schema_str() -> str:
    """The JSON Schema as a stably-formatted (sorted-key) JSON string."""
    return json.dumps(generate_json_schema(), indent=2, sort_keys=True)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point: write the JSON Schema to a file or stdout."""
    parser = argparse.ArgumentParser(description="Emit the Voltry evidence-bundle JSON Schema.")
    parser.add_argument(
        "-o",
        "--out",
        type=Path,
        default=None,
        help="Output path (default: stdout). E.g. schema/evidence_bundle.schema.json",
    )
    args = parser.parse_args(argv)
    text = json_schema_str()
    if args.out is None:
        sys.stdout.write(text + "\n")
    else:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text + "\n", encoding="utf-8")
        sys.stdout.write(f"wrote {args.out}\n")
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised via main() in tests
    raise SystemExit(main())


__all__ = ["generate_json_schema", "json_schema_str", "main"]
