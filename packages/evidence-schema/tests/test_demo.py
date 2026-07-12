"""The round-trip demo: build, canonicalize, sign, verify, tamper, verify fails."""

from __future__ import annotations

import io

from evidence_schema.demo import main, run


def test_demo_round_trips_and_detects_tamper():
    out = io.StringIO()
    ok = run(out=out)
    text = out.getvalue()
    assert ok is True
    assert "verify         : PASS" in text
    assert "tamper detected" in text
    assert "JSON Schema" in text
    assert "Voltry Evidence Bundle" in text


def test_demo_main_returns_zero():
    assert main() == 0
