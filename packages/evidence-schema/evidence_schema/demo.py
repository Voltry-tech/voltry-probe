"""``python -m evidence_schema.demo``: round-trip the contract end to end.

Builds a sample bundle, canonicalizes it, signs it with a freshly generated key,
verifies it, tampers a field, shows that verification now fails, and prints the JSON
Schema. Simulated data only; no real device reads and no persistent keys.
"""

from __future__ import annotations

import sys
from typing import TextIO

from .canonicalize import canonical_bytes
from .jsonschema import json_schema_str
from .samples import worked_example_a_bundle
from .sign import generate_keypair, sign_bundle, verify_bundle


def run(out: TextIO = sys.stdout) -> bool:
    """Run the round-trip demo, writing a narrative to ``out``. Returns True on success."""

    def line(msg: str = "") -> None:
        out.write(msg + "\n")

    bundle = worked_example_a_bundle()
    sr = bundle.measured.spare_rows
    exposure = "ASSESSED" if bundle.provenance.exposure_assessed else "NOT ASSESSED"
    line("Voltry evidence-schema demo")
    line("=" * 40)
    line(f"schema_version : {bundle.schema_version}")
    line(f"bundle_id      : {bundle.bundle_id}")
    line(f"device         : {bundle.identity.device_part}  ({bundle.provenance.tier})")
    line(f"spare rows     : {sr.remaining}/{sr.cap} remaining")
    line(f"exposure       : {exposure}")

    payload = canonical_bytes(bundle)
    line(f"\ncanonical bytes: {len(payload)} bytes")
    line(f"canonical head : {payload[:72].decode('utf-8')}...")

    private_key = generate_keypair()
    signed = sign_bundle(bundle, private_key, signer="operator")
    sig = signed.signature
    line(f"\nsigned         : algorithm={sig.algorithm} canon={sig.canonicalization}")

    ok = verify_bundle(signed)
    line(f"verify         : {'PASS' if ok else 'FAIL'}")
    if not ok:  # pragma: no cover - defensive: only fires on a contract regression
        line("UNEXPECTED: a freshly signed bundle failed to verify")
        return False

    # Tamper: changing a measured fact without re-signing changes the canonical
    # bytes, so verification must fail.
    tampered = signed.model_copy(deep=True)
    tampered.measured.spare_rows.remaining = 1
    tampered_ok = verify_bundle(tampered)
    line("tamper         : set spare_rows.remaining 509 -> 1")
    line(f"verify(tamper) : {'PASS (BUG!)' if tampered_ok else 'FAIL (correct: tamper detected)'}")
    if tampered_ok:  # pragma: no cover - defensive: only fires on a contract regression
        line("UNEXPECTED: tampered bundle still verified")
        return False

    line("\nJSON Schema")
    line("-" * 40)
    line(json_schema_str())
    return True


def main() -> int:
    """Entry point. Returns 0 on a successful round-trip, 1 otherwise."""
    return 0 if run() else 1


if __name__ == "__main__":  # pragma: no cover - script entry; main() is tested directly
    raise SystemExit(main())


__all__ = ["run", "main"]
