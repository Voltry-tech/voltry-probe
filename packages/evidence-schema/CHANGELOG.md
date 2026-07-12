# Changelog

All notable changes to `voltry-evidence-schema` are documented here, newest
first, one dated entry per release. Versioning is semantic, and the
distribution version is the schema version.

## [1.2.2] - 2026-07-12

Security patch, backward compatible. No wire-format or canonicalization change; the
embedded schema version string moves to 1.2.2 and bundles signed under any 1.x still
verify unchanged via the raw-bytes path.

- P-384 is now enforced when producing and loading keys, not only when verifying. Signing
  with a non-P-384 key raised nothing before and produced a bundle that failed its own
  verifier; `sign_bundle` now rejects any private key that is not on secp384r1, and
  `load_public_key_spki_b64` rejects any public key that is not on P-384 (so the verify
  and attestation paths that use it reject mismatched-curve keys at load time). Closes the
  re-audit N-02 finding.
- Softened two field descriptions that overstated hardware certainty: the row-remap counts
  are described as InfoROM-reported remaps counted toward the fixed cap, not a direct count
  of physical spare rows, and read alongside pending and failure state (re-audit N-04).

## [1.2.1] - 2026-07-11

Patch release: documentation and code-only fixes. No schema field was added,
removed, renamed, or retyped; the canonicalization rules are unchanged; bundles
signed under any 1.x version verify unchanged via the raw-bytes path
(`verify_bundle_json`).

- Prose and documentation overhaul across the package for the public repo:
  docstrings now explain mechanism and intent in plain language, and internal
  build vocabulary was removed.
- The worked example (`evidence_schema.samples.worked_example_a_bundle`) no
  longer claims an attestation freshness PASS it cannot substantiate: its
  placeholder report contains no challenge nonce, so a third party could never
  recompute the comparison. The sample now records `challenge=None` with
  `freshness=NOT_ASSESSED`, and its docstring explains how a real challenged
  scan earns PASS. The golden canonicalization vector was updated accordingly
  (sample content change only).
- `verify_bundle` and `verify_bundle_json` now return False, as documented,
  when the embedded public key uses an algorithm the crypto backend does not
  support (`cryptography.exceptions.UnsupportedAlgorithm` was previously
  uncaught and would raise).
- The versioning policy now states explicitly that PATCH covers code-only fixes
  (not just documentation) as long as field semantics and canonicalization are
  untouched.

## [1.2.0] - 2026-07-09

Additive minor release per the frozen versioning policy. Closes the attestation
freshness gap found while answering an independent review of the published
voltry-probe 0.2.2: a
genuine (nonce, vbios_hash, signatures) tuple could previously be replayed onto
a later bundle because the nonce was never compared to a verifier-chosen value.

- New `Attestation.challenge` (optional string): the operator-issued challenge
  nonce for the scan, recorded in the bundle so a third party can recompute the
  freshness comparison against the raw report's nonce (every certified claim
  must be independently recomputable).
- New `Attestation.freshness` (`GateResult`, default `NOT_ASSESSED`): PASS when
  the report's nonce matches the operator challenge, FAIL on mismatch (replay
  indication), NOT_ASSESSED when no challenge was issued. A report that was not
  challenge-bound is never marked fresh.
- Bundles parsed from pre-1.2.0 data read back with `challenge` as None and
  `freshness` as NOT_ASSESSED, never a fabricated PASS.
- Consistency is enforced at the model boundary: `freshness` PASS or FAIL with
  no recorded `challenge` is rejected (there would be nothing for a third party
  to recompute the comparison against).
- Cross-version verification locked for this transition by a committed
  1.1.0-signed fixture (`tests/fixtures/bundle_v1_1_0_signed.json`), mirroring
  the 1.0.0 fixture.
- The comparison itself is enforced in `voltry-probe`'s `verify_attestation`
  (challenge match, with a `measured_at` freshness window as the lower-confidence
  fallback when no challenge was issued).

## [1.1.0] - 2026-07-02

Additive minor release per the frozen versioning policy.

- Curve honesty: verification now rejects a signature whose key is not on P-384,
  even though the `algorithm` field declares P-384. A weaker/different curve
  masquerading as the declared one no longer verifies (found by a security audit;
  not a forgery, fails closed).
- The frozen crypto core (canonicalize + sign + models) is now enforced at 100%
  coverage in CI, not just measured.

- New `DutyBlock` on `MeasuredBlock.duty`: cumulative GPU-hours, thermal
  cycles, lifetime energy, sustained-high-power hours, with an explicit
  accumulation `basis`. All fields optional; duty is registry-accumulated and
  never fabricated from a single read.
- New `verify_bundle_json`: verifies a bundle from its raw JSON
  representation, byte-faithful across schema versions. A bundle signed under
  1.0.0 verifies under 1.1.0 and forever after; this is the documented
  cross-version verification path and is locked by a committed 1.0.0-signed
  fixture (`tests/fixtures/bundle_v1_0_0_signed.json`).
- Bundles parsed from 1.0.0 data read back with `duty` as None, never a
  fabricated default.

## [1.0.0] - 2026-07-02

First public release.

- Typed evidence bundle models (identity, measured, functional, raw reads,
  environment, provenance, signature), captured wide.
- RFC 8785 (JCS) canonical serialization as the single path to signable bytes.
- ECDSA P-384 / SHA-384 sign and verify over canonical bytes.
- Generated JSON Schema for cross-language consumers
  (`evidence-schema-jsonschema`).
- Python 3.10 through 3.13. Typed (`py.typed`).
- Distribution renamed to `voltry-evidence-schema`; the import name remains
  `evidence_schema`.
