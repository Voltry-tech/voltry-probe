# Contributing to voltry-evidence-schema

This package lives in the Voltry monorepo, which uses a `uv` workspace. Set up
from the repository root:

```bash
uv sync --all-packages --dev
```

## Running the tests

```bash
uv run --package voltry-evidence-schema pytest packages/evidence-schema -q
```

The suite is fast (a few seconds) and includes property tests plus a golden
canonicalization vector. If a schema change is intentional, the failing tests
tell you what to regenerate (the golden hash, the committed JSON Schema
artifact).

## Formatting and linting

```bash
uv run black packages/evidence-schema
uv run ruff check packages/evidence-schema
```

## Tests first for the core

Canonicalization and sign/verify are the load-bearing parts of this package: a
silent change there breaks verification of bundles that are already signed and
stored. Changes to `canonicalize.py`, `sign.py`, or field semantics in
`models.py` should land with the test that pins the new behavior written
first, and must not change the canonical bytes of existing bundles (the
cross-version fixtures under `tests/fixtures/` enforce this).

## Security reports

Do not open a public issue for a vulnerability. See
[SECURITY.md](https://github.com/Voltry-tech/voltry-probe/blob/main/SECURITY.md) at the
repository root for how to report privately.

Pull requests welcome.
