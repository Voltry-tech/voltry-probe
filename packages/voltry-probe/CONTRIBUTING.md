# Contributing to voltry-probe

Thanks for looking at the probe. This is the open, read-only agent: PyPI
`voltry-probe`, import `voltry_probe`, CLI `voltry`.

## Dev setup

The repo is a `uv` workspace. From the repo root:

```bash
uv sync --all-packages --dev
```

That installs this package (and its sibling `voltry-evidence-schema`) in
editable mode with all dev tools. No GPU needed: the test suite runs entirely
against captured fixtures.

## Running the tests

From the repo root:

```bash
uv run pytest packages/voltry-probe -q
```

Format and lint before pushing:

```bash
uv run black packages/voltry-probe
uv run ruff check packages/voltry-probe
```

## The invariant tests

Two test files enforce the boundaries the whole product rests on. Any
contribution must keep them green, and a change that needs to weaken them is
almost certainly wrong:

- `tests/test_read_only.py`: a scan never calls a mutating NVML API and never
  touches the network. Device-mutating code is allowed only under
  `voltry_probe/functional/`, behind explicit drain consent.
- `tests/test_import_safety.py`: `import voltry_probe` loads no functional,
  hardware, or network modules. The package root has to stay safe to import
  on any machine, including air-gapped ones.

## Security issues

Do not open a public issue for a suspected signature bypass or key-handling
flaw. See SECURITY.md at the repo root for the private reporting channel.

## Pull requests

- One concern per PR, with tests. Bug fixes come with a test that fails
  before the fix.
- Include the test output in the PR description; a claim that the tests pass
  is not evidence that they did.
- No new runtime dependencies without discussion first: scan and cert are
  deliberately offline and dependency-light.
- Nothing the probe emits may state or imply a price for the hardware, and
  nothing outside `voltry_probe/functional/` may mutate a device. These are
  hard rules, not review preferences.
