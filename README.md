# Voltry Probe

Source for the two Voltry packages published on PyPI:

- [`voltry-probe`](packages/voltry-probe/) - local evidence capture, signing,
  and offline certificate rendering for data-center GPUs. Scan reads NVML
  without mutating the device; submission is a separate opt-in command.
- [`voltry-evidence-schema`](packages/evidence-schema/) - the signed evidence
  bundle wire format: canonical JSON (RFC 8785) with ECDSA P-384 signatures.
  Import name `evidence_schema`.

Each package's README covers installation and usage. The published sdists on
PyPI correspond to the `packages/` directories here, so you can diff a release
against this tree.

```
pip install voltry-probe
```

## Development

```
uv sync --all-packages --dev
uv run --package voltry-probe pytest packages/voltry-probe -q
uv run --package voltry-evidence-schema pytest packages/evidence-schema -q
```

Contribution guides live in each package
([probe](packages/voltry-probe/CONTRIBUTING.md),
[schema](packages/evidence-schema/CONTRIBUTING.md)).

## Security

See [SECURITY.md](SECURITY.md). Do not open public issues for suspected
signature or verification flaws.

## Releases

Releases are tagged and published to PyPI with trusted publishing (OIDC) and
PEP 740 attestations from the maintainers' release pipeline; this repository
mirrors the released source. Certificates verify at
[verify.voltry.io](https://verify.voltry.io).

## License

Apache-2.0
