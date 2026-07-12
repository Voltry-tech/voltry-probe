# voltry-evidence-schema

The Voltry evidence bundle: the signed contract behind every Voltry Probe scan
and certificate.

Note the naming: the PyPI distribution is `voltry-evidence-schema`, the Python
package you import is `evidence_schema`.

```bash
pip install voltry-evidence-schema
```

```python
import evidence_schema
```

## What it provides

- Typed pydantic v2 models (`EvidenceBundle` and its blocks). The bundle
  carries measured facts only (there is no modeled-estimate type in this
  package), no single score anywhere, and no price field.
- One canonical serializer: RFC 8785 (JCS) over the bundle minus its
  signature. This is the only path to signable bytes.
- ECDSA P-384 (secp384r1) with SHA-384 sign and verify over those canonical
  bytes.
- A generated JSON Schema for cross-language consumers.

## Verifying a bundle

To check a stored bundle as a third party, verify the raw bytes exactly as they
were stored. This is the version-stable path: it reproduces the bytes that were
signed no matter which schema version signed them, so a bundle signed years ago
under an older 1.x still verifies today.

```python
from evidence_schema import verify_bundle_json

raw = open("bundle.json", "rb").read()  # the stored bytes, unmodified
print(verify_bundle_json(raw))  # True only if the signature covers these exact bytes
```

A True result proves integrity: the bundle is byte-identical to what the holder
of the embedded public key signed. It does not prove that key belongs to an
authorized signer; binding keys to registered operators is the platform's job,
checked against the Voltry registry.

Command line:

```bash
# Round-trip demo: build, canonicalize, sign, verify, tamper, verify fails
python -m evidence_schema.demo

# Emit the JSON Schema for non-Python consumers
evidence-schema-jsonschema -o evidence_bundle.schema.json
```

## Stability

The schema is versioned semantically, and a bundle captured today remains
valid and verifiable indefinitely: the 1.x field set only ever grows, existing
fields never change meaning, and verification runs over the raw stored bytes
so later schema versions cannot disturb it. Additive fields are minor
versions; anything breaking is a major version with a migration path.
Canonical bytes are covered by golden-vector tests in CI on Python 3.10 (the
supported floor) and 3.12; the package supports 3.10 through 3.13.

## Security

To report a vulnerability, see [SECURITY.md](https://github.com/Voltry-tech/voltry-probe/blob/main/SECURITY.md).

## License

Apache-2.0.
