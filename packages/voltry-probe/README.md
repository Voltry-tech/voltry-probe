# Voltry Probe

Voltry Probe captures, signs, and renders condition and provenance evidence
for data-center GPUs. `voltry scan` reads device state over NVML, read-only:
the scan path issues only non-mutating reads (no resets, reconfiguration, or
stress); validate against your own driver and GPU models before fleet-wide
rollout. The readings are signed into an evidence bundle, and
`voltry cert` renders that bundle into a self-contained HTML certificate you
can open with no network at all.

Two scoping notes, so the claims match the code you are installing:

- Live capture is NVML only in this release. The bundle format carries DCGM,
  Redfish, and attestation payloads, and `scan` maps them when a captured
  fixture provides them, but there is no live DCGM or Redfish collector yet.
- Attestation is verification, not capture. When a capture carries an
  operator-supplied attestation report, the probe verifies the ECDSA chain
  against a trusted root (and, if you issue a `--challenge`, freshness). The
  probe does not yet pull the report from the device itself.

It records what the hardware is. It never states or implies a price.

## Install

For live scans (needs an NVIDIA GPU and driver):

```bash
pipx install "voltry-probe[hardware]"
```

For everything else (fixture scans, certificate rendering, verification):

```bash
pipx install voltry-probe
```

No pipx? A stock Mac ships neither pipx nor a recent enough Python. If you
have [uv](https://docs.astral.sh/uv/) (for example from `brew install uv`), it
installs the tool and fetches a Python for it in one step:

```bash
uv tool install --python 3.12 voltry-probe
```

Extras work the same way with either tool, for example
`uv tool install --python 3.12 "voltry-probe[submit]"`.

Requires Python 3.10 or newer; stock DGX OS and Ubuntu 22.04 hosts work as-is.
`pip install` inside a virtualenv works too. Without `[hardware]`, a live
`voltry scan` exits with a clean error naming the missing extra and the exact
pip command to fix it; every other workflow needs no extra. `voltry submit`
(the opt-in submission client) lives behind the separate `[submit]` extra.

## Sixty seconds to a certificate

With a GPU and the `[hardware]` extra installed:

```bash
# 1. Scan. Read-only, works fully offline and air-gapped.
#    Reads live hardware; signs with your operator key.
voltry scan --signing-key operator.pem --out bundle.json

# 2. Render. A self-contained HTML certificate, no network needed to view.
voltry cert bundle.json --out cert.html
```

That is the whole loop. `voltry submit` exists as a separate, explicit,
opt-in step (see [Submitting to the Voltry registry](#submitting-to-the-voltry-registry));
scanning and rendering never phone home.

## No GPU? Run the same loop on a captured fixture

The test suite ships a real H100 capture. Fetch it, scan it with a throwaway
key, and render:

```bash
curl -LO https://raw.githubusercontent.com/Voltry-tech/voltry-probe/main/packages/voltry-probe/tests/fixtures/h100_read.json
voltry scan --fixture h100_read.json --ephemeral-key --out bundle.json
voltry cert bundle.json --out cert.html
```

This exercises the exact same reader, builder, signer, and renderer as a live
scan; only the source of the raw payloads differs.

## What read-only means

The probe never writes to, resets, reconfigures, or stress-tests a device
during a scan. It does write the local output files you ask for (the bundle
and the certificate).

Functional qualification (which does exercise the device) is a separate,
explicit operation and never part of a scan: it requires importing
`voltry_probe.functional` and giving drain consent at the call. This release
maps functional results captured elsewhere into the bundle; it does not yet
run the live diagnostics itself.

| Operation | Device mutation | Network |
|---|---|---|
| `import voltry_probe` | No | No |
| `voltry scan` | No | No |
| `voltry cert` | No (no device access) | No |
| `voltry submit` | No | Yes: opt-in, consent flag required |
| `voltry_probe.functional` | Mapping only in this release; live runs need drain consent | No |

## What the certificate says, and what it does not

The certificate keeps measured facts and modeled estimates in separate blocks
that never look alike:

- Deterministic gates: authenticity, firmware integrity, functional and
  sanitization results. Pass or fail, no model in the loop.
- Measured condition: ECC and Xid history, retired and remapped pages, spare
  rows remaining, throttle and clock behavior. Raw values against published
  thresholds.
- Provenance: certification history on the device's permanent identity. The
  platform registry may enforce append-only history so failed attempts cannot
  be hidden; this package alone signs individual bundles and does not provide
  that ledger.

It never contains a price, a dollar figure, or a lifetime guarantee. Power-chain
exposure reads "Not Assessed" unless the facility itself was instrumented; it
is never inferred from board power.

## Verifying a bundle yourself

Every bundle is signed (ECDSA P-384 over RFC 8785 canonical JSON) and anyone
with the `voltry-evidence-schema` package can check it. Verify the stored
bytes, not a re-parsed model: parsing materializes the current schema's
defaults, so a bundle signed under an older schema version would
re-canonicalize to different bytes and fail even though nothing was tampered
with. `verify_bundle_json` reproduces exactly the bytes that were signed.

```python
from pathlib import Path

from evidence_schema import verify_bundle_json

assert verify_bundle_json(Path("bundle.json").read_bytes())
```

Be clear about what this check proves. It proves the bundle's bytes have not
been modified since signing, under the public key embedded in the bundle
itself. It does not prove that key belongs to an authorized signer, and it
does not confirm the Signature envelope's `signer` or `signed_at` labels;
those are confirmed against the registry at the platform verify endpoint,
https://verify.voltry.io.

## Submitting to the Voltry registry

`voltry submit` is the only command that touches the network, and it does
nothing unless you pass `--i-consent-to-submit`. It needs the `[submit]`
extra (on a GPU host, `"voltry-probe[hardware,submit]"` gets both; with pipx,
add `--force` if the probe is already installed without it):

```bash
pipx install "voltry-probe[submit]"
voltry submit bundle.json --i-consent-to-submit
```

By default it uploads to the Voltry registry at
`https://api.voltry.io/v1/ingest`. Pass `--url` to send the bundle to a
different platform instead. The URL has to be https; plain http is only
allowed with `--allow-insecure-http`, which is meant for a local test server.

What leaves your machine is the bundle file exactly as `voltry scan` wrote
it: every measured reading, the raw reads it was built from, and the device
identifiers in it (serial number and GPU UUID). Before anything is sent, the
command checks that the file is a valid bundle and that its signature
verifies, and refuses to upload it otherwise. Your consent also travels with
the request, as `consent=true` on the URL, because the registry turns away
any upload that does not carry it. Accepted bundles are appended to the
device's permanent history in the registry; they are not edited or removed
later.

### Your signing key has to be registered first

Right now the registry only accepts self-submitted bundles signed by an
operator key that Voltry has registered. That is what stops a stranger from
flooding the registry with records. A bundle signed by any other key is
turned away with `unauthorized_signer` (HTTP 403), and that includes every
bundle made with `--ephemeral-key`, since a throwaway key can never be
registered.

To get set up:

1. Create one persistent P-384 operator key and keep it private. This works
   with the `openssl` that ships on macOS and on Linux:

   ```bash
   openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out operator.pem
   chmod 600 operator.pem
   ```

2. Export its public half. This file is safe to share:

   ```bash
   openssl pkey -in operator.pem -pubout -out operator.pub.pem
   ```

3. There is no self-service registration yet. Contact Voltry
   (https://www.voltry.io) and send them `operator.pub.pem`. Never send
   `operator.pem`.

4. Once the key is registered, scan with it and submit:

   ```bash
   voltry scan --signing-key operator.pem --out bundle.json
   voltry submit bundle.json --i-consent-to-submit
   ```

Every bundle you sign carries the same public key in its
`signature.public_key_spki_b64` field, and that is what the registry checks
against its list.

If the registry refuses an upload, `voltry submit` prints the reason code
and message it sent back (for example `unauthorized_signer` or
`duplicate_bundle`) and exits with status 4.

## Security

To report a vulnerability, see the repository security policy:
https://github.com/Voltry-tech/voltry-probe/blob/main/SECURITY.md. Please report
suspected signature bypasses or key-handling flaws privately, not in a public
issue.

## License

Apache-2.0.
