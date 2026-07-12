# Changelog

All notable changes to `voltry-probe` are documented here, newest first, one
dated entry per release.

## [0.3.2] - 2026-07-12

Security and honesty patch, backward compatible. No wire-format change. Depends on
evidence-schema >= 1.2.2 for the curve enforcement below.

- P-384 is enforced at every producer boundary, closing the re-audit N-02 finding. The
  CLI signing-key and trusted-root loaders reject any key not on secp384r1, and the
  attestation verifier refuses a non-P-384 device key (via the schema loader) or trusted
  root. Previously the CLI could sign with a P-256 key, emitting a bundle that failed its
  own verifier, and the attestation path accepted P-256 keys.
- The certificate no longer presents a bare "spare rows remaining" headroom number. It
  shows the InfoROM remap margin as used-against-cap, splits correctable from
  uncorrectable remaps, and renders row-remap failure and pending states as prominent
  rows that lead the group so a failure cannot hide under a clean-looking margin
  (re-audit N-04).
- Public-facing wording corrected (re-audit N-05/N-06): dropped "safe on a live
  production fleet" for a scoped non-mutating-reads statement with a validate-before-
  rollout note; scoped the append-only/cherry-picking claim to the platform registry
  rather than this standalone package; replaced "collects no personal data" with an
  accurate note that device identifiers (serial, GPU UUID) are collected and are
  linkable while no account identity is; removed the Dockerfile claim that the image is
  cosign-signed and Trivy-scanned in CI, which no public workflow runs; and replaced
  "verbatim/byte-exact" raw-reads language with "normalized JSON snapshot with an
  integrity hash over the canonical bytes."
- The default methodology identifier is now a content hash of the read-mode methodology
  rather than a bare "read-v0" label, so methodology_version_hash carries an actual hash.

## [0.3.1] - 2026-07-11

Public-repository polish release. No wire-format changes; the behavior
corrections below are listed individually.

- An attestation report only binds the permanent identity (`ecc384_id`) when
  its signatures verified against the trusted root. A report that fails
  verification, or is present but unverified because no trusted root was
  supplied, no longer donates its `device_id`; the NVML-read UUID is used
  instead. Operators who scanned attested captures without `--trusted-root`
  will see the identity move to the GPU UUID on their next scan.
- A missing, unreadable, or invalid `--fixture` file exits with a one-line
  error instead of a traceback, including payloads that parse but lack
  required health counters.
- `TelemetrySample` and `MonitorSession` reject naive (timezone-free)
  timestamps at construction instead of failing later in the bundle builder.
- The live memory-temperature read now checks the per-field NVML return
  status instead of suppressing all attribute and shape errors, so parser
  bugs surface instead of vanishing (live-hardware path only).

- Documentation rewritten for the public repository. The README now describes
  exactly what the shipped code does: live capture is NVML only, attestation
  is verification of an operator-supplied report (there is no live DCGM or
  Redfish collector yet), and the install instructions distinguish the
  `[hardware]` extra needed for live scans from the plain install that covers
  fixture scans, rendering, and verification. The bundle-verification example
  now uses `verify_bundle_json` over the stored bytes, which survives schema
  upgrades, and states plainly what that check does and does not prove.
- The decorative QR placeholder is removed from the offline certificate. It
  encoded nothing and could be mistaken for a verification affordance.
- The unused `sushy` dependency is removed from the `[hardware]` extra;
  nothing in the package imports it (there is no live Redfish reader yet).
- A live `voltry scan` without the `[hardware]` extra installed now exits
  with a clean error naming the extra and the pip command to install it,
  instead of a traceback. An unreadable or malformed `--trusted-root` file
  likewise produces a clean error.
- The attestation freshness window no longer accepts future-dated capture
  timestamps: a report claiming to be measured after the verification time is
  outside the window, not fresh.
- The retired-pages count and Xid events no longer conflate an absent reading
  with a measured zero: a payload reporting `retired: 0` keeps that measured
  value instead of being overwritten by a fallback sum, and a malformed Xid
  entry is skipped rather than recorded as "Xid 0". (The pending/failure
  flags keep their schema defaults; live capture always writes them.)
- Throttle stability flags now match exact normalized reason names emitted by
  live capture instead of substring matching, so an unrelated reason string
  containing "power" can no longer flip the power-throttle flag.
- The bundle-builder keyword surfaces are now explicitly typed.

## [0.3.0] - 2026-07-09

Trust-boundary release, prompted by an independent review of the published
0.2.2 package. The public API now matches the public claims exactly.

- Attestation freshness (closes a replay gap found while answering that
  review): `verify_attestation` now takes an `operator_challenge` and
  requires the report's signature-verified nonce to echo it exactly; a genuine
  but replayed report fails as a replay indication (authenticity gate FAIL,
  disqualifying). Without a challenge the verdict is unchanged for existing
  flows, but the outcome is marked (`freshness` NOT_ASSESSED) and confidence
  steps down, resting on a configurable `measured_at` freshness window
  (default 24 h) as the weak fallback. The issued challenge and the freshness
  result are recorded in the bundle (evidence-schema 1.2.0) so third parties
  can recompute the comparison. `voltry scan` gains `--challenge`, and
  `build_read_bundle` gains `operator_challenge`. Challenges shorter than 16
  characters are refused loudly (a guessable challenge defeats the protection),
  and an unknown attestation age scores as outside the window, never as fresh.
- The package root is limited to non-mutating, non-networked APIs. Functional
  APIs moved under `voltry_probe.functional` and are no longer re-exported
  from the root: `from voltry_probe.functional import build_functional_bundle,
  map_functional_results`. Breaking change, hence the minor version bump.
- `FunctionalRunner` is gone from the public API. Its live path was never
  runnable from a pip install, so advertising it was wrong. What shipped as
  `FunctionalRunner(...).run(results)` is now the pure function
  `map_functional_results(results)`, which needs no drain consent because it
  touches no hardware. Drain consent is now checked at the live-execution
  boundary, on every call, and live execution stays private until it runs on
  validated hardware.
- The runtime version is read from the installed distribution metadata, so
  `voltry --version` can no longer drift from the wheel.
- `voltry submit` validates before anything leaves the machine: the file must
  parse as an evidence bundle and its signature must verify, the ingest URL
  must be https (or `--allow-insecure-http` for local endpoints), a rejected
  or failed upload exits nonzero with a clean error instead of printing
  "submitted", and network failures no longer produce a raw traceback.
- An encrypted or unreadable signing key PEM now produces a clean error
  instead of a traceback.
- Boundary claims are now enforced by executable tests, not source grep alone:
  a fresh-process import test proves the root loads no functional, hardware,
  or network modules; a runtime NVML spy proves a live scan touches only
  read APIs; scan and cert run under blocked sockets and subprocesses; and
  the offline guard asserts unconditionally.
- Shipped prose (docstrings, comments, README, container) now describes
  operations instead of internal roadmap shorthand, and scopes every
  read-only claim to device state and network behavior. The container
  comments state precisely what is collected: device identifiers, no
  personal data.

## [0.2.2] - 2026-07-05

Measured-honesty fix in the NVLink reader, found by independent audit.

- NVLink error counters are now banked per counter, and only when actually
  measured: the counter's NVML_NVLINK_ERROR_DL_* constant must resolve and at
  least one per-link read must succeed. 0.2.1 guarded only the all-or-nothing
  case; on current nvidia-ml-py (12.575.51, 13.610.43), which dropped
  NVML_NVLINK_ERROR_DL_CRC but kept REPLAY/RECOVERY and the counter API, it
  banked a fabricated crc_errors: 0 even though CRC was never read. The key is
  now omitted (renders Not Assessed), matching how the probe treats all other
  absent telemetry. Same treatment when the constants resolve but the device
  refuses every per-link counter read.
- A genuinely-measured zero still banks as 0: a clean read is a valid fact.

## [0.2.1] - 2026-07-05

Hardening for the live path on the full range of rental and consumer hardware,
based on the NVML per-device-class support matrix. Previously a live scan of a
device outside the certifiable envelope died with a raw driver traceback.

- Honest refusals: a live scan of a device that cannot expose the required
  memory-health reads now raises `UnsupportedGpuError` (exported at package
  level) with a diagnosis naming the device and the reason, and `voltry scan`
  exits with a clean, specific error instead of a traceback. The cases:
  - consumer GPUs with no ECC memory (GeForce class), disambiguated from
  - ECC-capable devices with ECC currently disabled (common on workstation
    cards such as the RTX A6000, which ship ECC-off), with the fix named;
  - pre-Ampere devices with no row remapping (Tesla V100, T4, P100 class);
  - MIG-enabled devices, where row remapping is unreadable even on the parent
    handle.
- Board serial is now an optional read: on devices with no inforom serial
  (GeForce class, some virtualized environments) the reader omits the field
  instead of crashing; identity binds to the GPU UUID and the bundle records
  serial "UNKNOWN". Never fabricated.
- A generic NVML error on a required read still propagates unchanged: a driver
  fault stays a driver fault, distinct from an honest device-class refusal.
- More fields sealed into the signed record on every successful scan: MIG state (closing the
  gap where MIG appeared only in refusal messages), GPU core count, HBM memory
  temperature via the field-values API (banked only when the per-field status
  is clean; GDDR cards without the sensor omit it), and the per-bank
  row-remapper histogram where the binding exposes it.
- NVLink capture survives current nvidia-ml-py builds, which dropped the legacy
  error-counter API (the NVML_NVLINK_ERROR_DL_* constants and
  nvmlDeviceGetNvLinkErrorCounter). Link state is still captured; the error
  counters are omitted when the binding lacks the API, rendering Not Assessed
  instead of crashing the scan. Found live on a rented A100 SXM4, where 0.2.0
  dies with an AttributeError on any NVLink-bearing card.
- Refusal diagnoses only assert what was actually read: the pre-Ampere claim is
  made only when the device architecture was read and predates Ampere, and the
  no-ECC claim only on a clean NotSupported from the ECC-mode read (virtualized
  guests that hide board-level reads get an honest "not readable here" message
  instead of a fabricated device-class fact).

## [0.2.0] - 2026-07-04

- Lifetime duty (the odometer) on the certificate: GPU-hours, thermal cycles,
  sustained high-power time, energy through board, and the accumulation basis.
  Duty is caller-supplied (registry deltas or continuous monitoring) via a new
  `duty` parameter on `build_read_bundle`; the builder never derives it from a
  single point-in-time read, and absent accumulation renders
  "not accumulated (single read)", never zero hours.
- Brand refresh: the vendored token CSS and the offline certificate stylesheet
  are regenerated from the current brand source, and the offline certificate
  now shares its stylesheet rules with the web certificate so both render
  identically.
- Full Tier-1 live capture: thermals, clocks, power limits, decoded throttle
  reasons, PCIe link health (gen/width/replay), NVLink state and error
  counters, ECC mode disclosure, and observed driver/NVML/CUDA versions.
  Optional telemetry the device does not expose is omitted (renders Not
  Assessed), never fabricated; required health counters still fail loudly.
- Xid honesty: when a capture carried no Xid event source, the certificate
  renders "not read" instead of a clean zero. An observed empty history still
  renders 0.
- Row-remapping architectures (Ampere and newer) that do not support the
  retired-pages API are recorded explicitly as such rather than silently
  zeroed.
- `voltry cert` verifies bundles from their raw JSON bytes
  (`verify_bundle_json`), so certificates signed under older schema versions
  keep verifying after upgrades.
- Requires voltry-evidence-schema >=1.1 (hard floor: the builder and renderer
  import `DutyBlock`, which first appears in 1.1.0).

## [0.1.0] - 2026-07-02

First public release.

- `voltry scan`: read-only capture from NVML, DCGM, Redfish, and the NVIDIA
  attestation chain into a signed evidence bundle. Works fully offline and
  air-gapped. Live readers behind the `[hardware]` extra; fixtures and
  simulator supported everywhere.
- `voltry cert`: renders a bundle to a self-contained offline HTML
  certificate. Measured facts and modeled estimates are separate blocks;
  exposure renders "Not Assessed" without facility instrumentation. The command
  verifies the bundle signature and renders a prominent UNVERIFIED watermark
  (with a stderr warning) for any bundle whose signature does not validate, so
  the offline certificate can never look authoritative without cryptographic
  backing.
- `voltry submit`: separate, explicit, opt-in submission client behind the
  `[submit]` extra. Scan and cert never use the network.
- `voltry --version` reports the installed version; malformed inputs to `cert`
  produce a clean error and a non-zero exit, never a raw traceback.
- Readers refuse to fabricate any measured fact. Every counter the certificate
  renders as a Block-2 measured fact (ECC volatile and aggregate, spare-row
  headroom, and retired pages) must have actually been read at the leaf level;
  an absent, empty, or partially-populated block is rejected rather than
  certified as "0 errors" / "512/512 spare rows" / "0 retired pages". A
  genuinely-measured zero is still a valid clean read. The live reader now
  captures aggregate (lifetime) ECC and retired-page counts.
- Attestation verdicts reflect real chain state (VERIFIED, FAILED, UNVERIFIED,
  FALLBACK); never a stubbed pass.
- Python 3.10 through 3.13. Typed (`py.typed`).
