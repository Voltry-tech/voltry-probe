"""The ``voltry`` command line.

Three commands:
- ``voltry scan``   reads device state (no resets, no reconfiguration, no stress
  diagnostics) and writes a signed evidence bundle. Works fully offline.
- ``voltry cert``   renders a bundle to a self-contained offline HTML certificate.
- ``voltry submit`` uploads a signed bundle to the platform. Opt-in and separate: it is
  the only networked command, requires an explicit consent flag, and its HTTP client is
  an optional dependency so scan and cert stay offline and dependency-light.

Scan and cert make no network requests. Bundles carry device identifiers (serial, GPU
UUID) and no personal data: identity is device-level; account linkage happens
server-side.
"""

from __future__ import annotations

import platform
import sys
from pathlib import Path
from urllib.parse import urlsplit

import typer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from evidence_schema import (
    AgentInfo,
    EvidenceBundle,
    RunMode,
    generate_keypair,
    verify_bundle_json,
)

from . import __version__
from .attestation import MIN_CHALLENGE_LENGTH
from .evidence import build_read_bundle
from .render import render_certificate
from .sources import FixtureSource, UnsupportedGpuError

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help=(
        "Voltry Probe: GPU condition and provenance evidence. scan and cert are offline "
        "and never mutate the device; submit is opt-in."
    ),
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"voltry-probe {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the version and exit.",
    ),
) -> None:
    """Voltry Probe: GPU condition and provenance evidence."""


def _load_signing_key(signing_key: Path | None, ephemeral: bool) -> ec.EllipticCurvePrivateKey:
    """Load the operator signing key from PEM, or generate an ephemeral one if opted in."""
    if signing_key is not None:
        try:
            raw = signing_key.read_bytes()
        except OSError as exc:
            raise typer.BadParameter(f"signing key file not found: {signing_key}") from exc
        try:
            key = serialization.load_pem_private_key(raw, password=None)
        except TypeError as exc:
            raise typer.BadParameter(
                "signing key is encrypted; provide an unencrypted PKCS#8 PEM "
                "(passphrase input is not supported yet)"
            ) from exc
        except ValueError as exc:
            raise typer.BadParameter(
                f"signing key is not a readable PEM private key: {exc}"
            ) from exc
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise typer.BadParameter("signing key must be an EC (P-384) private key")
        return key
    if ephemeral:
        typer.echo(
            "WARNING: using an ephemeral signing key, not a persistent operator identity; "
            "for production pass --signing-key.",
            err=True,
        )
        return generate_keypair()
    raise typer.BadParameter("provide --signing-key PATH (PEM) or pass --ephemeral-key")


def _load_root_pubkey(path: Path | None) -> ec.EllipticCurvePublicKey | None:
    """Load the NVIDIA root public key (PEM), or None when no root was passed."""
    if path is None:
        return None
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise typer.BadParameter(f"trusted root file not found or unreadable: {path}") from exc
    try:
        key = serialization.load_pem_public_key(raw)
    except ValueError as exc:
        raise typer.BadParameter(
            f"trusted root is not a readable PEM public key ({path}): {exc}"
        ) from exc
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise typer.BadParameter("trusted root must be an EC public key")
    return key


@app.command()
def scan(
    fixture: Path = typer.Option(
        None, help="Captured RawCapture JSON (dev/sim). Omit to read live hardware."
    ),
    out: Path = typer.Option(
        None, "--out", "-o", help="Write the signed bundle JSON here (default: stdout)."
    ),
    methodology: str = typer.Option(
        "read-v0", help="Methodology version hash stamped into the bundle."
    ),
    signing_key: Path = typer.Option(
        None, help="Operator EC P-384 private key (PEM) to sign the bundle."
    ),
    ephemeral_key: bool = typer.Option(
        False, "--ephemeral-key", help="Sign with a throwaway key (dev only)."
    ),
    trusted_root: Path = typer.Option(
        None, help="NVIDIA root EC public key (PEM) for attestation."
    ),
    expected_vbios: str = typer.Option(None, help="Known-good VBIOS hash for re-flash detection."),
    challenge: str = typer.Option(
        None,
        help=(
            "Operator-issued challenge nonce for this scan. The attestation report must "
            "echo it, or attestation fails as a possible replay. Omitting it keeps the "
            "pre-1.2.0 behavior at lower, marked confidence."
        ),
    ),
) -> None:
    """Read device state (no mutation) and emit a signed evidence bundle. Offline."""
    if challenge is not None and len(challenge) < MIN_CHALLENGE_LENGTH:
        raise typer.BadParameter(
            f"challenge must be at least {MIN_CHALLENGE_LENGTH} characters; a short or "
            "guessable challenge defeats replay protection. Issue a fresh random nonce "
            "per scan, e.g. python -c 'import secrets; print(secrets.token_hex(32))'."
        )
    key = _load_signing_key(signing_key, ephemeral_key)
    root_pub = _load_root_pubkey(trusted_root)
    if fixture is not None:
        source = FixtureSource(fixture)
    else:  # pragma: no cover - requires a GPU + the [hardware] extra
        from .sources.live import LiveSource

        source = LiveSource()
    try:
        capture = source.capture()
    except UnsupportedGpuError as exc:
        # Device outside the certifiable envelope (consumer card, ECC off, MIG, ...):
        # exit clean with the per-device diagnosis instead of a driver traceback.
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(2) from exc
    except RuntimeError as exc:
        # LiveSource imports nvidia-ml-py lazily and raises RuntimeError when the
        # [hardware] extra is not installed; the message carries the pip install hint.
        # Exit 3 matches submit's missing-extra path so scripts can tell "install the
        # extra" (3) apart from "device refused" (2).
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(3) from exc
    except OSError as exc:
        if fixture is None:
            raise
        # The GPU-less quickstart path: a missing or unreadable fixture file should
        # print one line, not a traceback, matching the key and root file handling.
        typer.echo(f"ERROR: fixture file not found or unreadable: {exc}", err=True)
        raise typer.Exit(2) from exc
    except ValueError as exc:
        if fixture is None:
            raise
        # Covers JSON parse errors and capture-shape validation errors (pydantic's
        # ValidationError subclasses ValueError).
        typer.echo(f"ERROR: fixture is not a valid capture payload: {exc}", err=True)
        raise typer.Exit(2) from exc
    try:
        bundle = build_read_bundle(
            capture,
            signer_key=key,
            agent=AgentInfo(
                name="voltry-probe",
                version=__version__,
                run_mode=RunMode.READ,
                host_arch=platform.machine(),
            ),
            methodology_version_hash=methodology,
            trusted_root_public_key=root_pub,
            expected_vbios_hash=expected_vbios,
            operator_challenge=challenge,
            signer_label="operator",
        )
    except ValueError as exc:
        if fixture is None:
            raise
        # A payload can parse as a capture yet still lack required health counters;
        # the mappers raise ValueError for those. Same one-line treatment as above.
        typer.echo(f"ERROR: fixture is not a valid capture payload: {exc}", err=True)
        raise typer.Exit(2) from exc
    payload = bundle.model_dump_json(indent=2)
    if out is None:
        sys.stdout.write(payload + "\n")
    else:
        out.write_text(payload, encoding="utf-8")
        typer.echo(f"wrote signed bundle: {out}", err=True)


@app.command()
def cert(
    bundle: Path = typer.Argument(..., help="A signed evidence bundle JSON (from `voltry scan`)."),
    out: Path = typer.Option(
        None, "--out", "-o", help="Write the HTML certificate here (default: stdout)."
    ),
) -> None:
    """Render a bundle to a self-contained, offline HTML certificate. Offline."""
    try:
        text = bundle.read_text(encoding="utf-8")
    except OSError as exc:
        typer.echo(f"ERROR: bundle file not found: {bundle}", err=True)
        raise typer.Exit(2) from exc
    try:
        model = EvidenceBundle.model_validate_json(text)
    except ValueError as exc:
        typer.echo(f"ERROR: not a valid evidence bundle ({bundle}): {exc}", err=True)
        raise typer.Exit(2) from exc
    # A certificate is authoritative only if the signature actually verifies. Verify from
    # the RAW file bytes (cross-schema-version faithful; see evidence_schema.verify_bundle_json)
    # and render an unverified bundle with a prominent watermark rather than refusing outright,
    # but never let it look like proof.
    verified = verify_bundle_json(text)
    if not verified:
        typer.echo(
            "WARNING: bundle signature is UNVERIFIED; the certificate is a rendered view, "
            "not cryptographic proof.",
            err=True,
        )
    html = render_certificate(model, verified=verified)
    if out is None:
        sys.stdout.write(html + "\n")
    else:
        out.write_text(html, encoding="utf-8")
        typer.echo(f"wrote certificate: {out}", err=True)


@app.command()
def submit(
    bundle: Path = typer.Argument(..., help="A signed evidence bundle JSON to upload."),
    url: str = typer.Option(..., help="Platform ingest URL (https)."),
    i_consent_to_submit: bool = typer.Option(
        False,
        "--i-consent-to-submit",
        help="Required. Uploading the signed bundle (including raw reads) leaves your premises.",
    ),
    allow_insecure_http: bool = typer.Option(
        False,
        "--allow-insecure-http",
        help="Permit a plain-http ingest URL (local or test endpoints only).",
    ),
) -> None:
    """Upload a signed bundle to the platform. Opt-in and separate from scan/cert."""
    if not i_consent_to_submit:
        typer.echo(
            "ERROR: submission is opt-in and separate from scan/cert. Nothing leaves your "
            "premises without consent. Re-run with --i-consent-to-submit to upload the signed "
            "bundle (which includes its raw reads) to the platform.",
            err=True,
        )
        raise typer.Exit(2)
    try:
        data = bundle.read_text(encoding="utf-8")
    except OSError as exc:
        typer.echo(f"ERROR: bundle file not found: {bundle}", err=True)
        raise typer.Exit(2) from exc
    # Validate locally before anything leaves the machine: parse against the schema, then
    # verify the signature from the raw bytes. An unverifiable bundle is refused, never
    # uploaded. The raw text is what gets uploaded so the signature stays byte-exact.
    try:
        EvidenceBundle.model_validate_json(data)
    except ValueError as exc:
        typer.echo(f"ERROR: not a valid evidence bundle ({bundle}): {exc}", err=True)
        raise typer.Exit(2) from exc
    if not verify_bundle_json(data):
        typer.echo(
            "ERROR: bundle signature does not verify; refusing to upload. Pass a bundle "
            "produced and signed by `voltry scan`.",
            err=True,
        )
        raise typer.Exit(2)
    scheme = urlsplit(url).scheme.lower()
    if scheme != "https" and not (scheme == "http" and allow_insecure_http):
        typer.echo(
            "ERROR: submission requires an https:// ingest URL (or pass "
            "--allow-insecure-http for a local or test endpoint).",
            err=True,
        )
        raise typer.Exit(2)
    try:
        import httpx
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        typer.echo(
            "submit requires the network extra: pip install 'voltry-probe[submit]'", err=True
        )
        raise typer.Exit(3) from exc
    try:
        response = httpx.post(
            url,
            content=data,
            headers={"content-type": "application/json"},
            timeout=30.0,  # bound the consent-gated upload; never hang on a slow endpoint
        )
    except httpx.HTTPError as exc:
        typer.echo(f"ERROR: upload failed: {exc}", err=True)
        raise typer.Exit(4) from exc
    if response.status_code >= 400:
        typer.echo(f"ERROR: platform rejected the upload: HTTP {response.status_code}", err=True)
        raise typer.Exit(4)
    typer.echo(f"submitted to {url}: HTTP {response.status_code}")


def main() -> None:
    """Console-script entry point (`voltry`)."""
    app()


if __name__ == "__main__":  # pragma: no cover - module run
    main()
