"""The ``voltry`` command line.

The commands:
- ``voltry scan``   reads device state (no resets, no reconfiguration, no stress
  diagnostics) and writes a signed evidence bundle. Works fully offline.
- ``voltry cert``   renders a bundle to a self-contained offline HTML certificate.
- ``voltry submit`` uploads a signed bundle to the platform (the Voltry registry by
  default). Opt-in and separate: it is the only networked command, requires an explicit
  consent flag, and its HTTP client is an optional dependency so scan and cert stay
  offline and dependency-light. With ``--org-token-env NAME`` it uploads to your
  organization instead, with the organization upload token read from that environment
  variable (never from the command line).
- ``voltry key register`` proves possession of the signing key so an organization can
  register it, after the operator confirms which organization the challenge names;
  ``voltry key fingerprint`` prints a key's fingerprint. Both are offline.

Scan, cert and the key commands make no network requests. Bundles carry device
identifiers (serial, GPU UUID), which are persistent and can be linkable; no account or
user identity is collected here (account linkage, if any, happens server-side).
"""

from __future__ import annotations

import hashlib
import os
import platform
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import SplitResult, parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import UUID

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
from .keyreg import (
    ChallengeError,
    canonical_spki_der,
    fingerprint,
    parse_challenge,
    sign_registration,
)
from .render import render_certificate
from .sources import FixtureSource, UnsupportedGpuError

if TYPE_CHECKING:  # the HTTP client is the optional [submit] extra, imported lazily
    import httpx

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help=(
        "Voltry Probe: GPU condition and provenance evidence. scan and cert are offline "
        "and never mutate the device; submit is opt-in."
    ),
    # Never print local variables in a traceback: submit holds the organization upload
    # token in a local. Typer before 0.23 showed locals by default; the floor is 0.23 now,
    # and this stays explicit so no future default or downgrade can bring them back.
    pretty_exceptions_show_locals=False,
)

# The read-mode methodology this version implements, as a frozen descriptor. The default
# stamped into the bundle is a content hash of it, so methodology_version_hash carries an
# actual hash that pins a specific procedure rather than a bare "read-v0" label. Change the
# descriptor when the read procedure changes and the hash moves with it.
_READ_METHODOLOGY = (
    "voltry-probe read mode v0: non-mutating NVML identity and health-counter capture; "
    "RFC 8785 canonical evidence bundle; ECDSA P-384 signature; attestation verified "
    "against a supplied trusted root when provided."
)
DEFAULT_METHODOLOGY = (
    "read-v0.sha256-" + hashlib.sha256(_READ_METHODOLOGY.encode()).hexdigest()[:16]
)

#: The public Voltry registry ingest endpoint. ``voltry submit`` posts here unless --url
#: names another platform (a local or test instance, for example).
DEFAULT_INGEST_URL = "https://api.voltry.io/v1/ingest"

#: The organization upload endpoint. ``voltry submit --org-token-env`` posts here unless
#: --url names another platform. Records uploaded here are private to your organization.
DEFAULT_ORG_UPLOAD_URL = "https://api.voltry.io/v1/org/upload"

#: The header an organization upload token travels in (never ``Authorization``).
UPLOAD_TOKEN_HEADER = "X-Voltry-Upload-Token"  # noqa: S105 - a header name, not a credential

#: The shape of an organization upload token, ``vot_<24 hex>.<secret>``: the same grammar
#: the platform accepts (services/platform-api/app/org_upload/tokens.py). A value of any
#: other shape is refused locally, before anything is sent.
_UPLOAD_TOKEN_RE = re.compile(r"vot_[0-9a-f]{24}\.[A-Za-z0-9_-]{16,128}")

#: A portable environment variable name.
_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

#: The only hosts an upload token may be sent to over plain http (with --allow-insecure-http):
#: this machine. Anywhere else, a token over http would cross a network in cleartext.
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

# Printed after an unauthorized_signer refusal, so the operator learns what to do next
# rather than just that a key was refused.
_UNAUTHORIZED_SIGNER_HINT = (
    "Your signing key must be registered with Voltry before the registry accepts bundles "
    'signed with it; see "Submitting to the Voltry registry" in the voltry-probe README.'
)

# Printed after an unregistered_signer refusal on an organization upload.
_UNREGISTERED_SIGNER_HINT = (
    "An upload token only uploads bundles signed with a key registered to your organization. "
    "Check which key signed this bundle with `voltry key fingerprint --signing-key PEM`, and "
    "register it on the Signing keys page of the Voltry console (it gives you the "
    "`voltry key register` command to run)."
)

#: ``voltry key``: the signing-key commands, both offline.
key_app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help=(
        "Register the signing key your bundles are signed with to your Voltry organization, "
        "and print key fingerprints. Offline: nothing here uses the network."
    ),
    # The key commands hold private key material in locals: never print them.
    pretty_exceptions_show_locals=False,
)
app.add_typer(key_app, name="key")

# Server-supplied refusal text is echoed to the operator's terminal: keep it printable and
# bounded so a misbehaving endpoint cannot inject control sequences or flood the screen.
_MAX_SERVER_TEXT = 300


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
        if not isinstance(key.curve, ec.SECP384R1):
            raise typer.BadParameter(
                f"signing key must be on P-384 (secp384r1), got {key.curve.name}; "
                "a bundle signed with any other curve fails its own verifier"
            )
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
    if not isinstance(key.curve, ec.SECP384R1):
        raise typer.BadParameter(
            f"trusted root must be on P-384 (secp384r1), got {key.curve.name}; "
            "the attestation chain verifies P-384 signatures only"
        )
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
        DEFAULT_METHODOLOGY,
        help=(
            "Methodology identifier stamped into the bundle. The default is a content "
            "hash of this version's read-mode methodology; pass your own to pin a method."
        ),
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


def _with_consent(url: str) -> str:
    """Return ``url`` with ``consent=true`` in its query string, exactly once.

    The platform refuses an upload (``consent_required``) unless the request itself carries
    the consent, so the local flag alone is not enough: it has to travel with the upload.
    An existing ``consent`` parameter is replaced, never duplicated, and every other query
    parameter is kept in its original order.
    """
    parts = urlsplit(url)
    query = [
        (key, value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
        if key != "consent"
    ]
    query.append(("consent", "true"))
    return urlunsplit(parts._replace(query=urlencode(query)))


def _server_text(value: str) -> str:
    """A server-supplied string made safe to echo: printable characters only, bounded."""
    return "".join(ch if ch.isprintable() else "?" for ch in value)[:_MAX_SERVER_TEXT]


def _platform_refusal(response: httpx.Response) -> tuple[str, str] | None:
    """The platform's structured refusal as ``(code, message)``.

    The ingest route refuses with ``{"detail": {"code": ..., "message": ...}}``. Any other
    body (a proxy's HTML error page, a list-shaped validation error, no body at all)
    returns None and the caller falls back to the HTTP status line.
    """
    try:
        body = response.json()
    except ValueError:  # not JSON; json.JSONDecodeError and UnicodeDecodeError both land here
        return None
    detail = body.get("detail") if isinstance(body, dict) else None
    if not isinstance(detail, dict):
        return None
    code, message = detail.get("code"), detail.get("message")
    if not isinstance(code, str) or not isinstance(message, str):
        return None
    return _server_text(code), _server_text(message)


def _org_upload_token(env_name: str) -> str:
    """Read an organization upload token from the named environment variable.

    The token is only ever read from the environment: there is no option that takes the
    token itself, so it never lands in shell history or a process listing. The value is
    never echoed, in errors included.
    """
    if env_name.startswith("vot_") or _UPLOAD_TOKEN_RE.fullmatch(env_name):
        typer.echo(
            "ERROR: --org-token-env takes the NAME of an environment variable that holds "
            "your upload token, not the token itself. Put the token in an environment "
            "variable (for example VOLTRY_UPLOAD_TOKEN) and pass its name. If you typed the "
            "token on the command line, revoke it in the Voltry console and mint a new one: "
            "it may be in your shell history.",
            err=True,
        )
        raise typer.Exit(2)
    if not _ENV_NAME_RE.fullmatch(env_name):
        # Not echoed: a mistyped token is still a token.
        typer.echo(
            "ERROR: --org-token-env takes an environment variable name: letters, digits and "
            "underscores, not starting with a digit.",
            err=True,
        )
        raise typer.Exit(2)
    token = os.environ.get(env_name, "").strip()
    if not token:
        typer.echo(
            f"ERROR: the environment variable {env_name} is not set or is empty; set it to "
            "your organization upload token.",
            err=True,
        )
        raise typer.Exit(2)
    if not _UPLOAD_TOKEN_RE.fullmatch(token):
        typer.echo(
            f"ERROR: the value of {env_name} does not look like a Voltry upload token "
            "(vot_ followed by 24 hex characters, a dot, and the secret). Copy the whole "
            "token the console showed when you created it.",
            err=True,
        )
        raise typer.Exit(2)
    return token


def _split_url(url: str) -> SplitResult:
    """Parse ``--url``, refusing (exit 2) anything that does not parse as a URL.

    ``urlsplit`` raises ValueError on some malformed URLs (an unclosed IPv6 bracket) and
    ``.port`` on others (a non-numeric port), so both are touched here, before anything
    else happens with the URL. The URL itself is never echoed.
    """
    try:
        parts = urlsplit(url)
        _ = parts.port  # raises ValueError for a port that is not a number in range
    except ValueError as exc:
        typer.echo("ERROR: --url is not a valid URL. Nothing was sent.", err=True)
        raise typer.Exit(2) from exc
    return parts


def _check_org_upload_url(url: str) -> None:
    """Refuse to send an upload token anywhere but an organization upload endpoint.

    Runs BEFORE the token is read from the environment, so a refused URL never has the
    token in hand. The path must end in exactly ``/v1/org/upload``: an old script still
    pointing at the public ``/v1/ingest`` would otherwise send the token along and put the
    record on the public path, and a trailing slash would draw a redirect instead of an
    upload. Plain http is allowed only to this machine, even with --allow-insecure-http, so
    the token never crosses a network in cleartext.
    """
    parts = _split_url(url)
    if not parts.path.endswith("/v1/org/upload"):
        typer.echo(
            "ERROR: with --org-token-env the URL must be an organization upload endpoint "
            f"ending in /v1/org/upload (the default is {DEFAULT_ORG_UPLOAD_URL}). Nothing was "
            "sent.",
            err=True,
        )
        raise typer.Exit(2)
    if parts.scheme.lower() == "http" and (parts.hostname or "") not in _LOOPBACK_HOSTS:
        typer.echo(
            "ERROR: an upload token is only sent over plain http to this machine (localhost); "
            "use an https:// URL. Nothing was sent.",
            err=True,
        )
        raise typer.Exit(2)


@app.command()
def submit(
    bundle: Path = typer.Argument(..., help="A signed evidence bundle JSON to upload."),
    url: str = typer.Option(
        None,
        help=(
            "Platform ingest URL (https). Defaults to the Voltry registry "
            f"({DEFAULT_INGEST_URL}), or to your organization's upload endpoint "
            f"({DEFAULT_ORG_UPLOAD_URL}) with --org-token-env. Your consent is sent with "
            "the upload as consent=true in the query string."
        ),
        show_default=False,
    ),
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
    org_token_env: str = typer.Option(
        None,
        "--org-token-env",
        metavar="NAME",
        help=(
            "Upload to your organization with the upload token held in the environment "
            "variable NAME (created on the Signing keys page of the Voltry console). The "
            "token is read from the environment only, never from the command line. The "
            "bundle must be signed with a key registered to your organization, and the "
            "record is private to your organization."
        ),
    ),
) -> None:
    """Upload a signed bundle to the Voltry registry (or --url). Opt-in, separate from scan/cert."""
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
    if org_token_env is not None:
        url = url or DEFAULT_ORG_UPLOAD_URL
        _check_org_upload_url(url)
    else:
        url = url or DEFAULT_INGEST_URL
    scheme = _split_url(url).scheme.lower()
    if scheme != "https" and not (scheme == "http" and allow_insecure_http):
        typer.echo(
            "ERROR: submission requires an https:// ingest URL (or pass "
            "--allow-insecure-http for a local or test endpoint).",
            err=True,
        )
        raise typer.Exit(2)
    headers = {"content-type": "application/json"}
    if org_token_env is not None:
        # Read only now, once the URL has passed every check.
        headers[UPLOAD_TOKEN_HEADER] = _org_upload_token(org_token_env)
    try:
        import httpx
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        typer.echo(
            "submit requires the network extra: pip install 'voltry-probe[submit]'", err=True
        )
        raise typer.Exit(3) from exc
    # The consent the operator just gave locally travels with the upload; the platform
    # refuses a request that does not carry it.
    target = _with_consent(url)
    try:
        response = httpx.post(
            target,
            content=data,
            headers=headers,
            timeout=30.0,  # bound the consent-gated upload; never hang on a slow endpoint
        )
    except (httpx.HTTPError, httpx.InvalidURL, ValueError) as exc:
        # InvalidURL is not an HTTPError, and a host the IDNA codec rejects (an invalid
        # xn-- label, say) raises idna.IDNAError, a ValueError, from inside the transport.
        # None of these messages carries the request headers.
        typer.echo(f"ERROR: upload failed: {exc}", err=True)
        raise typer.Exit(4) from exc
    if 300 <= response.status_code < 400:
        # httpx does not follow redirects here, so a 3xx means nothing was recorded.
        typer.echo(
            f"ERROR: the upload was not recorded: HTTP {response.status_code} (a redirect). "
            "Check --url.",
            err=True,
        )
        raise typer.Exit(4)
    if not 200 <= response.status_code < 300:
        refusal = _platform_refusal(response)
        if refusal is None:
            typer.echo(
                f"ERROR: platform rejected the upload: HTTP {response.status_code}", err=True
            )
        else:
            code, message = refusal
            typer.echo(
                f"ERROR: platform rejected the upload: HTTP {response.status_code} "
                f"{code}: {message}",
                err=True,
            )
            if code == "unauthorized_signer":
                typer.echo(_UNAUTHORIZED_SIGNER_HINT, err=True)
            elif code == "unregistered_signer":
                typer.echo(_UNREGISTERED_SIGNER_HINT, err=True)
        raise typer.Exit(4)
    typer.echo(f"submitted to {target}: HTTP {response.status_code}")


def _load_p384_public_key(path: Path) -> ec.EllipticCurvePublicKey:
    """Load an EC P-384 public key from PEM, with one-line errors."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise typer.BadParameter(f"public key file not found or unreadable: {path}") from exc
    try:
        key = serialization.load_pem_public_key(raw)
    except ValueError as exc:
        raise typer.BadParameter(f"not a readable PEM public key ({path}): {exc}") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP384R1):
        raise typer.BadParameter("the public key must be an EC P-384 (secp384r1) key")
    return key


def _refuse_registration(message: str) -> typer.Exit:
    typer.echo(f"ERROR: {message} Nothing was signed.", err=True)
    return typer.Exit(2)


@key_app.command("register")
def key_register(
    signing_key: Path = typer.Option(
        ...,
        "--signing-key",
        help=(
            "Your operator EC P-384 private key (PEM): the key you sign bundles with "
            "(voltry scan --signing-key). It never leaves this machine."
        ),
    ),
    challenge: str = typer.Option(
        ...,
        "--challenge",
        help=(
            "The vsc1. registration challenge from the add-key page of the Voltry console. "
            "It is single use and expires 10 minutes after it was issued."
        ),
    ),
    yes_this_is_my_org: str = typer.Option(
        None,
        "--yes-this-is-my-org",
        metavar="ORG_ID",
        help=(
            "Confirm without a prompt (for scripts). Must be the organization id inside the "
            "challenge, as the console shows it on the add-key page, or nothing is signed."
        ),
    ),
) -> None:
    """Prove you hold a signing key so your organization can register it. Offline.

    Shows which organization the challenge is for and asks you to confirm BEFORE anything
    is signed: a key registers to one organization, once, and can never be moved or
    registered again, so only sign a challenge you started yourself in the console. Prints
    a vsr1. proof on stdout (paste it into the console) and the key fingerprint on stderr.

    The proof carries the key's DER SubjectPublicKeyInfo and an ECDSA P-384 / SHA-384
    signature in DER form (an ASN.1 SEQUENCE of r and s) over the registration challenge;
    the platform refuses a raw r||s signature.
    """
    try:
        org_id, _ = parse_challenge(challenge)
    except ChallengeError as exc:
        raise _refuse_registration(f"{exc}.") from exc
    key = _load_signing_key(signing_key, ephemeral=False)
    key_fingerprint = fingerprint(canonical_spki_der(key.public_key()))
    typer.echo(
        f"This challenge registers your signing key to the Voltry organization\n"
        f"  {org_id}\n"
        f"Key fingerprint:\n"
        f"  {key_fingerprint}\n"
        "A key registers to one organization, once, and can never be moved or registered "
        "again. Continue only if that is the organization shown on the add-key page you "
        "opened yourself. If someone else sent you this challenge, stop here.",
        err=True,
    )
    if yes_this_is_my_org is not None:
        try:
            confirmed = UUID(yes_this_is_my_org.strip())
        except ValueError as exc:
            raise _refuse_registration(
                f"--yes-this-is-my-org {_server_text(yes_this_is_my_org)!r} is not an "
                "organization id."
            ) from exc
        if confirmed != org_id:
            raise _refuse_registration(
                f"--yes-this-is-my-org {confirmed} does not match the organization in this "
                f"challenge ({org_id})."
            )
    else:
        # Asked on stderr and read straight from stdin, so stdout carries nothing but the
        # proof (click's own prompt writes a stray space to stdout). No answer, EOF, or
        # anything but y/yes is a no.
        typer.echo(f"Register this key to organization {org_id}? [y/N]: ", err=True, nl=False)
        if sys.stdin.readline().strip().lower() not in ("y", "yes"):
            raise _refuse_registration("Registration was not confirmed.")
        confirmed = org_id
    registration = sign_registration(key, challenge, confirmed_org_id=confirmed)
    sys.stdout.write(registration.proof + "\n")
    typer.echo(
        "Paste the vsr1. line above into the add-key form in the Voltry console, with a "
        "label for the key, before the challenge expires.",
        err=True,
    )


@key_app.command("fingerprint")
def key_fingerprint(
    signing_key: Path = typer.Option(
        None, "--signing-key", help="An EC P-384 private key (PEM). Its public half is used."
    ),
    public_key: Path = typer.Option(None, "--public-key", help="An EC P-384 public key (PEM)."),
) -> None:
    """Print a signing key's fingerprint (sha384: of its DER SubjectPublicKeyInfo). Offline.

    The same value the Voltry console lists for a registered key, so you can tell which of
    your keys a registration names.
    """
    if (signing_key is None) == (public_key is None):
        raise typer.BadParameter("pass exactly one of --signing-key or --public-key")
    if signing_key is not None:
        pub = _load_signing_key(signing_key, ephemeral=False).public_key()
    else:
        pub = _load_p384_public_key(public_key)
    sys.stdout.write(fingerprint(canonical_spki_der(pub)) + "\n")


def main() -> None:
    """Console-script entry point (`voltry`)."""
    app()


if __name__ == "__main__":  # pragma: no cover - module run
    main()
