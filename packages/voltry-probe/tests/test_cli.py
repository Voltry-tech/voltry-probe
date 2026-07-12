"""CLI surface: scan/cert offline end-to-end; submit opt-in and separate (consent-gated)."""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from evidence_schema import EvidenceBundle, GateResult, generate_keypair, verify_bundle
from evidence_schema.samples import worked_example_a_bundle
from evidence_schema.sign import public_key_to_spki_b64
from typer.testing import CliRunner

from voltry_probe.cli import app

runner = CliRunner()
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "h100_read.json"


def _text(result) -> str:
    """All captured text (stdout + stderr), robust across click versions."""
    out = result.stdout or ""
    try:
        err = result.stderr or ""
    except (ValueError, RuntimeError):  # stderr not separately captured
        err = ""
    return out + err


def test_help_lists_three_commands():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for cmd in ("scan", "cert", "submit"):
        assert cmd in result.output


def test_version_flag():
    from voltry_probe import __version__

    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_cert_missing_file_is_clean_error(tmp_path):
    result = runner.invoke(app, ["cert", str(tmp_path / "nope.json")])
    assert result.exit_code != 0
    assert "Traceback" not in _text(result)
    assert "not found" in _text(result).lower()


def test_cert_malformed_bundle_is_clean_error(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json at all", encoding="utf-8")
    result = runner.invoke(app, ["cert", str(bad)])
    assert result.exit_code != 0
    assert "Traceback" not in _text(result)


def test_cert_unsigned_bundle_is_watermarked(tmp_path):
    # A hand-authored, unsigned bundle must render as UNVERIFIED, never authoritative.
    bundle = worked_example_a_bundle()  # signature=None
    path = tmp_path / "unsigned.json"
    path.write_text(bundle.model_dump_json(), encoding="utf-8")
    out = tmp_path / "cert.html"
    result = runner.invoke(app, ["cert", str(path), "--out", str(out)])
    assert result.exit_code == 0, _text(result)
    assert "UNVERIFIED" in out.read_text()
    assert "unverified" in _text(result).lower()  # stderr warns too


def test_scan_then_cert_offline(tmp_path):
    bundle_path = tmp_path / "bundle.json"
    scanned = runner.invoke(
        app, ["scan", "--fixture", str(FIXTURE), "--ephemeral-key", "--out", str(bundle_path)]
    )
    assert scanned.exit_code == 0, _text(scanned)
    bundle = EvidenceBundle.model_validate_json(bundle_path.read_text())
    assert verify_bundle(bundle) is True
    assert bundle.identity.device_part == "H100-SXM5"
    assert bundle.measured.spare_rows.remaining == 509

    cert_path = tmp_path / "cert.html"
    rendered = runner.invoke(app, ["cert", str(bundle_path), "--out", str(cert_path)])
    assert rendered.exit_code == 0, _text(rendered)
    html = cert_path.read_text()
    assert "Certified by Voltry" in html
    assert 'class="exposure exposure--no"' in html  # offline, prominent exposure flag
    assert "UNVERIFIED" not in html  # a signed, valid bundle renders as verified


def test_scan_challenge_is_recorded_in_bundle(tmp_path):
    # --challenge plumbs through to the attestation block. The fixture carries no
    # attestation report, so the chain stays UNVERIFIED and freshness NOT_ASSESSED,
    # but the issued challenge is recorded for third-party recomputation.
    bundle_path = tmp_path / "bundle.json"
    result = runner.invoke(
        app,
        [
            "scan",
            "--fixture",
            str(FIXTURE),
            "--ephemeral-key",
            "--challenge",
            "cli-challenge-2026-07-09",
            "--out",
            str(bundle_path),
        ],
    )
    assert result.exit_code == 0, _text(result)
    bundle = EvidenceBundle.model_validate_json(bundle_path.read_text())
    assert verify_bundle(bundle) is True
    assert bundle.identity.attestation.challenge == "cli-challenge-2026-07-09"
    assert bundle.identity.attestation.freshness is GateResult.NOT_ASSESSED


def test_scan_short_challenge_is_clean_error(tmp_path):
    # A guessable challenge defeats replay protection: refuse loudly before scanning.
    result = runner.invoke(
        app,
        ["scan", "--fixture", str(FIXTURE), "--ephemeral-key", "--challenge", "weak"],
    )
    assert result.exit_code != 0
    assert "Traceback" not in _text(result)
    assert "16" in _text(result)


def test_scan_live_refusal_is_clean_and_specific(monkeypatch):
    # A live scan of a device outside the certifiable envelope (no ECC, pre-Ampere, MIG)
    # must exit nonzero with the diagnostic reason, never a raw driver traceback.
    from voltry_probe.sources import UnsupportedGpuError
    from voltry_probe.sources.live import LiveSource

    def _refuse(self):
        raise UnsupportedGpuError(
            "NVIDIA GeForce RTX 4090: this is a consumer-class GPU with no ECC memory."
        )

    monkeypatch.setattr(LiveSource, "capture", _refuse)
    result = runner.invoke(app, ["scan", "--ephemeral-key"])
    assert result.exit_code == 2
    text = _text(result)
    assert "no ECC" in text
    assert "Traceback" not in text


def test_scan_without_hardware_extra_is_clean_error(monkeypatch):
    # A stock install (no [hardware] extra) running a live scan: force the lazy
    # `import pynvml` inside LiveSource.capture to fail the way it would without the
    # extra (None in sys.modules makes the import raise ImportError). The CLI must exit
    # with the missing-extra code and the install hint, not a raw traceback.
    monkeypatch.setitem(sys.modules, "pynvml", None)
    result = runner.invoke(app, ["scan", "--ephemeral-key"])
    assert result.exit_code == 3
    text = _text(result)
    assert "voltry-probe[hardware]" in text
    assert "Traceback" not in text


def test_scan_missing_trusted_root_is_clean_error(tmp_path):
    result = runner.invoke(
        app,
        [
            "scan",
            "--fixture",
            str(FIXTURE),
            "--ephemeral-key",
            "--trusted-root",
            str(tmp_path / "nope.pem"),
        ],
    )
    assert result.exit_code != 0
    assert "Traceback" not in _text(result)
    assert "trusted root" in _text(result)


def test_scan_malformed_trusted_root_is_clean_error(tmp_path):
    pem = tmp_path / "junk.pem"
    pem.write_text("this is not a PEM public key", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "scan",
            "--fixture",
            str(FIXTURE),
            "--ephemeral-key",
            "--trusted-root",
            str(pem),
        ],
    )
    assert result.exit_code != 0
    assert "Traceback" not in _text(result)
    assert "public key" in _text(result).lower()


def test_scan_requires_a_signing_key():
    # No --signing-key and no --ephemeral-key: refuse (don't silently sign).
    result = runner.invoke(app, ["scan", "--fixture", str(FIXTURE)])
    assert result.exit_code != 0


def test_scan_ephemeral_warns():
    result = runner.invoke(app, ["scan", "--fixture", str(FIXTURE), "--ephemeral-key"])
    assert result.exit_code == 0
    assert "ephemeral" in _text(result).lower()


def _signed_bundle(tmp_path) -> Path:
    """Scan the fixture into a signed bundle file and return its path."""
    bundle_path = tmp_path / "bundle.json"
    result = runner.invoke(
        app, ["scan", "--fixture", str(FIXTURE), "--ephemeral-key", "--out", str(bundle_path)]
    )
    assert result.exit_code == 0, _text(result)
    return bundle_path


def _fake_httpx(status_code: int = 200, raise_error: bool = False):
    """A stand-in httpx module recording post() calls (or raising HTTPError)."""
    mod = types.ModuleType("httpx")

    class HTTPError(Exception):
        pass

    calls: list[dict] = []

    def post(url, content=None, headers=None, timeout=None):
        if raise_error:
            raise HTTPError("connection refused")
        calls.append({"url": url, "content": content, "headers": headers, "timeout": timeout})
        return types.SimpleNamespace(status_code=status_code)

    mod.HTTPError = HTTPError
    mod.post = post
    mod.calls = calls
    return mod


def test_submit_requires_explicit_consent(tmp_path, monkeypatch):
    fake = _fake_httpx()
    monkeypatch.setitem(sys.modules, "httpx", fake)
    bundle_path = _signed_bundle(tmp_path)
    # Without consent, submit refuses (nothing leaves premises) and never calls HTTP.
    result = runner.invoke(
        app, ["submit", str(bundle_path), "--url", "https://example.invalid/ingest"]
    )
    assert result.exit_code == 2
    assert "opt-in" in _text(result).lower()
    assert fake.calls == []


def test_submit_refuses_invalid_bundle_before_any_network(tmp_path, monkeypatch):
    fake = _fake_httpx()
    monkeypatch.setitem(sys.modules, "httpx", fake)
    bad = tmp_path / "bad.json"
    bad.write_text("{not a bundle", encoding="utf-8")
    result = runner.invoke(
        app,
        ["submit", str(bad), "--url", "https://example.invalid/ingest", "--i-consent-to-submit"],
    )
    assert result.exit_code == 2
    assert "not a valid evidence bundle" in _text(result)
    assert fake.calls == []


def test_submit_refuses_unverified_bundle(tmp_path, monkeypatch):
    fake = _fake_httpx()
    monkeypatch.setitem(sys.modules, "httpx", fake)
    unsigned = tmp_path / "unsigned.json"
    unsigned.write_text(worked_example_a_bundle().model_dump_json(), encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "submit",
            str(unsigned),
            "--url",
            "https://example.invalid/ingest",
            "--i-consent-to-submit",
        ],
    )
    assert result.exit_code == 2
    assert "does not verify" in _text(result)
    assert fake.calls == []


def test_submit_requires_https_unless_explicitly_allowed(tmp_path, monkeypatch):
    fake = _fake_httpx()
    monkeypatch.setitem(sys.modules, "httpx", fake)
    bundle_path = _signed_bundle(tmp_path)
    refused = runner.invoke(
        app,
        [
            "submit",
            str(bundle_path),
            "--url",
            "http://localhost:8080/ingest",
            "--i-consent-to-submit",
        ],
    )
    assert refused.exit_code == 2
    assert "https" in _text(refused).lower()
    assert fake.calls == []

    allowed = runner.invoke(
        app,
        [
            "submit",
            str(bundle_path),
            "--url",
            "http://localhost:8080/ingest",
            "--i-consent-to-submit",
            "--allow-insecure-http",
        ],
    )
    assert allowed.exit_code == 0, _text(allowed)
    assert len(fake.calls) == 1


def test_submit_uploads_the_exact_signed_bytes(tmp_path, monkeypatch):
    fake = _fake_httpx(status_code=200)
    monkeypatch.setitem(sys.modules, "httpx", fake)
    bundle_path = _signed_bundle(tmp_path)
    result = runner.invoke(
        app,
        [
            "submit",
            str(bundle_path),
            "--url",
            "https://ingest.example/v1",
            "--i-consent-to-submit",
        ],
    )
    assert result.exit_code == 0, _text(result)
    assert "submitted" in _text(result)
    # The raw file text is uploaded unmodified so the signature stays byte-exact.
    assert fake.calls[0]["content"] == bundle_path.read_text(encoding="utf-8")


def test_submit_rejected_upload_fails_cleanly(tmp_path, monkeypatch):
    fake = _fake_httpx(status_code=500)
    monkeypatch.setitem(sys.modules, "httpx", fake)
    bundle_path = _signed_bundle(tmp_path)
    result = runner.invoke(
        app,
        [
            "submit",
            str(bundle_path),
            "--url",
            "https://ingest.example/v1",
            "--i-consent-to-submit",
        ],
    )
    assert result.exit_code == 4
    text = _text(result)
    assert "500" in text
    assert "submitted" not in text
    assert "Traceback" not in text


def test_submit_network_error_is_clean(tmp_path, monkeypatch):
    fake = _fake_httpx(raise_error=True)
    monkeypatch.setitem(sys.modules, "httpx", fake)
    bundle_path = _signed_bundle(tmp_path)
    result = runner.invoke(
        app,
        [
            "submit",
            str(bundle_path),
            "--url",
            "https://ingest.example/v1",
            "--i-consent-to-submit",
        ],
    )
    assert result.exit_code == 4
    assert "upload failed" in _text(result)
    assert "Traceback" not in _text(result)


def test_scan_encrypted_signing_key_is_clean_error(tmp_path):
    key = generate_keypair()
    pem = tmp_path / "encrypted.pem"
    pem.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"passphrase"),
        )
    )
    result = runner.invoke(app, ["scan", "--fixture", str(FIXTURE), "--signing-key", str(pem)])
    assert result.exit_code != 0
    assert "Traceback" not in _text(result)
    assert "encrypted" in _text(result).lower()


def test_scan_and_cert_work_with_network_and_subprocess_blocked(tmp_path, monkeypatch):
    """The offline guarantee, enforced at runtime: scan and cert must complete with
    sockets and subprocess creation blocked, and without the HTTP client loaded."""
    import socket
    import subprocess

    def _blocked(*_a, **_k):
        raise AssertionError("network/subprocess use during an offline command")

    monkeypatch.setattr(socket, "socket", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(subprocess, "Popen", _blocked)
    monkeypatch.delitem(sys.modules, "httpx", raising=False)

    bundle_path = tmp_path / "bundle.json"
    scanned = runner.invoke(
        app, ["scan", "--fixture", str(FIXTURE), "--ephemeral-key", "--out", str(bundle_path)]
    )
    assert scanned.exit_code == 0, _text(scanned)
    rendered = runner.invoke(app, ["cert", str(bundle_path), "--out", str(tmp_path / "c.html")])
    assert rendered.exit_code == 0, _text(rendered)
    # Unconditional: a cold scan/cert run never pulls in the network client.
    assert "httpx" not in sys.modules


def test_scan_with_pem_signing_key_to_stdout(tmp_path):
    key = generate_keypair()
    pem = tmp_path / "operator.pem"
    pem.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    result = runner.invoke(app, ["scan", "--fixture", str(FIXTURE), "--signing-key", str(pem)])
    assert result.exit_code == 0, _text(result)
    bundle = EvidenceBundle.model_validate_json(result.stdout)  # no --out, so stdout
    assert verify_bundle(bundle) is True
    # Signed by the provided operator key (not an ephemeral one).
    assert bundle.signature.public_key_spki_b64 == public_key_to_spki_b64(key.public_key())


def test_cert_to_stdout(tmp_path):
    bundle_path = tmp_path / "b.json"
    runner.invoke(
        app, ["scan", "--fixture", str(FIXTURE), "--ephemeral-key", "--out", str(bundle_path)]
    )
    result = runner.invoke(app, ["cert", str(bundle_path)])  # no --out, so stdout
    assert result.exit_code == 0
    assert "Certified by Voltry" in result.stdout


def test_scan_with_attestation_root_passes_gates(
    tmp_path, root_key, device_key, make_report, good_vbios
):
    capture = json.loads(FIXTURE.read_text())
    capture["attestation"] = make_report(root_key, device_key)
    capfile = tmp_path / "attested.json"
    capfile.write_text(json.dumps(capture))
    rootpem = tmp_path / "root.pem"
    rootpem.write_bytes(
        root_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    bundle_path = tmp_path / "b.json"
    result = runner.invoke(
        app,
        [
            "scan",
            "--fixture",
            str(capfile),
            "--ephemeral-key",
            "--trusted-root",
            str(rootpem),
            "--expected-vbios",
            good_vbios,
            "--out",
            str(bundle_path),
        ],
    )
    assert result.exit_code == 0, _text(result)
    bundle = EvidenceBundle.model_validate_json(bundle_path.read_text())
    assert bundle.identity.gates.authenticity is GateResult.PASS
    assert bundle.identity.gates.firmware_vbios is GateResult.PASS


def test_scan_missing_fixture_is_clean_error(tmp_path):
    # The GPU-less quickstart path: a typo'd fixture path must print one line, not a
    # FileNotFoundError traceback.
    result = runner.invoke(
        app, ["scan", "--fixture", str(tmp_path / "nope.json"), "--ephemeral-key"]
    )
    assert result.exit_code == 2, _text(result)
    assert "fixture" in _text(result).lower()
    assert "Traceback" not in _text(result)


def test_scan_malformed_fixture_is_clean_error(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{this is not json", encoding="utf-8")
    result = runner.invoke(app, ["scan", "--fixture", str(bad), "--ephemeral-key"])
    assert result.exit_code == 2, _text(result)
    assert "fixture" in _text(result).lower()
    assert "Traceback" not in _text(result)


def test_scan_fixture_missing_required_counters_is_clean_error(tmp_path):
    # A payload that parses as a capture but lacks required health counters raises
    # ValueError deep in the mappers; the CLI must still print one line, not a
    # traceback, on the fixture path.
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    del payload["nvml"]["ecc"]
    shallow = tmp_path / "shallow.json"
    shallow.write_text(json.dumps(payload), encoding="utf-8")
    result = runner.invoke(app, ["scan", "--fixture", str(shallow), "--ephemeral-key"])
    assert result.exit_code == 2, _text(result)
    assert "fixture" in _text(result).lower()
    assert "Traceback" not in _text(result)
