"""`voltry key register` / `voltry key fingerprint`: offline proof of possession of a signing key.

The proof is checked by the Voltry platform, which has its own implementation of the
transcript. The two are held together by the shared golden vector in
``fixtures/org_signer_pop_vector.json``, which the platform's test suite asserts too.

Anti-phishing is the other half of this file: a key registers to one organization, once,
ever, so the command must show which organization a challenge names and refuse to sign
without an explicit confirmation of exactly that organization.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import socket
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from typer.testing import CliRunner

from voltry_probe.cli import app
from voltry_probe.keyreg import (
    NONCE_BYTES,
    SIGNER_POP_TAG,
    ChallengeError,
    OrgMismatchError,
    canonical_spki_der,
    fingerprint,
    format_proof,
    parse_challenge,
    sign_registration,
    transcript,
)

runner = CliRunner()
VECTOR = json.loads(
    (Path(__file__).resolve().parent / "fixtures" / "org_signer_pop_vector.json").read_text(
        encoding="utf-8"
    )
)


def _text(result) -> str:
    """All captured text (stdout + stderr), robust across click versions."""
    out = result.stdout or ""
    try:
        err = result.stderr or ""
    except (ValueError, RuntimeError):  # stderr not separately captured
        err = ""
    return out + err


def _proof_lines(result) -> list[str]:
    return [line for line in _text(result).splitlines() if line.startswith("vsr1.")]


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _challenge(org_id: UUID, nonce: bytes | None = None) -> str:
    return f"vsc1.{org_id}.{_b64url(nonce if nonce is not None else bytes(NONCE_BYTES))}"


def _write_key(tmp_path: Path, key, name: str = "signing.pem") -> Path:
    path = tmp_path / name
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return path


def _verify_proof(proof: str, challenge: str) -> bytes:
    """Check a proof the way the platform does; return the SPKI DER it names."""
    prefix, spki_part, sig_part = proof.split(".")
    assert prefix == "vsr1"
    spki_der, signature = _b64url_decode(spki_part), _b64url_decode(sig_part)
    org_id, nonce = parse_challenge(challenge)
    public_key = serialization.load_der_public_key(spki_der)
    assert isinstance(public_key, ec.EllipticCurvePublicKey)
    public_key.verify(
        signature,
        transcript(nonce=nonce, org_id=org_id, spki_der=spki_der),
        ec.ECDSA(hashes.SHA384()),
    )
    return spki_der


# ----------------------------------------------------------------- the shared golden vector


def test_the_transcript_matches_the_shared_golden_vector():
    org_id, nonce = parse_challenge(VECTOR["challenge"])
    assert str(org_id) == VECTOR["org_id"]
    assert nonce.hex() == VECTOR["nonce_hex"]
    assert VECTOR["tag"] == SIGNER_POP_TAG
    spki = bytes.fromhex(VECTOR["spki_der_hex"])
    message = transcript(nonce=nonce, org_id=org_id, spki_der=spki)
    assert len(message) == VECTOR["transcript_len"]
    assert hashlib.sha384(message).hexdigest() == VECTOR["transcript_sha384"]
    assert fingerprint(spki) == VECTOR["fingerprint"]
    signature = bytes.fromhex(VECTOR["signature_der_hex"])
    assert format_proof(spki, signature) == VECTOR["proof"]
    # The vector's signature really is over this transcript, under this key.
    assert _verify_proof(VECTOR["proof"], VECTOR["challenge"]) == spki


def test_the_transcript_matches_the_documented_grammar_by_hand():
    def lp(component: bytes) -> bytes:
        return len(component).to_bytes(4, "big") + component

    org_id = UUID(VECTOR["org_id"])
    nonce = bytes.fromhex(VECTOR["nonce_hex"])
    spki = bytes.fromhex(VECTOR["spki_der_hex"])
    expected = lp(b"voltry.org.signer-pop/v1") + lp(nonce) + lp(str(org_id).encode()) + lp(spki)
    assert transcript(nonce=nonce, org_id=org_id, spki_der=spki) == expected


@pytest.mark.parametrize("size", [0, 31, 33])
def test_a_wrong_size_nonce_is_never_signed(size):
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        transcript(nonce=b"\x00" * size, org_id=uuid4(), spki_der=b"spki")


# ----------------------------------------------------------------- parsing and signing


@pytest.mark.parametrize(
    "challenge",
    [
        "",
        "vsc1",
        "vsc2.00000000-0000-4000-8000-0000000000aa.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        "vsc1.00000000-0000-4000-8000-0000000000AA.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        "vsc1.not-a-uuid.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        "vsc1.00000000-0000-4000-8000-0000000000aa.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        "vsc1.00000000-0000-4000-8000-0000000000aa.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg",
        "vsc1.00000000-0000-4000-8000-0000000000aa.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh9",
        "vsc1.00000000-0000-4000-8000-0000000000aa.AAECAwQFBgcICQoLDA0ODxAREhMUFRYX+BkaGxwdHh8",
        "vsc1.00000000-0000-4000-8000-0000000000aa.x.y",
    ],
)
def test_a_malformed_challenge_is_refused(challenge):
    with pytest.raises(ChallengeError):
        parse_challenge(challenge)


def test_signing_requires_the_confirmed_org_to_be_the_challenges_org():
    key = ec.generate_private_key(ec.SECP384R1())
    org_id = uuid4()
    challenge = _challenge(org_id, bytes(range(32)))
    with pytest.raises(OrgMismatchError, match="nothing was signed"):
        sign_registration(key, challenge, confirmed_org_id=uuid4())
    registration = sign_registration(key, challenge, confirmed_org_id=org_id)
    assert registration.org_id == org_id
    assert registration.fingerprint == fingerprint(canonical_spki_der(key.public_key()))
    spki_der = _verify_proof(registration.proof, challenge)
    assert spki_der == canonical_spki_der(key.public_key())


def test_the_proof_signature_is_der_and_a_raw_r_s_form_does_not_verify():
    """The platform verifies DER signatures only; a raw r||s rendering of the same
    signature must not pass (it would be refused as possession_not_proven)."""
    key = ec.generate_private_key(ec.SECP384R1())
    org_id = uuid4()
    challenge = _challenge(org_id)
    proof = sign_registration(key, challenge, confirmed_org_id=org_id).proof
    _, spki_part, sig_part = proof.split(".")
    der_sig = _b64url_decode(sig_part)
    r, s = decode_dss_signature(der_sig)  # parses: it IS DER
    assert encode_dss_signature(r, s) == der_sig
    raw = r.to_bytes(48, "big") + s.to_bytes(48, "big")
    with pytest.raises(InvalidSignature):
        _verify_proof(f"vsr1.{spki_part}.{_b64url(raw)}", challenge)


def test_a_non_p384_key_is_never_signed_with():
    key = ec.generate_private_key(ec.SECP256R1())
    org_id = uuid4()
    with pytest.raises(ValueError, match="P-384"):
        sign_registration(key, _challenge(org_id), confirmed_org_id=org_id)


# ----------------------------------------------------------------- the CLI


@pytest.fixture
def key_file(tmp_path):
    key = ec.generate_private_key(ec.SECP384R1())
    return key, _write_key(tmp_path, key)


def test_register_shows_the_org_and_signs_only_after_a_yes(key_file):
    key, path = key_file
    org_id = uuid4()
    challenge = _challenge(org_id, bytes(range(32)))
    result = runner.invoke(
        app, ["key", "register", "--signing-key", str(path), "--challenge", challenge], input="y\n"
    )
    assert result.exit_code == 0, _text(result)
    text = _text(result)
    assert str(org_id) in text
    assert fingerprint(canonical_spki_der(key.public_key())) in text
    (proof,) = _proof_lines(result)
    assert _verify_proof(proof, challenge) == canonical_spki_der(key.public_key())
    assert "[y/N]" in text
    # stdout carries the proof alone, so it can be piped (when click separates the streams).
    try:
        stderr_separate = result.stderr is not None
    except (ValueError, RuntimeError):
        stderr_separate = False
    if stderr_separate:
        assert result.stdout == proof + "\n"


@pytest.mark.parametrize("answer", ["n\n", "\n", "", "maybe\n", "yess\n", " no\n"])
def test_register_refuses_to_sign_without_a_confirmation(key_file, answer):
    _, path = key_file
    org_id = uuid4()
    result = runner.invoke(
        app,
        ["key", "register", "--signing-key", str(path), "--challenge", _challenge(org_id)],
        input=answer,
    )
    assert result.exit_code == 2, _text(result)
    assert str(org_id) in _text(result)  # the org was shown before the question
    assert "Nothing was signed" in _text(result)
    assert _proof_lines(result) == []


def test_register_non_interactive_form_must_name_the_challenges_org(key_file):
    key, path = key_file
    org_id = uuid4()
    challenge = _challenge(org_id)
    base = ["key", "register", "--signing-key", str(path), "--challenge", challenge]

    ok = runner.invoke(app, [*base, "--yes-this-is-my-org", str(org_id)])
    assert ok.exit_code == 0, _text(ok)
    (proof,) = _proof_lines(ok)
    assert _verify_proof(proof, challenge) == canonical_spki_der(key.public_key())
    assert "[y/N]" not in _text(ok)  # no prompt in the non-interactive form
    # The flag skips the question, never the warning: in the phishing case the flag carries
    # the attacker's org id, so the stderr warning is the last thing standing.
    assert str(org_id) in _text(ok)
    assert "If someone else sent you this challenge, stop here." in _text(ok)
    # stdout carries the proof alone, so it can be piped (when click separates the streams).
    try:
        stderr_separate = ok.stderr is not None
    except (ValueError, RuntimeError):
        stderr_separate = False
    if stderr_separate:
        assert ok.stdout.strip() == proof
        assert "If someone else sent you this challenge, stop here." in ok.stderr

    for wrong in (str(uuid4()), "not-an-org-id", ""):
        refused = runner.invoke(app, [*base, "--yes-this-is-my-org", wrong], input="y\n")
        assert refused.exit_code == 2, _text(refused)
        assert "Nothing was signed" in _text(refused)
        assert _proof_lines(refused) == []


def test_register_refuses_a_malformed_challenge_before_touching_the_key(tmp_path):
    result = runner.invoke(
        app,
        [
            "key",
            "register",
            "--signing-key",
            str(tmp_path / "missing.pem"),
            "--challenge",
            "vsc1.garbage",
            "--yes-this-is-my-org",
            str(uuid4()),
        ],
    )
    assert result.exit_code == 2
    assert "Nothing was signed" in _text(result)
    assert "Traceback" not in _text(result)


def test_register_refuses_a_non_p384_signing_key(tmp_path):
    path = _write_key(tmp_path, ec.generate_private_key(ec.SECP256R1()))
    org_id = uuid4()
    result = runner.invoke(
        app,
        [
            "key",
            "register",
            "--signing-key",
            str(path),
            "--challenge",
            _challenge(org_id),
            "--yes-this-is-my-org",
            str(org_id),
        ],
    )
    assert result.exit_code == 2
    assert "P-384" in _text(result)
    assert _proof_lines(result) == []


def test_register_is_offline(key_file, monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("voltry key register must not open a network connection")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    _, path = key_file
    org_id = uuid4()
    result = runner.invoke(
        app,
        [
            "key",
            "register",
            "--signing-key",
            str(path),
            "--challenge",
            _challenge(org_id),
            "--yes-this-is-my-org",
            str(org_id),
        ],
    )
    assert result.exit_code == 0, _text(result)


def test_register_help_documents_the_der_signature_and_the_one_org_rule():
    # Plain, wide output whatever the host terminal (CI forces color, which splits option
    # names with escape codes); escapes and box rules are stripped as a second guard.
    result = runner.invoke(
        app,
        ["key", "register", "--help"],
        env={"NO_COLOR": "1", "TERM": "dumb", "COLUMNS": "200", "FORCE_COLOR": ""},
    )
    assert result.exit_code == 0
    plain = re.sub(r"\x1b\[[0-9;]*m", "", _text(result))
    text = " ".join(plain.replace("│", " ").split())
    assert "DER" in text
    assert "r||s" in text
    assert "once" in text
    assert "--yes-this-is-my-org" in text


def test_fingerprint_is_the_same_from_the_private_or_the_public_key(key_file, tmp_path):
    key, path = key_file
    public_path = tmp_path / "public.pem"
    public_path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    expected = fingerprint(canonical_spki_der(key.public_key()))
    from_private = runner.invoke(app, ["key", "fingerprint", "--signing-key", str(path)])
    from_public = runner.invoke(app, ["key", "fingerprint", "--public-key", str(public_path)])
    assert from_private.exit_code == 0 and from_public.exit_code == 0
    assert expected in from_private.stdout and expected in from_public.stdout


def test_fingerprint_needs_exactly_one_key(key_file, tmp_path):
    _, path = key_file
    assert runner.invoke(app, ["key", "fingerprint"]).exit_code != 0
    both = runner.invoke(
        app, ["key", "fingerprint", "--signing-key", str(path), "--public-key", str(path)]
    )
    assert both.exit_code != 0
    missing = runner.invoke(app, ["key", "fingerprint", "--public-key", str(tmp_path / "x.pem")])
    assert missing.exit_code != 0
    assert "Traceback" not in _text(missing)
