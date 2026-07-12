"""Fixtures + helpers for the probe tests.

All keys are ephemeral (generated per test) and no key material is committed. The
attestation-report builder mirrors what a real device + root CA would sign, so the
verifier is exercised against genuine signatures (and genuine tampering).
"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest
import rfc8785
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from evidence_schema import AgentInfo, IdentityScheme, RunMode, generate_keypair
from evidence_schema.sign import public_key_to_spki_b64

from voltry_probe.sources import FixtureSource, RawCapture

FIXTURES = Path(__file__).resolve().parent / "fixtures"
DEVICE_ID = "04a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d"
GOOD_VBIOS = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"


def _sign(key: ec.EllipticCurvePrivateKey, payload: bytes) -> str:
    return base64.b64encode(key.sign(payload, ec.ECDSA(hashes.SHA384()))).decode("ascii")


@pytest.fixture
def root_key() -> ec.EllipticCurvePrivateKey:
    return generate_keypair()


@pytest.fixture
def device_key() -> ec.EllipticCurvePrivateKey:
    return generate_keypair()


@pytest.fixture
def signer_key() -> ec.EllipticCurvePrivateKey:
    return generate_keypair()


@pytest.fixture
def agent() -> AgentInfo:
    return AgentInfo(name="voltry-probe", version="0.1.0", run_mode=RunMode.READ)


@pytest.fixture
def capture() -> RawCapture:
    return FixtureSource(FIXTURES / "h100_read.json").capture()


@pytest.fixture
def device_id() -> str:
    return DEVICE_ID


@pytest.fixture
def good_vbios() -> str:
    return GOOD_VBIOS


@pytest.fixture
def make_report():
    """A callable building a genuinely-signed attestation report dict (see below)."""
    return make_attestation_report


def make_attestation_report(
    root_key: ec.EllipticCurvePrivateKey,
    device_key: ec.EllipticCurvePrivateKey,
    *,
    device_id: str = DEVICE_ID,
    vbios_hash: str = GOOD_VBIOS,
    scheme: IdentityScheme = IdentityScheme.HARDWARE_ROOT,
    nonce: str = "nonce-2026-06-17",
    tamper: str | None = None,
) -> dict:
    """Build a genuinely-signed attestation report dict (or a tampered one).

    tamper is one of: None, "root_sig", "measurement_sig".
    """
    device_pub_b64 = public_key_to_spki_b64(device_key.public_key())
    root_stmt = rfc8785.dumps({"device_id": device_id, "device_public_key_b64": device_pub_b64})
    measurement = rfc8785.dumps({"nonce": nonce, "vbios_hash": vbios_hash})
    root_sig = _sign(root_key, root_stmt)
    meas_sig = _sign(device_key, measurement)

    if tamper == "root_sig":
        root_sig = _sign(generate_keypair(), root_stmt)  # signed by an untrusted key
    elif tamper == "measurement_sig":
        meas_sig = _sign(generate_keypair(), measurement)  # not the device key

    return {
        "scheme": scheme.value,
        "device_id": device_id,
        "device_public_key_b64": device_pub_b64,
        "root_signature_b64": root_sig,
        "vbios_hash": vbios_hash,
        "nonce": nonce,
        "measurement_signature_b64": meas_sig,
    }
