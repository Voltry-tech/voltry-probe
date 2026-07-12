"""The attestation report payload.

A deliberately small but faithful model of the NVIDIA Device Identity (over SPDM) chain:
a device identity key whose binding is signed by the NVIDIA root, plus a freshness-bound
measurement (VBIOS hash + nonce) signed by the device key. Verification (``verify.py``)
checks both signatures and the VBIOS hash. This mirrors the structure of the real chain
(the root signs the device cert, and the device key signs the measurement) without
re-implementing X.509/SPDM transport.
"""

from __future__ import annotations

from evidence_schema import IdentityScheme
from pydantic import BaseModel, ConfigDict, Field


class AttestationReport(BaseModel):
    """Verbatim attestation report to be verified (never trusted blindly)."""

    model_config = ConfigDict(extra="forbid")

    scheme: IdentityScheme = Field(description="HARDWARE_ROOT or SECONDARY_FALLBACK.")
    device_id: str = Field(description="Device identity id (the permanent ECC-384 id).")
    device_public_key_b64: str = Field(
        description="Device identity public key (SPKI DER, base64), P-384."
    )
    root_signature_b64: str = Field(
        description="Root CA signature over the canonical (device_id, device_public_key) binding."
    )
    vbios_hash: str = Field(description="VBIOS measurement hash attested by this report.")
    nonce: str = Field(description="Freshness nonce bound into the measurement signature.")
    measurement_signature_b64: str = Field(
        description="Device-key signature over the canonical (nonce, vbios_hash) measurement."
    )
