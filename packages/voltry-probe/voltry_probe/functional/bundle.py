"""Assemble a functional-mode evidence bundle from a capture plus functional results."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec
from evidence_schema import (
    AgentInfo,
    DutyBlock,
    EvidenceBundle,
    FunctionalBlock,
    History,
    Tier,
)
from evidence_schema.types import UtcDateTime

from ..evidence.builder import build_read_bundle
from ..sources.base import RawCapture


def build_functional_bundle(
    capture: RawCapture,
    *,
    functional: FunctionalBlock,
    signer_key: ec.EllipticCurvePrivateKey,
    agent: AgentInfo,
    methodology_version_hash: str,
    trusted_root_public_key: ec.EllipticCurvePublicKey | None = None,
    expected_vbios_hash: str | None = None,
    operator_challenge: str | None = None,
    signer_label: str = "operator",
    created_at: UtcDateTime | None = None,
    history: History = History.RECONSTRUCTED,
    born_on: UtcDateTime | None = None,
    duty: DutyBlock | None = None,
) -> EvidenceBundle:
    """A signed bundle carrying drained-unit functional results (``tier=SILVER``).

    The functional gates on the certificate derive from the ``functional`` block.
    Everything except ``functional`` is forwarded to :func:`build_read_bundle`
    unchanged; the keywords are spelled out (rather than taking **kwargs) so callers
    keep type checking and completion on the full keyword surface.
    """
    return build_read_bundle(
        capture,
        signer_key=signer_key,
        agent=agent,
        methodology_version_hash=methodology_version_hash,
        trusted_root_public_key=trusted_root_public_key,
        expected_vbios_hash=expected_vbios_hash,
        operator_challenge=operator_challenge,
        signer_label=signer_label,
        created_at=created_at,
        functional=functional,
        tier=Tier.SILVER,
        history=history,
        born_on=born_on,
        duty=duty,
    )
