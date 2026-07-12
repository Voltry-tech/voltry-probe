"""Cryptographic verification of the device identity chain.

``verify.py`` documents how each verdict is reached. Verdict semantics:

- ``VERIFIED``: the full identity chain and measurement signature check out under a
  hardware root; high confidence.
- ``FAILED``: a chain or measurement signature check failed; disqualifying.
- ``UNVERIFIED``: no report was available, or the trusted root/PKI was unreachable, so
  the chain could not be evaluated.
- ``FALLBACK``: the chain checks out under a secondary scheme with no hardware root;
  valid, but lower confidence and marked as such.
"""

from __future__ import annotations

from .model import AttestationReport
from .verify import (
    DEFAULT_FRESHNESS_WINDOW,
    MIN_CHALLENGE_LENGTH,
    AttestationOutcome,
    verify_attestation,
)

__all__ = [
    "AttestationReport",
    "AttestationOutcome",
    "verify_attestation",
    "DEFAULT_FRESHNESS_WINDOW",
    "MIN_CHALLENGE_LENGTH",
]
