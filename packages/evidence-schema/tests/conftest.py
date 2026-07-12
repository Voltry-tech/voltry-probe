"""Shared fixtures. No real keys or PII: keypairs are ephemeral, bundles are simulated.

The hypothesis strategy that generates varied bundles lives in ``test_canonical.py``
(its only consumer), kept out of conftest so nothing has to import across the
monorepo's same-named ``tests`` packages.
"""

from __future__ import annotations

import pytest

from evidence_schema import EvidenceBundle, generate_keypair
from evidence_schema.samples import worked_example_a_bundle


@pytest.fixture
def sample_bundle() -> EvidenceBundle:
    """Deterministic Worked Example A bundle (unsigned)."""
    return worked_example_a_bundle()


@pytest.fixture
def keypair():
    """A fresh ephemeral ECDSA P-384 private key."""
    return generate_keypair()
