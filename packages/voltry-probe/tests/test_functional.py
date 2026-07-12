"""Functional mode: pure result mapping needs no consent; live execution is consent-gated.

The functional API is importable only from ``voltry_probe.functional``; the package root
must not re-export it.
"""

from __future__ import annotations

import pytest
from evidence_schema import GateResult, Tier, verify_bundle

from voltry_probe.functional import (
    DrainConsentError,
    build_functional_bundle,
    map_functional_results,
)
from voltry_probe.functional.runner import _run_live_diagnostics

FUNCTIONAL_RESULTS = {
    "dcgm_runlevel": "r4",
    "dcgm_result": "PASS",
    "burnin_result": "PASS",
    "burnin_duration_s": 5400,
    "sdc_functional": "PASS",
    "sdc_detail": "no silent data corruption observed",
    "sanitization_method": "purge",
    "sanitization_result": "PASS",
    "sanitization_verified": True,
}


def test_mapping_is_pure_and_needs_no_consent():
    fb = map_functional_results(FUNCTIONAL_RESULTS)
    assert fb.dcgm_runlevel == "r4"
    assert fb.dcgm_result is GateResult.PASS
    assert fb.burnin_duration_s == 5400
    assert fb.sdc_functional is GateResult.PASS
    assert fb.sanitization.result is GateResult.PASS
    assert fb.sanitization.verified is True


def test_mapping_defaults_unassessed():
    fb = map_functional_results({})
    assert fb.dcgm_result is GateResult.NOT_ASSESSED
    assert fb.sdc_functional is GateResult.NOT_ASSESSED


def test_live_refuses_without_drain_consent():
    # Consent is checked at the action boundary, on every call.
    with pytest.raises(DrainConsentError):
        _run_live_diagnostics(drain_consent=False)


def test_live_is_not_available_even_with_consent():
    # Live execution has not shipped; it must refuse rather than pretend.
    with pytest.raises(NotImplementedError):
        _run_live_diagnostics(drain_consent=True)


def test_root_does_not_reexport_functional_api():
    import voltry_probe

    for name in (
        "FunctionalRunner",
        "DrainConsentError",
        "build_functional_bundle",
        "map_functional_results",
    ):
        assert not hasattr(voltry_probe, name), f"package root re-exports functional API: {name}"
        assert name not in voltry_probe.__all__


def test_build_functional_bundle_is_silver_with_functional_gates(capture, signer_key, agent):
    fb = map_functional_results(FUNCTIONAL_RESULTS)
    bundle = build_functional_bundle(
        capture,
        functional=fb,
        signer_key=signer_key,
        agent=agent,
        methodology_version_hash="func-v0",
    )
    assert verify_bundle(bundle) is True
    assert bundle.provenance.tier is Tier.SILVER
    assert bundle.functional is not None and bundle.functional.dcgm_result is GateResult.PASS
    # The deterministic functional gates derive from the functional block.
    assert bundle.identity.gates.functional_burnin is GateResult.PASS
    assert bundle.identity.gates.sdc_functional is GateResult.PASS
    assert bundle.identity.gates.data_sanitization is GateResult.PASS
