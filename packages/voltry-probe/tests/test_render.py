"""Offline HTML certificate render: Worked Example A structure, neutrality, offline."""

from __future__ import annotations

import re

from evidence_schema import Tier, generate_keypair
from evidence_schema.samples import worked_example_a_bundle
from evidence_schema.sign import sign_bundle

from voltry_probe import render_certificate

_PRICE = re.compile(
    r"price|valuation|apprais|resale|\bworth\b|market[_ -]?value|asset[_ -]?value|\$\d", re.I
)


def _html() -> str:
    # The worked-example sample is unsigned, so it renders as an unverified view.
    return render_certificate(worked_example_a_bundle(), verified=False)


def _signed_bundle():
    return sign_bundle(worked_example_a_bundle(), generate_keypair())


def test_xid_not_read_renders_as_not_assessed_never_zero():
    # A bundle whose capture had NO Xid event source must not claim "0 events":
    # absent telemetry is omitted, never recorded as zero.
    bundle = worked_example_a_bundle()
    bundle.measured.extensions = {}  # no xid_events_source stamp
    html = render_certificate(bundle, verified=False)
    assert "not read" in html
    assert ">0</span>" not in html.split("Xid critical events")[1][:120]


def test_xid_zero_renders_when_source_was_read():
    # The worked example models a payload-sourced scan: an observed zero is honest.
    html = render_certificate(worked_example_a_bundle(), verified=False)
    assert "Xid critical events" in html
    section = html.split("Xid critical events")[1][:120]
    assert ">0<" in section
    assert "not read" not in section


def test_unverified_bundle_is_watermarked():
    # A bundle whose signature does not verify must never render as authoritative.
    html = render_certificate(worked_example_a_bundle(), verified=False)
    assert "UNVERIFIED" in html
    assert "bound &amp; verified" not in html  # the "verified" claim requires a valid signature


def test_verified_bundle_is_not_watermarked():
    html = render_certificate(_signed_bundle(), verified=True)
    assert "UNVERIFIED" not in html
    assert "verified" in html


def test_renders_four_block_structure():
    html = _html()
    assert "Certified by Voltry" in html
    assert "1 · Deterministic gates" in html
    assert "2 · Measured condition" in html
    assert "3 · Modeled fields" in html
    assert "4 · Provenance" in html


def test_worked_example_a_facts_present():
    html = _html()
    assert "H100-SXM5" in html
    assert "SILVER" in html  # the sample bundle carries tier=SILVER
    assert "509 / 512" in html  # the spare-row end-of-life gauge
    assert "Authenticity" in html and "PASS" in html


def test_measured_and_modeled_visually_distinct():
    html = _html()
    # Distinct CSS treatments exist for facts vs estimates.
    assert "block--measured" in html
    assert "block--modeled" in html


def test_modeled_block_is_pending_never_faked():
    html = _html()
    # Modeled fields render as pending and as a band, never a single score.
    assert "pending" in html.lower()
    assert "estimate band: pending" in html
    # No fabricated numeric wear index / score leaked into the cert.
    assert "condition_score" not in html
    assert "overall score" not in html.lower()


def test_exposure_not_assessed_is_prominent():
    html = _html()
    assert "EXPOSURE ASSESSED" in html
    # The rendered exposure element (not just the CSS rule) uses the prominent "no" flag.
    assert 'class="exposure exposure--no"' in html
    assert "NOT assessed" in html


def test_exposure_assessed_variant_uses_distinct_flag():
    bundle = worked_example_a_bundle()
    bundle.provenance.exposure_assessed = True
    html = render_certificate(bundle, verified=False)
    # The rendered element switches to the "yes" flag (both classes are defined in CSS).
    assert 'class="exposure exposure--yes"' in html
    assert 'class="exposure exposure--no"' not in html


def test_verify_slot_is_plain_text_not_a_fake_code():
    # An earlier revision drew a decorative QR-looking SVG that encoded nothing; the
    # slot is plain text now (bundle id short form + the verify-at line). No inline SVG
    # means nothing on the cert can imply machine-verifiability it does not have.
    html = _html()
    assert "<svg" not in html
    assert "voltry verify" in html
    assert str(worked_example_a_bundle().bundle_id)[:12] in html


def test_no_price_anywhere():
    assert not _PRICE.search(_html())


def test_is_offline_self_contained():
    html = _html()
    # No external resource fetches: no stylesheet link, script, or remote src/href.
    assert "<script" not in html
    assert "stylesheet" not in html
    assert "@import" not in html
    assert 'src="http' not in html
    assert 'href="http' not in html
    # CSS is inlined (the generated tokens + layout).
    assert "<style>" in html
    assert "--surface-card" in html  # token vars are present inline


def test_render_is_deterministic():
    assert _html() == _html()


def test_tier_word_renders_for_each_tier():
    for tier in (Tier.BRONZE, Tier.SILVER, Tier.GOLD):
        bundle = worked_example_a_bundle()
        bundle.provenance.tier = tier
        assert tier.value in render_certificate(bundle, verified=False)


def test_duty_absent_renders_not_accumulated_never_zero():
    # A single cold-start read cannot measure lifetime duty; the cert must say so
    # honestly rather than claim zero hours (the odometer analogue of the Xid rule).
    html = _html()  # worked example carries no duty
    assert "Lifetime duty" in html
    assert "not accumulated" in html
    assert "0 GPU-h" not in html


def test_duty_present_renders_the_odometer():
    from datetime import datetime, timezone

    from evidence_schema import DutyBlock

    bundle = worked_example_a_bundle()
    bundle.measured.duty = DutyBlock(
        gpu_hours_total=3400.0,
        thermal_cycles_total=180,
        energy_kwh_total=1760.0,
        sustained_high_power_hours=1100.0,
        basis="monitor_continuous",
        since=datetime(2026, 1, 14, tzinfo=timezone.utc),
    )
    html = render_certificate(bundle, verified=False)
    assert "GPU-hours" in html and "3,400" in html
    assert "Thermal cycles" in html and "180" in html
    assert "high-power" in html and "1,100" in html
    assert "monitor" in html  # the basis is stated so a reader can weigh it
