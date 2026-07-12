"""Monitor mode (continuous read-only telemetry; bundles carry tier=GOLD) plus born-on."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from evidence_schema import History, Tier, verify_bundle

from voltry_probe import MonitorSession, TelemetrySample, build_monitor_bundle

_T0 = datetime(2026, 6, 17, 9, 0, tzinfo=timezone.utc)
_T1 = datetime(2026, 6, 17, 10, 0, tzinfo=timezone.utc)


def test_first_sample_sets_born_on():
    session = MonitorSession(ecc384_id="ECC-MON")
    assert session.is_born_on is False
    session.record(TelemetrySample(ts=_T0, metrics={"gpu_temp_c": 41, "power_draw_w": 312}))
    assert session.born_on == _T0
    assert session.is_born_on is True


def test_later_samples_do_not_change_born_on():
    session = MonitorSession(ecc384_id="ECC-MON")
    session.record(TelemetrySample(ts=_T0, metrics={"gpu_temp_c": 41}))
    session.record(TelemetrySample(ts=_T1, metrics={"gpu_temp_c": 43}))
    assert session.born_on == _T0  # born-on is the first-seen time, immutable
    assert len(session.samples) == 2


def test_to_timescale_rows_flattens_series():
    session = MonitorSession(ecc384_id="ECC-TS")
    session.record(TelemetrySample(ts=_T0, metrics={"a": 1.0, "b": 2.0}))
    rows = session.to_timescale_rows()
    assert ("ECC-TS", _T0, "a", 1.0) in rows
    assert ("ECC-TS", _T0, "b", 2.0) in rows
    assert len(rows) == 2


def test_build_monitor_bundle_is_gold_born_on(capture, signer_key, agent):
    bundle = build_monitor_bundle(
        capture, born_on=_T0, signer_key=signer_key, agent=agent, methodology_version_hash="mon-v0"
    )
    assert verify_bundle(bundle) is True
    assert bundle.provenance.tier is Tier.GOLD
    assert bundle.provenance.history is History.BORN_ON
    assert bundle.provenance.born_on == _T0
    assert bundle.provenance.chain_gaps is False  # born-on history means a continuous chain


def test_naive_timestamps_are_rejected():
    # Naive datetimes would only fail later, when born_on reaches the bundle
    # builder's UTC-validated fields; reject them at the producer instead.
    with pytest.raises(ValueError):
        TelemetrySample(ts=datetime(2026, 6, 17, 9, 0), metrics={"gpu_temp_c": 41})
    with pytest.raises(ValueError):
        MonitorSession(ecc384_id="ECC-MON", born_on=datetime(2026, 6, 17, 9, 0))
