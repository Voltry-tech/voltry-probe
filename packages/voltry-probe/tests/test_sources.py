"""Sources + mapper edge cases (construction, empty payloads, no-DCGM capture)."""

from __future__ import annotations

from datetime import datetime, timezone

from evidence_schema import AgentInfo, RunMode, verify_bundle

from voltry_probe import build_read_bundle
from voltry_probe.readers import map_nvml, map_redfish
from voltry_probe.sources import RawCapture
from voltry_probe.sources.live import LiveSource


def test_live_source_constructs_without_hardware():
    # Constructing the live source must not require pynvml; only .capture() does.
    src = LiveSource(index=2)
    assert isinstance(src, LiveSource)


def test_fixture_source_loads_capture(capture):
    assert capture.nvml["device"]["part"] == "H100-SXM5"
    assert capture.attestation is None


def test_map_redfish_none_is_empty():
    out = map_redfish(None)
    assert out.board_id is None and out.chassis is None


def test_map_nvml_skips_non_dict_xid_entries():
    out = map_nvml(
        {
            "device": {},
            "ecc": {
                "volatile": {"correctable": 0, "uncorrectable": 0},
                "aggregate": {"correctable": 0, "uncorrectable": 0},
            },
            "remapped_rows": {"corrRows": 0, "uncRows": 0},
            "pages": {"retired_sbe": 0, "retired_dbe": 0},
            "xid": ["not-a-dict", {"xid": 79}],
        }
    )
    assert [e.xid for e in out.xid] == [79]  # the bogus entry is skipped, not crashed on


def test_build_bundle_with_nvml_only(signer_key):
    capture = RawCapture(
        captured_at=datetime(2026, 6, 17, 9, 0, 0, tzinfo=timezone.utc),
        nvml={
            "device": {"part": "H100-SXM5", "uuid": "GPU-abc"},
            "ecc": {
                "volatile": {"correctable": 0, "uncorrectable": 0},
                "aggregate": {"correctable": 0, "uncorrectable": 0},
            },
            "remapped_rows": {"corrRows": 0, "uncRows": 0},
            "pages": {"retired_sbe": 0, "retired_dbe": 0},
        },
        dcgm=None,
        redfish=None,
        attestation=None,
    )
    bundle = build_read_bundle(
        capture,
        signer_key=signer_key,
        agent=AgentInfo(name="voltry-probe", version="0.1.0", run_mode=RunMode.READ),
        methodology_version_hash="read-v0",
    )
    assert verify_bundle(bundle) is True
    assert {p.source for p in bundle.raw_reads.payloads} == {"nvml"}
    assert bundle.measured.nvlink is None
