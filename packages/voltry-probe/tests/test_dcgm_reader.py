"""DCGM mapper tests: a telemetry payload maps to NVLink/PCIe status without diagnostics."""

from __future__ import annotations

from voltry_probe.readers import map_dcgm


def test_maps_nvlink_and_pcie(capture):
    out = map_dcgm(capture.dcgm)
    assert out.nvlink is not None and out.nvlink.active_links == 18
    assert out.nvlink.total_links == 18
    assert out.pcie is not None and out.pcie.gen == 5 and out.pcie.width == 16


def test_none_payload_yields_empty_readout():
    out = map_dcgm(None)
    assert out.nvlink is None and out.pcie is None


def test_partial_payload():
    out = map_dcgm({"pcie": {"gen": 4, "width": 16}})
    assert out.nvlink is None
    assert out.pcie is not None and out.pcie.gen == 4
