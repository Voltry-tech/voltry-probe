"""Maps a verbatim DCGM telemetry payload into NVLink/PCIe status.

Pure function of its input dict; telemetry only. Read mode uses DCGM for a
non-disruptive telemetry sample. The DCGM diagnostic run levels r1 to r4 stress the
device and require a drained GPU, so they live exclusively in
``voltry_probe/functional/``, never here.
"""

from __future__ import annotations

from evidence_schema import NvLinkStatus, PcieStatus
from pydantic import BaseModel, ConfigDict

from ._util import _d


class DcgmReadout(BaseModel):
    """Typed result of mapping a DCGM telemetry payload."""

    model_config = ConfigDict(extra="forbid")

    nvlink: NvLinkStatus | None
    pcie: PcieStatus | None


def map_dcgm(dcgm: dict | None) -> DcgmReadout:
    """Map a verbatim DCGM payload into NVLink/PCIe status (both optional)."""
    if not dcgm:
        return DcgmReadout(nvlink=None, pcie=None)

    # A near-twin construction lives in readers/nvml.py; this one additionally maps
    # the PCIe error counters only DCGM exposes. Intentionally not merged.
    nvlink_raw = _d(dcgm, "nvlink")
    pcie_raw = _d(dcgm, "pcie")
    nvlink = (
        NvLinkStatus(
            active_links=_d(nvlink_raw, "active"),
            total_links=_d(nvlink_raw, "total"),
            replay_errors=_d(nvlink_raw, "replay_errors"),
            recovery_errors=_d(nvlink_raw, "recovery_errors"),
            crc_errors=_d(nvlink_raw, "crc_errors"),
        )
        if isinstance(nvlink_raw, dict)
        else None
    )
    pcie = (
        PcieStatus(
            gen=_d(pcie_raw, "gen"),
            width=_d(pcie_raw, "width"),
            replay_counter=_d(pcie_raw, "replay_counter"),
            correctable_errors=_d(pcie_raw, "correctable_errors"),
            fatal_errors=_d(pcie_raw, "fatal_errors"),
            nonfatal_errors=_d(pcie_raw, "nonfatal_errors"),
        )
        if isinstance(pcie_raw, dict)
        else None
    )
    return DcgmReadout(nvlink=nvlink, pcie=pcie)
