"""Pure reader mappers: verbatim source payloads to typed evidence-schema blocks.

All mappers are pure functions over dicts: read-only by construction, with no NVML/DCGM
setters anywhere (enforced by the read-only invariant test).
"""

from __future__ import annotations

from .dcgm import DcgmReadout, map_dcgm
from .nvml import NvmlReadout, map_nvml
from .redfish import RedfishReadout, map_redfish
from .taxonomy import XID_TAXONOMY, normalize_xid

__all__ = [
    "map_nvml",
    "NvmlReadout",
    "map_dcgm",
    "DcgmReadout",
    "map_redfish",
    "RedfishReadout",
    "normalize_xid",
    "XID_TAXONOMY",
]
