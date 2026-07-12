"""Minimal Xid to normalized-taxonomy mapping (the certificate's Block 2 uses this).

Every source names events differently; they must be mapped to one taxonomy before any
pooling. This is the read-side subset; the full taxonomy and cross-source normalization
belong to the modeling engine and are not included here. An unknown Xid maps to
``("uncategorized", False)`` rather than being dropped, so a unit's first-scan record
stays complete even for codes nothing renders or models yet.
"""

from __future__ import annotations

from typing import NamedTuple


class XidClass(NamedTuple):
    category: str
    critical: bool
    description: str


# Representative, widely-cited Xids. Critical ones are disqualifying-adjacent signals.
XID_TAXONOMY: dict[int, XidClass] = {
    13: XidClass("gpu_exception", False, "Graphics engine exception"),
    31: XidClass("mmu_fault", False, "GPU memory page fault (MMU)"),
    43: XidClass("gpu_exception", False, "GPU stopped processing"),
    48: XidClass("memory_dbe", True, "Double-bit ECC error (DBE)"),
    63: XidClass("row_remap", False, "ECC page retirement or row remapping recorded"),
    64: XidClass("row_remap", False, "ECC row remapping failure"),
    74: XidClass("nvlink", True, "NVLink error"),
    79: XidClass("off_bus", True, "GPU has fallen off the bus"),
    92: XidClass("thermal", False, "High single-bit ECC error rate / HW slowdown"),
    94: XidClass("ecc_contained", True, "Contained ECC error"),
    95: XidClass("ecc_uncontained", True, "Uncontained ECC error"),
}


def normalize_xid(xid: int) -> XidClass:
    """Map an Xid code to its normalized taxonomy class (never drops unknowns)."""
    return XID_TAXONOMY.get(xid, XidClass("uncategorized", False, f"Xid {xid}"))
