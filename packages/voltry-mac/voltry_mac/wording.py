"""The fixed honesty copy: the words the report model hands every renderer.

docs/VOLTRY_MAC_SPEC.md, "Fixed notes (exact copy, pinned by tests)", Decision 6's section
order and the title block. The terminal summary, the PDF and a later render print these
strings as they are, so every form of a report says the same thing, and the limits of the
report come right after At a glance, before any detail. Nothing here states or implies a
verdict, a grade, a price or a prediction.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Final

TITLE: Final = "Mac hardware observation report"
DISCLAIMER: Final = "Point-in-time observations, not a diagnosis, grade or certificate."

FIXED_NOTES: Final = MappingProxyType(
    {
        "memory": (
            "These numbers come from a private Apple log that is not documented. Apple does "
            "not say how long it keeps records, or which Macs keep them. Zero means none are "
            "recorded there now. It does not mean the memory has never had an error. Macs "
            "offer no public memory error counter."
        ),
        "storage": (
            "Endurance used is the SSD controller's own estimate, not a prediction of "
            "remaining life. Unsafe shutdowns count sudden power losses the drive saw; they "
            "are not proof of damage. Zero media errors means the controller reports none, "
            "not that the storage is perfect."
        ),
        "battery": (
            "Maximum capacity is macOS's own figure. The gauge readings in mAh move with "
            "temperature and recent use."
        ),
        "power_and_thermal": (
            "A 5-second look while the Mac did its usual background work. macOS estimates "
            "these values. They are not wall power, not a stress test, and not comparable "
            "between Macs."
        ),
    }
)

# The sections after the title block, in Decision 6's order.
SECTIONS: Final = (
    "At a glance",
    "What this report cannot tell you",
    "This Mac",
    "Security settings",
    "System records",
    "Storage health and wear",
    "Battery",
    "Memory",
    "Power and thermal check",
    "Appendix A: everything this report tried to read",
    "Appendix B: how this report was made",
)
