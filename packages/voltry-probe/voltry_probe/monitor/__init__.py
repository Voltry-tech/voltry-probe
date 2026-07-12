"""Monitor mode collects continuous, non-disruptive telemetry over time.

Bundles produced in this mode carry tier=GOLD. ``born_on`` anchors a unit's record at
the moment it is first observed under continuous monitoring; a longer observed history
means more measurement behind the record, not more asserted confidence. Everything
here is read-only, like the rest of the package outside ``voltry_probe.functional``.
"""

from __future__ import annotations

from .monitor import MonitorSession, TelemetrySample

__all__ = ["MonitorSession", "TelemetrySample"]
