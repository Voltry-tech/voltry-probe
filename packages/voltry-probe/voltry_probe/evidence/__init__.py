"""Assembles reader outputs into a signed bundle.

The bundle contract (models, canonicalization, signing) lives in evidence-schema and
is imported from there, never re-implemented; this package only orchestrates assembly.
The functional-mode bundle builder lives in ``voltry_probe.functional`` with the rest
of the functional API.
"""

from __future__ import annotations

from .builder import build_monitor_bundle, build_read_bundle

__all__ = ["build_read_bundle", "build_monitor_bundle"]
