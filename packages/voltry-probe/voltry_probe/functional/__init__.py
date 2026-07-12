"""Device-mutating diagnostics are allowed here and nowhere else in the probe.

Everything outside ``voltry_probe/functional/`` reads device state and never mutates it;
the read-only invariant tests enforce that boundary. This release maps captured
functional results into typed blocks, and live execution of the diagnostics is not yet
included. Import from this module explicitly: the package root does not re-export
functional APIs.
"""

from __future__ import annotations

from .bundle import build_functional_bundle
from .runner import DrainConsentError, map_functional_results

__all__ = ["DrainConsentError", "build_functional_bundle", "map_functional_results"]
