"""Raw read sources: where device I/O lives. All sources are READ-ONLY.

A source pulls verbatim payloads from NVML/DCGM/Redfish/attestation (live hardware) or
from captured fixtures / the DCGM simulator (dev/CI), and hands them to the pure reader
mappers. No source performs a device-mutating call.
"""

from __future__ import annotations

from .base import RawCapture, RawSource, UnsupportedGpuError
from .fixture import FixtureSource

__all__ = ["RawCapture", "RawSource", "FixtureSource", "UnsupportedGpuError"]
