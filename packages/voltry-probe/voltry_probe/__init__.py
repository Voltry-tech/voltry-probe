"""Evidence capture, signing, and certificate tooling for data-center GPUs.

The root API reads device state, assembles signed evidence bundles, and renders offline
certificates. It does not mutate device state and makes no network requests. Functional
diagnostics (which exercise the device) require an explicit import from
``voltry_probe.functional`` and explicit drain consent; the package root does not
re-export them.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _distribution_version

from .attestation import AttestationOutcome, AttestationReport, verify_attestation
from .evidence import build_monitor_bundle, build_read_bundle
from .monitor import MonitorSession, TelemetrySample
from .readers import map_dcgm, map_nvml, map_redfish, normalize_xid
from .render import render_certificate
from .sources import FixtureSource, RawCapture, RawSource, UnsupportedGpuError

try:
    __version__ = _distribution_version("voltry-probe")
except PackageNotFoundError:  # running from a source checkout, not an installed wheel
    __version__ = "0.0.0+local"

__all__ = [
    "__version__",
    "build_read_bundle",
    "build_monitor_bundle",
    "MonitorSession",
    "TelemetrySample",
    "render_certificate",
    "map_nvml",
    "map_dcgm",
    "map_redfish",
    "normalize_xid",
    "verify_attestation",
    "AttestationReport",
    "AttestationOutcome",
    "FixtureSource",
    "RawCapture",
    "RawSource",
    "UnsupportedGpuError",
]
