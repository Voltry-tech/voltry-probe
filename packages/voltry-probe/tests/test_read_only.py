"""The read-only invariant: no device-mutating NVML/DCGM call outside functional/.

Two layers of proof:
1. A static scan of the package source for mutating symbol names (broad prefixes:
   setters, resets, clears, instance management, diagnostics).
2. A runtime spy: a live capture against a fake NVML that fails the test the moment
   any symbol outside the approved read set (init, shutdown, device getters, system
   getters, constants, error types) is touched.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent / "voltry_probe"

# Device-mutating NVML/DCGM symbols. Getters (nvmlDeviceGet*) are read-only and allowed.
# Freeze*/RegisterEvents/EventSet* mutate driver-side state (freeze latches the NVLink
# utilization counters; event registration allocates event sets and subscribes the
# process to device events), so they are forbidden here too even though the runtime
# spy below would also catch them.
FORBIDDEN = re.compile(
    r"nvmlDeviceSet\w*|nvmlDeviceClear\w*|nvmlDeviceReset\w*|nvmlDeviceModify\w*"
    r"|nvmlDeviceFreeze\w*|nvmlDeviceRegisterEvents|nvmlEventSet\w*"
    r"|nvmlUnitSet\w*|nvmlVgpu\w*Set\w*|nvmlGpuInstance\w*|nvmlComputeInstance\w*"
    r"|nvmlDeviceCreate\w*|nvmlDeviceRemove\w*"
    r"|dcgmConfigSet|dcgmReset|dcgmActionValidate|dcgm\w*RunDiagnostic"
)

# The complete NVML read surface the live source may touch at runtime.
ALLOWED_NVML = re.compile(
    r"^(nvmlInit|nvmlShutdown|nvmlSystemGet\w+|nvmlDeviceGetHandleByIndex|nvmlDeviceGet\w+"
    r"|nvmlErrorString|NVMLError\w*|NVML_\w+|nvmlClocksThrottleReason\w+)$"
)


def _python_files() -> list[Path]:
    return [p for p in PKG.rglob("*.py") if "__pycache__" not in p.parts]


def test_no_device_mutating_calls_outside_functional():
    offenders: list[str] = []
    for path in _python_files():
        if "functional" in path.relative_to(PKG).parts:
            continue  # the only place device-mutating calls may live
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if FORBIDDEN.search(line):
                offenders.append(f"{path.relative_to(PKG)}:{i}: {line.strip()}")
    assert not offenders, "device-mutating call(s) found outside functional/:\n" + "\n".join(
        offenders
    )


def test_forbidden_families_never_leak_into_the_read_allowlist():
    # The two layers must stay disjoint: every mutating family the static scan bans
    # must also be outside the runtime allowlist, and the read surface the live
    # source actually uses must never trip the static scan. Guards against a lazy
    # allowlist edit (e.g. widening nvmlDevice\w+) quietly approving a mutator.
    for name in (
        "nvmlDeviceFreezeNvLinkUtilizationCounter",
        "nvmlDeviceRegisterEvents",
        "nvmlEventSetCreate",
        "nvmlEventSetWait",
        "nvmlEventSetFree",
        "nvmlDeviceSetPowerManagementLimit",
        "nvmlDeviceResetGpuLockedClocks",
        "nvmlDeviceClearEccErrorCounts",
    ):
        assert FORBIDDEN.search(name), f"static scan must forbid {name}"
        assert not ALLOWED_NVML.match(name), f"runtime allowlist must not approve {name}"
    for name in (
        "nvmlDeviceGetNvLinkUtilizationCounter",  # the getter twin of the Freeze call
        "nvmlDeviceGetSupportedEventTypes",
        "nvmlDeviceGetTotalEccErrors",
    ):
        assert not FORBIDDEN.search(name), f"static scan must not flag the getter {name}"
        assert ALLOWED_NVML.match(name), f"runtime allowlist must approve the getter {name}"


def test_live_source_uses_only_getters():
    """Sanity: the live NVML source reads (has getters) and mutates nothing."""
    live = (PKG / "sources" / "live.py").read_text(encoding="utf-8")
    assert "nvmlDeviceGet" in live, "live source should read via NVML getters"
    assert not FORBIDDEN.search(live)


class _NvmlSpy:
    """Wraps the fake pynvml; fails the test on any non-read symbol access."""

    def __init__(self, inner) -> None:
        self._inner = inner
        self.touched: set[str] = set()

    def __getattr__(self, name: str):
        assert ALLOWED_NVML.match(
            name
        ), f"live source touched an NVML symbol outside the approved read set: {name}"
        self.touched.add(name)
        return getattr(self._inner, name)


def _load_live_fixture_module():
    """Load test_live_source.py by path to reuse its fake pynvml (tests are not a package)."""
    path = Path(__file__).with_name("test_live_source.py")
    spec = importlib.util.spec_from_file_location("_live_source_fixture", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_live_capture_touches_only_approved_nvml_symbols(monkeypatch):
    """Runtime enforcement: a full live capture may touch only the approved read set."""
    fixture_mod = _load_live_fixture_module()
    spy = _NvmlSpy(fixture_mod._fake_pynvml())
    monkeypatch.setitem(sys.modules, "pynvml", spy)

    from voltry_probe.sources.live import LiveSource

    capture = LiveSource().capture()
    assert capture.nvml, "the spy capture should have read a payload"
    assert any(n.startswith("nvmlDeviceGet") for n in spy.touched)
