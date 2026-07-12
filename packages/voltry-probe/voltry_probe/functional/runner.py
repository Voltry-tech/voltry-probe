"""Maps functional-diagnostic output today; will run the diagnostics once validated.

``map_functional_results`` converts captured diagnostic output (DCGM diagnostic level,
burn-in, the silent-data-corruption check, sanitization) into a typed ``FunctionalBlock``.
It is a pure mapping: it touches no hardware and needs no consent.

Live execution on a drained unit is not part of this release. The private
``_run_live_diagnostics`` hook below is the single sanctioned home for device-mutating
calls in this package. It checks drain consent immediately before touching the device,
on every call, and currently refuses because the live run has not shipped.
"""

from __future__ import annotations

from typing import Any

from evidence_schema import FunctionalBlock, GateResult, Sanitization


class DrainConsentError(Exception):
    """Raised when live functional diagnostics are invoked without explicit drain consent."""


def map_functional_results(results: dict[str, Any]) -> FunctionalBlock:
    """Map captured functional-diagnostic results into a ``FunctionalBlock``.

    ``results`` is the verbatim outcome of a functional run (DCGM diagnostic level,
    burn-in, SDC check, sanitization) captured on real hardware or from a fixture.
    Absent keys map to ``NOT_ASSESSED``, so a check that did not run reads as not run
    rather than as a pass. Mapping is pure and requires no drain consent because it
    never touches a device.
    """
    return FunctionalBlock(
        dcgm_runlevel=results.get("dcgm_runlevel"),
        dcgm_result=GateResult(results.get("dcgm_result", "NOT_ASSESSED")),
        burnin_result=GateResult(results.get("burnin_result", "NOT_ASSESSED")),
        burnin_duration_s=results.get("burnin_duration_s"),
        sdc_functional=GateResult(results.get("sdc_functional", "NOT_ASSESSED")),
        sdc_detail=results.get("sdc_detail"),
        sanitization=Sanitization(
            standard="IEEE-2883-2022",
            method=results.get("sanitization_method"),
            result=GateResult(results.get("sanitization_result", "NOT_ASSESSED")),
            verified=bool(results.get("sanitization_verified", False)),
        ),
    )


def _run_live_diagnostics(*, drain_consent: bool) -> FunctionalBlock:
    """Run device-mutating diagnostics on a drained unit. Not available in this release.

    Drain consent is checked here, at the action boundary, on every call: the diagnostics
    stress memory, PCIe, NVLink, compute, and power for hours and require a GPU drained of
    workloads. This function is private because live execution has not shipped; it becomes
    public only once it runs on validated hardware.
    """
    if not drain_consent:
        raise DrainConsentError(
            "live functional diagnostics stress and DRAIN the GPU; they require explicit "
            "drain consent"
        )
    raise NotImplementedError(
        "live functional execution is not available in this release; map captured "
        "results with map_functional_results() instead"
    )
