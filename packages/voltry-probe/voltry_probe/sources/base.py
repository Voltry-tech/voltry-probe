"""The raw-capture container and the read-source protocol."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from evidence_schema.types import UtcDateTime
from pydantic import BaseModel, ConfigDict, Field, JsonValue


class UnsupportedGpuError(RuntimeError):
    """The device cannot expose the reads certification requires (no ECC, pre-Ampere, MIG).

    Raised instead of a raw driver traceback so the operator gets a reason they can
    act on. The message always names the device and the specific unreadable mechanism.
    """


class RawCapture(BaseModel):
    """Verbatim payloads pulled from each source in one read pass.

    Values are typed JSON (no ``Any``). These are stored verbatim in the bundle's
    ``raw_reads`` (the replay substrate) and consumed by the pure reader mappers.
    """

    model_config = ConfigDict(extra="forbid")

    # UtcDateTime (the schema's tz-aware type) rather than a plain datetime: the rest
    # of the pipeline (bundle timestamps, challenge/freshness arithmetic) assumes
    # tz-aware UTC, and a naive value would only blow up later, far from its producer.
    # Rejecting it at construction points at the actual bug.
    captured_at: UtcDateTime = Field(description="When this capture was taken (UTC).")
    nvml: dict[str, JsonValue] = Field(description="Verbatim NVML readout payload.")
    dcgm: dict[str, JsonValue] | None = Field(
        default=None, description="Verbatim DCGM telemetry payload."
    )
    redfish: dict[str, JsonValue] | None = Field(
        default=None, description="Verbatim Redfish/BMC payload."
    )
    attestation: dict[str, JsonValue] | None = Field(
        default=None,
        description="Verbatim attestation report payload (verified, never trusted blindly).",
    )


@runtime_checkable
class RawSource(Protocol):
    """Anything that can produce a :class:`RawCapture` read-only."""

    def capture(self) -> RawCapture:
        """Return one read-only capture of the device's current state."""
        ...
