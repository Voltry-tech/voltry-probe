"""A MonitorSession accumulates telemetry samples in memory for one identity.

``born_on`` is the timestamp of the first observation under continuous monitoring,
set when the first sample is recorded and never moved afterwards. This module writes
to no database; a collector flattens the series with ``to_timescale_rows`` and
persists it wherever it likes. Samples come from the read-only NVML/DCGM readers, so
nothing here mutates device state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class TelemetrySample:
    """One point-in-time, read-only telemetry sample."""

    ts: datetime
    metrics: dict[str, float]

    def __post_init__(self) -> None:
        # Fail at the producer, not later: a naive timestamp recorded here would only
        # surface when born_on reaches the bundle builder's UTC-validated fields.
        if self.ts.tzinfo is None:
            raise ValueError("TelemetrySample.ts must be timezone-aware")


@dataclass
class MonitorSession:
    """Accumulates a telemetry series for one identity; tracks born-on (first-seen)."""

    ecc384_id: str
    born_on: datetime | None = None
    samples: list[TelemetrySample] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.born_on is not None and self.born_on.tzinfo is None:
            raise ValueError("MonitorSession.born_on must be timezone-aware")

    def record(self, sample: TelemetrySample) -> None:
        """Record a sample. The first sample sets born_on, the time of first observation."""
        if self.born_on is None:
            self.born_on = sample.ts
        self.samples.append(sample)

    @property
    def is_born_on(self) -> bool:
        """True once a first sample has established the born-on timestamp."""
        return self.born_on is not None

    def to_timescale_rows(self) -> list[tuple[str, datetime, str, float]]:
        """Flatten the series into (ecc384_id, ts, metric, value) rows; performs no write itself.

        The name is historical (the first collector wrote to TimescaleDB); the row shape
        is exporter-agnostic and any collector can persist it. Kept for API stability.
        """
        return [
            (self.ecc384_id, sample.ts, metric, value)
            for sample in self.samples
            for metric, value in sample.metrics.items()
        ]
