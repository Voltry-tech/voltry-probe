"""A read source backed by a captured fixture (dev/CI, the DCGM simulator, air-gapped)."""

from __future__ import annotations

import json
from pathlib import Path

from .base import RawCapture


class FixtureSource:
    """Loads a :class:`RawCapture` from a JSON fixture file. Read-only by nature."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def capture(self) -> RawCapture:
        data = json.loads(self._path.read_text(encoding="utf-8"))
        return RawCapture.model_validate(data)
