"""Maps a verbatim Redfish/BMC payload into board/chassis context.

Pure function of its input dict, read-only by construction. BMC coverage varies a
lot between vendors, so every field here is optional.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict


class RedfishReadout(BaseModel):
    """Board/chassis context from Redfish, where available."""

    model_config = ConfigDict(extra="forbid")

    board_id: str | None
    chassis: str | None


def map_redfish(redfish: dict[str, Any] | None) -> RedfishReadout:
    """Map a verbatim Redfish payload into board context (all optional)."""
    if not redfish:
        return RedfishReadout(board_id=None, chassis=None)
    return RedfishReadout(
        board_id=redfish.get("board_id") if isinstance(redfish.get("board_id"), str) else None,
        chassis=redfish.get("chassis") if isinstance(redfish.get("chassis"), str) else None,
    )
