"""Digital Twin Service (stub implementation).

Provides a minimal concrete implementation of the `DigitalTwinInterface` so that
FastAPI dependency wiring and test imports resolve.  All methods raise
`NotImplementedError` because production logic will be supplied by a real
Digital-Twin engine (see `mock_digital_twin_core_service.py` for a full mock
used in tests).

This keeps Clean-Architecture boundaries intact: presentation layer depends on
`DigitalTwinInterface`, infrastructure provides a concrete implementation, and
tests can override the dependency as needed.
"""
from __future__ import annotations

import logging
from typing import Any

from app.core.interfaces.services.digital_twin_interface import DigitalTwinInterface

logger = logging.getLogger(__name__)


class DigitalTwinService(DigitalTwinInterface):
    """Placeholder infrastructure service satisfying the interface."""

    # Note: All methods are async to match the interface; they currently raise
    # NotImplementedError.  Tests typically override the dependency with a
    # mock, so execution should never reach these paths during unit testing.

    async def create_digital_twin(self, patient_id: str, initial_data: dict[str, Any]) -> dict[str, Any]:  # noqa: D401
        logger.warning("DigitalTwinService.create_digital_twin called – stub implementation")
        raise NotImplementedError

    async def get_twin_status(self, twin_id: str) -> dict[str, Any]:
        logger.warning("DigitalTwinService.get_twin_status called – stub implementation")
        raise NotImplementedError

    async def update_twin_data(self, twin_id: str, data: dict[str, Any]) -> dict[str, Any]:
        logger.warning("DigitalTwinService.update_twin_data called – stub implementation")
        raise NotImplementedError

    async def get_insights(self, twin_id: str, insight_types: list[str]):
        logger.warning("DigitalTwinService.get_insights called – stub implementation")
        raise NotImplementedError

    async def interact(self, twin_id: str, query: str, context: dict[str, Any] | None = None):
        logger.warning("DigitalTwinService.interact called – stub implementation")
        raise NotImplementedError

    def is_healthy(self) -> bool:  # noqa: D401
        return False
