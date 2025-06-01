"""Actigraphy Service (stub implementation).

Concrete placeholder that satisfies `ActigraphyServiceInterface` so dependency
injection and imports resolve during testing.  All business methods raise
`NotImplementedError`; unit tests override this dependency with mocks.
"""
from __future__ import annotations

import logging
from typing import Any

from app.core.interfaces.services.actigraphy_service_interface import ActigraphyServiceInterface

logger = logging.getLogger(__name__)


class ActigraphyService(ActigraphyServiceInterface):
    """Stub Actigraphy service – not intended for production use."""

    async def initialize(self) -> None:  # noqa: D401
        logger.warning("ActigraphyService.initialize called – stub implementation")

    async def analyze_actigraphy(
        self,
        patient_id: str,
        readings: list[dict[str, Any]],
        device_info: dict[str, Any] | None = None,
        analysis_types: list[str] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        logger.warning("ActigraphyService.analyze_actigraphy called – stub implementation")
        raise NotImplementedError

    async def get_embeddings(
        self, patient_id: str, readings: list[dict[str, Any]] | None = None, **kwargs: Any
    ) -> dict[str, Any]:
        logger.warning("ActigraphyService.get_embeddings called – stub implementation")
        raise NotImplementedError

    async def get_analysis_by_id(self, analysis_id: str, patient_id: str | None = None) -> dict[str, Any]:
        logger.warning("ActigraphyService.get_analysis_by_id called – stub implementation")
        raise NotImplementedError

    async def get_patient_analyses(self, patient_id: str, limit: int = 10, offset: int = 0):
        logger.warning("ActigraphyService.get_patient_analyses called – stub implementation")
        raise NotImplementedError

    async def get_model_info(self) -> dict[str, Any]:
        logger.warning("ActigraphyService.get_model_info called – stub implementation")
        raise NotImplementedError

    async def get_analysis_types(self) -> list[str]:
        logger.warning("ActigraphyService.get_analysis_types called – stub implementation")
        return []

    async def integrate_with_digital_twin(
        self,
        patient_id: str,
        analysis_id: str,
        profile_id: str | None = None,
        integration_options: dict[str, bool] | None = None,
    ) -> dict[str, Any]:
        logger.warning("ActigraphyService.integrate_with_digital_twin called – stub implementation")
        raise NotImplementedError

    def is_healthy(self) -> bool:  # noqa: D401
        return False
