"""Stub Biometric Service implementation.

Provides a minimal concrete class that implements `BiometricServiceInterface`
so that import resolution and FastAPI dependency injection work during the
progressive refactor. All business methods raise ``NotImplementedError`` – they
should be overridden by mocks in tests or replaced by a full implementation
later.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, List
from uuid import UUID

from app.core.interfaces.services.biometric_service_interface import BiometricServiceInterface

logger = logging.getLogger(__name__)


class BiometricService(BiometricServiceInterface):
    """Placeholder biometric service."""

    async def process_biometric_data(
        self,
        patient_id: str | UUID,
        data_type: str,
        data: dict[str, Any],
        timestamp: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[bool, str | None, str | None]:
        logger.warning("BiometricService.process_biometric_data called – stub implementation")
        raise NotImplementedError

    async def get_biometric_data(
        self,
        patient_id: str | UUID,
        data_type: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 100,
        skip: int = 0,
    ) -> List[dict[str, Any]]:  # noqa: D401
        logger.warning("BiometricService.get_biometric_data called – stub implementation")
        raise NotImplementedError

    async def get_biometric_summary(
        self,
        patient_id: str | UUID,
        data_type: str,
        start_time: datetime,
        end_time: datetime,
        interval: str = "day",
    ) -> dict[str, Any]:
        logger.warning("BiometricService.get_biometric_summary called – stub implementation")
        raise NotImplementedError

    async def analyze_trends(
        self,
        patient_id: str | UUID,
        data_type: str,
        start_time: datetime,
        end_time: datetime,
        analysis_type: str | None = None,
    ) -> dict[str, Any]:
        logger.warning("BiometricService.analyze_trends called – stub implementation")
        raise NotImplementedError

    async def check_data_quality(
        self,
        patient_id: str | UUID,
        data_type: str,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> dict[str, Any]:
        logger.warning("BiometricService.check_data_quality called – stub implementation")
        raise NotImplementedError
