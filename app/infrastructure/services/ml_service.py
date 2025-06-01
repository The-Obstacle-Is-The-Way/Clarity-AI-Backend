"""Stub ML Service to satisfy dependency injection during migration."""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from app.core.interfaces.services.ml_service_interface import MLServiceInterface

logger = logging.getLogger(__name__)


class MLService(MLServiceInterface):
    """Placeholder MLService implementation."""

    def __init__(self, db: Session | None = None) -> None:  # noqa: D401
        self._db = db
        logger.info("MLService stub initialized (db=%s)", bool(db))

    async def predict(self, model_id: str, features: dict[str, Any], options: dict[str, Any] | None = None) -> dict[str, Any]:
        logger.warning("MLService.predict called – stub implementation")
        raise NotImplementedError

    async def batch_predict(self, model_id: str, batch_features: list[dict[str, Any]], options: dict[str, Any] | None = None) -> dict[str, Any]:
        logger.warning("MLService.batch_predict called – stub implementation")
        raise NotImplementedError

    async def get_model_info(self, model_id: str) -> dict[str, Any]:
        logger.warning("MLService.get_model_info called – stub implementation")
        raise NotImplementedError

    async def list_models(self) -> dict[str, Any]:
        logger.warning("MLService.list_models called – stub implementation")
        return {}

    async def get_feature_importance(self, model_id: str, features: dict[str, Any]) -> dict[str, Any]:
        logger.warning("MLService.get_feature_importance called – stub implementation")
        raise NotImplementedError

    def is_healthy(self) -> bool:  # noqa: D401
        return False

    def get_health_info(self) -> dict[str, Any]:
        return {"healthy": False}
