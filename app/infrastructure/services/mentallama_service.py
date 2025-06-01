"""MentaLLaMA Service (stub implementation).

A minimal concrete class implementing `MentaLLaMAInterface` so imports and DI
wiring resolve.  Real logic lives in specialised infrastructure adapters or
mock services during testing.
"""
from __future__ import annotations

import logging
from typing import Any

from app.core.services.ml.interface import MentaLLaMAInterface

logger = logging.getLogger(__name__)


class MentaLLaMAService(MentaLLaMAInterface):
    """Placeholder implementation – all methods raise `NotImplementedError`."""

    def initialize(self, config: dict[str, Any]):  # noqa: D401
        logger.warning("MentaLLaMAService.initialize called – stub implementation")
        raise NotImplementedError

    def is_healthy(self) -> bool:  # noqa: D401
        return False

    def shutdown(self) -> None:  # noqa: D401
        logger.warning("MentaLLaMAService.shutdown called – stub implementation")

    async def process(self, text: str, model_type: str | None = None, options: dict[str, Any] | None = None):  # type: ignore[override]
        logger.warning("MentaLLaMAService.process called – stub implementation")
        raise NotImplementedError

    async def detect_depression(self, text: str, options: dict[str, Any] | None = None):
        logger.warning("MentaLLaMAService.detect_depression called – stub implementation")
        raise NotImplementedError
