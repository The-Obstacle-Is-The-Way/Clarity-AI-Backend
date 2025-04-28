# -*- coding: utf-8 -*-
# app/application/interfaces/ai_model_service.py
# Interface for AI model services used by the digital twin
# Following Dependency Inversion Principle - high-level modules depend on abstractions

from abc import ABC, abstractmethod
from typing import Any, Dict
from uuid import UUID


class AIModelService(ABC):
    """
    Interface for AI model services used by the digital twin
    This follows the Interface Segregation Principle by providing focused interfaces
    """

    @abstractmethod
    async def predict(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Make a prediction using the AI model

        Args:
            input_data: Dictionary containing input data for the model

        Returns:
            Dictionary containing prediction results

        Raises:
            ValueError: If input data is invalid
        """
        pass

    @abstractmethod
    async def get_model_metadata(self) -> Dict[str, Any]:
        """
        Get metadata about the AI model

        Returns:
            Dictionary containing model metadata
        """
        pass

    @abstractmethod
    async def get_model_version(self) -> str:
        """
        Get the version of the AI model

        Returns:
            String representing the model version
        """
        pass
