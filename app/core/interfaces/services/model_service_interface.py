"""
Model Service Interface.

This module defines the interface for the model service, which is responsible
for managing ML models, their lifecycle, and inference operations following
Clean Architecture principles.
"""

from abc import ABC, abstractmethod
from typing import Any

from app.core.domain.entities.ml_model import InferenceResult, ModelInfo, ModelType


class IModelService(ABC):
    """
    Interface for model service.

    The model service is responsible for managing machine learning models,
    performing inference, and tracking model information.
    """

    @abstractmethod
    async def get_model_info(self, model_id: str) -> ModelInfo | None:
        """
        Get information about a specific model.

        Args:
            model_id: Unique identifier of the model

        Returns:
            ModelInfo object if model exists, None otherwise
        """
        pass

    @abstractmethod
    async def list_models(self, model_type: ModelType | None = None) -> list[ModelInfo]:
        """
        List available models, optionally filtered by type.

        Args:
            model_type: Optional filter by model type

        Returns:
            List of ModelInfo objects
        """
        pass

    @abstractmethod
    async def perform_inference(
        self, model_id: str, input_data: dict[str, Any], inference_id: str | None = None
    ) -> InferenceResult:
        """
        Perform inference using the specified model.

        Args:
            model_id: Identifier of the model to use
            input_data: Input data for the model
            inference_id: Optional identifier for the inference operation

        Returns:
            InferenceResult containing the results of inference

        Raises:
            ModelNotFoundException: If the specified model does not exist
            ModelNotInitializedException: If the model is not initialized
            InferenceException: If inference fails
        """
        pass

    @abstractmethod
    async def get_inference_result(self, inference_id: str) -> InferenceResult | None:
        """
        Get the result of a previous inference operation.

        Args:
            inference_id: Identifier of the inference operation

        Returns:
            InferenceResult if found, None otherwise
        """
        pass
