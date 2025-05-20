"""
Mock Model Service for Tests.

This module provides a mock implementation of the IModelService interface
for testing purposes, allowing tests to run without actual ML models.
"""

import uuid
from typing import Any

from app.core.domain.entities.ml_model import (
    InferenceResult,
    InferenceStatus,
    ModelInfo,
    ModelType,
)
from app.core.interfaces.services.model_service_interface import IModelService


class MockModelService(IModelService):
    """
    Mock implementation of IModelService for testing.

    This implementation simulates model operations without requiring actual
    machine learning models, allowing tests to run quickly and deterministically.
    """

    def __init__(self):
        """Initialize with default mock models and inference results."""
        self.models: dict[str, ModelInfo] = {}
        self.inference_results: dict[str, InferenceResult] = {}

        # Add some default mock models
        self.models["model1"] = ModelInfo(
            model_id="model1",
            model_name="Test XGBoost Model",
            model_type=ModelType.XGBOOST,
            version="1.0.0",
            description="Mock XGBoost model for testing",
            parameters=10000,
            supported_features=["classification", "regression"],
        )

        self.models["model2"] = ModelInfo(
            model_id="model2",
            model_name="Test PAT Model",
            model_type=ModelType.PAT,
            version="2.1.0",
            description="Mock Pretrained Actigraphy Transformer model for testing",
            parameters=50000000,
            supported_features=["activity_patterns", "sleep_quality"],
        )

    async def get_model_info(self, model_id: str) -> ModelInfo | None:
        """
        Get information about a specific model.

        Args:
            model_id: Unique identifier of the model

        Returns:
            ModelInfo object if model exists, None otherwise
        """
        return self.models.get(model_id)

    async def list_models(self, model_type: ModelType | None = None) -> list[ModelInfo]:
        """
        List available models, optionally filtered by type.

        Args:
            model_type: Optional filter by model type

        Returns:
            List of ModelInfo objects
        """
        if model_type is None:
            return list(self.models.values())

        return [model for model in self.models.values() if model.model_type == model_type]

    async def perform_inference(
        self, model_id: str, input_data: dict[str, Any], inference_id: str | None = None
    ) -> InferenceResult:
        """
        Perform inference using the specified model.

        This mock implementation always returns a successful result with
        predefined data based on the model_id.

        Args:
            model_id: Identifier of the model to use
            input_data: Input data for the model
            inference_id: Optional identifier for the inference operation

        Returns:
            InferenceResult containing mock results
        """
        if model_id not in self.models:
            # Return an error result if model doesn't exist
            result = InferenceResult(
                inference_id=inference_id or str(uuid.uuid4()),
                model_id=model_id,
                status=InferenceStatus.ERROR,
                error_message=f"Model {model_id} not found",
                processing_time_ms=10,
            )
        else:
            # Create a successful mock result
            result = InferenceResult(
                inference_id=inference_id or str(uuid.uuid4()),
                model_id=model_id,
                status=InferenceStatus.SUCCESS,
                result={"prediction": 0.75, "probability": 0.92},
                confidence=0.92,
                processing_time_ms=150,
                metadata={"input_shape": "scalar"},
            )

        # Store result for later retrieval
        self.inference_results[result.inference_id] = result
        return result

    async def get_inference_result(self, inference_id: str) -> InferenceResult | None:
        """
        Get the result of a previous inference operation.

        Args:
            inference_id: Identifier of the inference operation

        Returns:
            InferenceResult if found, None otherwise
        """
        return self.inference_results.get(inference_id)


def create_mock_model_service() -> IModelService:
    """
    Create a mock model service for testing.

    Returns:
        An instance of MockModelService implementing IModelService
    """
    return MockModelService()
