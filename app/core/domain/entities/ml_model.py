"""
ML Model Entities Module.

This module defines the core domain entities related to machine learning models
following Clean Architecture principles. These entities are used across the application
and represent the core business logic around ML models.
"""
from enum import Enum
from typing import Any


class ModelType(str, Enum):
    """Types of ML models supported by the system."""

    PAT = "pretrained_actigraphy_transformer"
    SYMPTOM_FORECASTING = "symptom_forecasting"
    XGBOOST = "xgboost"
    THERAPEUTIC_SUGGESTION = "therapeutic_suggestion"
    SENTIMENT_ANALYSIS = "sentiment_analysis"


class ModelInfo:
    """
    Domain entity representing ML model metadata information.

    This entity contains the core properties of a machine learning model
    that are used by the business logic, independent of implementation details.
    """

    def __init__(
        self,
        model_id: str,
        model_name: str,
        model_type: ModelType,
        version: str,
        description: str | None = None,
        parameters: int | None = None,
        supported_features: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ):
        """
        Initialize a ModelInfo entity.

        Args:
            model_id: Unique identifier for the model
            model_name: Human-readable name of the model
            model_type: Type of model (from ModelType enum)
            version: Version string of the model
            description: Optional description of the model's purpose and capabilities
            parameters: Optional count of model parameters
            supported_features: Optional list of features or capabilities supported by this model
            metadata: Optional additional metadata as key-value pairs
        """
        self.model_id = model_id
        self.model_name = model_name
        self.model_type = model_type
        self.version = version
        self.description = description
        self.parameters = parameters
        self.supported_features = supported_features or []
        self.metadata = metadata or {}


class InferenceStatus(str, Enum):
    """Status of an inference operation."""

    SUCCESS = "success"
    ERROR = "error"
    TIMEOUT = "timeout"
    PENDING = "pending"
    PROCESSING = "processing"


class InferenceResult:
    """
    Domain entity representing the result of an ML model inference.

    This entity contains the core properties of inference results
    that are used by the business logic, independent of implementation details.
    """

    def __init__(
        self,
        inference_id: str,
        model_id: str,
        status: InferenceStatus,
        result: dict[str, Any] | None = None,
        confidence: float | None = None,
        processing_time_ms: int | None = None,
        error_message: str | None = None,
        metadata: dict[str, Any] | None = None,
    ):
        """
        Initialize an InferenceResult entity.

        Args:
            inference_id: Unique identifier for this inference result
            model_id: Identifier of the model used for inference
            status: Status of the inference operation
            result: Optional dictionary containing the inference result
            confidence: Optional confidence score between 0 and 1
            processing_time_ms: Optional time taken to process in milliseconds
            error_message: Optional error message if status is ERROR
            metadata: Optional additional metadata as key-value pairs
        """
        self.inference_id = inference_id
        self.model_id = model_id
        self.status = status
        self.result = result or {}
        self.confidence = confidence
        self.processing_time_ms = processing_time_ms
        self.error_message = error_message
        self.metadata = metadata or {}
