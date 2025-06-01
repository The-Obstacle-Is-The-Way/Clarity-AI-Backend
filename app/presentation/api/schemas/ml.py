"""
Machine Learning Schemas Module.

This module defines Pydantic models for ML API validation,
serialization, and documentation in the presentation layer,
following HIPAA-compliant data handling practices.
"""

from typing import Any, ClassVar

from pydantic import Field

from app.presentation.api.schemas.base import BaseModelConfig


class PredictionRequest(BaseModelConfig):
    """Base schema for ML prediction requests."""
    
    model_id: str = Field(..., description="Identifier for the ML model to use")
    features: dict[str, Any] = Field(..., description="Input features for the prediction")
    options: dict[str, Any] = Field(default_factory=dict, description="Additional options for the prediction")
    
    class Config:
        """Pydantic configuration."""
        
        schema_extra: ClassVar[dict] = {
            "example": {
                "model_id": "anxiety_prediction_v1",
                "features": {
                    "sleep_hours": 6.5,
                    "activity_level": 3,
                    "stress_score": 7.2
                },
                "options": {
                    "threshold": 0.75,
                    "return_probabilities": True
                }
            }
        }


class PredictionResponse(BaseModelConfig):
    """Base schema for ML prediction responses."""
    
    prediction: Any = Field(..., description="Prediction result")
    confidence: float | None = Field(None, description="Confidence score for the prediction")
    model_id: str = Field(..., description="Identifier for the ML model used")
    model_version: str = Field(..., description="Version of the ML model used")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata about the prediction")
    
    class Config:
        """Pydantic configuration."""
        
        schema_extra: ClassVar[dict] = {
            "example": {
                "prediction": "moderate_anxiety",
                "confidence": 0.82,
                "model_id": "anxiety_prediction_v1",
                "model_version": "1.2.0",
                "metadata": {
                    "processing_time_ms": 156,
                    "feature_importance": {
                        "sleep_hours": 0.45,
                        "stress_score": 0.35,
                        "activity_level": 0.2
                    }
                }
            }
        }


class ModelInfoResponse(BaseModelConfig):
    """Schema for ML model information."""
    
    model_id: str = Field(..., description="Unique identifier for the model")
    name: str = Field(..., description="Human-readable name for the model")
    version: str = Field(..., description="Model version")
    description: str = Field(..., description="Description of the model's purpose")
    input_features: list[dict[str, Any]] = Field(..., description="Required input features")
    output_format: dict[str, Any] = Field(..., description="Description of the output format")
    performance_metrics: dict[str, Any] | None = Field(None, description="Model performance metrics")
    last_updated: str = Field(..., description="Last update timestamp")
    
    class Config:
        """Pydantic configuration."""
        
        schema_extra: ClassVar[dict] = {
            "example": {
                "model_id": "anxiety_prediction_v1",
                "name": "Anxiety Prediction Model",
                "version": "1.2.0",
                "description": "Predicts anxiety levels based on biometric and behavioral data",
                "input_features": [
                    {"name": "sleep_hours", "type": "float", "description": "Hours of sleep per night"},
                    {"name": "activity_level", "type": "integer", "description": "Activity level (1-10)"},
                    {"name": "stress_score", "type": "float", "description": "Subjective stress score (0-10)"}
                ],
                "output_format": {
                    "prediction": {"type": "string", "description": "Anxiety level category"},
                    "confidence": {"type": "float", "description": "Model confidence (0-1)"}
                },
                "performance_metrics": {
                    "accuracy": 0.86,
                    "precision": 0.84,
                    "recall": 0.82,
                    "f1_score": 0.83
                },
                "last_updated": "2023-06-01T12:00:00Z"
            }
        }


class BatchPredictionRequest(BaseModelConfig):
    """Schema for batch prediction requests."""
    
    model_id: str = Field(..., description="Identifier for the ML model to use")
    batch_features: list[dict[str, Any]] = Field(..., description="List of feature sets for batch prediction")
    options: dict[str, Any] = Field(default_factory=dict, description="Additional options for the prediction")
    
    class Config:
        """Pydantic configuration."""
        
        schema_extra: ClassVar[dict] = {
            "example": {
                "model_id": "anxiety_prediction_v1",
                "batch_features": [
                    {
                        "sleep_hours": 6.5,
                        "activity_level": 3,
                        "stress_score": 7.2
                    },
                    {
                        "sleep_hours": 8.0,
                        "activity_level": 7,
                        "stress_score": 4.5
                    }
                ],
                "options": {
                    "threshold": 0.75,
                    "return_probabilities": True
                }
            }
        }


class BatchPredictionResponse(BaseModelConfig):
    """Schema for batch prediction responses."""
    
    predictions: list[Any] = Field(..., description="List of prediction results")
    confidences: list[float] | None = Field(None, description="List of confidence scores")
    model_id: str = Field(..., description="Identifier for the ML model used")
    model_version: str = Field(..., description="Version of the ML model used")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata about the predictions")
    
    class Config:
        """Pydantic configuration."""
        
        schema_extra: ClassVar[dict] = {
            "example": {
                "predictions": ["moderate_anxiety", "low_anxiety"],
                "confidences": [0.82, 0.91],
                "model_id": "anxiety_prediction_v1",
                "model_version": "1.2.0",
                "metadata": {
                    "processing_time_ms": 312,
                    "batch_size": 2
                }
            }
        }


class ModelListResponse(BaseModelConfig):
    """Schema for listing available ML models."""
    
    models: list[dict[str, str]] = Field(..., description="List of available ML models")
    count: int = Field(..., description="Total number of available models")
    
    class Config:
        """Pydantic configuration."""
        
        schema_extra: ClassVar[dict] = {
            "example": {
                "models": [
                    {
                        "model_id": "anxiety_prediction_v1",
                        "name": "Anxiety Prediction Model",
                        "version": "1.2.0"
                    },
                    {
                        "model_id": "depression_screening_v2",
                        "name": "Depression Screening Model",
                        "version": "2.0.1"
                    }
                ],
                "count": 2
            }
        }


class FeatureImportanceRequest(BaseModelConfig):
    """Schema for feature importance requests."""
    
    model_id: str = Field(..., description="Identifier for the ML model")
    features: dict[str, Any] = Field(..., description="Input features for which to calculate importance")
    
    class Config:
        """Pydantic configuration."""
        
        schema_extra: ClassVar[dict] = {
            "example": {
                "model_id": "anxiety_prediction_v1",
                "features": {
                    "sleep_hours": 6.5,
                    "activity_level": 3,
                    "stress_score": 7.2
                }
            }
        }


class FeatureImportanceResponse(BaseModelConfig):
    """Schema for feature importance responses."""
    
    model_id: str = Field(..., description="Identifier for the ML model")
    feature_importance: dict[str, float] = Field(..., description="Importance scores for each feature")
    prediction: Any = Field(..., description="Prediction made with the provided features")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    
    class Config:
        """Pydantic configuration."""
        
        schema_extra: ClassVar[dict] = {
            "example": {
                "model_id": "anxiety_prediction_v1",
                "feature_importance": {
                    "sleep_hours": 0.45,
                    "stress_score": 0.35,
                    "activity_level": 0.2
                },
                "prediction": "moderate_anxiety",
                "metadata": {
                    "method": "SHAP",
                    "model_version": "1.2.0"
                }
            }
        }


class HealthCheckResponse(BaseModelConfig):
    """Schema for ML service health check responses."""
    
    status: str = Field(..., description="Health status of the ML service")
    available_models: int = Field(..., description="Number of available models")
    version: str = Field(..., description="ML service version")
    uptime: int | None = Field(None, description="Service uptime in seconds")
    
    class Config:
        """Pydantic configuration."""
        
        schema_extra: ClassVar[dict] = {
            "example": {
                "status": "healthy",
                "available_models": 5,
                "version": "1.3.2",
                "uptime": 86400
            }
        }
