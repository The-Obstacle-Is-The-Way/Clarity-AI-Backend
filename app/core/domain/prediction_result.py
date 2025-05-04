"""
Core domain model for prediction results.

This module contains the domain models for prediction results across ML services.
Following clean architecture principles, this exists in the core domain layer
to avoid dependencies on infrastructure or external services.
"""
from datetime import datetime
from typing import Any
from uuid import UUID


class PredictionResult:
    """
    Domain entity representing an ML model prediction result.
    
    This follows clean architecture principles by representing a core domain concept
    that is independent of any specific ML implementation or external service.
    """

    def __init__(
        self,
        prediction_id: str | UUID,
        model_type: str,
        patient_id: str,
        prediction_value: Any,
        confidence: float,
        features_used: list[str],
        timestamp: datetime | None = None,
        metadata: dict[str, Any] | None = None,
        model_version: str | None = None,
    ):
        """
        Initialize a new prediction result.
        
        Args:
            prediction_id: Unique identifier for this prediction
            model_type: Type of model used for prediction (e.g., "risk", "treatment")
            patient_id: ID of the patient this prediction is for
            prediction_value: The actual prediction result value
            confidence: Confidence score for this prediction (0.0-1.0)
            features_used: List of feature names used in making this prediction
            timestamp: When the prediction was made (defaults to now)
            metadata: Additional contextual information about the prediction
            model_version: Version of the model used for prediction
        """
        self.prediction_id = str(prediction_id)
        self.model_type = model_type
        self.patient_id = patient_id
        self.prediction_value = prediction_value
        self.confidence = confidence
        self.features_used = features_used
        self.timestamp = timestamp or datetime.now()
        self.metadata = metadata or {}
        self.model_version = model_version
        
    def to_dict(self) -> dict[str, Any]:
        """Convert the prediction result to a dictionary representation."""
        return {
            "prediction_id": self.prediction_id,
            "model_type": self.model_type,
            "patient_id": self.patient_id,
            "prediction_value": self.prediction_value,
            "confidence": self.confidence,
            "features_used": self.features_used,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
            "model_version": self.model_version
        }
        
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PredictionResult":
        """Create a PredictionResult from a dictionary representation."""
        # Convert timestamp string back to datetime if present
        if "timestamp" in data and isinstance(data["timestamp"], str):
            data = data.copy()  # Don't modify the original
            data["timestamp"] = datetime.fromisoformat(data["timestamp"])
            
        return cls(
            prediction_id=data["prediction_id"],
            model_type=data["model_type"],
            patient_id=data["patient_id"],
            prediction_value=data["prediction_value"],
            confidence=data["confidence"],
            features_used=data["features_used"],
            timestamp=data.get("timestamp"),
            metadata=data.get("metadata", {}),
            model_version=data.get("model_version")
        )
