"""
Base model class for all ML models in the NOVAMIND system.

This module provides a standardized interface for all machine learning models
used in the Digital Twin system, ensuring consistent implementation and
HIPAA compliance across all ML services.
"""

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from app.infrastructure.logging.logger import get_logger


class BaseModel(ABC):
    """
    Base class for all ML models in the NOVAMIND system.

    This abstract class defines the interface that all ML models must implement,
    ensuring consistency across the system and proper handling of patient data
    in accordance with HIPAA regulations.
    """

    def __init__(
        self,
        model_name: str,
        version: str,
        model_path: str | None = None,
        logger: logging.Logger | None = None,
    ):
        """
        Initialize the base model with common attributes.

        Args:
            model_name: Unique identifier for the model
            version: Version of the model
            model_path: Path to the saved model file
            logger: Logger instance for tracking model operations
        """
        self.model_name = model_name
        self.version = version
        self.model_path = model_path
        self.logger = logger or get_logger(f"model.{model_name}")
        self.last_training_date: datetime | None = None
        self.metrics: dict[str, float] = {}
        self._model: Any | None = None

    @abstractmethod
    def load(self) -> None:
        """
        Load the model from storage.

        This method should handle loading the model from the specified path
        and initializing any necessary components.

        Raises:
            FileNotFoundError: If the model file cannot be found
            ValueError: If the model file is invalid or corrupted
        """
        pass

    @abstractmethod
    def save(self, path: str | None = None) -> str:
        """
        Save the model to storage.

        Args:
            path: Optional path to save the model to. If not provided,
                 the model's default path will be used.

        Returns:
            The path where the model was saved

        Raises:
            PermissionError: If the model cannot be saved to the specified path
            ValueError: If the model is not initialized
        """
        pass

    @abstractmethod
    def preprocess(self, data: Any) -> Any:
        """
        Preprocess input data before prediction.

        This method should handle any necessary data cleaning, normalization,
        feature engineering, or other preprocessing steps required by the model.

        Args:
            data: Raw input data to be preprocessed

        Returns:
            Preprocessed data ready for model prediction

        Raises:
            ValueError: If the data is invalid or cannot be preprocessed
        """
        pass

    @abstractmethod
    def predict(self, data: Any) -> Any:
        """
        Make predictions using the model.

        This method should handle the core prediction logic, taking preprocessed
        data and returning raw model outputs.

        Args:
            data: Preprocessed data ready for model prediction

        Returns:
            Raw model predictions

        Raises:
            ValueError: If the model is not initialized or the data is invalid
        """
        pass

    @abstractmethod
    def postprocess(self, predictions: Any) -> dict[str, Any]:
        """
        Postprocess model predictions.

        This method should handle any necessary transformation of raw model outputs
        into a format suitable for the application, including confidence scores,
        interpretations, or other derived information.

        Args:
            predictions: Raw model predictions to be postprocessed

        Returns:
            Postprocessed predictions in a standardized format

        Raises:
            ValueError: If the predictions are invalid or cannot be postprocessed
        """
        pass

    def predict_with_processing(self, data: Any) -> dict[str, Any]:
        """
        Complete prediction pipeline with pre and post processing.

        This method orchestrates the full prediction process, from preprocessing
        raw input data to postprocessing model outputs.

        Args:
            data: Raw input data

        Returns:
            Processed predictions in a standardized format

        Raises:
            ValueError: If any step in the pipeline fails
        """
        try:
            self.logger.info(f"Starting prediction with model {self.model_name} v{self.version}")
            preprocessed_data = self.preprocess(data)
            raw_predictions = self.predict(preprocessed_data)
            processed_results = self.postprocess(raw_predictions)

            # Add metadata to results
            processed_results["model_metadata"] = {
                "model_name": self.model_name,
                "version": self.version,
                "prediction_time": datetime.now(timezone.utc).isoformat(),
            }

            self.logger.info(f"Completed prediction with model {self.model_name}")
            return processed_results

        except Exception as e:
            self.logger.error(f"Error during prediction: {e!s}")
            raise

    @abstractmethod
    def evaluate(self, test_data: Any, test_labels: Any) -> dict[str, float]:
        """
        Evaluate the model on test data.

        This method should calculate and return relevant performance metrics
        for the model based on test data and labels.

        Args:
            test_data: Test data for evaluation
            test_labels: True labels for the test data

        Returns:
            Dictionary of performance metrics

        Raises:
            ValueError: If the model is not initialized or the data is invalid
        """
        pass

    def get_model_info(self) -> dict[str, Any]:
        """
        Get information about the model.

        Returns:
            Dictionary containing model metadata and performance metrics
        """
        return {
            "name": self.model_name,
            "version": self.version,
            "last_training_date": self.last_training_date,
            "metrics": self.metrics,
            "model_path": self.model_path,
        }

    def sanitize_patient_data(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Sanitize patient data to ensure HIPAA compliance.

        This method removes or masks any protected health information (PHI)
        that should not be logged or stored in the model.

        Args:
            data: Patient data that may contain PHI

        Returns:
            Sanitized data with PHI removed or masked
        """
        # Define PHI fields that should be redacted
        phi_fields = {
            "patient_name",
            "full_name",
            "name",
            "ssn",
            "social_security",
            "address",
            "email",
            "phone",
            "dob",
            "date_of_birth",
            "mrn",
        }

        # Create a copy to avoid modifying the original
        sanitized = {}

        # Recursively sanitize nested dictionaries
        for key, value in data.items():
            if key.lower() in phi_fields:
                sanitized[key] = "[REDACTED]"
            elif isinstance(value, dict):
                sanitized[key] = self.sanitize_patient_data(value)
            elif isinstance(value, list) and all(isinstance(item, dict) for item in value):
                sanitized[key] = [self.sanitize_patient_data(item) for item in value]
            else:
                sanitized[key] = value

        return sanitized
