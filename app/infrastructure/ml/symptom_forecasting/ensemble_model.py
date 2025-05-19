"""
Ensemble model for psychiatric symptom forecasting in the NOVAMIND system.

This module implements an ensemble approach that combines transformer-based and
XGBoost models for improved psychiatric symptom forecasting accuracy, following
Clean Architecture principles and ensuring HIPAA compliance.
"""

import json
import logging
import os
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

import numpy as np
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score

from app.domain.utils.datetime_utils import UTC
from app.infrastructure.ml.base.base_model import BaseModel
from app.infrastructure.ml.symptom_forecasting.transformer_model import (
    SymptomTransformerModel,
)

# from app.infrastructure.ml.utils.preprocessing import DataPreprocessor # Removed unused import


class SymptomForecastingEnsemble(BaseModel):
    """
    Ensemble model for psychiatric symptom forecasting.

    This class implements an ensemble approach that combines transformer-based and
    XGBoost models for improved psychiatric symptom forecasting accuracy. The ensemble
    uses a weighted average of the predictions from each model, with weights determined
    based on each model's performance on validation data.
    """

    def __init__(
        self,
        model_name: str = "symptom_forecasting_ensemble",
        version: str = "1.0.0",
        model_path: str | None = None,
        logger: logging.Logger | None = None,
        transformer_config: dict[str, Any] | None = None,
        xgboost_config: dict[str, Any] | None = None,
        ensemble_weights: dict[str, float] | None = None,
    ):
        """
        Initialize the symptom forecasting ensemble model.

        Args:
            model_name: Name of the ensemble model
            version: Version of the ensemble model
            model_path: Path to the saved ensemble model
            logger: Logger for tracking model operations
            transformer_config: Configuration for the transformer model
            xgboost_config: Configuration for the XGBoost model
            ensemble_weights: Weights for each model in the ensemble
        """
        super().__init__(model_name, version, model_path, logger)

        # Initialize component models
        self.transformer_model = SymptomTransformerModel(
            model_name=f"{model_name}_transformer",
            version=version,
            **(transformer_config or {}),
        )

        self.xgboost_model = SymptomXGBoostModel(
            model_name=f"{model_name}_xgboost",
            version=version,
            **(xgboost_config or {}),
        )

        # Set default weights if not provided
        self.ensemble_weights = ensemble_weights or {"transformer": 0.6, "xgboost": 0.4}

        # Validate weights
        total_weight = sum(self.ensemble_weights.values())
        if abs(total_weight - 1.0) > 1e-6:
            self.logger.warning(
                f"Ensemble weights do not sum to 1.0 (sum: {total_weight}). "
                f"Normalizing weights."
            )
            # Normalize weights
            for model_name in self.ensemble_weights:
                self.ensemble_weights[model_name] /= total_weight

        self.models = {
            "transformer": self.transformer_model,
            "xgboost": self.xgboost_model,
        }

        self.forecast_horizon = 30  # Default forecast horizon in days
        self.symptom_types = []  # Will be populated during training/loading

    def load(self) -> None:
        """
        Load the ensemble model from storage.

        This method loads all component models and ensemble metadata from the
        specified path.

        Raises:
            FileNotFoundError: If the model files cannot be found
            ValueError: If the model files are invalid or corrupted
        """
        if not self.model_path:
            raise ValueError("Model path must be specified to load the model")

        try:
            # Load ensemble metadata
            meta_path = f"{self.model_path}/ensemble.meta.json"
            with open(meta_path) as f:
                metadata = json.load(f)

            # Update ensemble attributes from metadata
            self.ensemble_weights = metadata.get("ensemble_weights", self.ensemble_weights)
            self.forecast_horizon = metadata.get("forecast_horizon", self.forecast_horizon)
            self.symptom_types = metadata.get("symptom_types", self.symptom_types)
            self.version = metadata.get("version", self.version)
            self.last_training_date = metadata.get("last_training_date")
            self.metrics = metadata.get("metrics", {})

            # Load component models
            for model_name, model in self.models.items():
                model.model_path = f"{self.model_path}/{model_name}.model"
                model.load()

            self.logger.info(f"Successfully loaded ensemble model from {self.model_path}")

        except Exception as e:
            self.logger.error(f"Failed to load ensemble model: {e!s}")
            raise

    def save(self, path: str | None = None) -> str:
        """
        Save the ensemble model to storage.

        This method saves all component models and ensemble metadata to the
        specified path.

        Args:
            path: Path to save the ensemble model to

        Returns:
            The path where the ensemble model was saved

        Raises:
            PermissionError: If the model cannot be saved to the specified path
            ValueError: If the model is not initialized
        """
        save_path = path or self.model_path
        if not save_path:
            raise ValueError("Save path must be specified")

        try:
            # Create directory if it doesn't exist
            os.makedirs(save_path, exist_ok=True)

            # Save ensemble metadata
            metadata = {
                "ensemble_weights": self.ensemble_weights,
                "forecast_horizon": self.forecast_horizon,
                "symptom_types": self.symptom_types,
                "version": self.version,
                "last_training_date": self.last_training_date,
                "metrics": self.metrics,
                "saved_at": datetime.now(UTC).isoformat(),
            }

            meta_path = f"{save_path}/ensemble.meta.json"
            with open(meta_path, "w") as f:
                json.dump(metadata, f, indent=2)

            # Save component models
            for model_name, model in self.models.items():
                model_path = f"{save_path}/{model_name}.model"
                model.save(model_path)

            self.model_path = save_path
            self.logger.info(f"Successfully saved ensemble model to {save_path}")
            return save_path

        except Exception as e:
            self.logger.error(f"Failed to save ensemble model: {e!s}")
            raise

    def preprocess(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Preprocess input data for prediction.

        This method preprocesses the input data for each component model in the
        ensemble, ensuring that the data is in the correct format for prediction.

        Args:
            data: Raw input data containing symptom history and patient information

        Returns:
            Preprocessed data for each model in the ensemble

        Raises:
            ValueError: If the data is invalid or cannot be preprocessed
        """
        try:
            # Sanitize patient data for HIPAA compliance
            sanitized_data = self.sanitize_patient_data(data)

            # Preprocess for each model
            preprocessed_data = {}
            for model_name, model in self.models.items():
                preprocessed_data[model_name] = model.preprocess(sanitized_data)

            return preprocessed_data

        except Exception as e:
            self.logger.error(f"Error during preprocessing: {e!s}")
            raise ValueError(f"Failed to preprocess data: {e!s}")

    def predict(self, preprocessed_data: dict[str, Any]) -> dict[str, Any]:
        """
        Generate predictions using the ensemble model.

        This method generates predictions using each component model in the
        ensemble and combines them using the ensemble weights.

        Args:
            preprocessed_data: Preprocessed data for each model in the ensemble

        Returns:
            Raw predictions from each model and the ensemble

        Raises:
            ValueError: If the model is not initialized or the data is invalid
        """
        try:
            # Generate predictions from each model
            model_predictions = {}
            for model_name, model in self.models.items():
                model_data = preprocessed_data[model_name]
                model_predictions[model_name] = model.predict(model_data)

            # Combine predictions using ensemble weights
            ensemble_predictions = {}

            # Combine forecasts for each symptom type
            for symptom_type in self.symptom_types:
                # Initialize with zeros
                forecast_length = len(model_predictions["transformer"][symptom_type])
                ensemble_forecast = np.zeros(forecast_length)

                # Weighted average of each model's forecast
                for model_name, weight in self.ensemble_weights.items():
                    model_forecast = model_predictions[model_name][symptom_type]
                    ensemble_forecast += weight * np.array(model_forecast)

                ensemble_predictions[symptom_type] = ensemble_forecast.tolist()

            # Add individual model predictions for transparency
            return {"ensemble": ensemble_predictions, "models": model_predictions}

        except Exception as e:
            self.logger.error(f"Error during prediction: {e!s}")
            raise ValueError(f"Failed to generate predictions: {e!s}")

    def postprocess(self, predictions: dict[str, Any]) -> dict[str, Any]:
        """
        Postprocess model predictions.

        This method postprocesses the ensemble predictions, adding confidence
        intervals, risk levels, and other derived information.

        Args:
            predictions: Raw predictions from the ensemble model

        Returns:
            Postprocessed predictions with additional information

        Raises:
            ValueError: If the predictions are invalid or cannot be postprocessed
        """
        try:
            ensemble_predictions = predictions["ensemble"]
            model_predictions = predictions["models"]

            # Initialize postprocessed results
            results = {
                "forecasts": {},
                "risk_levels": {},
                "confidence_intervals": {},
                "model_contributions": {},
            }

            # Process each symptom type
            for symptom_type in self.symptom_types:
                ensemble_forecast = ensemble_predictions[symptom_type]

                # Calculate confidence intervals based on model disagreement
                model_forecasts = np.array(
                    [model_predictions[model_name][symptom_type] for model_name in self.models]
                )

                # Standard deviation across models as uncertainty measure
                std_dev = np.std(model_forecasts, axis=0)

                # 95% confidence interval (assuming normal distribution)
                lower_bound = np.array(ensemble_forecast) - 1.96 * std_dev
                upper_bound = np.array(ensemble_forecast) + 1.96 * std_dev

                # Ensure bounds are within valid range (0-10 for symptom severity)
                lower_bound = np.clip(lower_bound, 0, 10)
                upper_bound = np.clip(upper_bound, 0, 10)

                # Determine risk level based on forecast and uncertainty
                risk_levels = []
                for i, (forecast, lower, upper) in enumerate(
                    zip(ensemble_forecast, lower_bound, upper_bound, strict=False)
                ):
                    # High risk if forecast is high or uncertainty is high
                    if forecast >= 7 or (upper - lower) > 4:
                        risk = "high"
                    elif forecast >= 4 or (upper - lower) > 2:
                        risk = "medium"
                    else:
                        risk = "low"
                    risk_levels.append(risk)

                # Calculate model contributions
                contributions = {}
                for model_name, weight in self.ensemble_weights.items():
                    contributions[model_name] = weight

                # Store results
                results["forecasts"][symptom_type] = ensemble_forecast
                results["confidence_intervals"][symptom_type] = {
                    "lower": lower_bound.tolist(),
                    "upper": upper_bound.tolist(),
                }
                results["risk_levels"][symptom_type] = risk_levels
                results["model_contributions"][symptom_type] = contributions

            return results

        except Exception as e:
            self.logger.error(f"Error during postprocessing: {e!s}")
            raise ValueError(f"Failed to postprocess predictions: {e!s}")

    def evaluate(self, test_data: dict[str, Any], test_labels: dict[str, Any]) -> dict[str, float]:
        """
        Evaluate the ensemble model on test data.

        This method evaluates the ensemble model on test data, calculating
        performance metrics for each component model and the ensemble.

        Args:
            test_data: Test data for evaluation
            test_labels: True labels for the test data

        Returns:
            Dictionary of performance metrics

        Raises:
            ValueError: If the model is not initialized or the data is invalid
        """
        try:
            # Preprocess test data
            preprocessed_data = self.preprocess(test_data)

            # Generate predictions
            predictions = self.predict(preprocessed_data)
            ensemble_predictions = predictions["ensemble"]

            # Calculate metrics for ensemble
            metrics = {}

            # Overall metrics
            all_true = []
            all_pred = []

            # Calculate metrics for each symptom type
            for symptom_type in self.symptom_types:
                true_values = test_labels[symptom_type]
                pred_values = ensemble_predictions[symptom_type]

                # Add to overall metrics
                all_true.extend(true_values)
                all_pred.extend(pred_values)

                # Calculate metrics for this symptom type
                metrics[symptom_type] = {
                    "mae": mean_absolute_error(true_values, pred_values),
                    "rmse": np.sqrt(mean_squared_error(true_values, pred_values)),
                    "r2": r2_score(true_values, pred_values),
                }

            # Calculate overall metrics
            metrics["overall"] = {
                "mae": mean_absolute_error(all_true, all_pred),
                "rmse": np.sqrt(mean_squared_error(all_true, all_pred)),
                "r2": r2_score(all_true, all_pred),
            }

            # Also evaluate individual models
            metrics["models"] = {}
            for model_name, model in self.models.items():
                model_predictions = predictions["models"][model_name]

                model_all_true = []
                model_all_pred = []

                for symptom_type in self.symptom_types:
                    true_values = test_labels[symptom_type]
                    pred_values = model_predictions[symptom_type]

                    model_all_true.extend(true_values)
                    model_all_pred.extend(pred_values)

                metrics["models"][model_name] = {
                    "mae": mean_absolute_error(model_all_true, model_all_pred),
                    "rmse": np.sqrt(mean_squared_error(model_all_true, model_all_pred)),
                    "r2": r2_score(model_all_true, model_all_pred),
                }

            # Update model metrics
            self.metrics = metrics

            return metrics

        except Exception as e:
            self.logger.error(f"Error during evaluation: {e!s}")
            raise ValueError(f"Failed to evaluate model: {e!s}")

    def train(
        self,
        training_data: dict[str, Any],
        validation_data: dict[str, Any] | None = None,
        symptom_types: list[str] | None = None,
        forecast_horizon: int = 30,
        optimize_weights: bool = True,
    ) -> dict[str, Any]:
        """
        Train the ensemble model.

        This method trains each component model in the ensemble and optimizes
        the ensemble weights based on validation performance.

        Args:
            training_data: Data for training the models
            validation_data: Data for validating the models and optimizing weights
            symptom_types: List of symptom types to forecast
            forecast_horizon: Number of days to forecast
            optimize_weights: Whether to optimize ensemble weights

        Returns:
            Dictionary of training metrics

        Raises:
            ValueError: If the training data is invalid
        """
        try:
            # Update model parameters
            self.forecast_horizon = forecast_horizon
            self.symptom_types = symptom_types or self.symptom_types

            if not self.symptom_types:
                raise ValueError("Symptom types must be specified for training")

            # Train each model
            training_metrics = {}
            for model_name, model in self.models.items():
                self.logger.info(f"Training {model_name} model...")
                model_metrics = model.train(
                    training_data=training_data,
                    validation_data=validation_data,
                    symptom_types=self.symptom_types,
                    forecast_horizon=forecast_horizon,
                )
                training_metrics[model_name] = model_metrics

            # Optimize ensemble weights if requested
            if optimize_weights and validation_data is not None:
                self.logger.info("Optimizing ensemble weights...")
                self._optimize_weights(validation_data)

            # Update last training date
            self.last_training_date = datetime.now(UTC).isoformat()

            # Evaluate on validation data if available
            if validation_data is not None:
                validation_metrics = self.evaluate(
                    validation_data,
                    {
                        symptom_type: validation_data[f"{symptom_type}_future"]
                        for symptom_type in self.symptom_types
                    },
                )
                training_metrics["validation"] = validation_metrics

            return training_metrics

        except Exception as e:
            self.logger.error(f"Error during training: {e!s}")
            raise ValueError(f"Failed to train model: {e!s}")

    def _optimize_weights(self, validation_data: dict[str, Any]) -> None:
        """
        Optimize ensemble weights based on validation performance.

        This method optimizes the ensemble weights by evaluating each model
        on validation data and assigning weights based on relative performance.

        Args:
            validation_data: Data for validating the models and optimizing weights

        Raises:
            ValueError: If the validation data is invalid
        """
        try:
            # Preprocess validation data
            preprocessed_data = {}
            for model_name, model in self.models.items():
                preprocessed_data[model_name] = model.preprocess(validation_data)

            # Generate predictions for each model
            model_predictions = {}
            for model_name, model in self.models.items():
                model_data = preprocessed_data[model_name]
                model_predictions[model_name] = model.predict(model_data)

            # Calculate error metrics for each model
            model_errors = {}
            for model_name in self.models:
                predictions = model_predictions[model_name]

                # Calculate RMSE for each symptom type
                rmse_values = []
                for symptom_type in self.symptom_types:
                    true_values = validation_data[f"{symptom_type}_future"]
                    pred_values = predictions[symptom_type]

                    rmse = np.sqrt(mean_squared_error(true_values, pred_values))
                    rmse_values.append(rmse)

                # Average RMSE across symptom types
                model_errors[model_name] = np.mean(rmse_values)

            # Calculate weights based on inverse error (lower error = higher weight)
            inverse_errors = {
                model_name: 1.0 / (error + 1e-10)  # Add small constant to avoid division by zero
                for model_name, error in model_errors.items()
            }

            # Normalize weights to sum to 1
            total_inverse_error = sum(inverse_errors.values())
            self.ensemble_weights = {
                model_name: inverse_error / total_inverse_error
                for model_name, inverse_error in inverse_errors.items()
            }

            self.logger.info(f"Optimized ensemble weights: {self.ensemble_weights}")

        except Exception as e:
            self.logger.error(f"Error during weight optimization: {e!s}")
            raise ValueError(f"Failed to optimize weights: {e!s}")

    def forecast_symptoms(
        self,
        patient_id: UUID,
        symptom_history: list[dict[str, Any]],
        patient_data: dict[str, Any] | None = None,
        forecast_days: int = 30,
    ) -> dict[str, Any]:
        """
        Generate symptom forecasts for a patient.

        This method generates forecasts for each symptom type for the specified
        number of days, based on the patient's symptom history and other data.

        Args:
            patient_id: ID of the patient
            symptom_history: History of the patient's symptoms
            patient_data: Additional patient data
            forecast_days: Number of days to forecast

        Returns:
            Dictionary containing symptom forecasts and related information

        Raises:
            ValueError: If the input data is invalid
        """
        try:
            # Prepare input data
            input_data = {
                "patient_id": str(patient_id),
                "symptom_history": symptom_history,
                "forecast_days": forecast_days,
            }

            if patient_data:
                input_data.update(patient_data)

            # Generate forecast
            preprocessed_data = self.preprocess(input_data)
            raw_predictions = self.predict(preprocessed_data)
            processed_results = self.postprocess(raw_predictions)

            # Add forecast dates
            start_date = datetime.now()
            forecast_dates = [
                (start_date + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(forecast_days)
            ]
            processed_results["forecast_dates"] = forecast_dates

            # Add metadata
            processed_results["metadata"] = {
                "patient_id": str(patient_id),
                "forecast_generated_at": datetime.now(UTC).isoformat(),
                "forecast_days": forecast_days,
                "model_name": self.model_name,
                "model_version": self.version,
            }

            return processed_results

        except Exception as e:
            self.logger.error(f"Error during symptom forecasting: {e!s}")
            raise ValueError(f"Failed to forecast symptoms: {e!s}")
