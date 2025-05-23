"""
Symptom Forecasting Model Service for the NOVAMIND Digital Twin.

This module implements the service layer for the Symptom Forecasting microservice,
providing an ensemble of models for psychiatric symptom prediction with uncertainty
quantification, following Clean Architecture principles.
"""

import asyncio
import logging
import os
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

import numpy as np

from app.domain.utils.datetime_utils import UTC

# Removed import for exceptions as they are not available
# from app.domain.exceptions import ModelInferenceError, ValidationError
from app.infrastructure.ml.symptom_forecasting.transformer_model import (
    SymptomTransformerModel,
)
from app.infrastructure.ml.symptom_forecasting.xgboost_model import XGBoostSymptomModel


class SymptomForecastingService:
    """
    Service for psychiatric symptom forecasting using an ensemble of models.

    This service implements the core functionality of the Symptom Forecasting
    microservice, providing a clean interface for the domain layer to interact
    with the ML models while maintaining separation of concerns.
    """

    def __init__(
        self,
        model_dir: str,
        transformer_model_path: str | None = None,
        xgboost_model_path: str | None = None,
        feature_names: list[str] | None = None,
        target_names: list[str] | None = None,
    ):
        """
        Initialize the symptom forecasting service.

        Args:
            model_dir: Directory for model storage
            transformer_model_path: Path to pretrained transformer model
            xgboost_model_path: Path to pretrained XGBoost model
            feature_names: Names of input features
            target_names: Names of target variables
        """
        self.model_dir = model_dir
        self.feature_names = feature_names
        self.target_names = target_names

        # Create model directory if it doesn't exist
        os.makedirs(model_dir, exist_ok=True)

        # Initialize models
        self.transformer_model = SymptomTransformerModel(
            model_path=transformer_model_path,
            input_dim=len(feature_names) if feature_names else 20,
            output_dim=len(target_names) if target_names else 10,
        )

        self.xgboost_model = XGBoostSymptomModel(
            model_path=xgboost_model_path,
            feature_names=feature_names,
            target_names=target_names,
        )

        # Model weights for ensemble
        self.model_weights = {"transformer": 0.7, "xgboost": 0.3}

        logging.info("Symptom Forecasting Service initialized")

    async def preprocess_patient_data(self, patient_id: UUID, data: dict[str, Any]) -> np.ndarray:
        """
        Preprocess patient data for model input.

        Args:
            patient_id: UUID of the patient
            data: Raw patient data

        Returns:
            Preprocessed numpy array ready for model input
        """
        try:
            # Extract time series data
            time_series = data.get("time_series", [])

            if not time_series:
                raise Exception("No time series data provided")

            # Extract features
            features = []

            for entry in time_series:
                # Extract relevant features
                feature_vector = []

                # Add symptom severity scores
                for symptom in self.feature_names or []:
                    feature_vector.append(entry.get(symptom, 0.0))

                features.append(feature_vector)

            # Convert to numpy array
            features_array = np.array(features, dtype=np.float32)

            # Normalize features (simple min-max scaling)
            for i in range(features_array.shape[1]):
                col_min = features_array[:, i].min()
                col_max = features_array[:, i].max()

                if col_max > col_min:
                    features_array[:, i] = (features_array[:, i] - col_min) / (col_max - col_min)

            return features_array

        except Exception as e:
            logging.error(f"Error preprocessing patient data: {e!s}")
            raise Exception(f"Failed to preprocess patient data: {e!s}")

    async def forecast_symptoms(
        self,
        patient_id: UUID,
        data: dict[str, Any],
        horizon: int = 14,
        use_ensemble: bool = True,
    ) -> dict[str, Any]:
        """
        Generate symptom forecasts for a patient.

        Args:
            patient_id: UUID of the patient
            data: Patient data
            horizon: Forecast horizon in days
            use_ensemble: Whether to use ensemble of models

        Returns:
            Dictionary containing forecast results
        """
        try:
            # Preprocess data
            preprocessed_data = await self.preprocess_patient_data(patient_id, data)

            if preprocessed_data.shape[0] < 5:
                raise Exception(
                    "Insufficient time series data for forecasting (minimum 5 points required)"
                )

            # Reshape for model input
            model_input = preprocessed_data.reshape(1, *preprocessed_data.shape)

            # Generate forecasts
            if use_ensemble:
                # Run both models in parallel
                transformer_future = self.transformer_model.predict(model_input, horizon)
                xgboost_future = self.xgboost_model.predict(model_input, horizon)

                # Await results
                transformer_results, xgboost_results = await asyncio.gather(
                    transformer_future, xgboost_future
                )

                # Combine results using weighted average
                ensemble_values = (
                    self.model_weights["transformer"] * transformer_results["values"]
                    + self.model_weights["xgboost"] * xgboost_results["values"]
                )

                # Get uncertainty intervals from transformer model
                lower_bound = transformer_results["intervals"]["lower"]
                upper_bound = transformer_results["intervals"]["upper"]

                # Get feature importance from XGBoost model
                feature_importance = xgboost_results["feature_importance"]

                forecast_results = {
                    "values": ensemble_values,
                    "intervals": {"lower": lower_bound, "upper": upper_bound},
                    "feature_importance": feature_importance,
                    "model_type": "ensemble",
                }
            else:
                # Use only transformer model
                forecast_results = await self.transformer_model.predict(model_input, horizon)

            # Add metadata
            forecast_results.update(
                {
                    "patient_id": str(patient_id),
                    "forecast_generated_at": datetime.now(UTC).isoformat(),
                    "forecast_horizon": horizon,
                    "forecast_dates": [
                        (datetime.now(UTC) + timedelta(days=i)).isoformat()
                        for i in range(1, horizon + 1)
                    ],
                    "target_names": self.target_names,
                }
            )

            return forecast_results

        except Exception as e:
            logging.error(f"Error forecasting symptoms: {e!s}")
            raise Exception(f"Failed to forecast symptoms: {e!s}")

    async def evaluate_treatment_impact(
        self,
        patient_id: UUID,
        baseline_data: dict[str, Any],
        treatment_options: list[dict[str, Any]],
        horizon: int = 30,
    ) -> dict[str, Any]:
        """
        Evaluate the potential impact of different treatment options.

        Args:
            patient_id: UUID of the patient
            baseline_data: Baseline patient data
            treatment_options: List of treatment options to evaluate
            horizon: Forecast horizon in days

        Returns:
            Dictionary containing treatment impact evaluation results
        """
        try:
            # Preprocess baseline data
            baseline_preprocessed = await self.preprocess_patient_data(patient_id, baseline_data)

            if baseline_preprocessed.shape[0] < 5:
                raise Exception("Insufficient baseline data for treatment impact evaluation")

            # Reshape for model input
            baseline_preprocessed.reshape(1, *baseline_preprocessed.shape)

            # Generate baseline forecast
            baseline_forecast = await self.forecast_symptoms(
                patient_id=patient_id, data=baseline_data, horizon=horizon
            )

            # Evaluate each treatment option
            treatment_forecasts = []

            for treatment in treatment_options:
                # Apply treatment effect to baseline data
                # This is a simplified approach - in practice, we would use a more sophisticated method
                baseline_data.copy()

                # Modify the time series based on treatment effect
                treatment_effect = treatment.get("expected_effect", {})

                for symptom, effect in treatment_effect.items():
                    if symptom in self.feature_names:
                        idx = self.feature_names.index(symptom)

                        # Apply effect to the last few points
                        for i in range(1, min(5, baseline_preprocessed.shape[0]) + 1):
                            baseline_preprocessed[-i, idx] *= 1 - effect

                # Generate forecast with treatment effect
                treatment_input = baseline_preprocessed.reshape(1, *baseline_preprocessed.shape)
                treatment_forecast = await self.transformer_model.predict(treatment_input, horizon)

                # Add treatment metadata
                treatment_forecast.update(
                    {
                        "treatment_id": treatment.get("id"),
                        "treatment_name": treatment.get("name"),
                        "treatment_description": treatment.get("description"),
                    }
                )

                treatment_forecasts.append(treatment_forecast)

            # Calculate comparative metrics
            comparative_metrics = []

            for treatment_forecast in treatment_forecasts:
                # Calculate improvement over baseline
                baseline_values = baseline_forecast["values"]
                treatment_values = treatment_forecast["values"]

                # Calculate percent improvement for each symptom
                improvements = {}

                for i, target in enumerate(self.target_names or []):
                    baseline_mean = np.mean(baseline_values[0, :, i])
                    treatment_mean = np.mean(treatment_values[0, :, i])

                    if baseline_mean > 0:
                        percent_improvement = (baseline_mean - treatment_mean) / baseline_mean * 100
                    else:
                        percent_improvement = 0

                    improvements[target] = percent_improvement

                comparative_metrics.append(
                    {
                        "treatment_id": treatment_forecast.get("treatment_id"),
                        "treatment_name": treatment_forecast.get("treatment_name"),
                        "improvements": improvements,
                        "average_improvement": np.mean(list(improvements.values())),
                    }
                )

            # Sort treatments by average improvement
            comparative_metrics.sort(key=lambda x: x["average_improvement"], reverse=True)

            return {
                "patient_id": str(patient_id),
                "baseline_forecast": baseline_forecast,
                "treatment_forecasts": treatment_forecasts,
                "comparative_metrics": comparative_metrics,
                "evaluation_generated_at": datetime.now(UTC).isoformat(),
                "forecast_horizon": horizon,
            }

        except Exception as e:
            logging.error(f"Error evaluating treatment impact: {e!s}")
            raise Exception(f"Failed to evaluate treatment impact: {e!s}")

    async def detect_symptom_patterns(
        self, patient_id: UUID, data: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Detect patterns in symptom time series data.

        Args:
            patient_id: UUID of the patient
            data: Patient data

        Returns:
            Dictionary containing detected patterns
        """
        try:
            # Preprocess data
            preprocessed_data = await self.preprocess_patient_data(patient_id, data)

            if preprocessed_data.shape[0] < 10:
                raise Exception(
                    "Insufficient time series data for pattern detection (minimum 10 points required)"
                )

            # Detect trends
            trends = {}

            for i, feature in enumerate(self.feature_names or []):
                # Calculate simple linear trend
                x = np.arange(preprocessed_data.shape[0])
                y = preprocessed_data[:, i]

                # Linear regression
                A = np.vstack([x, np.ones(len(x))]).T
                m, c = np.linalg.lstsq(A, y, rcond=None)[0]

                # Determine trend direction and strength
                if abs(m) < 0.01:
                    trend = "stable"
                    strength = 0
                elif m > 0:
                    trend = "increasing"
                    strength = m
                else:
                    trend = "decreasing"
                    strength = -m

                trends[feature] = {
                    "direction": trend,
                    "strength": float(strength),
                    "slope": float(m),
                    "intercept": float(c),
                }

            # Detect seasonality (simplified approach)
            seasonality = {}

            for i, feature in enumerate(self.feature_names or []):
                # Check for weekly patterns
                y = preprocessed_data[:, i]

                if len(y) >= 14:
                    # Calculate autocorrelation
                    autocorr = np.correlate(y, y, mode="full")
                    autocorr = autocorr[len(autocorr) // 2 :]

                    # Normalize
                    autocorr /= autocorr[0]

                    # Check for peaks at 7-day intervals
                    weekly_pattern = False

                    if len(autocorr) > 7:
                        if autocorr[7] > 0.3:
                            weekly_pattern = True

                    seasonality[feature] = {
                        "weekly_pattern": weekly_pattern,
                        "weekly_correlation": (float(autocorr[7]) if len(autocorr) > 7 else 0),
                    }

            # Detect correlations between symptoms
            correlations = {}

            if preprocessed_data.shape[1] > 1:
                corr_matrix = np.corrcoef(preprocessed_data.T)

                for i, feature_i in enumerate(self.feature_names or []):
                    feature_correlations = {}

                    for j, feature_j in enumerate(self.feature_names or []):
                        if i != j:
                            feature_correlations[feature_j] = float(corr_matrix[i, j])

                    correlations[feature_i] = feature_correlations

            return {
                "patient_id": str(patient_id),
                "trends": trends,
                "seasonality": seasonality,
                "correlations": correlations,
                "analysis_generated_at": datetime.now(UTC).isoformat(),
                "data_points": preprocessed_data.shape[0],
            }

        except Exception as e:
            logging.error(f"Error detecting symptom patterns: {e!s}")
            raise Exception(f"Failed to detect symptom patterns: {e!s}")

    def get_service_info(self) -> dict[str, Any]:
        """
        Get information about the service.

        Returns:
            Dictionary containing service information
        """
        return {
            "service_name": "Symptom Forecasting Service",
            "models": {
                "transformer": self.transformer_model.get_model_info(),
                "xgboost": self.xgboost_model.get_model_info(),
            },
            "model_weights": self.model_weights,
            "feature_names": self.feature_names,
            "target_names": self.target_names,
            "timestamp": datetime.now(UTC).isoformat(),
        }
