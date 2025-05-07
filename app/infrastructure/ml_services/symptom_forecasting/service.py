"""
/mnt/c/Users/JJ/Desktop/NOVAMIND-WEB/Novamind-Backend/app/infrastructure/ml_services/symptom_forecasting/service.py

Implementation of the Symptom Forecasting Service that connects to the ML models
for predicting psychiatric symptom trajectories.
"""

import logging
from datetime import datetime
from typing import Any
from uuid import UUID

# Use canonical config path
# from app.config.settings import get_settings # Legacy import
from app.core.config.settings import get_settings # Corrected import
from app.domain.interfaces.ml_services import SymptomForecastingService
from app.infrastructure.ml.symptom_forecasting.ensemble_model import (
    SymptomEnsembleModel,
)
from app.infrastructure.ml.symptom_forecasting.transformer_model import (
    SymptomTransformerModel,
)
from app.infrastructure.ml.symptom_forecasting.xgboost_model import SymptomXGBoostModel
from app.infrastructure.ml.utils.preprocessing import preprocess_time_series_data
from app.infrastructure.ml.utils.serialization import (
    serialize_prediction,
)

logger = logging.getLogger(__name__)


class SymptomForecastingServiceImpl(SymptomForecastingService):
    """
    Implementation of the Symptom Forecasting Service.

    This service connects to the ML models for predicting psychiatric symptom
    trajectories using an ensemble of transformer and XGBoost models.

    Attributes:
        transformer_model: The transformer-based forecasting model
        xgboost_model: The XGBoost-based forecasting model
        ensemble_model: The ensemble model combining both approaches
    """

    def __init__(self):
        """Initialize the Symptom Forecasting Service with required models."""
        self.transformer_model = SymptomTransformerModel()
        self.xgboost_model = SymptomXGBoostModel()
        self.ensemble_model = SymptomEnsembleModel(
            models=[self.transformer_model, self.xgboost_model],
            weights=[0.6, 0.4],  # Default weights favoring transformer model
        )

        # Load models
        self._load_models()

        logger.info("Symptom Forecasting Service initialized successfully")

    def _load_models(self) -> None:
        """Load all required models from storage."""
        try:
            model_path = get_settings().SYMPTOM_FORECASTING_MODEL_PATH

            # Load individual models
            self.transformer_model.load(f"{model_path}/transformer_model.pkl")
            self.xgboost_model.load(f"{model_path}/xgboost_model.pkl")

            # Load ensemble weights if available
            try:
                self.ensemble_model.load(f"{model_path}/ensemble_weights.json")
            except FileNotFoundError:
                logger.warning("Ensemble weights not found, using default weights")

            logger.info("All symptom forecasting models loaded successfully")
        except Exception as e:
            logger.error(f"Error loading symptom forecasting models: {e!s}")
            raise RuntimeError(f"Failed to load symptom forecasting models: {e!s}")

    async def generate_forecast(
        self,
        patient_id: UUID,
        data: dict[str, Any],
        horizon_days: int = 30,
        use_ensemble: bool = True,
    ) -> dict[str, Any]:
        """
        Generate symptom forecast for a patient.

        Args:
            patient_id: UUID of the patient
            data: Dictionary containing time series data of symptoms and other relevant features
            horizon_days: Number of days to forecast into the future
            use_ensemble: Whether to use the ensemble model or just the transformer model

        Returns:
            Dictionary containing the forecast results with confidence intervals
        """
        logger.info(
            f"Generating forecast for patient {patient_id}, horizon: {horizon_days} days"
        )

        try:
            # Preprocess the input data
            processed_data = preprocess_time_series_data(data)

            # Generate forecasts
            if use_ensemble:
                logger.debug("Using ensemble model for forecasting")
                forecast, confidence_intervals = self.ensemble_model.predict(
                    processed_data, horizon=horizon_days
                )
            else:
                logger.debug("Using transformer model for forecasting")
                forecast, confidence_intervals = self.transformer_model.predict(
                    processed_data, horizon=horizon_days
                )

            # Format the results
            result = {
                "patient_id": str(patient_id),
                "forecast_generated_at": datetime.now().isoformat(),
                "horizon_days": horizon_days,
                "forecasts": serialize_prediction(forecast),
                "confidence_intervals": {
                    "lower_bound": serialize_prediction(confidence_intervals[0]),
                    "upper_bound": serialize_prediction(confidence_intervals[1]),
                },
                "model_used": "ensemble" if use_ensemble else "transformer",
            }

            logger.info(f"Forecast successfully generated for patient {patient_id}")
            return result

        except Exception as e:
            logger.error(
                f"Error generating forecast for patient {patient_id}: {e!s}"
            )
            raise RuntimeError(f"Failed to generate symptom forecast: {e!s}")

    async def analyze_symptom_patterns(
        self, patient_id: UUID, data: dict[str, Any], lookback_days: int = 90
    ) -> dict[str, Any]:
        """
        Analyze historical symptom patterns for a patient.

        Args:
            patient_id: UUID of the patient
            data: Dictionary containing time series data of symptoms
            lookback_days: Number of days to look back for pattern analysis

        Returns:
            Dictionary containing pattern analysis results
        """
        logger.info(
            f"Analyzing symptom patterns for patient {patient_id}, lookback: {lookback_days} days"
        )

        try:
            # Preprocess the input data
            processed_data = preprocess_time_series_data(
                data, max_history=lookback_days
            )

            # Extract key patterns using the transformer model's attention mechanism
            patterns = self.transformer_model.extract_patterns(processed_data)

            # Identify correlations between different symptoms
            correlations = self.transformer_model.analyze_correlations(processed_data)

            # Format the results
            result = {
                "patient_id": str(patient_id),
                "analysis_generated_at": datetime.now().isoformat(),
                "lookback_days": lookback_days,
                "identified_patterns": patterns,
                "symptom_correlations": correlations,
                "summary": self._generate_pattern_summary(patterns, correlations),
            }

            logger.info(f"Symptom pattern analysis completed for patient {patient_id}")
            return result

        except Exception as e:
            logger.error(
                f"Error analyzing symptom patterns for patient {patient_id}: {e!s}"
            )
            raise RuntimeError(f"Failed to analyze symptom patterns: {e!s}")

    async def detect_anomalies(
        self, patient_id: UUID, data: dict[str, Any], sensitivity: float = 0.8
    ) -> dict[str, Any]:
        """
        Detect anomalies in patient symptom data.

        Args:
            patient_id: UUID of the patient
            data: Dictionary containing time series data of symptoms
            sensitivity: Sensitivity threshold for anomaly detection (0.0-1.0)

        Returns:
            Dictionary containing detected anomalies with severity scores
        """
        logger.info(
            f"Detecting anomalies for patient {patient_id}, sensitivity: {sensitivity}"
        )

        try:
            # Preprocess the input data
            processed_data = preprocess_time_series_data(data)

            # Detect anomalies using the ensemble model
            anomalies = self.ensemble_model.detect_anomalies(
                processed_data, threshold=sensitivity
            )

            # Format the results
            result = {
                "patient_id": str(patient_id),
                "analysis_generated_at": datetime.now().isoformat(),
                "sensitivity": sensitivity,
                "detected_anomalies": anomalies,
                "has_critical_anomalies": any(a["severity"] > 0.7 for a in anomalies),
                "recommendation": self._generate_anomaly_recommendations(anomalies),
            }

            logger.info(f"Anomaly detection completed for patient {patient_id}")
            return result

        except Exception as e:
            logger.error(
                f"Error detecting anomalies for patient {patient_id}: {e!s}"
            )
            raise RuntimeError(f"Failed to detect symptom anomalies: {e!s}")

    def _generate_pattern_summary(
        self, patterns: list[dict[str, Any]], correlations: list[dict[str, Any]]
    ) -> str:
        """Generate a human-readable summary of identified patterns."""
        # Implementation would create a natural language summary of patterns
        # This is a placeholder for the actual implementation
        return "Pattern analysis summary would be generated here."

    def _generate_anomaly_recommendations(self, anomalies: list[dict[str, Any]]) -> str:
        """Generate recommendations based on detected anomalies."""
        # Implementation would create recommendations based on anomalies
        # This is a placeholder for the actual implementation
        return "Clinical recommendations would be generated here."
