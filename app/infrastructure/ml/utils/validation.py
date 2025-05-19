"""
Validation utilities for ML models in the NOVAMIND system.

This module provides standardized methods for validating input and output data
for machine learning models used in the Digital Twin system, ensuring data integrity
and HIPAA compliance across all ML services.
"""

import re
import uuid
from datetime import datetime
from typing import Any

import pandas as pd
from pydantic import ValidationError

from app.infrastructure.logging.logger import get_logger

logger = get_logger(__name__)


class ValidationError(Exception):
    """Exception raised for validation errors in ML model inputs or outputs."""

    pass


class ModelInputValidator:
    """
    Utility class for validating ML model inputs.

    This class provides standardized methods for validating input data for
    different types of machine learning models, ensuring data integrity and
    HIPAA compliance across all ML services.
    """

    @staticmethod
    def validate_patient_id(patient_id: str | uuid.UUID) -> uuid.UUID:
        """
        Validate a patient ID.

        Args:
            patient_id: Patient ID to validate

        Returns:
            Validated UUID object

        Raises:
            ValidationError: If the patient ID is invalid
        """
        try:
            if isinstance(patient_id, str):
                return uuid.UUID(patient_id)
            elif isinstance(patient_id, uuid.UUID):
                return patient_id
            else:
                raise ValueError("Patient ID must be a string or UUID")
        except (ValueError, AttributeError) as e:
            logger.error(f"Invalid patient ID format: {e!s}")
            raise ValidationError(f"Invalid patient ID format: {e!s}")

    @staticmethod
    def validate_time_series_data(
        data: list[dict[str, Any]] | pd.DataFrame,
        required_fields: list[str],
        date_field: str = "date",
        min_data_points: int = 5,
        max_missing_pct: float = 0.2,
    ) -> pd.DataFrame:
        """
        Validate time series data.

        Args:
            data: Time series data to validate
            required_fields: List of required fields
            date_field: Name of the date field
            min_data_points: Minimum number of data points required
            max_missing_pct: Maximum percentage of missing values allowed

        Returns:
            Validated pandas DataFrame

        Raises:
            ValidationError: If the data is invalid
        """
        try:
            # Convert to DataFrame if list of dicts
            if isinstance(data, list):
                df = pd.DataFrame(data)
            else:
                df = data.copy()

            # Check if DataFrame is empty
            if df.empty:
                raise ValueError("Time series data is empty")

            # Check minimum number of data points
            if len(df) < min_data_points:
                raise ValueError(
                    f"Insufficient data points: {len(df)} provided, "
                    f"minimum {min_data_points} required"
                )

            # Check required fields
            missing_fields = [field for field in required_fields if field not in df.columns]
            if missing_fields:
                raise ValueError(f"Missing required fields: {', '.join(missing_fields)}")

            # Check date field
            if date_field not in df.columns:
                raise ValueError(f"Missing date field: {date_field}")

            # Convert date field to datetime
            try:
                df[date_field] = pd.to_datetime(df[date_field])
            except Exception as e:
                raise ValueError(f"Invalid date format in {date_field}: {e!s}")

            # Sort by date
            df = df.sort_values(by=date_field)

            # Check for duplicated dates
            if df[date_field].duplicated().any():
                raise ValueError("Duplicate dates found in time series data")

            # Check for missing values
            for field in required_fields:
                missing_pct = df[field].isna().mean()
                if missing_pct > max_missing_pct:
                    raise ValueError(
                        f"Field '{field}' has {missing_pct:.1%} missing values, "
                        f"maximum {max_missing_pct:.1%} allowed"
                    )

            return df

        except (ValueError, KeyError, TypeError) as e:
            logger.error(f"Time series validation error: {e!s}")
            raise ValidationError(f"Time series validation error: {e!s}")

    @staticmethod
    def validate_genetic_markers(
        genetic_markers: dict[str, Any], required_markers: list[str] | None = None
    ) -> dict[str, Any]:
        """
        Validate genetic marker data.

        Args:
            genetic_markers: Dictionary of genetic markers
            required_markers: Optional list of required markers

        Returns:
            Validated genetic markers dictionary

        Raises:
            ValidationError: If the genetic markers are invalid
        """
        try:
            if not genetic_markers:
                raise ValueError("Genetic markers dictionary is empty")

            # Default required markers if not specified
            if required_markers is None:
                required_markers = ["CYP2D6", "CYP2C19", "CYP2C9"]

            # Check required markers
            missing_markers = [
                marker for marker in required_markers if marker not in genetic_markers
            ]
            if missing_markers:
                raise ValueError(f"Missing required genetic markers: {', '.join(missing_markers)}")

            # Validate marker values
            for marker, value in genetic_markers.items():
                if not isinstance(value, (int, float)):
                    raise ValueError(f"Genetic marker '{marker}' has invalid value: {value}")

            return genetic_markers

        except (ValueError, TypeError) as e:
            logger.error(f"Genetic marker validation error: {e!s}")
            raise ValidationError(f"Genetic marker validation error: {e!s}")

    @staticmethod
    def validate_medication_list(
        medications: list[str], known_medications: list[str] | None = None
    ) -> list[str]:
        """
        Validate a list of medications.

        Args:
            medications: List of medications to validate
            known_medications: Optional list of known medications

        Returns:
            Validated list of medications

        Raises:
            ValidationError: If the medication list is invalid
        """
        try:
            if not medications:
                raise ValueError("Medication list is empty")

            # Check for duplicates
            if len(medications) != len(set(medications)):
                raise ValueError("Duplicate medications found in list")

            # Check against known medications if provided
            if known_medications:
                unknown_meds = [med for med in medications if med not in known_medications]
                if unknown_meds:
                    logger.warning(f"Unknown medications in list: {', '.join(unknown_meds)}")

            return medications

        except (ValueError, TypeError) as e:
            logger.error(f"Medication list validation error: {e!s}")
            raise ValidationError(f"Medication list validation error: {e!s}")

    @staticmethod
    def validate_biometric_data(
        biometric_data: list[dict[str, Any]],
        required_metrics: list[str] | None = None,
        date_field: str = "date",
    ) -> pd.DataFrame:
        """
        Validate biometric data.

        Args:
            biometric_data: List of biometric data points
            required_metrics: Optional list of required biometric metrics
            date_field: Name of the date field

        Returns:
            Validated pandas DataFrame

        Raises:
            ValidationError: If the biometric data is invalid
        """
        try:
            # Default required metrics if not specified
            if required_metrics is None:
                required_metrics = ["heart_rate", "sleep_quality"]

            # Add date field to required fields
            required_fields = required_metrics.copy()
            if date_field not in required_fields:
                required_fields.append(date_field)

            # Use time series validation
            return ModelInputValidator.validate_time_series_data(
                data=biometric_data,
                required_fields=required_fields,
                date_field=date_field,
            )

        except ValidationError as e:
            logger.error(f"Biometric data validation error: {e!s}")
            raise ValidationError(f"Biometric data validation error: {e!s}")

    @staticmethod
    def validate_forecast_horizon(horizon: int, min_horizon: int = 1, max_horizon: int = 90) -> int:
        """
        Validate forecast horizon.

        Args:
            horizon: Forecast horizon to validate
            min_horizon: Minimum allowed horizon
            max_horizon: Maximum allowed horizon

        Returns:
            Validated forecast horizon

        Raises:
            ValidationError: If the horizon is invalid
        """
        try:
            horizon_int = int(horizon)
            if horizon_int < min_horizon:
                raise ValueError(
                    f"Forecast horizon ({horizon_int}) is less than "
                    f"minimum allowed ({min_horizon})"
                )
            if horizon_int > max_horizon:
                raise ValueError(
                    f"Forecast horizon ({horizon_int}) exceeds " f"maximum allowed ({max_horizon})"
                )
            return horizon_int

        except (ValueError, TypeError) as e:
            logger.error(f"Forecast horizon validation error: {e!s}")
            raise ValidationError(f"Forecast horizon validation error: {e!s}")


class ModelOutputValidator:
    """
    Utility class for validating ML model outputs.

    This class provides standardized methods for validating output data from
    different types of machine learning models, ensuring data integrity and
    HIPAA compliance across all ML services.
    """

    @staticmethod
    def validate_forecast_output(
        forecasts: dict[str, Any], expected_length: int, required_metrics: list[str]
    ) -> dict[str, Any]:
        """
        Validate forecast output.

        Args:
            forecasts: Forecast output to validate
            expected_length: Expected length of forecast arrays
            required_metrics: Required metrics in the forecast

        Returns:
            Validated forecast output

        Raises:
            ValidationError: If the forecast output is invalid
        """
        try:
            if not forecasts:
                raise ValueError("Forecast output is empty")

            # Check required metrics
            missing_metrics = [metric for metric in required_metrics if metric not in forecasts]
            if missing_metrics:
                raise ValueError(
                    f"Missing required metrics in forecast: {', '.join(missing_metrics)}"
                )

            # Check forecast lengths
            for metric, values in forecasts.items():
                if len(values) != expected_length:
                    raise ValueError(
                        f"Forecast length mismatch for '{metric}': "
                        f"expected {expected_length}, got {len(values)}"
                    )

                # Check for invalid values
                if not all(isinstance(v, (int, float)) or v is None for v in values):
                    raise ValueError(f"Invalid values in forecast for '{metric}'")

            return forecasts

        except (ValueError, TypeError) as e:
            logger.error(f"Forecast output validation error: {e!s}")
            raise ValidationError(f"Forecast output validation error: {e!s}")

    @staticmethod
    def validate_confidence_intervals(
        intervals: dict[str, dict[str, list[float]]],
        metrics: list[str],
        expected_length: int,
    ) -> dict[str, dict[str, list[float]]]:
        """
        Validate confidence intervals.

        Args:
            intervals: Confidence intervals to validate
            metrics: Expected metrics in the intervals
            expected_length: Expected length of interval arrays

        Returns:
            Validated confidence intervals

        Raises:
            ValidationError: If the confidence intervals are invalid
        """
        try:
            if not intervals:
                raise ValueError("Confidence intervals are empty")

            # Check required metrics
            missing_metrics = [metric for metric in metrics if metric not in intervals]
            if missing_metrics:
                raise ValueError(
                    f"Missing required metrics in confidence intervals: "
                    f"{', '.join(missing_metrics)}"
                )

            # Check interval structure and lengths
            for metric, bounds in intervals.items():
                if "lower" not in bounds or "upper" not in bounds:
                    raise ValueError(f"Missing 'lower' or 'upper' bound for metric '{metric}'")

                if (
                    len(bounds["lower"]) != expected_length
                    or len(bounds["upper"]) != expected_length
                ):
                    raise ValueError(
                        f"Confidence interval length mismatch for '{metric}': "
                        f"expected {expected_length}"
                    )

                # Check that lower bounds are less than or equal to upper bounds
                for i, (lower, upper) in enumerate(
                    zip(bounds["lower"], bounds["upper"], strict=False)
                ):
                    if lower > upper:
                        raise ValueError(
                            f"Lower bound exceeds upper bound for '{metric}' at index {i}: "
                            f"{lower} > {upper}"
                        )

            return intervals

        except (ValueError, TypeError, KeyError) as e:
            logger.error(f"Confidence interval validation error: {e!s}")
            raise ValidationError(f"Confidence interval validation error: {e!s}")

    @staticmethod
    def validate_medication_predictions(
        predictions: dict[str, dict[str, Any]],
        medications: list[str],
        required_fields: list[str] | None = None,
    ) -> dict[str, dict[str, Any]]:
        """
        Validate medication prediction outputs.

        Args:
            predictions: Medication predictions to validate
            medications: Expected medications in the predictions
            required_fields: Required fields for each medication prediction

        Returns:
            Validated medication predictions

        Raises:
            ValidationError: If the predictions are invalid
        """
        try:
            if not predictions:
                raise ValueError("Medication predictions are empty")

            # Default required fields if not specified
            if required_fields is None:
                required_fields = [
                    "response_probability",
                    "side_effect_risk",
                    "effectiveness_score",
                ]

            # Check required medications
            missing_meds = [med for med in medications if med not in predictions]
            if missing_meds:
                raise ValueError(f"Missing predictions for medications: {', '.join(missing_meds)}")

            # Check prediction structure
            for med, pred in predictions.items():
                missing_fields = [field for field in required_fields if field not in pred]
                if missing_fields:
                    raise ValueError(
                        f"Missing required fields for medication '{med}': "
                        f"{', '.join(missing_fields)}"
                    )

                # Check effectiveness score
                if "effectiveness_score" in pred:
                    score = pred["effectiveness_score"]
                    if not isinstance(score, (int, float)) or score < 0 or score > 1:
                        raise ValueError(f"Invalid effectiveness score for '{med}': {score}")

            return predictions

        except (ValueError, TypeError, KeyError) as e:
            logger.error(f"Medication prediction validation error: {e!s}")
            raise ValidationError(f"Medication prediction validation error: {e!s}")

    @staticmethod
    def validate_correlation_results(
        correlations: dict[str, Any], required_sections: list[str] | None = None
    ) -> dict[str, Any]:
        """
        Validate correlation analysis results.

        Args:
            correlations: Correlation results to validate
            required_sections: Required sections in the results

        Returns:
            Validated correlation results

        Raises:
            ValidationError: If the correlation results are invalid
        """
        try:
            if not correlations:
                raise ValueError("Correlation results are empty")

            # Default required sections if not specified
            if required_sections is None:
                required_sections = ["key_indicators", "lag_correlations"]

            # Check required sections
            missing_sections = [
                section for section in required_sections if section not in correlations
            ]
            if missing_sections:
                raise ValueError(
                    f"Missing required sections in correlation results: "
                    f"{', '.join(missing_sections)}"
                )

            # Validate key indicators
            if "key_indicators" in correlations:
                indicators = correlations["key_indicators"]
                if not isinstance(indicators, list):
                    raise ValueError("'key_indicators' must be a list")

                for i, indicator in enumerate(indicators):
                    if not isinstance(indicator, dict):
                        raise ValueError(f"Invalid indicator at index {i}: not a dictionary")

                    required_indicator_fields = [
                        "biometric",
                        "mental_health_indicator",
                        "correlation",
                    ]
                    missing_fields = [
                        field for field in required_indicator_fields if field not in indicator
                    ]
                    if missing_fields:
                        raise ValueError(
                            f"Missing required fields in indicator at index {i}: "
                            f"{', '.join(missing_fields)}"
                        )

                    # Check correlation value
                    corr = indicator["correlation"]
                    if not isinstance(corr, (int, float)) or corr < -1 or corr > 1:
                        raise ValueError(f"Invalid correlation value at index {i}: {corr}")

            return correlations

        except (ValueError, TypeError, KeyError) as e:
            logger.error(f"Correlation result validation error: {e!s}")
            raise ValidationError(f"Correlation result validation error: {e!s}")

    @staticmethod
    def validate_digital_twin_insights(
        insights: dict[str, Any], required_services: list[str], patient_id: uuid.UUID
    ) -> dict[str, Any]:
        """
        Validate Digital Twin insights.

        Args:
            insights: Digital Twin insights to validate
            required_services: Required services in the insights
            patient_id: Patient ID for validation

        Returns:
            Validated Digital Twin insights

        Raises:
            ValidationError: If the insights are invalid
        """
        try:
            if not insights:
                raise ValueError("Digital Twin insights are empty")

            # Check patient ID
            if "patient_id" not in insights:
                raise ValueError("Missing 'patient_id' in Digital Twin insights")

            insight_patient_id = insights["patient_id"]
            try:
                if isinstance(insight_patient_id, str):
                    insight_patient_id = uuid.UUID(insight_patient_id)

                if insight_patient_id != patient_id:
                    raise ValueError(
                        f"Patient ID mismatch: expected {patient_id}, got {insight_patient_id}"
                    )
            except (ValueError, AttributeError):
                raise ValueError(f"Invalid patient ID in insights: {insight_patient_id}")

            # Check required services
            missing_services = [service for service in required_services if service not in insights]
            if missing_services:
                raise ValueError(
                    f"Missing required services in insights: {', '.join(missing_services)}"
                )

            # Check timestamp
            if "generated_at" not in insights:
                raise ValueError("Missing 'generated_at' timestamp in insights")

            try:
                timestamp = insights["generated_at"]
                if isinstance(timestamp, str):
                    datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                raise ValueError(f"Invalid timestamp format: {timestamp}")

            return insights

        except (ValueError, TypeError, KeyError) as e:
            logger.error(f"Digital Twin insights validation error: {e!s}")
            raise ValidationError(f"Digital Twin insights validation error: {e!s}")


class DataSanitizer:
    """
    Utility class for sanitizing data to ensure HIPAA compliance.

    This class provides methods for sanitizing input and output data to ensure
    that no Protected Health Information (PHI) is inadvertently included in logs,
    error messages, or other non-secure contexts.
    """

    @staticmethod
    def sanitize_patient_id(patient_id: str | uuid.UUID) -> str:
        """
        Sanitize a patient ID for logging or error messages.

        Args:
            patient_id: Patient ID to sanitize

        Returns:
            Sanitized patient ID (first 4 characters + last 4 characters)
        """
        try:
            if isinstance(patient_id, uuid.UUID):
                id_str = str(patient_id)
            else:
                id_str = str(patient_id)

            if len(id_str) > 8:
                return f"{id_str[:4]}...{id_str[-4:]}"
            else:
                return "****"
        except:
            return "****"

    @staticmethod
    def sanitize_error_message(message: str) -> str:
        """
        Sanitize error messages to remove potential PHI.

        Args:
            message: Error message to sanitize

        Returns:
            Sanitized error message
        """
        # Sanitize potential UUIDs
        uuid_pattern = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
        sanitized = re.sub(
            uuid_pattern, "****-****-****-****-********", message, flags=re.IGNORECASE
        )

        # Sanitize potential dates
        date_patterns = [
            r"\d{4}-\d{2}-\d{2}",  # YYYY-MM-DD
            r"\d{2}/\d{2}/\d{4}",  # MM/DD/YYYY
            r"\d{2}-\d{2}-\d{4}",  # MM-DD-YYYY
        ]

        for pattern in date_patterns:
            sanitized = re.sub(pattern, "****-**-**", sanitized)

        return sanitized

    @staticmethod
    def sanitize_dict_for_logging(
        data: dict[str, Any], sensitive_keys: list[str]
    ) -> dict[str, Any]:
        """
        Sanitize a dictionary for logging by removing or masking sensitive fields.

        Args:
            data: Dictionary to sanitize
            sensitive_keys: List of sensitive keys to mask

        Returns:
            Sanitized dictionary
        """
        if not isinstance(data, dict):
            return data

        sanitized = {}
        for key, value in data.items():
            if key.lower() in [k.lower() for k in sensitive_keys]:
                sanitized[key] = "****"
            elif isinstance(value, dict):
                sanitized[key] = DataSanitizer.sanitize_dict_for_logging(value, sensitive_keys)
            elif isinstance(value, list):
                sanitized[key] = [
                    (
                        DataSanitizer.sanitize_dict_for_logging(item, sensitive_keys)
                        if isinstance(item, dict)
                        else item
                    )
                    for item in value
                ]
            else:
                sanitized[key] = value

        return sanitized
