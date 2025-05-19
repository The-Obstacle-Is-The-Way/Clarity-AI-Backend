"""
Biometric Domain Entity Module.

This module defines the core domain entities for biometric data,
representing physiological measurements captured from patients.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from app.core.utils.date_utils import utcnow


class BiometricType(str, Enum):
    """Types of biometric data that can be captured."""

    HEART_RATE = "heart_rate"
    BLOOD_PRESSURE = "blood_pressure"
    BLOOD_GLUCOSE = "blood_glucose"
    WEIGHT = "weight"
    TEMPERATURE = "temperature"
    SLEEP = "sleep"
    ACTIVITY = "activity"
    STRESS = "stress"
    MOOD = "mood"
    OXYGEN_SATURATION = "oxygen_saturation"
    RESPIRATION_RATE = "respiration_rate"
    ECG = "ecg"
    EEG = "eeg"
    CORTISOL = "cortisol"


class MetricType(str, Enum):
    """Types of metrics that can be used in biometric alert rules.

    This is a more fine-grained set of metrics that can be monitored
    for alerts, including both direct biometric measurements and
    derived/calculated metrics.
    """

    # Cardiovascular metrics
    HEART_RATE = "heart_rate"
    BLOOD_PRESSURE_SYSTOLIC = "blood_pressure_systolic"
    BLOOD_PRESSURE_DIASTOLIC = "blood_pressure_diastolic"
    HEART_RATE_VARIABILITY = "heart_rate_variability"

    # Blood/metabolic metrics
    BLOOD_GLUCOSE = "blood_glucose"
    HEMOGLOBIN_A1C = "hemoglobin_a1c"
    CHOLESTEROL_TOTAL = "cholesterol_total"
    CHOLESTEROL_LDL = "cholesterol_ldl"
    CHOLESTEROL_HDL = "cholesterol_hdl"
    TRIGLYCERIDES = "triglycerides"

    # Respiratory metrics
    OXYGEN_SATURATION = "oxygen_saturation"
    RESPIRATION_RATE = "respiration_rate"

    # Physical metrics
    WEIGHT = "weight"
    BMI = "bmi"
    BODY_TEMPERATURE = "body_temperature"
    STEPS = "steps"
    EXERCISE_MINUTES = "exercise_minutes"

    # Sleep metrics
    SLEEP_DURATION = "sleep_duration"
    SLEEP_QUALITY = "sleep_quality"
    SLEEP_DEEP_PERCENTAGE = "sleep_deep_percentage"
    SLEEP_REM_PERCENTAGE = "sleep_rem_percentage"

    # Mental health metrics
    STRESS_LEVEL = "stress_level"
    MOOD_SCORE = "mood_score"
    ANXIETY_SCORE = "anxiety_score"
    DEPRESSION_SCORE = "depression_score"
    PHQ9_SCORE = "phq9_score"
    GAD7_SCORE = "gad7_score"

    # Hormone/neurotransmitter levels
    CORTISOL = "cortisol"
    SEROTONIN = "serotonin"
    DOPAMINE = "dopamine"
    MELATONIN = "melatonin"

    def __str__(self) -> str:
        """Return the string value of the enum."""
        return self.value


class Biometric:
    """
    Biometric domain entity representing physiological measurements.

    Biometrics are key indicators of physical health that may correlate with
    mental health status, enabling integrated care insights.

    Attributes:
        id: Unique identifier for the biometric record
        biometric_type: Type of biometric measurement
        timestamp: When the biometric was recorded
        value: The measurement value
        device_id: ID of the device that recorded the biometric
        metadata: Additional contextual data
        user_id: ID of the patient this biometric belongs to
    """

    def __init__(
        self,
        id: str | None,
        biometric_type: BiometricType,
        timestamp: datetime,
        value: dict[str, Any],
        device_id: str | None,
        metadata: dict[str, Any],
        user_id: str,
    ):
        """
        Initialize a new Biometric entity.

        Args:
            id: Unique identifier (None for new records)
            biometric_type: Type of biometric measurement
            timestamp: When the biometric was recorded
            value: The measurement value
            device_id: ID of the device that recorded the biometric
            metadata: Additional contextual data
            user_id: ID of the patient this biometric belongs to

        Raises:
            ValueError: If required fields are missing or invalid
        """
        self.id = id
        self.biometric_type = biometric_type
        self.timestamp = timestamp
        self.value = value
        self.device_id = device_id
        self.metadata = metadata or {}
        self.user_id = user_id

        # Validate entity state
        self._validate()

    def _validate(self) -> None:
        """
        Validate the entity state.

        Raises:
            ValueError: If entity state is invalid
        """
        if not self.biometric_type:
            raise ValueError("Biometric type cannot be empty")

        if not self.timestamp:
            raise ValueError("Timestamp cannot be empty")

        if not self.value:
            raise ValueError("Biometric value cannot be empty")

        if self.timestamp > utcnow():
            raise ValueError("Timestamp cannot be in the future")

        # Type-specific validations
        if self.biometric_type == BiometricType.HEART_RATE:
            if "bpm" not in self.value:
                raise ValueError("Heart rate must include 'bpm' value")
            if not isinstance(self.value["bpm"], (int, float)) or self.value["bpm"] <= 0:
                raise ValueError("Heart rate bpm must be a positive number")

        elif self.biometric_type == BiometricType.BLOOD_PRESSURE:
            if "systolic" not in self.value or "diastolic" not in self.value:
                raise ValueError("Blood pressure must include 'systolic' and 'diastolic' values")

    def get_summary_value(self) -> dict[str, Any]:
        """
        Get a summarized version of the biometric value.

        Returns:
            Summarized biometric value
        """
        # Type-specific summary logic
        if self.biometric_type == BiometricType.HEART_RATE:
            return {"bpm": self.value.get("bpm")}

        elif self.biometric_type == BiometricType.BLOOD_PRESSURE:
            return {
                "systolic": self.value.get("systolic"),
                "diastolic": self.value.get("diastolic"),
            }

        elif self.biometric_type == BiometricType.SLEEP:
            hours = self.value.get("duration_minutes", 0) / 60
            return {"hours": round(hours, 1)}

        # Default summary is the entire value
        return self.value

    def to_dict(self) -> dict[str, Any]:
        """
        Convert entity to dictionary.

        Returns:
            Dictionary representation of the entity
        """
        return {
            "id": self.id,
            "biometric_type": self.biometric_type.value
            if isinstance(self.biometric_type, BiometricType)
            else self.biometric_type,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "value": self.value,
            "device_id": self.device_id,
            "metadata": self.metadata,
            "user_id": self.user_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Biometric":
        """
        Create entity from dictionary.

        Args:
            data: Dictionary representation of entity

        Returns:
            Biometric entity
        """
        # Convert string enum values to enum instances
        biometric_type = (
            BiometricType(data["biometric_type"])
            if isinstance(data["biometric_type"], str)
            else data["biometric_type"]
        )

        # Parse timestamps
        timestamp = (
            datetime.fromisoformat(data["timestamp"])
            if isinstance(data["timestamp"], str)
            else data["timestamp"]
        )

        return cls(
            id=data.get("id"),
            biometric_type=biometric_type,
            timestamp=timestamp,
            value=data["value"],
            device_id=data.get("device_id"),
            metadata=data.get("metadata", {}),
            user_id=data["user_id"],
        )
