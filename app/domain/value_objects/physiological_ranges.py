"""
Physiological range value objects.

This module defines value objects for physiological ranges,
providing validation and comparison of biometric measurements.
"""

from typing import ClassVar, Optional


class PhysiologicalRange:
    """
    Physiological range for biometric measurements.

    This value object defines normal and critical ranges for biometric values,
    providing methods to check if a value is within normal or critical limits.
    """

    # Class-level default ranges for common biometric types
    DEFAULT_RANGES: ClassVar[dict[str, dict[str, float]]] = {
        "heart_rate": {
            "min": 60.0,
            "max": 100.0,
            "critical_min": 40.0,
            "critical_max": 140.0,
        },
        "blood_pressure": {  # Using systolic value as reference
            "min": 90.0,
            "max": 120.0,
            "critical_min": 70.0,
            "critical_max": 180.0,
        },
        "temperature": {
            "min": 36.5,
            "max": 37.5,
            "critical_min": 35.0,
            "critical_max": 39.0,
        },
        "respiratory_rate": {
            "min": 12.0,
            "max": 20.0,
            "critical_min": 8.0,
            "critical_max": 30.0,
        },
        "blood_glucose": {
            "min": 70.0,
            "max": 120.0,
            "critical_min": 55.0,
            "critical_max": 200.0,
        },
        "oxygen_saturation": {
            "min": 95.0,
            "max": 100.0,
            "critical_min": 90.0,
            "critical_max": 100.0,
        },
        "hrv": {"min": 20.0, "max": 80.0, "critical_min": 10.0, "critical_max": 100.0},
    }

    def __init__(self, min: float, max: float, critical_min: float, critical_max: float):
        """
        Initialize a physiological range.

        Args:
            min: Minimum value of normal range
            max: Maximum value of normal range
            critical_min: Minimum value before critical
            critical_max: Maximum value before critical

        Raises:
            ValueError: If range values are invalid
        """
        if min >= max:
            raise ValueError("Minimum value must be less than maximum value")

        if critical_min > min:
            raise ValueError("Critical minimum must be <= minimum")

        if critical_max < max:
            raise ValueError("Critical maximum must be >= maximum")

        self.min = min
        self.max = max
        self.critical_min = critical_min
        self.critical_max = critical_max

    def is_normal(self, value: float) -> bool:
        """
        Check if a value is within normal range.

        Args:
            value: The value to check

        Returns:
            True if within normal range
        """
        return self.min <= value <= self.max

    def is_abnormal(self, value: float) -> bool:
        """
        Check if a value is outside normal range but not critical.

        Args:
            value: The value to check

        Returns:
            True if abnormal but not critical
        """
        return not self.is_normal(value) and not self.is_critical(value)

    def is_critical(self, value: float) -> bool:
        """
        Check if a value is in critical range.

        Args:
            value: The value to check

        Returns:
            True if in critical range
        """
        return value < self.critical_min or value > self.critical_max

    def get_severity(self, value: float) -> str:
        """
        Get the severity level of a value.

        Args:
            value: The value to check

        Returns:
            Severity level: 'normal', 'abnormal', or 'critical'
        """
        if self.is_normal(value):
            return "normal"
        elif self.is_critical(value):
            return "critical"
        else:
            return "abnormal"

    def to_dict(self) -> dict[str, float]:
        """
        Convert to dictionary representation.

        Returns:
            Dictionary with range values
        """
        return {
            "min": self.min,
            "max": self.max,
            "critical_min": self.critical_min,
            "critical_max": self.critical_max,
        }

    @classmethod
    def from_dict(cls, data: dict[str, float]) -> "PhysiologicalRange":
        """
        Create a PhysiologicalRange from a dictionary.

        Args:
            data: Dictionary with range values

        Returns:
            New PhysiologicalRange instance
        """
        return cls(
            min=data["min"],
            max=data["max"],
            critical_min=data["critical_min"],
            critical_max=data["critical_max"],
        )

    @classmethod
    def get_default_range(cls, biometric_type: str) -> Optional["PhysiologicalRange"]:
        """
        Get default range for a biometric type.

        Args:
            biometric_type: Type of biometric

        Returns:
            PhysiologicalRange for the type or None
        """
        range_data = cls.DEFAULT_RANGES.get(biometric_type)
        if not range_data:
            return None

        return cls(
            min=range_data["min"],
            max=range_data["max"],
            critical_min=range_data["critical_min"],
            critical_max=range_data["critical_max"],
        )
