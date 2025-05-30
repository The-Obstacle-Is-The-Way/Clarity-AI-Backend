"""
Medication dosage value object for the NOVAMIND backend.

This module contains the MedicationDosage value object, which represents
a medication dosage with immutable properties and validation.
"""

from dataclasses import dataclass
from enum import Enum


class DosageUnit(Enum):
    """Enumeration of medication dosage units"""

    MG = "mg"
    MCG = "mcg"
    G = "g"
    ML = "ml"
    MG_ML = "mg/ml"
    TABLET = "tablet"
    CAPSULE = "capsule"
    PATCH = "patch"
    SPRAY = "spray"
    DROP = "drop"
    UNIT = "unit"
    PERCENT = "percent"


@dataclass(frozen=True)
class MedicationDosage:
    """
    Value object representing a medication dosage.

    This is an immutable value object with validation logic.
    """

    value: float
    unit: DosageUnit
    frequency_per_day: float
    max_daily_value: float | None = None

    def __post_init__(self) -> None:
        """Validate the dosage values"""
        self.validate_dosage()

        if self.frequency_per_day <= 0:
            raise ValueError("Frequency must be positive")

        if self.max_daily_value is not None and self.max_daily_value < self.value:
            raise ValueError("Maximum daily value cannot be less than single dose value")

    def validate_dosage(self) -> None:
        """
        Validate that the dosage amount and unit are valid.

        Raises:
            ValueError: If dosage amount is negative or unit is invalid
        """
        if self.value < 0:
            raise ValueError("Dosage amount cannot be negative")

        if not isinstance(self.unit, DosageUnit):
            raise ValueError(
                f"Invalid dosage unit. Must be one of: {', '.join([unit.value for unit in DosageUnit])}"
            )

    @property
    def daily_value(self) -> float:
        """Calculate the total daily value"""
        return self.value * self.frequency_per_day

    @property
    def is_within_max_daily(self) -> bool:
        """Check if the daily value is within the maximum daily value"""
        if self.max_daily_value is None:
            return True
        return self.daily_value <= self.max_daily_value

    def __str__(self) -> str:
        """String representation of the dosage"""
        base = f"{self.value} {self.unit.value}"
        if self.frequency_per_day == 1:
            return f"{base} once daily"
        elif self.frequency_per_day == 2:
            return f"{base} twice daily"
        elif self.frequency_per_day == 3:
            return f"{base} three times daily"
        elif self.frequency_per_day == 4:
            return f"{base} four times daily"
        else:
            return f"{base} {self.frequency_per_day} times daily"
