"""Psychiatric assessment value object."""

from dataclasses import dataclass
from datetime import date
from typing import Any
from uuid import UUID, uuid4


@dataclass(frozen=True)
class PsychiatricAssessment:
    """
    Immutable value object for psychiatric assessment data.

    Contains PHI that must be handled according to HIPAA regulations.
    """

    assessment_date: date
    diagnosis: str
    severity: str
    treatment_plan: str
    notes: str | None = None
    id: UUID = uuid4()

    def __post_init__(self) -> None:
        """Validate assessment data."""
        if not self.diagnosis:
            raise ValueError("Diagnosis cannot be empty")

        if not self.severity:
            raise ValueError("Severity cannot be empty")

        if not self.treatment_plan:
            raise ValueError("Treatment plan cannot be empty")

    def __repr__(self) -> str:
        """String representation of the assessment."""
        assessment_date_str = str(self.assessment_date)
        return f"PsychiatricAssessment(date={assessment_date_str}, diagnosis='{self.diagnosis}', severity='{self.severity}')"

    def to_dict(self) -> dict[str, str | date | None]:
        """Convert to dictionary."""
        return {
            "assessment_date": (
                self.assessment_date.isoformat()
                if isinstance(self.assessment_date, date)
                else self.assessment_date
            ),
            "diagnosis": self.diagnosis,
            "severity": self.severity,
            "treatment_plan": self.treatment_plan,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PsychiatricAssessment":
        """Create a PsychiatricAssessment from a dictionary."""
        # Handle date conversion if the date is a string
        assessment_date = data["assessment_date"]
        if isinstance(assessment_date, str):
            assessment_date = date.fromisoformat(assessment_date)

        return cls(
            assessment_date=assessment_date,
            diagnosis=data["diagnosis"],
            severity=data["severity"],
            treatment_plan=data["treatment_plan"],
            notes=data.get("notes"),
        )
