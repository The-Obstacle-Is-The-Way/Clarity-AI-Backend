"""Psychiatric assessment value object."""

from dataclasses import dataclass, field
from datetime import date
from uuid import UUID, uuid4


@dataclass(frozen=True)
class PsychiatricAssessment:
    """
    Immutable value object for psychiatric assessment data.
    
    Contains PHI that must be handled according to HIPAA regulations.
    """
    
    assessment_date: date
    psychiatrist_id: UUID
    diagnoses: list[str]
    assessment_notes: str
    treatment_plan: str
    id: UUID = field(default_factory=uuid4)
    severity_score: int | None = None
    medications: list[dict[str, str]] = field(default_factory=list)
    follow_up_date: date | None = None
    
    def __post_init__(self) -> None:
        """Validate assessment data."""
        # Validate severity score if provided
        if self.severity_score is not None and not (0 <= self.severity_score <= 10):
            raise ValueError("Severity score must be between 0 and 10")
        
        # Validate medication format
        for med in self.medications:
            if "name" not in med or "dosage" not in med:
                raise ValueError("Medications must include name and dosage")
    
    def get_primary_diagnosis(self) -> str | None:
        """Get primary diagnosis if available."""
        return self.diagnoses[0] if self.diagnoses else None
    
    def requires_follow_up(self) -> bool:
        """Check if assessment requires follow-up."""
        return self.follow_up_date is not None
    
    def to_dict(self) -> dict:
        """Convert to dictionary with PHI masking."""
        return {
            "id": str(self.id),
            "assessment_date": str(self.assessment_date),
            "psychiatrist_id": str(self.psychiatrist_id),
            "diagnoses": self.diagnoses,
            "assessment_notes": "[REDACTED]",  # PHI masked
            "treatment_plan": "[REDACTED]",  # PHI masked
            "severity_score": self.severity_score,
            "medications": self.medications,
            "follow_up_date": str(self.follow_up_date) if self.follow_up_date else None
        }
