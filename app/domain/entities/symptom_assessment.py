"""
Domain entity representing a Symptom Assessment.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from app.domain.entities.base_entity import BaseEntity
from app.domain.utils.datetime_utils import now_utc


class AssessmentType(str, Enum):
    PHQ9 = "PHQ-9"
    GAD7 = "GAD-7"
    CUSTOM = "Custom"
    # Add other standard scales (e.g., BDI, MADRS, YBOCS)


@dataclass(kw_only=True)
class SymptomAssessment(BaseEntity):
    """Symptom Assessment entity."""

    # Fields without defaults first
    patient_id: UUID
    assessment_type: AssessmentType
    assessment_date: datetime  # Date/time the assessment was completed
    scores: dict[
        str, Any
    ]  # e.g., {"total_score": 15, "q1": 2, "q2": 3, ...} or {"custom_symptom": "severity_level"}

    # Fields with defaults
    id: UUID = field(default_factory=uuid4)
    source: str | None = None  # e.g., "Patient Reported", "Clinician Administered"
    created_at: datetime = field(default_factory=now_utc)
    last_updated: datetime = field(
        default_factory=now_utc
    )  # Usually same as created_at for assessments

    def __post_init__(self):
        # Call BaseEntity's post_init if it exists
        if hasattr(super(), "__post_init__"):
            super().__post_init__()
        # Add validation if needed (e.g., score range for known types)

    def touch(self):
        """Update the last_updated timestamp."""
        self.last_updated = now_utc()  # Should ideally not change post-creation
