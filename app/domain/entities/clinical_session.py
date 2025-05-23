"""
Domain entity representing a Clinical Session record.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from app.domain.entities.base_entity import BaseEntity
from app.domain.utils.datetime_utils import now_utc


class SessionType(str, Enum):
    THERAPY = "therapy"
    PSYCHIATRY = "psychiatry"
    ASSESSMENT = "assessment"
    CASE_MANAGEMENT = "case_management"


@dataclass
class ClinicalSession(BaseEntity):
    """Clinical Session entity."""

    id: UUID = field(default_factory=uuid4)
    patient_id: UUID
    provider_id: UUID
    appointment_id: UUID | None = None  # Link to appointment if scheduled
    session_datetime: datetime  # Actual time the session occurred
    duration_minutes: int
    session_type: SessionType
    summary: str | None = None  # Clinician's summary of the session
    subjective_notes: str | None = None  # Patient's report (SOAP note S)
    objective_notes: str | None = None  # Clinician's observations (SOAP note O)
    assessment_notes: str | None = None  # Clinician's assessment (SOAP note A)
    plan_notes: str | None = None  # Treatment plan adjustments (SOAP note P)
    structured_data: dict[str, Any] = field(
        default_factory=dict
    )  # For specific assessments, scales used, etc.
    created_at: datetime = field(default_factory=now_utc)
    last_updated: datetime = field(default_factory=now_utc)

    def __post_init__(self):
        # Call BaseEntity's post_init if it exists
        if hasattr(super(), "__post_init__"):
            super().__post_init__()

    def touch(self) -> None:
        """Update the last_updated timestamp."""
        self.last_updated = now_utc()
