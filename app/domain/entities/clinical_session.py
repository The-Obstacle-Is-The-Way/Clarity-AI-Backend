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


@dataclass(kw_only=True)
class ClinicalSession(BaseEntity):
    """Clinical Session entity."""

    # Required fields (no defaults) must come first
    patient_id: UUID
    provider_id: UUID
    session_datetime: datetime  # Actual time the session occurred
    duration_minutes: int
    session_type: SessionType

    # Optional/defaulted fields come after required fields
    id: UUID = field(default_factory=uuid4)
    appointment_id: UUID | None = None  # Link to appointment if scheduled
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

    def __post_init__(self) -> None:
        """Initialize the clinical session entity."""
        # BaseEntity doesn't define __post_init__, so no super() call needed
        pass

    def touch(self) -> None:
        """Update the last_updated timestamp."""
        self.last_updated = now_utc()
