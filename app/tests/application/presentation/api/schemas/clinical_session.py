"""
Pydantic schemas for Clinical Session API endpoints.
"""
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

# Import enums from domain entity
from app.domain.entities.clinical_session import SessionType


class ClinicalSessionBase(BaseModel):
    patient_id: UUID
    provider_id: UUID
    appointment_id: UUID | None = None
    session_datetime: datetime
    duration_minutes: int = Field(gt=0)  # Duration must be positive
    session_type: SessionType
    summary: str | None = None
    subjective_notes: str | None = None
    objective_notes: str | None = None
    assessment_notes: str | None = None
    plan_notes: str | None = None
    structured_data: dict[str, Any] | None = {}


class ClinicalSessionCreate(ClinicalSessionBase):
    pass


class ClinicalSessionUpdate(BaseModel):
    # Allow updating specific fields, typically notes or structured data
    duration_minutes: int | None = Field(default=None, gt=0)
    summary: str | None = None
    subjective_notes: str | None = None
    objective_notes: str | None = None
    assessment_notes: str | None = None
    plan_notes: str | None = None
    structured_data: dict[str, Any] | None = None
    # Usually patient/provider/type/time are not updatable after creation


class ClinicalSessionResponse(ClinicalSessionBase):
    id: UUID
    created_at: datetime
    last_updated: datetime

    model_config = ConfigDict(from_attributes=True)  # Enable ORM mode equivalent


# Schema for listing clinical sessions with potential filters
class ClinicalSessionListQuery(BaseModel):
    patient_id: UUID | None = None
    provider_id: UUID | None = None
    appointment_id: UUID | None = None
    start_date: datetime | None = None
    end_date: datetime | None = None
    session_type: SessionType | None = None
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)
