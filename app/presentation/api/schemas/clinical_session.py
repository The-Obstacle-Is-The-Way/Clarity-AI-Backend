"""
Pydantic schemas for Clinical Session API endpoints.
"""
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, Dict, Any
from uuid import UUID
from datetime import datetime

# Import enums from domain entity
from app.domain.entities.clinical_session import SessionType

class ClinicalSessionBase(BaseModel):
    patient_id: UUID
    provider_id: UUID
    appointment_id: Optional[UUID] = None
    session_datetime: datetime
    duration_minutes: int = Field(gt=0) # Duration must be positive
    session_type: SessionType
    summary: Optional[str] = None
    subjective_notes: Optional[str] = None
    objective_notes: Optional[str] = None
    assessment_notes: Optional[str] = None
    plan_notes: Optional[str] = None
    structured_data: Optional[Dict[str, Any]] = {}

class ClinicalSessionCreate(ClinicalSessionBase):
    pass

class ClinicalSessionUpdate(BaseModel):
    # Allow updating specific fields, typically notes or structured data
    duration_minutes: Optional[int] = Field(default=None, gt=0)
    summary: Optional[str] = None
    subjective_notes: Optional[str] = None
    objective_notes: Optional[str] = None
    assessment_notes: Optional[str] = None
    plan_notes: Optional[str] = None
    structured_data: Optional[Dict[str, Any]] = None
    # Usually patient/provider/type/time are not updatable after creation

class ClinicalSessionResponse(ClinicalSessionBase):
    id: UUID
    created_at: datetime
    last_updated: datetime

    model_config = ConfigDict(from_attributes=True) # Enable ORM mode equivalent

# Schema for listing clinical sessions with potential filters
class ClinicalSessionListQuery(BaseModel):
    patient_id: Optional[UUID] = None
    provider_id: Optional[UUID] = None
    appointment_id: Optional[UUID] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    session_type: Optional[SessionType] = None
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)

