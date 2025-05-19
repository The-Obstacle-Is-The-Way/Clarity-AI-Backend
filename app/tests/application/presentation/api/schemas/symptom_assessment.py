"""
Pydantic schemas for Symptom Assessment API endpoints.
"""
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

# Import enums from domain entity
from app.domain.entities.symptom_assessment import AssessmentType
from app.domain.utils.datetime_utils import now_utc


class SymptomAssessmentBase(BaseModel):
    patient_id: UUID
    assessment_type: AssessmentType
    assessment_date: datetime = Field(default_factory=now_utc)
    scores: dict[str, Any]
    source: str | None = None


class SymptomAssessmentCreate(SymptomAssessmentBase):
    pass


# Assessments are typically immutable, so Update schema might not be needed
# class SymptomAssessmentUpdate(BaseModel):
#     scores: Optional[Dict[str, Any]] = None
#     source: Optional[str] = None


class SymptomAssessmentResponse(SymptomAssessmentBase):
    id: UUID
    created_at: datetime
    last_updated: datetime  # Will likely be same as created_at

    model_config = {"from_attributes": True}  # Enable ORM mode equivalent


# Schema for listing assessments with potential filters
class SymptomAssessmentListQuery(BaseModel):
    patient_id: UUID  # Usually required when listing assessments
    assessment_type: AssessmentType | None = None
    start_date: datetime | None = None
    end_date: datetime | None = None
    source: str | None = None
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)
