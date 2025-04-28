"""
Pydantic schemas for Symptom Assessment API endpoints.
"""
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from uuid import UUID
from datetime import datetime
from app.domain.utils.datetime_utils import now_utc, UTC

# Import enums from domain entity
from app.domain.entities.symptom_assessment import AssessmentType

class SymptomAssessmentBase(BaseModel):
    patient_id: UUID
    assessment_type: AssessmentType
    assessment_date: datetime = Field(default_factory=now_utc)
    scores: Dict[str, Any]
    source: Optional[str] = None

class SymptomAssessmentCreate(SymptomAssessmentBase):
    pass

# Assessments are typically immutable, so Update schema might not be needed
# class SymptomAssessmentUpdate(BaseModel):
#     scores: Optional[Dict[str, Any]] = None
#     source: Optional[str] = None

class SymptomAssessmentResponse(SymptomAssessmentBase):
    id: UUID
    created_at: datetime
    last_updated: datetime # Will likely be same as created_at

    model_config = {"from_attributes": True} # Enable ORM mode equivalent

# Schema for listing assessments with potential filters
class SymptomAssessmentListQuery(BaseModel):
    patient_id: UUID # Usually required when listing assessments
    assessment_type: Optional[AssessmentType] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    source: Optional[str] = None
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)

