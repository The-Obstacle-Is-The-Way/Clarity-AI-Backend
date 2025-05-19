from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class DigitalTwinComponentStatus(BaseModel):
    has_model: bool | None = None
    last_updated: datetime | None = None
    service_available: bool | None = None
    service_info: dict[str, Any] | None = None


class DigitalTwinStatusResponse(BaseModel):
    patient_id: UUID
    status: str
    completeness: float = Field(..., ge=0, le=100)
    components: dict[str, DigitalTwinComponentStatus]
    last_checked: datetime


class PersonalizedInsightResponse(BaseModel):
    insight_id: UUID
    digital_twin_id: UUID
    query: str | None = None
    insight_type: str
    insight: str
    key_points: list[str]
    confidence: float = Field(..., ge=0, le=1)
    timestamp: datetime


class ClinicalTextAnalysisRequest(BaseModel):
    clinical_text: str = Field(..., min_length=1)
    analysis_focus: str | None = None  # e.g., 'mood', 'symptoms', 'risk_assessment'


class ClinicalTextAnalysisResponse(BaseModel):
    analysis_id: UUID
    patient_id: UUID
    timestamp: datetime
    status: str  # e.g., 'completed', 'processing', 'failed'
    summary: str | None = None
    extracted_entities: list[
        dict[str, Any]
    ] | None = None  # e.g., [{'text': 'anxiety', 'label': 'SYMPTOM'}]
    sentiment: dict[str, float] | None = None  # e.g., {'score': -0.5, 'magnitude': 0.8}
    risk_assessment: dict[str, Any] | None = None  # e.g., {'suicidal_ideation': 'low'}
