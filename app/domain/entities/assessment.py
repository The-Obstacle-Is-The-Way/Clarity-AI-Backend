"""
Assessment entities for the PAT (Personalized Adaptive Testing) system.

This module defines the data structures used for psychological assessments
and their results.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Dict, Union, Optional
from uuid import UUID


class AssessmentType(str, Enum):
    """Types of psychological assessments supported by the PAT system."""

    PHQ9 = "PHQ9"  # Patient Health Questionnaire-9 (depression)
    GAD7 = "GAD7"  # Generalized Anxiety Disorder-7
    MOOD = "MOOD"  # Daily mood tracking


@dataclass
class AssessmentResult:
    """
    Result of a completed psychological assessment.

    This includes raw scores, normalized scores, and interpretation
    of the assessment results.
    """

    id: UUID
    patient_id: UUID
    assessment_type: AssessmentType
    timestamp: datetime
    raw_score: float
    normalized_score: float  # 0-100 scale for consistent comparisons
    severity: str  # Interpretation of the score (e.g., "Minimal", "Moderate", "Severe")
    responses: Dict[str, Union[int, float, str]] = field(default_factory=dict)
    notes: Optional[str] = None
