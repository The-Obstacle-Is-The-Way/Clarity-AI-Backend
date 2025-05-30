"""
Interface for the Symptom Assessment Repository.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from uuid import UUID

from app.domain.entities.symptom_assessment import AssessmentType, SymptomAssessment


class ISymptomAssessmentRepository(ABC):
    """Abstract base class defining the symptom assessment repository interface."""

    @abstractmethod
    async def get_by_id(self, assessment_id: UUID) -> SymptomAssessment | None:
        """Retrieve a symptom assessment by its ID."""
        pass

    @abstractmethod
    async def create(self, assessment: SymptomAssessment) -> SymptomAssessment:
        """Create a new symptom assessment record."""
        pass

    # Assessments are typically immutable, so update/delete might not be standard
    # @abstractmethod
    # async def update(self, assessment: SymptomAssessment) -> Optional[SymptomAssessment]:
    #     """Update an existing symptom assessment record."""
    #     pass

    # @abstractmethod
    # async def delete(self, assessment_id: UUID) -> bool:
    #     """Delete a symptom assessment record by its ID."""
    #     pass

    @abstractmethod
    async def list_by_patient_id(
        self,
        patient_id: UUID,
        assessment_type: AssessmentType | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> list[SymptomAssessment]:
        """List symptom assessments for a specific patient, optionally filtered by type and date range."""
        pass
