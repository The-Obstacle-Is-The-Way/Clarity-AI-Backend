import abc
from uuid import UUID

from app.presentation.api.schemas.digital_twin_schemas import (
    ClinicalTextAnalysisResponse,
    DigitalTwinStatusResponse,
    PersonalizedInsightResponse,
)


class IDigitalTwinIntegrationService(abc.ABC):
    """Interface for digital twin integration services."""

    @abc.abstractmethod
    async def get_digital_twin_status(self, patient_id: UUID) -> DigitalTwinStatusResponse | None:
        """Retrieve the status of the digital twin for a given patient."""
        raise NotImplementedError

    @abc.abstractmethod
    async def generate_comprehensive_patient_insights(
        self, patient_id: UUID
    ) -> PersonalizedInsightResponse | None:
        """Generate comprehensive insights for a given patient's digital twin."""
        raise NotImplementedError

    @abc.abstractmethod
    async def analyze_clinical_text_mentallama(
        self, patient_id: UUID, text_data: str
    ) -> ClinicalTextAnalysisResponse | None:
        """Analyze clinical text using MentaLLaMA for a given patient."""
        raise NotImplementedError
