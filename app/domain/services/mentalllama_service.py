"""
Domain service interface for MentalLLaMA-33B NLP analysis.
Pure domain interface with no infrastructure dependencies.
"""
from abc import ABC, abstractmethod
from uuid import UUID

from app.domain.entities.digital_twin import ClinicalInsight  # Corrected import path


class MentalLLaMAService(ABC):
    """
    Abstract interface for MentalLLaMA-33B language model operations.
    Concrete implementations will be provided in the infrastructure layer.
    """

    @abstractmethod
    async def analyze_clinical_notes(
        self, patient_id: UUID, note_text: str, context: dict | None = None
    ) -> list[ClinicalInsight]:
        """
        Analyze clinical notes using MentalLLaMA-33B to extract insights.

        Args:
            patient_id: UUID of the patient
            note_text: Raw text of the clinical note
            context: Optional additional context for the analysis

        Returns:
            List of ClinicalInsight objects derived from the notes
        """
        pass

    @abstractmethod
    async def generate_treatment_recommendations(
        self,
        patient_id: UUID,
        diagnosis_codes: list[str],
        current_medications: list[str],
        clinical_history: str,
        digital_twin_state_id: UUID | None = None,
    ) -> list[dict]:
        """
        Generate treatment recommendations based on patient information.

        Args:
            patient_id: UUID of the patient
            diagnosis_codes: List of diagnosis codes (ICD-10 or DSM-5)
            current_medications: List of current medications
            clinical_history: Summary of clinical history
            digital_twin_state_id: Optional reference to Digital Twin state

        Returns:
            List of dictionaries containing treatment recommendations
        """
        pass

    @abstractmethod
    async def analyze_risk_factors(
        self,
        patient_id: UUID,
        clinical_data: dict,
        digital_twin_state_id: UUID | None = None,
    ) -> dict:
        """
        Analyze risk factors from patient data using NLP techniques.

        Args:
            patient_id: UUID of the patient
            clinical_data: Dictionary containing relevant clinical data
            digital_twin_state_id: Optional reference to Digital Twin state

        Returns:
            Dictionary with risk factor analysis
        """
        pass

    @abstractmethod
    async def semantic_search(self, patient_id: UUID, query: str, limit: int = 10) -> list[dict]:
        """
        Perform semantic search across patient records.

        Args:
            patient_id: UUID of the patient
            query: Search query text
            limit: Maximum number of results to return

        Returns:
            List of search results with relevance scores
        """
        pass

    @abstractmethod
    async def summarize_patient_history(
        self,
        patient_id: UUID,
        time_range: str | None = "all",
        focus_areas: list[str] | None = None,
    ) -> str:
        """
        Generate a concise summary of patient history.

        Args:
            patient_id: UUID of the patient
            time_range: Optional time range to focus on (e.g., "last_month")
            focus_areas: Optional list of clinical areas to focus on

        Returns:
            Textual summary of patient history
        """
        pass
