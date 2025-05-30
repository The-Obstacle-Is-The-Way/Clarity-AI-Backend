"""
MentaLLaMA Service Interface Module

This module defines the core interfaces and protocols for the MentaLLaMA service layer
following pure clean architecture principles by separating interface from implementation.
All concrete implementations must conform to these interfaces to ensure proper
dependency inversion and modular design.
"""

from abc import ABC, abstractmethod
from typing import Any
from uuid import UUID

from app.domain.entities.clinical_insight import ClinicalInsight


class MentaLLaMAServiceInterface(ABC):
    """
    Core interface for the MentaLLaMA service.

    This interface defines the contract that all MentaLLaMA service implementations
    must adhere to, enabling clean dependency injection and proper separation of concerns.
    """

    @abstractmethod
    async def analyze_clinical_notes(
        self, patient_id: UUID, note_text: str, context: dict[str, Any] | None = None
    ) -> list[ClinicalInsight]:
        """
        Analyze clinical notes to extract structured insights.

        Args:
            patient_id: UUID of the patient
            note_text: The clinical note text to analyze
            context: Optional additional context

        Returns:
            List of ClinicalInsight objects
        """
        pass

    @abstractmethod
    async def get_analysis_by_id(
        self, analysis_id: UUID | str, patient_id: UUID | None = None
    ) -> dict[str, Any]:
        """
        Retrieve a previously generated analysis by its ID.

        Args:
            analysis_id: UUID of the analysis to retrieve
            patient_id: Optional UUID of the patient for validation

        Returns:
            Dictionary containing the complete analysis

        Raises:
            ValueError: If the analysis is not found
        """
        pass

    @abstractmethod
    async def get_patient_analyses(
        self, patient_id: UUID, limit: int = 10, offset: int = 0
    ) -> list[dict[str, Any]]:
        """
        Retrieve all analyses for a specific patient.

        Args:
            patient_id: UUID of the patient
            limit: Maximum number of analyses to return
            offset: Number of analyses to skip

        Returns:
            List of analysis dictionaries
        """
        pass

    @abstractmethod
    async def get_model_info(self) -> dict[str, Any]:
        """
        Get information about the MentaLLaMA model.

        Returns:
            Dictionary with model information
        """
        pass
