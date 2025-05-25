"""
Recommendation Engine Interface.

This module defines the interface for the recommendation engine service
that generates treatment and monitoring recommendations based on patient insights.
"""

from abc import ABC, abstractmethod
from typing import Any
from uuid import UUID


class IRecommendationEngine(ABC):
    """
    Interface for the Recommendation Engine Service.

    This interface defines the contract that any implementation of the
    Recommendation Engine Service must fulfill, allowing the domain layer
    to interact with the service without depending on its implementation.
    """

    @abstractmethod
    async def generate_recommendations(
        self, patient_id: UUID, insights: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """
        Generate personalized recommendations based on patient insights.

        Args:
            patient_id: UUID of the patient
            insights: Dictionary containing insights from various ML services

        Returns:
            List of recommendation dictionaries, each containing:
                - type: Type of recommendation (e.g., "medication", "behavioral")
                - recommendation: The actual recommendation text
                - confidence: Confidence score (0.0-1.0)
                - supporting_evidence: List of evidence supporting the recommendation
                - priority: Priority level ("high", "medium", "low")

        Raises:
            ValidationError: If the input data is invalid
            ModelInferenceError: If the recommendation generation fails
        """
        pass

    @abstractmethod
    async def get_recommendation_history(
        self, patient_id: UUID, limit: int = 10
    ) -> list[dict[str, Any]]:
        """
        Get historical recommendations for a patient.

        Args:
            patient_id: UUID of the patient
            limit: Maximum number of recommendations to return

        Returns:
            List of historical recommendation dictionaries

        Raises:
            ValidationError: If the patient ID is invalid
            ModelInferenceError: If the retrieval fails
        """
        pass

    @abstractmethod
    async def evaluate_recommendation_effectiveness(
        self, recommendation_id: UUID, outcome_data: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Evaluate the effectiveness of a previous recommendation.

        Args:
            recommendation_id: UUID of the recommendation
            outcome_data: Data about the outcome after following the recommendation

        Returns:
            Dictionary containing effectiveness evaluation

        Raises:
            ValidationError: If the input data is invalid
            ModelInferenceError: If the evaluation fails
        """
        pass
