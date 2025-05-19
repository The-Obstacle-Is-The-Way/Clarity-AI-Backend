"""
Personalized Adaptive Testing (PAT) Service Interface.

This module defines the interface for interacting with the PAT system,
which handles psychological assessments and their scoring.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from uuid import UUID


class PATService(ABC):
    """
    Interface for Personalized Adaptive Testing (PAT) services.

    This interface defines the contract for any PAT service implementation,
    whether it's a mock for testing or a real implementation connecting
    to external services.
    """

    @abstractmethod
    def get_assessment_questions(
        self, patient_id: UUID, assessment_type: str
    ) -> List[Dict[str, Any]]:
        """
        Get a list of assessment questions for a patient.

        Args:
            patient_id: The patient's UUID
            assessment_type: Type of assessment (PHQ9, GAD7, etc.)

        Returns:
            List of question dictionaries
        """
        pass

    @abstractmethod
    def submit_assessment(
        self,
        patient_id: UUID,
        assessment_type: str,
        responses: Dict[str, Union[int, float, str]],
    ) -> Any:
        """
        Submit an assessment for a patient and get the result.

        Args:
            patient_id: The patient's UUID
            assessment_type: Type of assessment (PHQ9, GAD7, etc.)
            responses: Dict mapping question IDs to response values

        Returns:
            AssessmentResult with scores
        """
        pass

    @abstractmethod
    def get_assessment_history(
        self, patient_id: UUID, assessment_type: Optional[str] = None, limit: int = 10
    ) -> List[Any]:
        """
        Get assessment history for a patient.

        Args:
            patient_id: The patient's UUID
            assessment_type: Optional filter by assessment type
            limit: Maximum number of results to return

        Returns:
            List of AssessmentResult objects
        """
        pass

    @abstractmethod
    def get_trend_analysis(
        self,
        patient_id: UUID,
        assessment_type: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Get trend analysis for a patient's assessment results.

        Args:
            patient_id: The patient's UUID
            assessment_type: Type of assessment to analyze
            start_date: Optional start date for filtering
            end_date: Optional end date for filtering

        Returns:
            Dictionary with trend analysis results
        """
        pass
