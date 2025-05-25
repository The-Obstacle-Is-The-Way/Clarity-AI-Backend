"""
Mock PAT service for testing purposes.

This provides a mock implementation of the PAT (Personalized Adaptive Testing)
service for use in testing without depending on the actual external service.
"""

import random
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from app.domain.entities.assessment import AssessmentResult, AssessmentType
from app.domain.interfaces.pat_service import PATService
from app.domain.utils.datetime_utils import UTC


class MockPATService(PATService):
    """
    Mock implementation of the PAT service interface for testing.

    This implementation provides predictable responses without
    requiring connection to external services.
    """

    def __init__(self, seed: int | None = None):
        """
        Initialize the mock PAT service.

        Args:
            seed: Random seed for reproducible results
        """
        self.rng = random.Random(seed)
        self._assessments: dict[UUID, list[AssessmentResult]] = {}

    def get_assessment_questions(
        self, patient_id: UUID, assessment_type: str
    ) -> list[dict[str, Any]]:
        """
        Get a list of assessment questions for a patient.

        Args:
            patient_id: The patient's UUID
            assessment_type: Type of assessment (PHQ9, GAD7, etc.)

        Returns:
            List of question dictionaries
        """
        # Convert string to AssessmentType enum
        try:
            assessment_enum = AssessmentType(assessment_type)
        except ValueError:
            # Return empty list for unknown assessment types
            return []
            
        # Mock questions for different assessment types
        questions = {
            AssessmentType.PHQ9: [
                {
                    "id": "phq1",
                    "text": "Little interest or pleasure in doing things?",
                    "min_score": 0,
                    "max_score": 3,
                },
                {
                    "id": "phq2",
                    "text": "Feeling down, depressed, or hopeless?",
                    "min_score": 0,
                    "max_score": 3,
                },
                # ... more questions would be here in real implementation
            ],
            AssessmentType.GAD7: [
                {
                    "id": "gad1",
                    "text": "Feeling nervous, anxious, or on edge?",
                    "min_score": 0,
                    "max_score": 3,
                },
                {
                    "id": "gad2",
                    "text": "Not being able to stop or control worrying?",
                    "min_score": 0,
                    "max_score": 3,
                },
                # ... more questions would be here in real implementation
            ],
            AssessmentType.MOOD: [
                {
                    "id": "mood1",
                    "text": "How would you rate your mood today?",
                    "min_score": 1,
                    "max_score": 10,
                },
                {
                    "id": "mood2",
                    "text": "How would you rate your energy level today?",
                    "min_score": 1,
                    "max_score": 10,
                },
            ],
        }

        return questions.get(assessment_enum, [])

    def submit_assessment(
        self,
        patient_id: UUID,
        assessment_type: str,
        responses: dict[str, int | float | str],
    ) -> AssessmentResult:
        """
        Submit an assessment for a patient and get the result.

        Args:
            patient_id: The patient's UUID
            assessment_type: Type of assessment (PHQ9, GAD7, etc.)
            responses: Dict mapping question IDs to response values

        Returns:
            AssessmentResult with scores
        """
        # Convert string to AssessmentType enum
        try:
            assessment_enum = AssessmentType(assessment_type)
        except ValueError:
            # For unknown assessment types, use a default enum value
            # Since we can't create an AssessmentResult with a string type,
            # we'll use PHQ9 as a fallback and note the issue in severity
            return AssessmentResult(
                id=uuid4(),
                patient_id=patient_id,
                assessment_type=AssessmentType.PHQ9,  # Use a valid enum as fallback
                timestamp=datetime.now(UTC),
                raw_score=0,
                normalized_score=0,
                severity=f"Unknown assessment type: {assessment_type}",
                responses=responses,
            )
            
        # Initialize default values
        raw_score: float = 0.0
        normalized_score: float = 0.0
        severity = "Unknown"
        
        # Calculate scores based on assessment type
        if assessment_enum == AssessmentType.PHQ9:
            # For PHQ-9, sum the scores (0-27 range)
            raw_score = sum(int(score) for score in responses.values())
            normalized_score = min(100.0, raw_score * 3.7)  # Scale to 0-100

            # Determine severity
            if raw_score < 5:
                severity = "Minimal"
            elif raw_score < 10:
                severity = "Mild"
            elif raw_score < 15:
                severity = "Moderate"
            elif raw_score < 20:
                severity = "Moderately Severe"
            else:
                severity = "Severe"

        elif assessment_enum == AssessmentType.GAD7:
            # For GAD-7, sum the scores (0-21 range)
            raw_score = sum(int(score) for score in responses.values())
            normalized_score = min(100.0, raw_score * 4.76)  # Scale to 0-100

            # Determine severity
            if raw_score < 5:
                severity = "Minimal"
            elif raw_score < 10:
                severity = "Mild"
            elif raw_score < 15:
                severity = "Moderate"
            else:
                severity = "Severe"

        elif assessment_enum == AssessmentType.MOOD:
            # For mood, average the scores (1-10 range)
            raw_score = sum(float(score) for score in responses.values()) / len(responses)
            normalized_score = raw_score * 10  # Scale to 0-100

            # Determine severity
            if normalized_score > 70:
                severity = "Good"
            elif normalized_score > 40:
                severity = "Moderate"
            else:
                severity = "Poor"
        # Note: We don't need an else block here as we've already initialized default values

        # Create result
        result = AssessmentResult(
            id=uuid4(),
            patient_id=patient_id,
            assessment_type=assessment_enum,  # Use the enum value, not the string
            timestamp=datetime.now(UTC),
            raw_score=raw_score,
            normalized_score=normalized_score,
            severity=severity,
            responses=responses,
        )

        # Store the result for this patient
        if patient_id not in self._assessments:
            self._assessments[patient_id] = []

        self._assessments[patient_id].append(result)

        return result

    def get_assessment_history(
        self,
        patient_id: UUID,
        assessment_type: str | None = None,
        limit: int = 10,
    ) -> list[AssessmentResult]:
        """
        Get assessment history for a patient.

        Args:
            patient_id: The patient's UUID
            assessment_type: Optional filter by assessment type
            limit: Maximum number of results to return

        Returns:
            List of AssessmentResult objects
        """
        if patient_id not in self._assessments:
            return []

        results = self._assessments[patient_id]

        # Filter by assessment type if specified
        if assessment_type:
            try:
                assessment_enum = AssessmentType(assessment_type)
                results = [r for r in results if r.assessment_type == assessment_enum]
            except ValueError:
                # Return empty list for unknown assessment types
                return []

        # Sort by timestamp (newest first) and limit
        return sorted(results, key=lambda r: r.timestamp, reverse=True)[:limit]

    def get_trend_analysis(
        self,
        patient_id: UUID,
        assessment_type: str,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> dict[str, Any]:
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
        results = self.get_assessment_history(patient_id)
        
        # Convert string to AssessmentType enum
        try:
            assessment_enum = AssessmentType(assessment_type)
            results = [r for r in results if r.assessment_type == assessment_enum]
        except ValueError:
            # Return empty result for unknown assessment types
            return {
                "trend": "invalid_assessment_type",
                "average_score": None,
                "min_score": None,
                "max_score": None,
                "scores_by_date": {},
            }

        # Filter by date range if specified
        if start_date:
            results = [r for r in results if r.timestamp >= start_date]
        if end_date:
            results = [r for r in results if r.timestamp <= end_date]

        if not results:
            return {
                "trend": "insufficient_data",
                "average_score": None,
                "min_score": None,
                "max_score": None,
                "scores_by_date": {},
            }

        # Extract scores
        scores = [r.normalized_score for r in results]
        dates = [r.timestamp for r in results]

        # Calculate trend
        if len(scores) < 2:
            trend = "insufficient_data"
        else:
            # Simple trend calculation
            first_half = scores[: len(scores) // 2]
            second_half = scores[len(scores) // 2 :]
            first_avg = sum(first_half) / len(first_half)
            second_avg = sum(second_half) / len(second_half)

            if second_avg < first_avg * 0.9:
                trend = "improving"  # Lower scores are better
            elif second_avg > first_avg * 1.1:
                trend = "worsening"
            else:
                trend = "stable"

        return {
            "trend": trend,
            "average_score": sum(scores) / len(scores),
            "min_score": min(scores),
            "max_score": max(scores),
            "scores_by_date": {d.isoformat(): s for d, s in zip(dates, scores, strict=False)},
        }

    def generate_random_assessments(
        self,
        patient_id: UUID,
        assessment_type: str,
        count: int = 5,
        days_between: int = 7,
    ) -> list[AssessmentResult]:
        """
        Generate random assessment data for testing.

        Args:
            patient_id: The patient's UUID
            assessment_type: Type of assessment to generate
            count: Number of assessments to generate
            days_between: Days between each assessment

        Returns:
            List of generated AssessmentResult objects
        """
        results = []
        base_date = datetime.now(UTC) - timedelta(days=count * days_between)

        # Convert string to AssessmentType enum once before the loop
        try:
            assessment_enum = AssessmentType(assessment_type)
        except ValueError:
            # Return empty list for unknown assessment types
            return []
        
        for i in range(count):
            timestamp = base_date + timedelta(days=i * days_between)
            
            # Generate random responses based on assessment type
            # Use explicit type annotation to help MyPy understand the type
            responses: dict[str, int | float | str] = {}
            
            if assessment_enum == AssessmentType.PHQ9:
                # Convert to the more general type to satisfy MyPy
                responses = {f"phq{j}": self.rng.randint(0, 3) for j in range(1, 10)}
            elif assessment_enum == AssessmentType.GAD7:
                responses = {f"gad{j}": self.rng.randint(0, 3) for j in range(1, 8)}
            elif assessment_enum == AssessmentType.MOOD:
                responses = {f"mood{j}": self.rng.randint(1, 10) for j in range(1, 3)}

            # Submit the assessment to get a result
            result = self.submit_assessment(
                patient_id=patient_id,
                assessment_type=assessment_type,  # Use the original string parameter
                responses=responses,
            )

            # Override the timestamp
            result.timestamp = timestamp
            results.append(result)

        return results
