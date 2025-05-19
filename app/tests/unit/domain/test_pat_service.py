"""
Unit tests for the PAT service.

These tests verify the functionality of the PAT service and its mock implementation.
"""

import pytest
from unittest.mock import MagicMock
from datetime import datetime, timedelta
from uuid import UUID, uuid4

from app.domain.services.mocks.mock_pat_service import MockPATService
from app.domain.entities.assessment import AssessmentType, AssessmentResult
from app.domain.utils.datetime_utils import UTC


@pytest.fixture
def sample_patient_id():
    """Return a sample patient UUID for testing."""
    return UUID("12345678-1234-5678-1234-567812345678")


@pytest.fixture
def pat_service():
    """Return a MockPATService instance with a fixed seed for testing."""
    return MockPATService(seed=42)


class TestMockPATService:
    """Tests for the MockPATService implementation."""

    def test_init(self):
        """Test initializing the mock PAT service."""
        service = MockPATService(seed=42)
        assert service is not None
        assert service.rng is not None

    def test_get_assessment_questions(self, pat_service, sample_patient_id):
        """Test getting assessment questions for various types."""
        # PHQ-9 questions
        phq9_questions = pat_service.get_assessment_questions(
            patient_id=sample_patient_id, assessment_type=AssessmentType.PHQ9
        )
        assert len(phq9_questions) > 0
        assert "text" in phq9_questions[0]
        assert "min_score" in phq9_questions[0]
        assert "max_score" in phq9_questions[0]

        # GAD-7 questions
        gad7_questions = pat_service.get_assessment_questions(
            patient_id=sample_patient_id, assessment_type=AssessmentType.GAD7
        )
        assert len(gad7_questions) > 0

        # Unknown assessment type should return empty list
        unknown_questions = pat_service.get_assessment_questions(
            patient_id=sample_patient_id, assessment_type="UNKNOWN"
        )
        assert len(unknown_questions) == 0

    def test_submit_phq9_assessment(self, pat_service, sample_patient_id):
        """Test submitting a PHQ-9 assessment."""
        # Create responses (0-3 scale for each question)
        responses = {"phq1": 2, "phq2": 1, "phq3": 3, "phq4": 0, "phq5": 2}

        # Submit the assessment
        result = pat_service.submit_assessment(
            patient_id=sample_patient_id,
            assessment_type=AssessmentType.PHQ9,
            responses=responses,
        )

        # Verify the result
        assert result.patient_id == sample_patient_id
        assert result.assessment_type == AssessmentType.PHQ9
        assert result.raw_score == sum(responses.values())
        assert result.normalized_score == min(100, result.raw_score * 3.7)
        assert result.severity in [
            "Minimal",
            "Mild",
            "Moderate",
            "Moderately Severe",
            "Severe",
        ]
        assert result.responses == responses

    def test_submit_gad7_assessment(self, pat_service, sample_patient_id):
        """Test submitting a GAD-7 assessment."""
        # Create responses (0-3 scale for each question)
        responses = {"gad1": 1, "gad2": 2, "gad3": 0, "gad4": 3}

        # Submit the assessment
        result = pat_service.submit_assessment(
            patient_id=sample_patient_id,
            assessment_type=AssessmentType.GAD7,
            responses=responses,
        )

        # Verify the result
        assert result.patient_id == sample_patient_id
        assert result.assessment_type == AssessmentType.GAD7
        assert result.raw_score == sum(responses.values())
        assert result.normalized_score == min(100, result.raw_score * 4.76)
        assert result.severity in ["Minimal", "Mild", "Moderate", "Severe"]
        assert result.responses == responses

    def test_submit_mood_assessment(self, pat_service, sample_patient_id):
        """Test submitting a mood assessment."""
        # Create responses (1-10 scale for each question)
        responses = {"mood1": 7, "mood2": 5}

        # Submit the assessment
        result = pat_service.submit_assessment(
            patient_id=sample_patient_id,
            assessment_type=AssessmentType.MOOD,
            responses=responses,
        )

        # Verify the result
        assert result.patient_id == sample_patient_id
        assert result.assessment_type == AssessmentType.MOOD
        assert result.raw_score == sum(responses.values()) / len(responses)
        assert result.normalized_score == result.raw_score * 10
        assert result.severity in ["Good", "Moderate", "Poor"]
        assert result.responses == responses

    def test_get_assessment_history(self, pat_service, sample_patient_id):
        """Test getting assessment history for a patient."""
        # Submit multiple assessments
        pat_service.submit_assessment(
            patient_id=sample_patient_id,
            assessment_type=AssessmentType.PHQ9,
            responses={"phq1": 2, "phq2": 1},
        )

        pat_service.submit_assessment(
            patient_id=sample_patient_id,
            assessment_type=AssessmentType.GAD7,
            responses={"gad1": 1, "gad2": 2},
        )

        # Get history for all types
        all_history = pat_service.get_assessment_history(sample_patient_id)
        assert len(all_history) == 2

        # Get history for PHQ-9 only
        phq9_history = pat_service.get_assessment_history(
            patient_id=sample_patient_id, assessment_type=AssessmentType.PHQ9
        )
        assert len(phq9_history) == 1
        assert phq9_history[0].assessment_type == AssessmentType.PHQ9

        # Get history for non-existent patient
        empty_history = pat_service.get_assessment_history(
            UUID("00000000-0000-0000-0000-000000000000")
        )
        assert len(empty_history) == 0

    def test_generate_random_assessments(self, pat_service, sample_patient_id):
        """Test generating random assessment data."""
        # Generate 5 random PHQ-9 assessments
        results = pat_service.generate_random_assessments(
            patient_id=sample_patient_id,
            assessment_type=AssessmentType.PHQ9,
            count=5,
            days_between=7,
        )

        # Verify the results
        assert len(results) == 5
        assert all(r.patient_id == sample_patient_id for r in results)
        assert all(r.assessment_type == AssessmentType.PHQ9 for r in results)

        # Verify the timestamps are spaced correctly
        for i in range(1, len(results)):
            day_diff = abs((results[i].timestamp - results[i - 1].timestamp).days)
            assert day_diff == 7

    def test_get_trend_analysis(self, pat_service, sample_patient_id):
        """Test getting trend analysis for a patient."""
        # Generate some assessment data
        pat_service.generate_random_assessments(
            patient_id=sample_patient_id,
            assessment_type=AssessmentType.PHQ9,
            count=5,
            days_between=7,
        )

        # Get trend analysis
        analysis = pat_service.get_trend_analysis(
            patient_id=sample_patient_id, assessment_type=AssessmentType.PHQ9
        )

        # Verify the analysis
        assert "trend" in analysis
        assert analysis["trend"] in [
            "improving",
            "worsening",
            "stable",
            "insufficient_data",
        ]
        assert "average_score" in analysis
        assert "min_score" in analysis
        assert "max_score" in analysis
        assert "scores_by_date" in analysis
        assert len(analysis["scores_by_date"]) == 5

        # Test with date range
        start_date = datetime.now(UTC) - timedelta(days=30)
        end_date = datetime.now(UTC)

        filtered_analysis = pat_service.get_trend_analysis(
            patient_id=sample_patient_id,
            assessment_type=AssessmentType.PHQ9,
            start_date=start_date,
            end_date=end_date,
        )

        assert "trend" in filtered_analysis
