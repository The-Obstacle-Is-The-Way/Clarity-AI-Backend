#!/bin/bash
set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========== PAT SERVICE TEST MIGRATION ==========${NC}"
echo -e "${YELLOW}This script migrates standalone PAT mock tests to proper unit tests${NC}"

# Source and destination files
STANDALONE_TESTS=(
  "app/tests/standalone/core/test_pat_mock.py"
  "app/tests/standalone/core/test_standalone_pat_mock.py"
)
STANDALONE_MOCK="app/tests/standalone/mock_pat_service.py"

UNIT_TEST="app/tests/unit/domain/test_pat_service.py"
UNIT_DIR=$(dirname "$UNIT_TEST")
UNIT_MOCK="app/domain/services/mocks/mock_pat_service.py"
MOCK_DIR=$(dirname "$UNIT_MOCK")

# Create directories if they don't exist
mkdir -p "$UNIT_DIR"
mkdir -p "$MOCK_DIR"

# Create backup of existing unit test if it exists
if [ -f "$UNIT_TEST" ]; then
    BACKUP_FILE="${UNIT_TEST}.backup.$(date +%Y%m%d%H%M%S)"
    echo -e "${YELLOW}Creating backup of existing unit test: ${BACKUP_FILE}${NC}"
    cp "$UNIT_TEST" "$BACKUP_FILE"
fi

# First migrate the mock service to proper location
echo -e "${BLUE}Migrating mock PAT service to: ${UNIT_MOCK}${NC}"

cat > "$UNIT_MOCK" << 'EOF'
"""
Mock PAT service for testing purposes.

This provides a mock implementation of the PAT (Personalized Adaptive Testing)
service for use in testing without depending on the actual external service.
"""

from typing import Dict, List, Optional, Any, Union
import random
from datetime import datetime, timedelta
from uuid import UUID, uuid4

from app.domain.interfaces.pat_service import PATService
from app.domain.entities.assessment import AssessmentResult, AssessmentType
from app.domain.entities.patient import Patient
from app.domain.utils.datetime_utils import UTC


class MockPATService(PATService):
    """
    Mock implementation of the PAT service interface for testing.
    
    This implementation provides predictable responses without
    requiring connection to external services.
    """
    
    def __init__(self, seed: Optional[int] = None):
        """
        Initialize the mock PAT service.
        
        Args:
            seed: Random seed for reproducible results
        """
        self.rng = random.Random(seed)
        self._assessments: Dict[UUID, List[AssessmentResult]] = {}
    
    def get_assessment_questions(self, patient_id: UUID, assessment_type: AssessmentType) -> List[Dict[str, Any]]:
        """
        Get a list of assessment questions for a patient.
        
        Args:
            patient_id: The patient's UUID
            assessment_type: Type of assessment (PHQ9, GAD7, etc.)
            
        Returns:
            List of question dictionaries
        """
        # Mock questions for different assessment types
        questions = {
            AssessmentType.PHQ9: [
                {"id": "phq1", "text": "Little interest or pleasure in doing things?", "min_score": 0, "max_score": 3},
                {"id": "phq2", "text": "Feeling down, depressed, or hopeless?", "min_score": 0, "max_score": 3},
                # ... more questions would be here in real implementation
            ],
            AssessmentType.GAD7: [
                {"id": "gad1", "text": "Feeling nervous, anxious, or on edge?", "min_score": 0, "max_score": 3},
                {"id": "gad2", "text": "Not being able to stop or control worrying?", "min_score": 0, "max_score": 3},
                # ... more questions would be here in real implementation
            ],
            AssessmentType.MOOD: [
                {"id": "mood1", "text": "How would you rate your mood today?", "min_score": 1, "max_score": 10},
                {"id": "mood2", "text": "How would you rate your energy level today?", "min_score": 1, "max_score": 10},
            ]
        }
        
        return questions.get(assessment_type, [])
    
    def submit_assessment(
        self, 
        patient_id: UUID, 
        assessment_type: AssessmentType,
        responses: Dict[str, Union[int, float, str]]
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
        # Calculate scores based on assessment type
        if assessment_type == AssessmentType.PHQ9:
            # For PHQ-9, sum the scores (0-27 range)
            raw_score = sum(int(score) for score in responses.values())
            normalized_score = min(100, raw_score * 3.7)  # Scale to 0-100
            
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
                
        elif assessment_type == AssessmentType.GAD7:
            # For GAD-7, sum the scores (0-21 range)
            raw_score = sum(int(score) for score in responses.values())
            normalized_score = min(100, raw_score * 4.76)  # Scale to 0-100
            
            # Determine severity
            if raw_score < 5:
                severity = "Minimal"
            elif raw_score < 10:
                severity = "Mild"
            elif raw_score < 15:
                severity = "Moderate"
            else:
                severity = "Severe"
                
        elif assessment_type == AssessmentType.MOOD:
            # For mood, average the scores (1-10 range)
            raw_score = sum(int(score) for score in responses.values()) / len(responses)
            normalized_score = raw_score * 10  # Scale to 0-100
            
            # Determine severity
            if normalized_score > 70:
                severity = "Good"
            elif normalized_score > 40:
                severity = "Moderate"
            else:
                severity = "Poor"
        else:
            raw_score = 0
            normalized_score = 0
            severity = "Unknown"
        
        # Create result
        result = AssessmentResult(
            id=uuid4(),
            patient_id=patient_id,
            assessment_type=assessment_type,
            timestamp=datetime.now(UTC),
            raw_score=raw_score,
            normalized_score=normalized_score,
            severity=severity,
            responses=responses
        )
        
        # Store the result for this patient
        if patient_id not in self._assessments:
            self._assessments[patient_id] = []
        
        self._assessments[patient_id].append(result)
        
        return result
    
    def get_assessment_history(
        self, 
        patient_id: UUID, 
        assessment_type: Optional[AssessmentType] = None,
        limit: int = 10
    ) -> List[AssessmentResult]:
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
            results = [r for r in results if r.assessment_type == assessment_type]
            
        # Sort by timestamp (newest first) and limit
        return sorted(results, key=lambda r: r.timestamp, reverse=True)[:limit]
    
    def get_trend_analysis(
        self, 
        patient_id: UUID, 
        assessment_type: AssessmentType,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
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
        results = self.get_assessment_history(patient_id)
        results = [r for r in results if r.assessment_type == assessment_type]
        
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
                "scores_by_date": {}
            }
            
        # Extract scores
        scores = [r.normalized_score for r in results]
        dates = [r.timestamp for r in results]
        
        # Calculate trend
        if len(scores) < 2:
            trend = "insufficient_data"
        else:
            # Simple trend calculation
            first_half = scores[:len(scores)//2]
            second_half = scores[len(scores)//2:]
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
            "scores_by_date": {d.isoformat(): s for d, s in zip(dates, scores)}
        }
    
    def generate_random_assessments(
        self, 
        patient_id: UUID,
        assessment_type: AssessmentType,
        count: int = 5,
        days_between: int = 7
    ) -> List[AssessmentResult]:
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
        
        for i in range(count):
            timestamp = base_date + timedelta(days=i * days_between)
            
            # Generate random responses based on assessment type
            if assessment_type == AssessmentType.PHQ9:
                responses = {f"phq{j}": self.rng.randint(0, 3) for j in range(1, 10)}
            elif assessment_type == AssessmentType.GAD7:
                responses = {f"gad{j}": self.rng.randint(0, 3) for j in range(1, 8)}
            elif assessment_type == AssessmentType.MOOD:
                responses = {f"mood{j}": self.rng.randint(1, 10) for j in range(1, 3)}
            else:
                responses = {}
                
            # Submit the assessment to get a result
            result = self.submit_assessment(
                patient_id=patient_id,
                assessment_type=assessment_type,
                responses=responses
            )
            
            # Override the timestamp
            result.timestamp = timestamp
            results.append(result)
            
        return results
EOF

echo -e "${GREEN}Created mock PAT service at: ${UNIT_MOCK}${NC}"

# Now create the unit test
echo -e "${BLUE}Creating unit test for PAT service: ${UNIT_TEST}${NC}"

cat > "$UNIT_TEST" << 'EOF'
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
            patient_id=sample_patient_id, 
            assessment_type=AssessmentType.PHQ9
        )
        assert len(phq9_questions) > 0
        assert "text" in phq9_questions[0]
        assert "min_score" in phq9_questions[0]
        assert "max_score" in phq9_questions[0]
        
        # GAD-7 questions
        gad7_questions = pat_service.get_assessment_questions(
            patient_id=sample_patient_id, 
            assessment_type=AssessmentType.GAD7
        )
        assert len(gad7_questions) > 0
        
        # Unknown assessment type should return empty list
        unknown_questions = pat_service.get_assessment_questions(
            patient_id=sample_patient_id, 
            assessment_type="UNKNOWN"
        )
        assert len(unknown_questions) == 0
    
    def test_submit_phq9_assessment(self, pat_service, sample_patient_id):
        """Test submitting a PHQ-9 assessment."""
        # Create responses (0-3 scale for each question)
        responses = {
            "phq1": 2,
            "phq2": 1,
            "phq3": 3,
            "phq4": 0,
            "phq5": 2
        }
        
        # Submit the assessment
        result = pat_service.submit_assessment(
            patient_id=sample_patient_id,
            assessment_type=AssessmentType.PHQ9,
            responses=responses
        )
        
        # Verify the result
        assert result.patient_id == sample_patient_id
        assert result.assessment_type == AssessmentType.PHQ9
        assert result.raw_score == sum(responses.values())
        assert result.normalized_score == min(100, result.raw_score * 3.7)
        assert result.severity in ["Minimal", "Mild", "Moderate", "Moderately Severe", "Severe"]
        assert result.responses == responses
    
    def test_submit_gad7_assessment(self, pat_service, sample_patient_id):
        """Test submitting a GAD-7 assessment."""
        # Create responses (0-3 scale for each question)
        responses = {
            "gad1": 1,
            "gad2": 2,
            "gad3": 0,
            "gad4": 3
        }
        
        # Submit the assessment
        result = pat_service.submit_assessment(
            patient_id=sample_patient_id,
            assessment_type=AssessmentType.GAD7,
            responses=responses
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
        responses = {
            "mood1": 7,
            "mood2": 5
        }
        
        # Submit the assessment
        result = pat_service.submit_assessment(
            patient_id=sample_patient_id,
            assessment_type=AssessmentType.MOOD,
            responses=responses
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
            responses={"phq1": 2, "phq2": 1}
        )
        
        pat_service.submit_assessment(
            patient_id=sample_patient_id,
            assessment_type=AssessmentType.GAD7,
            responses={"gad1": 1, "gad2": 2}
        )
        
        # Get history for all types
        all_history = pat_service.get_assessment_history(sample_patient_id)
        assert len(all_history) == 2
        
        # Get history for PHQ-9 only
        phq9_history = pat_service.get_assessment_history(
            patient_id=sample_patient_id,
            assessment_type=AssessmentType.PHQ9
        )
        assert len(phq9_history) == 1
        assert phq9_history[0].assessment_type == AssessmentType.PHQ9
        
        # Get history for non-existent patient
        empty_history = pat_service.get_assessment_history(UUID("00000000-0000-0000-0000-000000000000"))
        assert len(empty_history) == 0
    
    def test_generate_random_assessments(self, pat_service, sample_patient_id):
        """Test generating random assessment data."""
        # Generate 5 random PHQ-9 assessments
        results = pat_service.generate_random_assessments(
            patient_id=sample_patient_id,
            assessment_type=AssessmentType.PHQ9,
            count=5,
            days_between=7
        )
        
        # Verify the results
        assert len(results) == 5
        assert all(r.patient_id == sample_patient_id for r in results)
        assert all(r.assessment_type == AssessmentType.PHQ9 for r in results)
        
        # Verify the timestamps are spaced correctly
        for i in range(1, len(results)):
            day_diff = abs((results[i].timestamp - results[i-1].timestamp).days)
            assert day_diff == 7
    
    def test_get_trend_analysis(self, pat_service, sample_patient_id):
        """Test getting trend analysis for a patient."""
        # Generate some assessment data
        pat_service.generate_random_assessments(
            patient_id=sample_patient_id,
            assessment_type=AssessmentType.PHQ9,
            count=5,
            days_between=7
        )
        
        # Get trend analysis
        analysis = pat_service.get_trend_analysis(
            patient_id=sample_patient_id,
            assessment_type=AssessmentType.PHQ9
        )
        
        # Verify the analysis
        assert "trend" in analysis
        assert analysis["trend"] in ["improving", "worsening", "stable", "insufficient_data"]
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
            end_date=end_date
        )
        
        assert "trend" in filtered_analysis
EOF

echo -e "${GREEN}Created unit test for PAT service at: ${UNIT_TEST}${NC}"

# Run the tests to verify
echo -e "${BLUE}Running tests to verify migration...${NC}"
python -m pytest "$UNIT_TEST" -v || echo -e "${YELLOW}Tests need further adjustments${NC}"

echo -e "\n${BLUE}========== MIGRATION SUMMARY ==========${NC}"
echo -e "${GREEN}✅ Created mock PAT service at: ${UNIT_MOCK}${NC}"
echo -e "${GREEN}✅ Created unit test for PAT service at: ${UNIT_TEST}${NC}"
echo -e "${YELLOW}⚠️ After verification, you can remove the original standalone tests:${NC}"

for test in "${STANDALONE_TESTS[@]}"; do
    echo -e "${RED}rm ${test}${NC}"
done
echo -e "${RED}rm ${STANDALONE_MOCK}${NC}"

echo -e "\n${BLUE}Next steps:${NC}"
echo -e "1. Fix any failing tests in the migrated file"
echo -e "2. Run the tests again to ensure they pass"
echo -e "3. Remove the original standalone tests and mock implementation" 