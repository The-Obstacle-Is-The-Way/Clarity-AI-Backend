#!/bin/bash
set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========== DIGITAL TWIN TEST MIGRATION ==========${NC}"
echo -e "${YELLOW}This script migrates standalone Digital Twin tests to proper unit tests${NC}"

# Source and destination files
STANDALONE_TESTS=(
  "app/tests/standalone/core/test_digital_twin.py"
  "app/tests/standalone/core/test_standalone_digital_twin.py"
  "app/tests/standalone/core/test_mock_digital_twin.py"
  "app/tests/standalone/domain/test_digital_twin.py"
)

UNIT_TEST="app/tests/unit/domain/test_digital_twin.py"
UNIT_DIR=$(dirname "$UNIT_TEST")

# Create directory if it doesn't exist
mkdir -p "$UNIT_DIR"

# Create backup of existing unit test if it exists
if [ -f "$UNIT_TEST" ]; then
    BACKUP_FILE="${UNIT_TEST}.backup.$(date +%Y%m%d%H%M%S)"
    echo -e "${YELLOW}Creating backup of existing unit test: ${BACKUP_FILE}${NC}"
    cp "$UNIT_TEST" "$BACKUP_FILE"
fi

# Create the migrated test file
echo -e "${BLUE}Creating migrated test file: ${UNIT_TEST}${NC}"

cat > "$UNIT_TEST" << 'EOF'
"""
Unit tests for the Digital Twin models and services.

These tests use the actual implementations from the domain layer.
"""

import pytest
from unittest.mock import MagicMock, patch
import numpy as np
from datetime import datetime, timedelta

# Import the actual implementations
from app.domain.entities.digital_twin import (
    DigitalTwin, 
    NeurotransmitterTwinModel, 
    MentalStateModel,
    MedicationResponseModel
)
from app.domain.services.digital_twin_service import DigitalTwinService
from app.domain.services.medication_service import MedicationService
from app.domain.entities.patient import Patient
from app.domain.entities.medication import Medication
from app.domain.exceptions.base_exceptions import ValidationError
from app.domain.utils.datetime_utils import UTC


@pytest.fixture
def sample_patient():
    """Create a sample patient for testing."""
    return Patient(
        id="12345678-1234-5678-1234-567812345678",
        first_name="Test",
        last_name="Patient",
        date_of_birth=datetime(1990, 1, 1),
        gender="female",
        email="test@example.com"
    )


@pytest.fixture
def sample_medication():
    """Create a sample medication for testing."""
    return Medication(
        id="87654321-8765-4321-8765-432187654321",
        name="Prozac",
        generic_name="Fluoxetine",
        medication_class="SSRI",
        dosage=20,
        dosage_unit="mg",
        frequency=1,
        frequency_unit="daily"
    )


@pytest.fixture
def digital_twin(sample_patient):
    """Create a digital twin instance for testing."""
    return DigitalTwin(
        patient_id=sample_patient.id,
        baseline_serotonin=1.0,
        baseline_dopamine=1.0,
        baseline_gaba=1.0,
        baseline_norepinephrine=1.0,
        cortisol_sensitivity=0.5,
        medication_sensitivity=1.0,
        therapy_sensitivity=0.8
    )


class TestDigitalTwin:
    """Tests for the DigitalTwin entity."""
    
    def test_init(self, sample_patient):
        """Test that a digital twin can be initialized with valid parameters."""
        twin = DigitalTwin(
            patient_id=sample_patient.id,
            baseline_serotonin=1.0,
            baseline_dopamine=1.0,
            baseline_gaba=1.0,
            baseline_norepinephrine=1.0,
            cortisol_sensitivity=0.5,
            medication_sensitivity=1.0,
            therapy_sensitivity=0.8
        )
        
        assert twin.patient_id == sample_patient.id
        assert twin.baseline_serotonin == 1.0
        assert twin.baseline_dopamine == 1.0
        assert twin.baseline_gaba == 1.0
        assert twin.baseline_norepinephrine == 1.0
        assert twin.cortisol_sensitivity == 0.5
        assert twin.medication_sensitivity == 1.0
        assert twin.therapy_sensitivity == 0.8
    
    def test_invalid_parameters(self, sample_patient):
        """Test that initialization fails with invalid parameters."""
        with pytest.raises(ValidationError):
            DigitalTwin(
                patient_id=sample_patient.id,
                baseline_serotonin=-1.0,  # Negative value not allowed
                baseline_dopamine=1.0,
                baseline_gaba=1.0,
                baseline_norepinephrine=1.0,
                cortisol_sensitivity=0.5,
                medication_sensitivity=1.0,
                therapy_sensitivity=0.8
            )


class TestNeurotransmitterTwinModel:
    """Tests for the NeurotransmitterTwinModel."""
    
    def test_init(self, digital_twin):
        """Test initializing the neurotransmitter model."""
        model = NeurotransmitterTwinModel(digital_twin=digital_twin)
        
        assert model.digital_twin == digital_twin
        assert model.current_serotonin == digital_twin.baseline_serotonin
        assert model.current_dopamine == digital_twin.baseline_dopamine
        assert model.current_gaba == digital_twin.baseline_gaba
        assert model.current_norepinephrine == digital_twin.baseline_norepinephrine
    
    def test_simulate_medication_effect(self, digital_twin, sample_medication):
        """Test simulating medication effects on neurotransmitters."""
        model = NeurotransmitterTwinModel(digital_twin=digital_twin)
        
        # Test SSRI effect (increases serotonin)
        initial_serotonin = model.current_serotonin
        model.simulate_medication_effect(sample_medication, days=7)
        
        # SSRI should increase serotonin
        assert model.current_serotonin > initial_serotonin
        
        # Test with a different medication class
        model.reset_to_baseline()
        sample_medication.medication_class = "SNRI"
        initial_serotonin = model.current_serotonin
        initial_norepinephrine = model.current_norepinephrine
        
        model.simulate_medication_effect(sample_medication, days=7)
        
        # SNRI should increase both serotonin and norepinephrine
        assert model.current_serotonin > initial_serotonin
        assert model.current_norepinephrine > initial_norepinephrine
    
    def test_simulate_stress(self, digital_twin):
        """Test simulating stress effects on neurotransmitters."""
        model = NeurotransmitterTwinModel(digital_twin=digital_twin)
        
        initial_serotonin = model.current_serotonin
        initial_dopamine = model.current_dopamine
        
        # Simulate high stress
        model.simulate_stress(stress_level=0.8, days=3)
        
        # High stress should decrease serotonin and dopamine
        assert model.current_serotonin < initial_serotonin
        assert model.current_dopamine < initial_dopamine
    
    def test_reset_to_baseline(self, digital_twin):
        """Test resetting neurotransmitters to baseline levels."""
        model = NeurotransmitterTwinModel(digital_twin=digital_twin)
        
        # Change some values
        model.current_serotonin = 2.0
        model.current_dopamine = 0.5
        
        # Reset
        model.reset_to_baseline()
        
        # Should be back to baseline
        assert model.current_serotonin == digital_twin.baseline_serotonin
        assert model.current_dopamine == digital_twin.baseline_dopamine


class TestMentalStateModel:
    """Tests for the MentalStateModel."""
    
    def test_init(self, digital_twin):
        """Test initializing the mental state model."""
        neurotransmitter_model = NeurotransmitterTwinModel(digital_twin=digital_twin)
        model = MentalStateModel(neurotransmitter_model=neurotransmitter_model)
        
        assert model.neurotransmitter_model == neurotransmitter_model
        assert 0 <= model.depression_score <= 100
        assert 0 <= model.anxiety_score <= 100
    
    def test_calculate_depression_score(self, digital_twin):
        """Test calculating depression score from neurotransmitter levels."""
        neurotransmitter_model = NeurotransmitterTwinModel(digital_twin=digital_twin)
        model = MentalStateModel(neurotransmitter_model=neurotransmitter_model)
        
        # Normal baseline should have moderate depression score
        baseline_score = model.depression_score
        
        # Lower serotonin and dopamine should increase depression
        neurotransmitter_model.current_serotonin *= 0.5
        neurotransmitter_model.current_dopamine *= 0.5
        model.update_scores()
        
        assert model.depression_score > baseline_score
    
    def test_calculate_anxiety_score(self, digital_twin):
        """Test calculating anxiety score from neurotransmitter levels."""
        neurotransmitter_model = NeurotransmitterTwinModel(digital_twin=digital_twin)
        model = MentalStateModel(neurotransmitter_model=neurotransmitter_model)
        
        # Normal baseline should have moderate anxiety score
        baseline_score = model.anxiety_score
        
        # Lower GABA should increase anxiety
        neurotransmitter_model.current_gaba *= 0.5
        # Higher norepinephrine should increase anxiety
        neurotransmitter_model.current_norepinephrine *= 1.5
        
        model.update_scores()
        
        assert model.anxiety_score > baseline_score


class TestMedicationResponseModel:
    """Tests for the MedicationResponseModel."""
    
    def test_init(self, digital_twin, sample_medication):
        """Test initializing the medication response model."""
        neurotransmitter_model = NeurotransmitterTwinModel(digital_twin=digital_twin)
        model = MedicationResponseModel(
            neurotransmitter_model=neurotransmitter_model,
            medication=sample_medication
        )
        
        assert model.neurotransmitter_model == neurotransmitter_model
        assert model.medication == sample_medication
    
    def test_predict_response(self, digital_twin, sample_medication):
        """Test predicting response to medication over time."""
        neurotransmitter_model = NeurotransmitterTwinModel(digital_twin=digital_twin)
        model = MedicationResponseModel(
            neurotransmitter_model=neurotransmitter_model,
            medication=sample_medication
        )
        
        # For SSRI, we expect improvement in depression scores over time
        response = model.predict_response(weeks=8)
        
        # Check that depression score decreases over time
        assert response["depression_scores"][0] > response["depression_scores"][-1]
        
        # Check timeline is correct length
        assert len(response["timeline"]) == 8  # 8 weeks
        assert len(response["depression_scores"]) == 8
        assert len(response["anxiety_scores"]) == 8
        
        # First date should be current date
        today = datetime.now(UTC).date()
        assert response["timeline"][0] == today


class TestDigitalTwinService:
    """Tests for the DigitalTwinService."""
    
    @pytest.fixture
    def twin_service(self):
        """Create a digital twin service with mocked repository."""
        mock_repo = MagicMock()
        return DigitalTwinService(repository=mock_repo)
    
    def test_generate_digital_twin(self, twin_service, sample_patient):
        """Test generating a digital twin for a patient."""
        # Mock the save method to return the twin
        twin_service.repository.save.side_effect = lambda x: x
        
        twin = twin_service.generate_digital_twin(
            patient=sample_patient,
            questionnaire_results={"neuroticism": 0.7, "extraversion": 0.5}
        )
        
        assert twin.patient_id == sample_patient.id
        assert 0.5 <= twin.baseline_serotonin <= 1.5
        assert 0.5 <= twin.baseline_dopamine <= 1.5
        
        # Verify the repository was called
        twin_service.repository.save.assert_called_once()
    
    def test_predict_medication_response(self, twin_service, digital_twin, sample_medication):
        """Test predicting medication response for a patient."""
        # Mock the repository to return our test twin
        twin_service.repository.get_by_patient_id.return_value = digital_twin
        
        response = twin_service.predict_medication_response(
            patient_id=digital_twin.patient_id,
            medication=sample_medication,
            weeks=6
        )
        
        # Check that we get a valid response
        assert "timeline" in response
        assert "depression_scores" in response
        assert "anxiety_scores" in response
        assert len(response["timeline"]) == 6  # 6 weeks
        
        # Verify the repository was called
        twin_service.repository.get_by_patient_id.assert_called_once_with(digital_twin.patient_id)
EOF

echo -e "${GREEN}Created migrated test file: ${UNIT_TEST}${NC}"

# Run the tests to verify
echo -e "${BLUE}Running tests to verify migration...${NC}"
python -m pytest "$UNIT_TEST" -v || echo -e "${YELLOW}Tests need further adjustments${NC}"

echo -e "\n${BLUE}========== MIGRATION SUMMARY ==========${NC}"
echo -e "${GREEN}✅ Created migrated test file at ${UNIT_TEST}${NC}"
echo -e "${YELLOW}⚠️ After verification, you can remove the original standalone tests:${NC}"

for test in "${STANDALONE_TESTS[@]}"; do
    echo -e "${RED}rm ${test}${NC}"
done

echo -e "\n${BLUE}Next steps:${NC}"
echo -e "1. Fix any failing tests in the migrated file"
echo -e "2. Run the tests again to ensure they pass"
echo -e "3. Remove the original standalone tests" 