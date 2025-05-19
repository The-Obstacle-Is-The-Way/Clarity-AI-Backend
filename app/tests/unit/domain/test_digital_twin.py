"""
Unit tests for the Digital Twin models and services.

These tests use the actual implementations from the domain layer.
"""

from datetime import datetime
from unittest.mock import MagicMock

import pytest

# Import the actual implementations
from app.domain.entities.digital_twin import (
    DigitalTwin,
    MedicationResponseModel,
    MentalStateModel,
    NeurotransmitterTwinModel,
)
from app.domain.entities.medication import DosageSchedule, Medication
from app.domain.entities.patient import Patient
from app.domain.exceptions.base_exceptions import ValidationError
from app.domain.services.mocks.digital_twin_service import MockDigitalTwinService
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
        email="test@example.com",
    )


@pytest.fixture
def sample_medication(sample_patient):
    """Create a sample medication for testing."""
    # Create a dosage schedule
    dosage = DosageSchedule(amount="20mg", frequency="once daily", timing="morning")

    # Create a UUID for the provider
    provider_id = "98765432-9876-5432-9876-543298765432"

    # Create the medication with the actual Medication class
    medication = Medication(
        id="87654321-8765-4321-8765-432187654321",
        name="Prozac",
        patient_id=sample_patient.id,
        provider_id=provider_id,
        dosage_schedule=dosage,
        start_date=datetime.now(UTC),
        reason_prescribed="Depression",
        tags={"SSRI"},  # We'll use tags to store the medication class
    )

    # Add medication_class attribute for test compatibility
    medication.medication_class = "SSRI"

    return medication


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
        therapy_sensitivity=0.8,
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
            therapy_sensitivity=0.8,
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
                therapy_sensitivity=0.8,
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

        # Depression score should increase with lower serotonin/dopamine
        assert model.depression_score > baseline_score

    def test_calculate_anxiety_score(self, digital_twin):
        """Test calculating anxiety score from neurotransmitter levels."""
        neurotransmitter_model = NeurotransmitterTwinModel(digital_twin=digital_twin)
        model = MentalStateModel(neurotransmitter_model=neurotransmitter_model)

        # Normal baseline should have moderate anxiety score
        baseline_score = model.anxiety_score

        # Lower GABA and higher norepinephrine should increase anxiety
        neurotransmitter_model.current_gaba *= 0.5
        neurotransmitter_model.current_norepinephrine *= 1.5
        model.update_scores()

        # Anxiety score should increase
        assert model.anxiety_score > baseline_score


class TestMedicationResponseModel:
    """Tests for the MedicationResponseModel."""

    def test_init(self, digital_twin, sample_medication):
        """Test initializing the medication response model."""
        neurotransmitter_model = NeurotransmitterTwinModel(digital_twin=digital_twin)
        model = MedicationResponseModel(neurotransmitter_model=neurotransmitter_model)

        assert model.neurotransmitter_model == neurotransmitter_model

    def test_predict_response(self, digital_twin, sample_medication):
        """Test predicting medication response."""
        neurotransmitter_model = NeurotransmitterTwinModel(digital_twin=digital_twin)
        model = MedicationResponseModel(neurotransmitter_model=neurotransmitter_model)

        # Predict response to SSRI
        response = model.predict_response(sample_medication)

        # Check that we get expected prediction metrics
        assert "depression_improvement" in response
        assert "anxiety_improvement" in response
        assert "side_effect_risk" in response
        assert "overall_benefit" in response

        # SSRI should have better depression improvement than anxiety
        assert response["depression_improvement"] > 0


class TestDigitalTwinService:
    """Tests for the DigitalTwinService."""

    @pytest.fixture
    def twin_service(self):
        """Create a twin service for testing."""
        mock_repo = MagicMock()
        return MockDigitalTwinService(repository=mock_repo)

    def test_generate_digital_twin(self, twin_service, sample_patient):
        """Test generating a digital twin for a patient."""
        digital_twin = twin_service.generate_digital_twin(sample_patient)

        assert digital_twin.patient_id == sample_patient.id
        assert digital_twin.baseline_serotonin == 1.0
        assert digital_twin.baseline_dopamine == 1.0
        assert digital_twin.baseline_gaba == 1.0
        assert digital_twin.baseline_norepinephrine == 1.0
        assert digital_twin.cortisol_sensitivity == 0.5
        assert digital_twin.medication_sensitivity == 1.0
        assert digital_twin.therapy_sensitivity == 0.8

    def test_predict_medication_response(self, twin_service, digital_twin, sample_medication):
        """Test predicting medication response."""
        response = twin_service.predict_medication_response(digital_twin, sample_medication)

        # Check that we get expected prediction metrics
        assert "depression_improvement" in response
        assert "anxiety_improvement" in response
        assert "side_effect_risk" in response
        assert "overall_benefit" in response
