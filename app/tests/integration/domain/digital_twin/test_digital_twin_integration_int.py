"""
Integration test for the Digital Twin system.
Demonstrates the interaction between all components.
"""
import asyncio
import uuid
from datetime import datetime, timedelta

import pytest

from app.domain.utils.datetime_utils import UTC

# Mark all tests in this module as asyncio tests
pytestmark = pytest.mark.asyncio

# Removed Gender, Diagnosis, Medication
from app.domain.entities.patient import Patient
from app.infrastructure.factories.mock_digital_twin_factory import MockDigitalTwinFactory


@pytest.mark.asyncio()
@pytest.mark.db_required()
async def test_digital_twin_complete_workflow():
    """
    Test a complete Digital Twin workflow from patient creation to treatment recommendations.
    This test demonstrates how all components work together in a typical scenario.
    """
    # Create a complete system using our factory
    system = MockDigitalTwinFactory.create_complete_system()

    # Extract components
    patient_repo = system["repositories"]["patient_repository"]
    digital_twin_repo = system["repositories"]["digital_twin_repository"]
    digital_twin_core = system["services"]["digital_twin_core"]

    # 1. Create a test patient
    patient_id = uuid.uuid4()
    patient = Patient(
        id=patient_id,
        first_name="Jane",
        last_name="Doe",
        date_of_birth=datetime.now() - timedelta(days=365 * 35),  # 35 years old
        gender="female",  # Use string literal
        email="jane.doe@example.com", # Pass email directly
        phone="+1-555-123-4567", # Pass phone directly
        # Use strings for diagnoses as per patient.py entity
        diagnoses=[
            "F32.1: Major depressive disorder, single episode, moderate",
            "F41.1: Generalized anxiety disorder",
        ],
        # Use strings for medications as per patient.py entity
        medications=["Sertraline 50mg daily"],
        allergies=["Penicillin"]
    )
    
    # Save the patient
    saved_patient = await patient_repo.save(patient)
    assert saved_patient.id == patient_id

    # 2. Initialize Digital Twin
    initial_twin_state = await digital_twin_core.initialize_digital_twin(
        patient_id=patient_id,
        include_genetic_data=False,
        include_biomarkers=True
    )

    # Verify the initial state was created
    assert initial_twin_state is not None
    assert initial_twin_state.patient_id == patient_id
    assert "brain_state" in initial_twin_state.data
    assert "neurotransmitter_levels" in initial_twin_state.data["brain_state"]

    # 3. Retrieve the initial state from the repository
    retrieved_state = await digital_twin_repo.get_latest_state(patient_id)
    assert retrieved_state is not None
    assert retrieved_state.id == initial_twin_state.id

    # 4. Simulate a treatment event - adding a medication
    treatment_event = {
        "type": "medication_added",
        "medication": "Escitalopram 10mg daily",
        "date": datetime.now(UTC),
        "prescriber": "Dr. Smith",
        "notes": "Initial prescription for depression and anxiety",
    }

    # Update the digital twin with the treatment event
    updated_twin_state = await digital_twin_core.process_treatment_event(
        patient_id=patient_id, event_data=treatment_event
    )

    # Verify the state was updated
    assert updated_twin_state is not None
    assert updated_twin_state.id != initial_twin_state.id
    assert updated_twin_state.version > initial_twin_state.version
    assert "treatment_history" in updated_twin_state.data
    assert len(updated_twin_state.data["treatment_history"]) > 0

    # 5. Generate treatment recommendations
    recommendations = await digital_twin_core.generate_treatment_recommendations(
        patient_id=patient_id,
        consider_current_medications=True,
        include_therapy_options=True
    )

    # Verify recommendations were generated
    assert recommendations is not None
    assert len(recommendations) > 0
    assert "rationale" in recommendations[0]

    # Check that we have both medication and therapy recommendations based on diagnoses
    has_medication = False
    has_therapy = False

    for rec in recommendations:
        if rec["type"] == "medication":
            has_medication = True
        elif rec["type"] == "therapy":
            has_therapy = True

    assert has_medication
    assert has_therapy

    # 6. Get visualization data for the 3D brain model
    visualization_data = await digital_twin_core.get_visualization_data(
        patient_id=patient_id, visualization_type="brain_model"
    )

    # Verify visualization data was generated
    assert visualization_data["visualization_type"] == "brain_model_3d"
    assert len(visualization_data["brain_regions"]) > 0

    # 7. Compare states to see changes over time
    comparison = await digital_twin_core.compare_states(
        patient_id=patient_id,
        state_id_1=initial_twin_state.id,
        state_id_2=updated_twin_state.id
    )

    # Verify comparison data
    assert comparison["state_1"]["id"] == str(initial_twin_state.id)
    assert comparison["state_2"]["id"] == str(updated_twin_state.id)
    assert "brain_state_changes" in comparison
    assert "new_insights" in comparison
    assert len(comparison["new_insights"]) > 0

    # 8. Generate a comprehensive clinical summary
    summary = await digital_twin_core.generate_clinical_summary(
        patient_id=patient_id, include_treatment_history=True, include_predictions=True
    )

    # Verify summary data
    assert summary["patient"]["id"] == str(patient_id)
    assert summary["patient"]["name"] == "Jane Doe"
    assert "digital_twin_state" in summary
    assert "significant_insights" in summary
    assert "treatment_recommendations" in summary
    assert "treatment_history" in summary
    assert len(summary["treatment_history"]) > 0


if __name__ == "__main__":
    # Run the test directly when the script is executed
    asyncio.run(test_digital_twin_complete_workflow())
    print("Integration test completed successfully!")