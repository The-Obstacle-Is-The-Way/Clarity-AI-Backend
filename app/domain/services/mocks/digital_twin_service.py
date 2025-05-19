"""
Mock Digital Twin service for testing.

This module provides a simplified, synchronous implementation 
of the DigitalTwinService for test purposes.
"""

from app.domain.entities.digital_twin import (
    DigitalTwin,
    NeurotransmitterTwinModel,
    MedicationResponseModel,
)
from app.domain.entities.patient import Patient
from app.domain.entities.medication import Medication


class MockDigitalTwinService:
    """Mock implementation of DigitalTwinService for testing"""

    def __init__(self, repository=None):
        """Initialize with optional mock repository"""
        self.repository = repository

    def generate_digital_twin(self, patient: Patient) -> DigitalTwin:
        """Generate a digital twin for a patient"""
        return DigitalTwin(
            patient_id=patient.id,
            baseline_serotonin=1.0,
            baseline_dopamine=1.0,
            baseline_gaba=1.0,
            baseline_norepinephrine=1.0,
            cortisol_sensitivity=0.5,
            medication_sensitivity=1.0,
            therapy_sensitivity=0.8,
        )

    def predict_medication_response(
        self, digital_twin: DigitalTwin, medication: Medication
    ) -> dict:
        """Predict medication response for a digital twin"""
        # Add a medication_class attribute to the medication instance for compatibility
        if not hasattr(medication, "medication_class"):
            # If medication doesn't have a class attribute, use the first tag
            medication.medication_class = (
                next(iter(medication.tags)) if medication.tags else "SSRI"
            )

        nt_model = NeurotransmitterTwinModel(digital_twin=digital_twin)
        med_model = MedicationResponseModel(neurotransmitter_model=nt_model)
        return med_model.predict_response(medication)
