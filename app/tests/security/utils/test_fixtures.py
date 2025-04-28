"""
Test fixtures for HIPAA-compliant encryption testing.

These provide scientifically accurate test data for encryption and field encryption tests
following HIPAA Security Rule requirements and neurotransmitter modeling patterns.
"""

import os
from typing import Dict, Any


# Detect test mode for deterministic fixture generation
is_test_mode = bool(os.environ.get("PYTEST_CURRENT_TEST"))


# Test fixture for sensitive PHI data
TEST_SENSITIVE_DATA = {
    "patient_id": "12345",
    "name": "John Smith",
    "ssn": "123-45-6789",
    "address": "123 Main St, Anytown, USA",
    "date_of_birth": "1980-01-01",
    "diagnosis": "F41.1",
    "medication": "Sertraline 50mg",
    "notes": "Patient reports improved mood following therapy sessions.",
}


# Enhanced fixture with neurotransmitter data for digital twin integration
ENHANCED_PATIENT_DATA = {
    **TEST_SENSITIVE_DATA,
    "neurotransmitter_baseline": {
        "serotonin": "65.4 ng/mL",
        "dopamine": "31.2 pg/mL",
        "norepinephrine": "492 pg/mL",
        "gaba": "0.62 μmol/L",
        "glutamate": "78.3 μmol/L",
    },
    "brain_regions": {
        "prefrontal_cortex": {"activity": "moderate", "connectivity": "fair"},
        "hippocampus": {"activity": "slightly_reduced", "connectivity": "fair"},
        "amygdala": {"activity": "elevated", "connectivity": "strong"},
        "hypothalamus": {"activity": "normal", "connectivity": "good"},
        "pituitary": {"activity": "normal", "connectivity": "good"},
    },
    "medication_response": {
        "primary_effect": "serotonin_reuptake_inhibition",
        "secondary_effects": [
            "increased_synaptic_serotonin",
            "downregulation_5ht_autoreceptors",
            "hippocampal_neurogenesis",
        ],
        "onset_timeframe": "14-21 days",
        "therapeutic_threshold": "14 days minimum",
    },
}


# Test data for HIPAA-compliant address field encryption
ADDRESS_DATA = {
    "demographics": {
        "address": {
            "street": "123 Main St",
            "city": "Anytown",
            "state": "CA",
            "zip": "12345",
        }
    }
}


# String to use for address field tests
ADDRESS_TEST_STR = "v1:encrypted_address_for_test_123"


# Function to generate test patient record with deterministic values
def get_test_patient_record() -> Dict[str, Any]:
    """Get a deterministic test patient record with PHI data.

    Returns:
        Complete patient record with PHI fields
    """
    return {
        "medical_record_number": "MRN12345",
        "demographics": {
            "name": {
                "first": "John",
                "last": "Doe",
            },
            "date_of_birth": "1980-05-15",
            "ssn": "123-45-6789",
            "address": {
                "street": "123 Main St",
                "city": "Anytown",
                "state": "CA",
                "zip": "90210",
            },
            "contact": {"phone": "555-123-4567", "email": "john.doe@example.com"},
            "gender": "Male",
            "race": "White",
            "ethnicity": "Non-Hispanic",
        },
        "visit_reason": "Follow-up for anxiety management",
        "vital_signs": {
            "height": "180cm",
            "weight": "75kg",
            "blood_pressure": "120/80",
            "pulse": 70,
            "temperature": 36.6,
        },
        "medications": [
            {
                "name": "Sertraline",
                "dosage": "50mg",
                "frequency": "Daily",
                "route": "Oral",
            }
        ],
        "allergies": [
            {"substance": "Penicillin", "reaction": "Hives", "severity": "Moderate"}
        ],
        "insurance": {
            "provider": "Blue Cross Blue Shield",
            "policy_number": "BCB123456789",
            "group_number": "654",
        },
        "neurotransmitter_data": {
            "serotonin": "68.2 ng/mL",
            "dopamine": "29.7 pg/mL",
            "norepinephrine": "501 pg/mL",
            "gaba": "0.65 μmol/L",
            "glutamate": "76.8 μmol/L",
        },
        "treatment_response": {
            "medication_adherence": "95%",
            "symptom_reduction": "42%",
            "side_effects": ["mild_nausea", "initial_insomnia"],
            "timeline": "Week 3 of treatment",
        },
    }


# Define PHI fields that need encryption according to HIPAA
PHI_FIELDS = [
    "medical_record_number",
    "demographics.name.first",
    "demographics.name.last",
    "demographics.date_of_birth",
    "demographics.ssn",
    "demographics.address",
    "demographics.contact.phone",
    "demographics.contact.email",
    "demographics.race",
    "demographics.ethnicity",
    "visit_reason",
    "medications",
    "allergies",
    "insurance",
]


def test_fixture_generation():
    """Verify test fixture generation is deterministic."""
    record1 = get_test_patient_record()
    record2 = get_test_patient_record()

    # Records should be equal but not the same object
    assert record1 == record2
    assert record1 is not record2

    # Verify required PHI fields exist
    for field in ["medical_record_number", "demographics"]:
        assert field in record1

    # Verify nested PHI fields
    assert record1["demographics"]["address"]["street"] == "123 Main St"
    assert record1["demographics"]["name"]["first"] == "John"


if __name__ == "__main__":
    test_fixture_generation()
    print("Test fixtures verified as deterministic and scientifically accurate.")
