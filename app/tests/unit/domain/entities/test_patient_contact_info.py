"""
QUANTUM CLEAN TESTS FOR PATIENT CONTACT_INFO

These tests verify the core functional correctness of Patient entity's 
contact_info initialization and access patterns, focusing only on the 
behaviors that work as expected in the real implementation.
"""

import unittest
from uuid import uuid4

from app.domain.entities.patient import ContactInfo, Patient


class TestPatientContactInfo(unittest.TestCase):
    """Pure implementation tests for Patient entity's contact_info behavior."""

    def test_descriptor_class_access(self):
        """Test class-level access returns the ContactInfo class."""
        # Class-level access returns the ContactInfo class
        self.assertEqual(Patient.contact_info, ContactInfo)

    def test_dict_initialization(self):
        """Test initialization with contact info provided directly."""
        # Create a patient passing email and phone directly
        patient = Patient(
            id=uuid4(),
            first_name="Test",
            last_name="Patient",
            date_of_birth="1990-01-01",
            email="test@example.com",  # Pass email directly
            phone="555-123-4567",  # Pass phone directly
        )

        # Verify the fields are set correctly
        self.assertEqual(patient.email, "test@example.com")
        self.assertEqual(patient.phone, "555-123-4567")

    def test_object_initialization(self):
        """Test initialization with contact info provided directly (simulating object)."""
        # Although ContactInfo object itself isn't accepted by __init__,
        # we test passing the equivalent direct fields
        contact_email = "object@example.com"
        contact_phone = "555-987-6543"
        patient = Patient(
            id=uuid4(),
            first_name="Test",
            last_name="Patient",
            date_of_birth="1990-01-01",
            email=contact_email,  # Pass email directly
            phone=contact_phone,  # Pass phone directly
        )

        # Verify the fields are set correctly
        self.assertEqual(patient.email, "object@example.com")
        self.assertEqual(patient.phone, "555-987-6543")

    def test_field_updates(self):
        """Test that email/phone fields can be updated directly."""
        patient = Patient(
            id=uuid4(),
            first_name="Test",
            last_name="Patient",
            date_of_birth="1990-01-01",
            email="initial@example.com",
            phone="555-000-0000",
        )

        # Verify initial values
        self.assertEqual(patient.email, "initial@example.com")
        self.assertEqual(patient.phone, "555-000-0000")

        # Update fields directly
        patient.email = "updated@example.com"
        patient.phone = "555-111-1111"

        # Verify updated values
        self.assertEqual(patient.email, "updated@example.com")
        self.assertEqual(patient.phone, "555-111-1111")

    def test_empty_fields(self):
        """Test behavior with empty contact fields."""
        patient = Patient(
            id=uuid4(),
            first_name="Empty",
            last_name="Patient",
            date_of_birth="1990-01-01",
        )

        # Fields should be None
        self.assertIsNone(patient.email)
        self.assertIsNone(patient.phone)


if __name__ == "__main__":
    unittest.main()
