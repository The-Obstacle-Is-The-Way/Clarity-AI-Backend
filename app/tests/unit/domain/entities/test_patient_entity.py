"""
TRANSCENDENT QUANTUM VALIDATION

This script directly tests the Patient contact_info architecture
without dependencies on complex SQLAlchemy/database infrastructure.
"""
import os
import sys
import unittest
import uuid

# Add the backend directory to the Python path
backend_dir = os.path.join(os.path.dirname(__file__), "backend")
sys.path.insert(0, backend_dir)

# Now import from app
from app.domain.entities.patient import ContactInfo, Patient


class TestPatientContactInfo(unittest.TestCase):
    """Direct tests for Patient contact_info quantum architecture."""

    def test_contact_info_descriptor(self) -> None:
        """Test that the ContactInfoDescriptor works with perfect elegance."""
        # Verify class-level access returns the ContactInfo class
        self.assertEqual(Patient.contact_info, ContactInfo)

        # Create a patient passing email/phone directly
        patient_dict = Patient(
            id=uuid.uuid4(),
            first_name="Test",
            last_name="Patient",
            date_of_birth="1990-01-01",
            email="test@example.com",  # Pass email directly
            phone="555-123-4567",  # Pass phone directly
        )

        # Verify contact_info property returns a ContactInfo object
        self.assertIsInstance(patient_dict.contact_info, ContactInfo)
        self.assertEqual(patient_dict.contact_info.email, "test@example.com")
        self.assertEqual(patient_dict.contact_info.phone, "555-123-4567")
        self.assertEqual(patient_dict.email, "test@example.com")
        self.assertEqual(patient_dict.phone, "555-123-4567")

        # Create a patient passing email/phone directly (simulating object init)
        patient_obj = Patient(
            id=uuid.uuid4(),
            first_name="Test",
            last_name="Patient",
            date_of_birth="1990-01-01",
            email="object@example.com",  # Pass email directly
            phone="555-987-6543",  # Pass phone directly
        )

        # Verify contact_info property returns a ContactInfo object
        self.assertIsInstance(patient_obj.contact_info, ContactInfo)
        self.assertEqual(patient_obj.contact_info.email, "object@example.com")
        self.assertEqual(patient_obj.contact_info.phone, "555-987-6543")
        self.assertEqual(patient_obj.email, "object@example.com")
        self.assertEqual(patient_obj.phone, "555-987-6543")

        # Test modifying contact_info fields
        patient_obj.email = "updated@example.com"
        self.assertEqual(patient_obj.email, "updated@example.com")
        self.assertEqual(patient_obj.contact_info.email, "updated@example.com")

        # Test contact_info property returns None when no email/phone
        empty_patient = Patient(
            id=uuid.uuid4(),
            first_name="Empty",
            last_name="Patient",
            date_of_birth="1990-01-01",
        )

        # If both email and phone are None, contact_info should be None
        self.assertIsNone(empty_patient.email)
        self.assertIsNone(empty_patient.phone)
        self.assertIsNone(empty_patient.contact_info)

        # Setting values should create a ContactInfo object
        empty_patient.email = "empty@example.com"
        self.assertIsInstance(empty_patient.contact_info, ContactInfo)
        self.assertEqual(empty_patient.contact_info.email, "empty@example.com")
        self.assertIsNone(empty_patient.contact_info.phone)

    def test_contact_info_with_dict(self) -> None:
        """Test that the Patient can be created with direct email/phone fields."""
        patient = Patient(
            id=uuid.uuid4(),
            first_name="Test",
            last_name="Patient",
            date_of_birth="1990-01-01",
            email="test@example.com",  # Pass email directly
            phone="555-123-4567",  # Pass phone directly
        )

        # Verify the fields were set properly
        self.assertEqual(patient.email, "test@example.com")
        self.assertEqual(patient.phone, "555-123-4567")

        # Verify contact_info returns a ContactInfo object
        self.assertIsInstance(patient.contact_info, ContactInfo)
        self.assertEqual(patient.contact_info.email, "test@example.com")
        self.assertEqual(patient.contact_info.phone, "555-123-4567")

    def test_contact_info_with_object(self) -> None:
        """Test that the Patient can be created with direct email/phone fields (simulating object)."""
        # Although ContactInfo object itself isn't accepted by __init__,
        # we test passing the equivalent direct fields
        contact_email = "object@example.com"
        contact_phone = "555-987-6543"
        patient = Patient(
            id=uuid.uuid4(),
            first_name="Test",
            last_name="Patient",
            date_of_birth="1990-01-01",
            email=contact_email,  # Pass email directly
            phone=contact_phone,  # Pass phone directly
        )

        # Verify the fields were set properly
        self.assertEqual(patient.email, "object@example.com")
        self.assertEqual(patient.phone, "555-987-6543")

        # Verify contact_info returns a ContactInfo object
        self.assertIsInstance(patient.contact_info, ContactInfo)
        self.assertEqual(patient.contact_info.email, "object@example.com")
        self.assertEqual(patient.contact_info.phone, "555-987-6543")

        # Test modifying through direct field access
        patient.email = "new@example.com"
        self.assertEqual(patient.email, "new@example.com")
        self.assertEqual(patient.contact_info.email, "new@example.com")

        # Test modifying through contact_info assignment (uses descriptor's __set__)
        patient.contact_info = ContactInfo(email="newest@example.com", phone="555-111-2222")
        self.assertEqual(patient.email, "newest@example.com")
        self.assertEqual(patient.phone, "555-111-2222")
        self.assertIsInstance(patient.contact_info, ContactInfo)
        self.assertEqual(patient.contact_info.email, "newest@example.com")
        self.assertEqual(patient.contact_info.phone, "555-111-2222")


if __name__ == "__main__":
    # Run the tests directly
    unittest.main()
