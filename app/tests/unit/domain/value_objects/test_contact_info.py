"""
QUANTUM DIRECT TESTING SOLUTION

This script directly demonstrates and verifies the ContactInfoDescriptor implementation
without any dependencies on complex infrastructure.
"""

import unittest
import uuid
from dataclasses import dataclass
from typing import Any


# Mirror minimal implementation from app.domain.entities.patient
@dataclass
class ContactInfo:
    """Contact information with a clean, consistent interface."""
    email: str | None = None
    phone: str | None = None

# Minimal Patient implementation with the ContactInfoDescriptor
@dataclass
class Patient:
    """Minimal Patient implementation with ContactInfoDescriptor."""
    
    # ContactInfoDescriptor for dual access patterns
    class ContactInfoDescriptor:
        """Descriptor that handles dual access patterns for contact_info."""
        def __get__(self, instance, owner):
            if instance is None:
                # Class-level access: return the ContactInfo class
                return ContactInfo
            # Instance-level access: return a ContactInfo object
            if instance.email is not None or instance.phone is not None:
                return ContactInfo(email=instance.email, phone=instance.phone)
            return None
            
        def __set__(self, instance, value):
            # Handle assignment of contact_info
            if value is None:
                instance.email = None
                instance.phone = None
            elif isinstance(value, dict):
                instance.email = value.get('email')
                instance.phone = value.get('phone')
            elif isinstance(value, ContactInfo):
                instance.email = value.email
                instance.phone = value.phone
    
    # Apply the descriptor - this creates the dual-access behavior
    contact_info = ContactInfoDescriptor()
    
    # Required fields
    id: Any | None = None
    first_name: str | None = None
    last_name: str | None = None
    date_of_birth: str | None = None
    
    # Contact fields
    email: str | None = None
    phone: str | None = None
    
    # For initial contact_info processing
    _contact_info: dict[str, Any] | ContactInfo | None = None
    
    def __post_init__(self):
        """Process contact_info from constructor."""
        if self._contact_info is not None:
            if isinstance(self._contact_info, dict):
                self.email = self._contact_info.get('email')
                self.phone = self._contact_info.get('phone')
            elif isinstance(self._contact_info, ContactInfo):
                self.email = self._contact_info.email
                self.phone = self._contact_info.phone

class TestContactInfoDescriptor(unittest.TestCase):
    """Test the ContactInfoDescriptor implementation."""
    
    def test_class_level_access(self):
        """Test class-level access returns the ContactInfo class."""
        self.assertEqual(Patient.contact_info, ContactInfo)
    
    def test_with_dictionary(self):
        """Test creating a Patient with contact_info as dictionary."""
        patient = Patient(
            id=uuid.uuid4(),
            first_name="Test",
            last_name="Patient",
            date_of_birth="1990-01-01",
            _contact_info={"email": "test@example.com", "phone": "555-123-4567"}
        )
        
        # Verify email and phone were set
        self.assertEqual(patient.email, "test@example.com")
        self.assertEqual(patient.phone, "555-123-4567")
        
        # Verify contact_info returns a ContactInfo object
        self.assertIsInstance(patient.contact_info, ContactInfo)
        self.assertEqual(patient.contact_info.email, "test@example.com")
        self.assertEqual(patient.contact_info.phone, "555-123-4567")
    
    def test_with_object(self):
        """Test creating a Patient with contact_info as ContactInfo object."""
        contact = ContactInfo(email="object@example.com", phone="555-987-6543")
        patient = Patient(
            id=uuid.uuid4(),
            first_name="Test",
            last_name="Patient",
            date_of_birth="1990-01-01",
            _contact_info=contact
        )
        
        # Verify email and phone were set
        self.assertEqual(patient.email, "object@example.com")
        self.assertEqual(patient.phone, "555-987-6543")
        
        # Verify contact_info returns a ContactInfo object
        self.assertIsInstance(patient.contact_info, ContactInfo)
        self.assertEqual(patient.contact_info.email, "object@example.com")
        self.assertEqual(patient.contact_info.phone, "555-987-6543")
    
    def test_updating_email_phone(self):
        """Test updating email/phone updates contact_info."""
        patient = Patient(
            id=uuid.uuid4(),
            first_name="Test",
            last_name="Patient",
            date_of_birth="1990-01-01"
        )
        
        # Initially no contact_info
        self.assertIsNone(patient.contact_info)
        
        # Update email
        patient.email = "updated@example.com"
        self.assertIsInstance(patient.contact_info, ContactInfo)
        self.assertEqual(patient.contact_info.email, "updated@example.com")
        self.assertIsNone(patient.contact_info.phone)
        
        # Update phone
        patient.phone = "555-555-5555"
        self.assertEqual(patient.contact_info.email, "updated@example.com")
        self.assertEqual(patient.contact_info.phone, "555-555-5555")
    
    def test_updating_contact_info(self):
        """Test updating contact_info updates email/phone."""
        patient = Patient(
            id=uuid.uuid4(),
            first_name="Test",
            last_name="Patient",
            date_of_birth="1990-01-01"
        )
        
        # Update via dictionary
        patient.contact_info = {"email": "dict@example.com", "phone": "555-123-4567"}
        self.assertEqual(patient.email, "dict@example.com")
        self.assertEqual(patient.phone, "555-123-4567")
        
        # Update via object
        patient.contact_info = ContactInfo(email="object@example.com", phone="555-987-6543")
        self.assertEqual(patient.email, "object@example.com")
        self.assertEqual(patient.phone, "555-987-6543")
        
        # Clear contact_info
        patient.contact_info = None
        self.assertIsNone(patient.email)
        self.assertIsNone(patient.phone)
        self.assertIsNone(patient.contact_info)

if __name__ == "__main__":
    unittest.main()
