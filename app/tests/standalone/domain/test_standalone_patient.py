"""
Self-contained test for Patient entity.

This module contains both the patient entity implementation and tests in a single file,
making it completely independent of the rest of the application.
"""

import unittest
from datetime import date
from enum import Enum
from typing import Any
from uuid import uuid4

# ============= Patient Entity Implementation =============

class Gender(str, Enum):
    """Gender enumeration."""
    MALE = "male"
    FEMALE = "female"
    NON_BINARY = "non_binary"
    OTHER = "other"
    PREFER_NOT_TO_SAY = "prefer_not_to_say"


class InsuranceStatus(str, Enum):
    """Insurance status enumeration."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    PENDING = "pending"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


class PatientStatus(str, Enum):
    """Patient status enumeration."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    ONBOARDING = "onboarding"
    DISCHARGED = "discharged"
    TERMINATED = "terminated"


class EmergencyContact:
    """Emergency contact information."""

    def __init__(
        self,
        name: str,
        relationship: str,
        phone: str,
        email: str | None = None
    ):
        self.name = name
        self.relationship = relationship
        self.phone = phone
        self.email = email

        # Validation
        if not name or not name.strip():
            raise ValueError("Emergency contact name cannot be empty")
        if not relationship or not relationship.strip():
            raise ValueError("Emergency contact relationship cannot be empty")
        if not phone or not phone.strip():
            raise ValueError("Emergency contact phone cannot be empty")

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "relationship": self.relationship,
            "phone": self.phone,
            "email": self.email
        }


class Insurance:
    """Insurance information."""

    def __init__(
        self,
        provider: str,
        policy_number: str,
        group_number: str | None = None,
        status: InsuranceStatus = InsuranceStatus.ACTIVE
    ):
        self.provider = provider
        self.policy_number = policy_number
        self.group_number = group_number
        self.status = status

        # Validation
        if not provider or not provider.strip():
            raise ValueError("Insurance provider cannot be empty")
        if not policy_number or not policy_number.strip():
            raise ValueError("Insurance policy number cannot be empty")

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "provider": self.provider,
            "policy_number": self.policy_number,
            "group_number": self.group_number,
            "status": self.status
        }

    def update_status(self, status: InsuranceStatus | str):
        """Update insurance status."""
        if isinstance(status, str):
            status = InsuranceStatus(status)
        self.status = status


class Patient:
    """Patient entity."""

    def __init__(
        self,
        first_name: str,
        last_name: str,
        date_of_birth: date,
        gender: Gender | str,
        email: str | None = None,
        phone: str | None = None,
        address: str | None = None,
        status: PatientStatus | str = PatientStatus.ACTIVE,
        emergency_contacts: list[EmergencyContact] | None = None,
        insurance: Insurance | None = None,
        medical_record_number: str | None = None,
        notes: str | None = None
    ):
        self.id = uuid4()
        self.first_name = first_name
        self.last_name = last_name
        self.date_of_birth = date_of_birth
        
        # Convert string to enum if needed
        if isinstance(gender, str):
            gender = Gender(gender)
        self.gender = gender
        
        self.email = email
        self.phone = phone
        self.address = address
        
        # Convert string to enum if needed
        if isinstance(status, str):
            status = PatientStatus(status)
        self.status = status
        
        self.emergency_contacts = emergency_contacts or []
        self.insurance = insurance
        self.medical_record_number = medical_record_number or f"MRN-{self.id.hex[:8].upper()}"
        self.notes = notes

        # Validation
        self._validate()

    def _validate(self):
        """Validate patient data."""
        if not self.first_name or not self.first_name.strip():
            raise ValueError("First name cannot be empty")
        if not self.last_name or not self.last_name.strip():
            raise ValueError("Last name cannot be empty")
        if not self.date_of_birth:
            raise ValueError("Date of birth cannot be empty")
        if self.date_of_birth > date.today():
            raise ValueError("Date of birth cannot be in the future")
        
        # At least one contact method is required
        if not self.email and not self.phone and not self.address:
            raise ValueError("At least one contact method (email, phone, or address) is required")

    def add_emergency_contact(
        self,
        name: str,
        relationship: str,
        phone: str,
        email: str | None = None
    ) -> EmergencyContact:
        """Add an emergency contact."""
        contact = EmergencyContact(name, relationship, phone, email)
        self.emergency_contacts.append(contact)
        return contact

    def set_insurance(
        self,
        provider: str,
        policy_number: str,
        group_number: str | None = None,
        status: InsuranceStatus = InsuranceStatus.ACTIVE
    ) -> Insurance:
        """Set insurance information."""
        self.insurance = Insurance(provider, policy_number, group_number, status)
        return self.insurance

    def update_status(self, status: PatientStatus | str):
        """Update patient status."""
        if isinstance(status, str):
            status = PatientStatus(status)
        self.status = status

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        result = {
            "id": str(self.id),
            "first_name": self.first_name,
            "last_name": self.last_name,
            "date_of_birth": self.date_of_birth.isoformat(),
            "gender": self.gender,
            "email": self.email,
            "phone": self.phone,
            "address": self.address,
            "status": self.status,
            "medical_record_number": self.medical_record_number,
            "notes": self.notes,
            "emergency_contacts": [contact.to_dict() for contact in self.emergency_contacts],
        }
        
        if self.insurance:
            result["insurance"] = self.insurance.to_dict()
        else:
            result["insurance"] = None
            
        return result


# ============= Patient Entity Tests =============

class TestEmergencyContact(unittest.TestCase):
    """Tests for the EmergencyContact class."""
    
    def test_create_emergency_contact(self):
        """Test creating an emergency contact."""
        contact = EmergencyContact(
            name="Jane Doe",
            relationship="Spouse",
            phone="555-123-4567",
            email="jane.doe@example.com"
        )
        
        self.assertEqual(contact.name, "Jane Doe")
        self.assertEqual(contact.relationship, "Spouse")
        self.assertEqual(contact.phone, "555-123-4567")
        self.assertEqual(contact.email, "jane.doe@example.com")
    
    def test_contact_validation(self):
        """Test validation when creating an emergency contact."""
        # Empty name
        with self.assertRaises(ValueError):
            EmergencyContact(
                name="",
                relationship="Spouse",
                phone="555-123-4567"
            )
        
        # Empty relationship
        with self.assertRaises(ValueError):
            EmergencyContact(
                name="Jane Doe",
                relationship="",
                phone="555-123-4567"
            )
        
        # Empty phone
        with self.assertRaises(ValueError):
            EmergencyContact(
                name="Jane Doe",
                relationship="Spouse",
                phone=""
            )
    
    def test_to_dict(self):
        """Test converting an emergency contact to a dictionary."""
        contact = EmergencyContact(
            name="Jane Doe",
            relationship="Spouse",
            phone="555-123-4567",
            email="jane.doe@example.com"
        )
        
        data = contact.to_dict()
        
        self.assertEqual(data["name"], "Jane Doe")
        self.assertEqual(data["relationship"], "Spouse")
        self.assertEqual(data["phone"], "555-123-4567")
        self.assertEqual(data["email"], "jane.doe@example.com")


class TestInsurance(unittest.TestCase):
    """Tests for the Insurance class."""
    
    def test_create_insurance(self):
        """Test creating insurance information."""
        insurance = Insurance(
            provider="Blue Cross",
            policy_number="BC123456789",
            group_number="G987654321",
            status=InsuranceStatus.ACTIVE
        )
        
        self.assertEqual(insurance.provider, "Blue Cross")
        self.assertEqual(insurance.policy_number, "BC123456789")
        self.assertEqual(insurance.group_number, "G987654321")
        self.assertEqual(insurance.status, InsuranceStatus.ACTIVE)
    
    def test_insurance_validation(self):
        """Test validation when creating insurance information."""
        # Empty provider
        with self.assertRaises(ValueError):
            Insurance(
                provider="",
                policy_number="BC123456789"
            )
        
        # Empty policy number
        with self.assertRaises(ValueError):
            Insurance(
                provider="Blue Cross",
                policy_number=""
            )
    
    def test_update_status(self):
        """Test updating insurance status."""
        insurance = Insurance(
            provider="Blue Cross",
            policy_number="BC123456789"
        )
        
        self.assertEqual(insurance.status, InsuranceStatus.ACTIVE)
        
        insurance.update_status(InsuranceStatus.EXPIRED)
        self.assertEqual(insurance.status, InsuranceStatus.EXPIRED)
        
        insurance.update_status("pending")
        self.assertEqual(insurance.status, InsuranceStatus.PENDING)
    
    def test_to_dict(self):
        """Test converting insurance information to a dictionary."""
        insurance = Insurance(
            provider="Blue Cross",
            policy_number="BC123456789",
            group_number="G987654321",
            status=InsuranceStatus.ACTIVE
        )
        
        data = insurance.to_dict()
        
        self.assertEqual(data["provider"], "Blue Cross")
        self.assertEqual(data["policy_number"], "BC123456789")
        self.assertEqual(data["group_number"], "G987654321")
        self.assertEqual(data["status"], InsuranceStatus.ACTIVE)


class TestPatient(unittest.TestCase):
    """Tests for the Patient class."""
    
    def test_create_patient(self):
        """Test creating a patient."""
        patient = Patient(
            first_name="John",
            last_name="Doe",
            date_of_birth=date(1980, 1, 15),
            gender=Gender.MALE,
            email="john.doe@example.com",
            phone="555-123-4567",
            address="123 Main St, Anytown, USA"
        )
        
        self.assertEqual(patient.first_name, "John")
        self.assertEqual(patient.last_name, "Doe")
        self.assertEqual(patient.date_of_birth, date(1980, 1, 15))
        self.assertEqual(patient.gender, Gender.MALE)
        self.assertEqual(patient.email, "john.doe@example.com")
        self.assertEqual(patient.phone, "555-123-4567")
        self.assertEqual(patient.address, "123 Main St, Anytown, USA")
        self.assertEqual(patient.status, PatientStatus.ACTIVE)
        self.assertEqual(len(patient.emergency_contacts), 0)
        self.assertIsNone(patient.insurance)
        self.assertTrue(patient.medical_record_number.startswith("MRN-"))
    
    def test_patient_validation(self):
        """Test validation when creating a patient."""
        # Empty first name
        with self.assertRaises(ValueError):
            Patient(
                first_name="",
                last_name="Doe",
                date_of_birth=date(1980, 1, 15),
                gender=Gender.MALE,
                email="john.doe@example.com"
            )
        
        # Empty last name
        with self.assertRaises(ValueError):
            Patient(
                first_name="John",
                last_name="",
                date_of_birth=date(1980, 1, 15),
                gender=Gender.MALE,
                email="john.doe@example.com"
            )
        
        # Future date of birth
        future_date = date.today().replace(year=date.today().year + 1)
        with self.assertRaises(ValueError):
            Patient(
                first_name="John",
                last_name="Doe",
                date_of_birth=future_date,
                gender=Gender.MALE,
                email="john.doe@example.com"
            )
        
        # No contact information
        with self.assertRaises(ValueError):
            Patient(
                first_name="John",
                last_name="Doe",
                date_of_birth=date(1980, 1, 15),
                gender=Gender.MALE
            )
    
    def test_string_gender(self):
        """Test creating a patient with string gender."""
        patient = Patient(
            first_name="John",
            last_name="Doe",
            date_of_birth=date(1980, 1, 15),
            gender="male",
            email="john.doe@example.com"
        )
        
        self.assertEqual(patient.gender, Gender.MALE)
    
    def test_string_status(self):
        """Test creating a patient with string status."""
        patient = Patient(
            first_name="John",
            last_name="Doe",
            date_of_birth=date(1980, 1, 15),
            gender=Gender.MALE,
            email="john.doe@example.com",
            status="onboarding"
        )
        
        self.assertEqual(patient.status, PatientStatus.ONBOARDING)
    
    def test_add_emergency_contact(self):
        """Test adding an emergency contact."""
        patient = Patient(
            first_name="John",
            last_name="Doe",
            date_of_birth=date(1980, 1, 15),
            gender=Gender.MALE,
            email="john.doe@example.com"
        )
        
        self.assertEqual(len(patient.emergency_contacts), 0)
        
        contact = patient.add_emergency_contact(
            name="Jane Doe",
            relationship="Spouse",
            phone="555-123-4567",
            email="jane.doe@example.com"
        )
        
        self.assertEqual(len(patient.emergency_contacts), 1)
        self.assertEqual(patient.emergency_contacts[0].name, "Jane Doe")
        self.assertEqual(contact.name, "Jane Doe")
    
    def test_set_insurance(self):
        """Test setting insurance information."""
        patient = Patient(
            first_name="John",
            last_name="Doe",
            date_of_birth=date(1980, 1, 15),
            gender=Gender.MALE,
            email="john.doe@example.com"
        )
        
        self.assertIsNone(patient.insurance)
        
        insurance = patient.set_insurance(
            provider="Blue Cross",
            policy_number="BC123456789",
            group_number="G987654321"
        )
        
        self.assertIsNotNone(patient.insurance)
        self.assertEqual(patient.insurance.provider, "Blue Cross")
        self.assertEqual(insurance.provider, "Blue Cross")
    
    def test_update_status(self):
        """Test updating patient status."""
        patient = Patient(
            first_name="John",
            last_name="Doe",
            date_of_birth=date(1980, 1, 15),
            gender=Gender.MALE,
            email="john.doe@example.com"
        )
        
        self.assertEqual(patient.status, PatientStatus.ACTIVE)
        
        patient.update_status(PatientStatus.DISCHARGED)
        self.assertEqual(patient.status, PatientStatus.DISCHARGED)
        
        patient.update_status("inactive")
        self.assertEqual(patient.status, PatientStatus.INACTIVE)

    def test_to_dict(self):
        """Test converting patient to dictionary."""
        patient = Patient(
            first_name="John",
            last_name="Doe",
            date_of_birth=date(1980, 1, 15),
            gender=Gender.MALE,
            email="john.doe@example.com",
            phone="555-123-4567",
            address="123 Main St, Anytown, USA"
        )
        
        patient.add_emergency_contact(
            name="Jane Doe",
            relationship="Spouse",
            phone="555-123-4567",
            email="jane.doe@example.com"
        )
        
        patient.set_insurance(
            provider="Blue Cross",
            policy_number="BC123456789",
            group_number="G987654321"
        )
        
        data = patient.to_dict()
        
        self.assertEqual(data["first_name"], "John")
        self.assertEqual(data["last_name"], "Doe")
        self.assertEqual(data["date_of_birth"], "1980-01-15")
        self.assertEqual(data["gender"], Gender.MALE)
        self.assertEqual(data["email"], "john.doe@example.com")
        self.assertEqual(data["phone"], "555-123-4567")
        self.assertEqual(data["address"], "123 Main St, Anytown, USA")
        self.assertEqual(data["status"], PatientStatus.ACTIVE)
        self.assertEqual(len(data["emergency_contacts"]), 1)
        self.assertEqual(data["emergency_contacts"][0]["name"], "Jane Doe")
        self.assertEqual(data["insurance"]["provider"], "Blue Cross")


# Run the tests if this file is executed directly
if __name__ == "__main__":
    unittest.main()