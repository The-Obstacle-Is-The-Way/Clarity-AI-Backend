"""
Enhanced unit tests for domain value objects.

This test suite provides comprehensive coverage for value objects including
EmergencyContact, PsychiatricAssessment, Address, and ContactInfo, ensuring
proper data encapsulation and validation.
"""

from datetime import date
from typing import Any

import pytest

from app.domain.value_objects.address import Address
from app.domain.value_objects.contact_info import ContactInfo
from app.domain.value_objects.emergency_contact import EmergencyContact
from app.domain.value_objects.psychiatric_assessment import PsychiatricAssessment


@pytest.mark.venv_only()
class TestEmergencyContact:
    """Comprehensive tests for the EmergencyContact value object."""

    @pytest.fixture
    def valid_contact_data(self) -> dict[str, Any]:
        """Create valid emergency contact data."""
        return {
            "name": "Jane Doe",
            "relationship": "Spouse",
            "phone": "555-123-4567",
            "email": "jane.doe@example.com",
            "address": {
                "street": "123 Main St",
                "city": "Boston",
                "state": "MA",
                "zip_code": "02115",
                "country": "USA",
            },
        }

    def test_emergency_contact_creation(self, valid_contact_data):
        """Test successful creation of emergency contact."""
        contact = EmergencyContact(**valid_contact_data)

        # Verify all attributes
        assert contact.name == valid_contact_data["name"]
        assert contact.relationship == valid_contact_data["relationship"]
        assert contact.phone == valid_contact_data["phone"]
        assert contact.email == valid_contact_data["email"]
        assert isinstance(contact.address, Address)
        assert contact.address.street == valid_contact_data["address"]["street"]
        assert contact.address.city == valid_contact_data["address"]["city"]

    def test_emergency_contact_validation(self):
        """Test validation of emergency contact data."""
        # Test with missing required fields
        with pytest.raises(ValueError, match="Name cannot be empty"):
            EmergencyContact(
                name="",
                relationship="Spouse",
                phone="555-123-4567",
                email="jane.doe@example.com",
            )

        with pytest.raises(ValueError, match="Relationship cannot be empty"):
            EmergencyContact(
                name="Jane Doe",
                relationship="",
                phone="555-123-4567",
                email="jane.doe@example.com",
            )

        # Test with invalid phone number
        with pytest.raises(ValueError, match="Invalid phone number format"):
            EmergencyContact(
                name="Jane Doe",
                relationship="Spouse",
                phone="invalid-phone",
                email="jane.doe@example.com",
            )

        # Test with invalid email
        with pytest.raises(ValueError, match="Invalid email format"):
            EmergencyContact(
                name="Jane Doe",
                relationship="Spouse",
                phone="555-123-4567",
                email="invalid-email",
            )

    def test_emergency_contact_optional_fields(self, valid_contact_data):
        """Test emergency contact with optional fields."""
        # Test with missing email
        data = valid_contact_data.copy()
        data.pop(
            "email",
        )
        contact = EmergencyContact(**data)
        assert contact.email is None

        # Test with missing address
        data = valid_contact_data.copy()
        data.pop(
            "address",
        )
        contact = EmergencyContact(**data)
        assert contact.address is None

    def test_emergency_contact_equality(self, valid_contact_data):
        """Test equality comparison of emergency contacts."""
        contact1 = EmergencyContact(
            **valid_contact_data,
        )
        contact2 = EmergencyContact(**valid_contact_data)

        # Same data should be equal
        assert contact1 == contact2

        # Different data should not be equal
        different_data = valid_contact_data.copy()
        different_data["name"] = "Different Name"
        contact3 = EmergencyContact(**different_data)
        assert contact1 != contact3

    def test_emergency_contact_repr(self, valid_contact_data):
        """Test string representation of emergency contact."""
        contact = EmergencyContact(
            **valid_contact_data,
        )
        repr_str = repr(contact)

        # Representation should include key attributes
        assert contact.name in repr_str
        assert contact.relationship in repr_str
        assert contact.phone in repr_str

    def test_emergency_contact_to_dict(self, valid_contact_data):
        """Test conversion of emergency contact to dictionary."""
        contact = EmergencyContact(
            **valid_contact_data,
        )
        contact_dict = contact.to_dict()

        # Dictionary should contain all attributes
        assert contact_dict["name"] == valid_contact_data["name"]
        assert contact_dict["relationship"] == valid_contact_data["relationship"]
        assert contact_dict["phone"] == valid_contact_data["phone"]
        assert contact_dict["email"] == valid_contact_data["email"]
        assert isinstance(contact_dict["address"], dict)
        assert (
            contact_dict["address"]["street"] == valid_contact_data["address"]["street"]
        )


class TestPsychiatricAssessment:
    """Comprehensive tests for the PsychiatricAssessment value object."""

    @pytest.fixture
    def valid_assessment_data(self) -> dict[str, Any]:
        """Create valid psychiatric assessment data."""
        return {
            "assessment_date": date(2025, 3, 15),
            "diagnosis": "Major Depressive Disorder",
            "severity": "Moderate",
            "treatment_plan": "Weekly therapy, medication management",
            "notes": "Patient shows improvement with current regimen",
        }

    def test_psychiatric_assessment_creation(self, valid_assessment_data):
        """Test successful creation of psychiatric assessment."""
        assessment = PsychiatricAssessment(**valid_assessment_data)

        # Verify all attributes
        assert assessment.assessment_date == valid_assessment_data["assessment_date"]
        assert assessment.diagnosis == valid_assessment_data["diagnosis"]
        assert assessment.severity == valid_assessment_data["severity"]
        assert assessment.treatment_plan == valid_assessment_data["treatment_plan"]
        assert assessment.notes == valid_assessment_data["notes"]

    def test_psychiatric_assessment_validation(self):
        """Test validation of psychiatric assessment data."""
        # Test with missing required fields
        with pytest.raises(ValueError, match="Diagnosis cannot be empty"):
            PsychiatricAssessment(
                assessment_date=date(2025, 3, 15),
                diagnosis="",
                severity="Moderate",
                treatment_plan="Weekly therapy, medication management",
            )

        with pytest.raises(ValueError, match="Severity cannot be empty"):
            PsychiatricAssessment(
                assessment_date=date(2025, 3, 15),
                diagnosis="Major Depressive Disorder",
                severity="",
                treatment_plan="Weekly therapy, medication management",
            )

        with pytest.raises(ValueError, match="Treatment plan cannot be empty"):
            PsychiatricAssessment(
                assessment_date=date(2025, 3, 15),
                diagnosis="Major Depressive Disorder",
                severity="Moderate",
                treatment_plan="",
            )

    def test_psychiatric_assessment_optional_fields(self, valid_assessment_data):
        """Test psychiatric assessment with optional fields."""
        # Test with missing notes
        data = valid_assessment_data.copy()
        data.pop(
            "notes",
        )
        assessment = PsychiatricAssessment(**data)
        assert assessment.notes is None

    def test_psychiatric_assessment_equality(self, valid_assessment_data):
        """Test equality comparison of psychiatric assessments."""
        assessment1 = PsychiatricAssessment(
            **valid_assessment_data,
        )
        assessment2 = PsychiatricAssessment(**valid_assessment_data)

        # Same data should be equal
        assert assessment1 == assessment2

        # Different data should not be equal
        different_data = valid_assessment_data.copy()
        different_data["diagnosis"] = "Different Diagnosis"
        assessment3 = PsychiatricAssessment(**different_data)
        assert assessment1 != assessment3

    def test_psychiatric_assessment_repr(self, valid_assessment_data):
        """Test string representation of psychiatric assessment."""
        assessment = PsychiatricAssessment(
            **valid_assessment_data,
        )
        repr_str = repr(assessment)

        # Representation should include key attributes
        assert str(assessment.assessment_date) in repr_str
        assert assessment.diagnosis in repr_str
        assert assessment.severity in repr_str

    def test_psychiatric_assessment_to_dict(self, valid_assessment_data):
        """Test conversion of psychiatric assessment to dictionary."""
        assessment = PsychiatricAssessment(
            **valid_assessment_data,
        )
        assessment_dict = assessment.to_dict()

        # Dictionary should contain all attributes
        assert (
            assessment_dict["assessment_date"]
            == valid_assessment_data["assessment_date"].isoformat()
        )
        assert assessment_dict["diagnosis"] == valid_assessment_data["diagnosis"]
        assert assessment_dict["severity"] == valid_assessment_data["severity"]
        assert (
            assessment_dict["treatment_plan"] == valid_assessment_data["treatment_plan"]
        )
        assert assessment_dict["notes"] == valid_assessment_data["notes"]

    def test_psychiatric_assessment_from_dict(self, valid_assessment_data):
        """Test creation of psychiatric assessment from dictionary."""
        # Convert date to string as it would come from JSON
        dict_data = valid_assessment_data.copy()
        dict_data["assessment_date"] = valid_assessment_data[
            "assessment_date"
        ].isoformat()

        assessment = PsychiatricAssessment.from_dict(dict_data)

        # Verify all attributes
        assert assessment.assessment_date == valid_assessment_data["assessment_date"]
        assert assessment.diagnosis == valid_assessment_data["diagnosis"]
        assert assessment.severity == valid_assessment_data["severity"]


class TestAddressValueObject:
    """Tests for the Address value object."""

    @pytest.fixture
    def valid_address_data(self) -> dict[str, Any]:
        """Create valid address data."""
        return {
            "street": "123 Main St",
            "city": "Boston",
            "state": "MA",
            "zip_code": "02115",
            "country": "USA",
        }

    def test_address_creation(self, valid_address_data):
        """Test successful creation of address."""
        address = Address(**valid_address_data)

        # Verify all attributes
        assert address.street == valid_address_data["street"]
        assert address.city == valid_address_data["city"]
        assert address.state == valid_address_data["state"]
        assert address.zip_code == valid_address_data["zip_code"]
        assert address.country == valid_address_data["country"]

    def test_address_validation(self):
        """Test validation of address data."""
        # Test with missing required fields
        with pytest.raises(ValueError):
            Address(
                street="",  # Empty street
                city="Boston",
                state="MA",
                zip_code="02115",
                country="USA",
            )

        with pytest.raises(ValueError):
            Address(
                street="123 Main St",
                city="",  # Empty city
                state="MA",
                zip_code="02115",
                country="USA",
            )

    def test_address_to_dict(self, valid_address_data):
        """Test conversion of address to dictionary."""
        address = Address(
            **valid_address_data,
        )
        address_dict = address.to_dict()

        # Dictionary should contain all attributes
        assert address_dict == valid_address_data


class TestContactInfoValueObject:
    """Tests for the ContactInfo value object."""

    @pytest.fixture
    def valid_contact_info_data(self) -> dict[str, Any]:
        """Create valid contact info data."""
        return {
            "email": "patient@example.com",
            "phone": "555-123-4567",
            "preferred_contact_method": "email",
        }

    def test_contact_info_creation(self, valid_contact_info_data):
        """Test successful creation of contact info."""
        contact_info = ContactInfo(**valid_contact_info_data)

        # Verify all attributes
        assert contact_info.email == valid_contact_info_data["email"]
        assert contact_info.phone == valid_contact_info_data["phone"]
        assert (
            contact_info.preferred_contact_method
            == valid_contact_info_data["preferred_contact_method"]
        )

    def test_contact_info_validation(self):
        """Test validation of contact info data."""
        # Test with invalid email
        with pytest.raises(ValueError):
            ContactInfo(
                email="invalid-email",  # Invalid email
                phone="555-123-4567",
                preferred_contact_method="email",
            )

        # Test with invalid phone
        with pytest.raises(ValueError):
            ContactInfo(
                email="patient@example.com",
                phone="invalid-phone",  # Invalid phone
                preferred_contact_method="phone",
            )

        # Test with invalid preferred contact method
        with pytest.raises(ValueError):
            ContactInfo(
                email="patient@example.com",
                phone="555-123-4567",
                preferred_contact_method="invalid-method",  # Invalid method
            )

    def test_contact_info_optional_fields(self, valid_contact_info_data):
        """Test contact info with optional fields."""
        # Test with missing email
        data = valid_contact_info_data.copy()
        data.pop(
            "email",
        )
        contact_info = ContactInfo(**data)
        assert contact_info.email is None

        # Test with missing phone
        data = valid_contact_info_data.copy()
        data.pop(
            "phone",
        )
        contact_info = ContactInfo(**data)
        assert contact_info.phone is None

    def test_contact_info_to_dict(self, valid_contact_info_data):
        """Test conversion of contact info to dictionary."""
        contact_info = ContactInfo(
            **valid_contact_info_data,
        )
        contact_info_dict = contact_info.to_dict()

        # Dictionary should contain all attributes
        assert contact_info_dict == valid_contact_info_data
