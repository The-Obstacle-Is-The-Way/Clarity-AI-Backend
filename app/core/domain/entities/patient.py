"""
Patient Entity Module.

Defines the Patient domain entity, representing a patient within the system.
This entity encapsulates patient data and related business logic.
It is designed to be persistence-agnostic, following Clean Architecture principles.
"""

import uuid
from datetime import date, datetime, timezone
from typing import Any  # For dict fields initially

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.core.domain.enums import Gender
from app.domain.value_objects.address import (
    Address,
)  # Assuming this is the canonical Pydantic/dataclass VO
from app.domain.value_objects.emergency_contact import (
    EmergencyContact,
)  # Assuming this is the canonical Pydantic/dataclass VO


class ContactInfo(BaseModel):
    """
    Represents a patient's contact information.

    Attributes:
        email: Patient's email address (optional).
        phone: Patient's phone number (optional).
        email_secondary: Patient's secondary email address (optional).
    """

    email: EmailStr | None = Field(None, description="Patient's primary email address")
    phone: str | None = Field(None, description="Patient's primary phone number")
    email_secondary: EmailStr | None = Field(None, description="Patient's secondary email address")

    model_config = {
        "from_attributes": True,
        "str_strip_whitespace": True,
        "validate_assignment": True,
    }


class Patient(BaseModel):
    """
    Represents a Patient in the domain layer.
    """

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    user_id: uuid.UUID | None = Field(
        None, description="Associated user account ID"
    )  # Added user_id
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Core PII
    first_name: str = Field(..., min_length=1, description="Patient's first name")
    middle_name: str | None = Field(None, description="Patient's middle name")
    last_name: str = Field(..., min_length=1, description="Patient's last name")
    date_of_birth: date = Field(..., description="Patient's date of birth")
    gender: Gender | None = Field(None, description="Patient's gender")
    sex_at_birth: str | None = Field(
        None, description="Patient's sex assigned at birth"
    )  # Consider enum if appropriate
    pronouns: str | None = Field(None, description="Patient's preferred pronouns")

    # Contact Information
    email: EmailStr | None = Field(None, description="Patient's primary email address")
    phone_number: str | None = Field(None, description="Patient's primary phone number")
    address: Address | None = Field(None, description="Patient's primary address")
    contact_info: ContactInfo = Field(
        default_factory=ContactInfo, description="Detailed contact information object"
    )
    emergency_contact: EmergencyContact | None = Field(
        None, description="Patient's emergency contact"
    )

    # Demographics & Social
    ethnicity: str | None = Field(None, description="Patient's ethnicity")
    race: str | None = Field(None, description="Patient's race")
    preferred_language: str | None = Field(None, description="Patient's preferred language")
    religion_spirituality: str | None = Field(
        None, description="Patient's religion or spirituality"
    )
    occupation: str | None = Field(None, description="Patient's occupation")
    education_level: str | None = Field(None, description="Patient's education level")
    marital_status: str | None = Field(None, description="Patient's marital status")
    living_arrangement: str | None = Field(None, description="Patient's living arrangement")

    # Identifiers (LVE - Limited Value Encryption, often stored encrypted)
    medical_record_number_lve: str | None = Field(
        None, description="Patient's Medical Record Number"
    )
    social_security_number_lve: str | None = Field(
        None, description="Patient's Social Security Number"
    )
    drivers_license_number_lve: str | None = Field(
        None, description="Patient's Driver's License Number"
    )
    insurance_policy_number_lve: str | None = Field(
        None, description="Patient's Insurance Policy Number"
    )
    insurance_group_number_lve: str | None = Field(
        None, description="Patient's Insurance Group Number"
    )

    # Clinical Information (often as lists of strings/simple dicts, or dedicated VOs)
    # These may be stored as EncryptedText or EncryptedJSON in DB model
    medical_history: list[str] = Field(
        default_factory=list, description="List of medical conditions or history items"
    )
    medications: list[dict[str, Any]] = Field(
        default_factory=list,
        description="List of medications (e.g., {'name': 'MedX', 'dosage': '10mg'})",
    )
    allergies: list[str] = Field(default_factory=list, description="List of allergies")
    allergies_sensitivities: str | None = Field(
        None, description="Detailed allergies and sensitivities text"
    )  # if different from list
    problem_list: str | None = Field(None, description="Patient's problem list text")
    primary_care_physician: str | None = Field(
        None, description="Patient's primary care physician details"
    )
    pharmacy_information: str | None = Field(
        None, description="Patient's preferred pharmacy details"
    )
    care_team_contact_info: str | None = Field(
        None, description="Care team contact information text"
    )
    treatment_history_notes: str | None = Field(None, description="Notes on treatment history")
    current_medications_lve: str | None = Field(
        None, description="Current medications text (LVE)"
    )  # if different from list

    # Audit and metadata fields
    audit_id: uuid.UUID | None = Field(
        None, description="ID linking to audit log entry for this record"
    )
    created_by: uuid.UUID | None = Field(None, description="ID of the user who created this record")
    updated_by: uuid.UUID | None = Field(
        None, description="ID of the user who last updated this record"
    )

    # Security and system fields
    is_active: bool = Field(True, description="Whether the patient record is active")
    external_id: str | None = Field(None, description="External system identifier")
    notes: str | None = Field(None, description="General notes about the patient")

    # Other / Preferences
    preferences_json: dict[str, Any] | None = Field(
        default_factory=dict, description="Patient preferences as JSON-like dict"
    )
    contact_details_json: dict[str, Any] | None = Field(
        default_factory=dict, description="Additional contact details as JSON-like dict"
    )
    confidential_information_lve: str | None = Field(
        None, description="Confidential information (LVE)"
    )
    additional_notes_lve: str | None = Field(None, description="Additional notes (LVE)")

    model_config = {
        "from_attributes": True,
        "str_strip_whitespace": True,
        "validate_assignment": True,
        "populate_by_name": True,  # Allows using alias if defined, useful for _lve fields
    }

    def __init__(self, **data):
        # Ensure contact_info gets populated from top-level email/phone if provided directly
        # and contact_info itself isn't in data or is missing fields.
        raw_contact_info = data.pop("contact_info", None)

        super().__init__(**data)

        # Initialize or update self.contact_info
        current_contact_info_data = {}
        if raw_contact_info:
            if isinstance(raw_contact_info, ContactInfo):
                current_contact_info_data = raw_contact_info.model_dump(exclude_none=True)
            elif isinstance(raw_contact_info, dict):
                current_contact_info_data = raw_contact_info

        # Prioritize direct fields if contact_info fields are missing
        final_contact_email = current_contact_info_data.get("email", self.email)
        final_contact_phone = current_contact_info_data.get("phone", self.phone_number)
        final_contact_email_secondary = current_contact_info_data.get("email_secondary")

        self.contact_info = ContactInfo(
            email=final_contact_email,
            phone=final_contact_phone,
            email_secondary=final_contact_email_secondary,
        )
        # Sync back to top-level fields if they were None and contact_info had values
        if self.email is None and self.contact_info.email is not None:
            self.email = self.contact_info.email
        if self.phone_number is None and self.contact_info.phone is not None:
            self.phone_number = self.contact_info.phone

    @field_validator("date_of_birth", mode="before")
    @classmethod
    def ensure_dob_is_past(cls, v):
        if isinstance(v, str):
            try:
                v = date.fromisoformat(v)
            except ValueError:
                pass
        if not isinstance(v, date):
            raise ValueError("date_of_birth must be a valid date object or an ISO format string.")
        if v >= date.today():
            raise ValueError("Date of birth must be in the past")
        return v

    @field_validator("gender", mode="before")
    @classmethod
    def validate_gender(cls, v):
        """Validate and normalize gender values"""
        if v is None:
            return None

        if isinstance(v, Gender):
            return v

        # Handle string values
        if isinstance(v, str):
            try:
                # Try to convert to Gender enum
                return Gender(v)
            except ValueError:
                # Check if it matches any enum value (case insensitive)
                v_lower = v.lower()
                for gender in Gender:
                    if gender.value.lower() == v_lower:
                        return gender

                # If we get here, no match was found
                raise ValueError(
                    f"Invalid gender value: {v}. Must be one of: {', '.join([g.value for g in Gender])}"
                )

        # If not None, Gender instance, or string, it's invalid
        raise ValueError(f"Gender must be a string or Gender enum instance, got {type(v)}")

    def update_timestamp(self):
        self.updated_at = datetime.now(timezone.utc)

    def get_full_name(self) -> str:
        parts = [self.first_name, self.middle_name, self.last_name]
        return " ".join(p for p in parts if p)

    def get_age(self) -> int:
        today = date.today()
        return (
            today.year
            - self.date_of_birth.year
            - ((today.month, today.day) < (self.date_of_birth.month, self.date_of_birth.day))
        )

    def is_minor(self) -> bool:
        return self.get_age() < 18
