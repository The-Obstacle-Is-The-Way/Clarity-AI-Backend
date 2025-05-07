"""
Patient Entity Module.

Defines the Patient domain entity, representing a patient within the system.
This entity encapsulates patient data and related business logic.
It is designed to be persistence-agnostic, following Clean Architecture principles.
"""

import uuid
from datetime import date, datetime

from pydantic import BaseModel, EmailStr, Field, field_validator


class Patient(BaseModel):
    """
    Represents a Patient in the domain layer.
    
    Attributes:
        id: Unique identifier for the patient (UUID).
        created_at: Timestamp when the patient record was created.
        updated_at: Timestamp when the patient record was last updated.
        first_name: Patient's first name.
        last_name: Patient's last name.
        date_of_birth: Patient's date of birth.
        email: Patient's email address (optional).
        phone_number: Patient's phone number (optional).
        # Add other relevant non-PHI identifying or clinical summary fields here.
        # Sensitive PHI (e.g., detailed address, SSN, full medical history)
        # should ideally be managed separately or encrypted.
    """
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    first_name: str = Field(..., min_length=1, description="Patient's first name")
    last_name: str = Field(..., min_length=1, description="Patient's last name")
    date_of_birth: date = Field(..., description="Patient's date of birth")
    email: EmailStr | None = Field(None, description="Patient's email address")
    phone_number: str | None = Field(None, description="Patient's phone number")

    model_config = {
        'from_attributes': True,  # Renamed from orm_mode
        'str_strip_whitespace': True,  # Renamed from anystr_strip_whitespace
        'validate_assignment': True  # Ensure validators run on assignment
    }

    @field_validator('date_of_birth', mode='before')
    def ensure_dob_is_past(cls, v):
        if isinstance(v, str):
            try:
                v = date.fromisoformat(v) # Convert string to date
            except ValueError:
                # Let Pydantic's main validation attempt to parse it or raise its own error
                # if the format is truly invalid for the 'date' type.
                # This validator specifically checks the logical condition (must be in the past).
                pass # Fall through to Pydantic's parsing / or the type check below

        if not isinstance(v, date):
            # This case should ideally be caught by Pydantic's own type validation if the string wasn't parseable
            # and 'v' remained something other than a date object. However, being explicit can help.
            raise ValueError("date_of_birth must be a valid date object or an ISO format string.")

        if v >= date.today():
            raise ValueError('Date of birth must be in the past')
        return v

    def update_timestamp(self):
        """Updates the updated_at timestamp."""
        self.updated_at = datetime.now()

    def get_full_name(self) -> str:
        """Returns the full name of the patient."""
        return f"{self.first_name} {self.last_name}"

    def get_age(self) -> int:
        """Calculates the current age of the patient."""
        today = date.today()
        return today.year - self.date_of_birth.year - \
               ((today.month, today.day) < (self.date_of_birth.month, self.date_of_birth.day))

    # Example placeholder for domain logic
    def is_minor(self) -> bool:
        """Checks if the patient is considered a minor (e.g., under 18)."""
        return self.get_age() < 18 