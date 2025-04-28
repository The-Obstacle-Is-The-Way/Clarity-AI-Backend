# -*- coding: utf-8 -*-
"""
Patient Entity Module.

Defines the Patient domain entity, representing a patient within the system.
This entity encapsulates patient data and related business logic.
It is designed to be persistence-agnostic, following Clean Architecture principles.
"""

import uuid
from datetime import date, datetime
from typing import Optional, List, Dict, Any

from pydantic import BaseModel, Field, EmailStr, validator


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
    email: Optional[EmailStr] = Field(None, description="Patient's email address")
    phone_number: Optional[str] = Field(None, description="Patient's phone number")

    class Config:
        from_attributes = True  # Renamed from orm_mode
        str_strip_whitespace = True # Renamed from anystr_strip_whitespace
        validate_assignment = True # Ensure validators run on assignment

    @validator('date_of_birth')
    def ensure_dob_is_past(cls, v):
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