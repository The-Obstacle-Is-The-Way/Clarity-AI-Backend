import uuid
from datetime import date, datetime

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    computed_field,
)


class PatientBase(BaseModel):
    first_name: str = Field(..., description="Patient's first name")
    last_name: str = Field(..., description="Patient's last name")
    date_of_birth: date = Field(..., description="Patient's date of birth")
    email: EmailStr | None = Field(None, description="Patient's email address")
    phone_number: str | None = Field(None, description="Patient's phone number")


class PatientCreateRequest(PatientBase):
    # Fields specific to creation, if any. For now, inherits all from PatientBase.
    pass


class PatientRead(PatientBase):
    id: uuid.UUID = Field(
        ..., description="Unique identifier for the patient"
    )
    created_at: datetime | None = Field(None, description="When the patient record was created")
    updated_at: datetime | None = Field(
        None, description="When the patient record was last updated"
    )
    created_by: uuid.UUID | None = Field(
        None, description="ID of the user who created the patient record"
    )

    @property
    @computed_field
    def name(self) -> str:
        return f"{self.first_name} {self.last_name}"

    model_config = ConfigDict(from_attributes=True)


# Create a specific response for patient creation as a separate model (not inheriting from PatientRead)
class PatientCreateResponse(BaseModel):
    """Response model for patient creation endpoint."""
    # Copy all fields from PatientBase
    first_name: str = Field(..., description="Patient's first name")
    last_name: str = Field(..., description="Patient's last name")
    date_of_birth: date = Field(..., description="Patient's date of birth")
    email: EmailStr | None = Field(None, description="Patient's email address")
    phone_number: str | None = Field(None, description="Patient's phone number")
    
    # Add fields that were in PatientRead but as non-optional
    id: uuid.UUID = Field(..., description="Unique identifier for the patient")
    created_at: datetime = Field(..., description="When the patient record was created")
    updated_at: datetime = Field(..., description="When the patient record was last updated")
    created_by: uuid.UUID = Field(..., description="ID of the user who created the patient record")
    
    # Add the computed field for name
    @property
    @computed_field
    def name(self) -> str:
        return f"{self.first_name} {self.last_name}"
    
    model_config = ConfigDict(from_attributes=True)
