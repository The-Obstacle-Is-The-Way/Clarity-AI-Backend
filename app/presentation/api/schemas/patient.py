import uuid # Add import for uuid
from datetime import date, datetime # Add import for date and datetime
from pydantic import BaseModel, Field, EmailStr, computed_field # Add EmailStr and computed_field


class PatientBase(BaseModel):
    # name: str = Field(..., min_length=1, description="Name of the patient") # Removed
    # Keep other common base fields if any, or make it very minimal
    first_name: str = Field(..., description="Patient's first name")
    last_name: str = Field(..., description="Patient's last name")
    date_of_birth: date = Field(..., description="Patient's date of birth")
    email: EmailStr | None = Field(None, description="Patient's email address")
    phone_number: str | None = Field(None, description="Patient's phone number")


class PatientCreateRequest(PatientBase):
    # Fields specific to creation, if any. For now, inherits all from PatientBase.
    pass


class PatientRead(PatientBase):
    id: uuid.UUID = Field(..., description="Unique identifier for the patient") # Changed to uuid.UUID
    # Inherits first_name, last_name, dob, email, phone_number from PatientBase
    created_at: datetime | None = Field(None, description="When the patient record was created")
    updated_at: datetime | None = Field(None, description="When the patient record was last updated")
    created_by: uuid.UUID | None = Field(None, description="ID of the user who created the patient record")

    @computed_field
    @property
    def name(self) -> str:
        return f"{self.first_name} {self.last_name}"

    class Config:
        from_attributes = True # orm_mode = True for Pydantic v1

# Create a specific response for patient creation
class PatientCreateResponse(PatientRead):
    """Response model for patient creation endpoint."""
    created_at: datetime = Field(..., description="When the patient record was created")
    updated_at: datetime = Field(..., description="When the patient record was last updated")
    created_by: uuid.UUID = Field(..., description="ID of the user who created the patient record")
