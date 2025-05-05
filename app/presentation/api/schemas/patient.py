from pydantic import BaseModel, Field


class PatientBase(BaseModel):
    name: str = Field(..., min_length=1, description="Name of the patient")
    # Add other relevant patient fields here as needed


class PatientCreateRequest(PatientBase):
    # Fields specific to creation, if any
    pass


class PatientRead(PatientBase):
    id: str = Field(..., description="Unique identifier for the patient")

    class Config:
        from_attributes = True # orm_mode = True for Pydantic v1

# For now, the response after creation will be the same as reading the patient
PatientCreateResponse = PatientRead
