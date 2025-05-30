"""
Pydantic schemas for Appointment API endpoints.
"""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Import enums from domain entity
from app.domain.entities.appointment import AppointmentStatus, AppointmentType


class AppointmentBase(BaseModel):
    patient_id: UUID
    provider_id: UUID
    start_time: datetime
    end_time: datetime
    appointment_type: AppointmentType
    location: str | None = None
    notes: str | None = None

    @field_validator("end_time")
    def end_time_must_be_after_start_time(self, v, values):
        if "start_time" in values.data and v <= values.data["start_time"]:
            raise ValueError("End time must be after start time")
        return v


class AppointmentCreate(AppointmentBase):
    # Status is usually set by the system on creation, not provided by client
    pass


class AppointmentUpdate(BaseModel):
    # Allow updating specific fields
    start_time: datetime | None = None
    end_time: datetime | None = None
    status: AppointmentStatus | None = None
    location: str | None = None
    notes: str | None = None
    # Add patient_id/provider_id/type only if reassigning appointments is allowed

    @field_validator("end_time")
    def end_time_must_be_after_start_time_optional(self, v, values):
        # Only validate if both start and end are being updated
        if v is not None and "start_time" in values.data and values.data["start_time"] is not None:
            if v <= values.data["start_time"]:
                raise ValueError("End time must be after start time")
        # Also handle if only end_time is provided (need original start_time, complex)
        # Simplification: Validation might be better handled in the service layer for updates
        return v


class AppointmentResponse(AppointmentBase):
    id: UUID
    status: AppointmentStatus
    created_at: datetime
    last_updated: datetime

    model_config = ConfigDict(from_attributes=True)  # Enable ORM mode equivalent


# Schema for listing appointments with potential filters
class AppointmentListQuery(BaseModel):
    patient_id: UUID | None = None
    provider_id: UUID | None = None
    start_date: datetime | None = None
    end_date: datetime | None = None
    status: AppointmentStatus | None = None
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)
