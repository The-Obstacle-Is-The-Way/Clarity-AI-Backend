"""
Pydantic schemas for Digital Twin API endpoints.
"""
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict


# --- Configuration Schemas ---
class DigitalTwinConfigurationBase(BaseModel):
    simulation_granularity_hours: int | None = 1
    prediction_models_enabled: list[str] | None = ["risk_relapse", "treatment_response"]
    data_sources_enabled: list[str] | None = ["actigraphy", "symptoms", "sessions"]
    alert_thresholds: dict[str, float] | None = {}


class DigitalTwinConfigurationCreate(DigitalTwinConfigurationBase):
    pass  # Usually same as base for creation, or stricter


class DigitalTwinConfigurationUpdate(DigitalTwinConfigurationBase):
    # All fields optional for updates
    simulation_granularity_hours: int | None = None
    prediction_models_enabled: list[str] | None = None
    data_sources_enabled: list[str] | None = None
    alert_thresholds: dict[str, float] | None = None


class DigitalTwinConfigurationResponse(DigitalTwinConfigurationBase):
    pass  # Usually same as base


# --- State Schemas ---
class DigitalTwinStateBase(BaseModel):
    overall_risk_level: str | None = None
    dominant_symptoms: list[str] | None = []
    current_treatment_effectiveness: str | None = None
    predicted_phq9_trajectory: list[dict[str, Any]] | None = None


class DigitalTwinStateResponse(DigitalTwinStateBase):
    last_sync_time: datetime | None = None


# --- Digital Twin Schemas ---
class DigitalTwinBase(BaseModel):
    patient_id: UUID


class DigitalTwinCreate(DigitalTwinBase):
    # Allow setting initial configuration during creation
    configuration: DigitalTwinConfigurationCreate | None = None


class DigitalTwinUpdate(BaseModel):
    # Allow updating configuration and potentially state (though state updates might have dedicated endpoints)
    configuration: DigitalTwinConfigurationUpdate | None = None
    # state: Optional[Dict[str, Any]] = None # Example if state update is allowed here


class DigitalTwinResponse(DigitalTwinBase):
    id: UUID
    configuration: DigitalTwinConfigurationResponse
    state: DigitalTwinStateResponse
    created_at: datetime
    last_updated: datetime
    version: int

    model_config = ConfigDict(from_attributes=True)  # Enable ORM mode equivalent
