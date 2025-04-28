"""
Pydantic schemas for Digital Twin API endpoints.
"""
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Dict, Any
from uuid import UUID
from datetime import datetime

# --- Configuration Schemas ---
class DigitalTwinConfigurationBase(BaseModel):
    simulation_granularity_hours: Optional[int] = 1
    prediction_models_enabled: Optional[List[str]] = ["risk_relapse", "treatment_response"]
    data_sources_enabled: Optional[List[str]] = ["actigraphy", "symptoms", "sessions"]
    alert_thresholds: Optional[Dict[str, float]] = {}

class DigitalTwinConfigurationCreate(DigitalTwinConfigurationBase):
    pass # Usually same as base for creation, or stricter

class DigitalTwinConfigurationUpdate(DigitalTwinConfigurationBase):
    # All fields optional for updates
    simulation_granularity_hours: Optional[int] = None
    prediction_models_enabled: Optional[List[str]] = None
    data_sources_enabled: Optional[List[str]] = None
    alert_thresholds: Optional[Dict[str, float]] = None

class DigitalTwinConfigurationResponse(DigitalTwinConfigurationBase):
    pass # Usually same as base

# --- State Schemas ---
class DigitalTwinStateBase(BaseModel):
    overall_risk_level: Optional[str] = None
    dominant_symptoms: Optional[List[str]] = []
    current_treatment_effectiveness: Optional[str] = None
    predicted_phq9_trajectory: Optional[List[Dict[str, Any]]] = None

class DigitalTwinStateResponse(DigitalTwinStateBase):
    last_sync_time: Optional[datetime] = None

# --- Digital Twin Schemas ---
class DigitalTwinBase(BaseModel):
    patient_id: UUID

class DigitalTwinCreate(DigitalTwinBase):
    # Allow setting initial configuration during creation
    configuration: Optional[DigitalTwinConfigurationCreate] = None

class DigitalTwinUpdate(BaseModel):
    # Allow updating configuration and potentially state (though state updates might have dedicated endpoints)
    configuration: Optional[DigitalTwinConfigurationUpdate] = None
    # state: Optional[Dict[str, Any]] = None # Example if state update is allowed here

class DigitalTwinResponse(DigitalTwinBase):
    id: UUID
    configuration: DigitalTwinConfigurationResponse
    state: DigitalTwinStateResponse
    created_at: datetime
    last_updated: datetime
    version: int

    model_config = ConfigDict(from_attributes=True) # Enable ORM mode equivalent

