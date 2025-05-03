"""
Digital Twin Schemas Module.

This module defines Pydantic models for digital twin data validation,
serialization, and documentation in the presentation layer, ensuring
strict validation of all input and output data for HIPAA compliance.
"""

from datetime import datetime
from typing import Dict, Any, Optional
from uuid import UUID

from pydantic import Field

from app.core.domain.entities.digital_twin import TwinType, SimulationType
from app.presentation.api.schemas.base import BaseModelConfig


class DigitalTwinBase(BaseModelConfig):
    """Base schema for digital twin data with common fields."""
    twin_type: TwinType
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=1000)


class DigitalTwinCreateRequest(DigitalTwinBase):
    """Request schema for creating a new digital twin."""
    data: Dict[str, Any] = Field(..., description="Digital twin model data")
    patient_id: Optional[str] = None  # For provider-created twins


class DigitalTwinUpdateRequest(BaseModelConfig):
    """Request schema for updating an existing digital twin."""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=1000)
    version: Optional[str] = None
    data: Optional[Dict[str, Any]] = None


class DigitalTwinResponse(DigitalTwinBase):
    """Response schema for digital twin data."""
    id: UUID
    created_at: datetime
    updated_at: datetime
    version: str
    data: Optional[Dict[str, Any]] = None
    user_id: str  # The ID of the patient this digital twin belongs to


class TwinSimulationRequest(BaseModelConfig):
    """Request schema for running a digital twin simulation."""
    simulation_type: SimulationType
    parameters: Dict[str, Any] = Field(..., description="Simulation parameters")
    timeframe_days: int = Field(30, ge=1, le=365, description="Simulation timeframe in days")


class TwinSimulationResponse(BaseModelConfig):
    """Response schema for digital twin simulation results."""
    simulation_id: str
    twin_id: str
    simulation_type: SimulationType
    executed_at: datetime
    timeframe_days: int
    results: Dict[str, Any]
