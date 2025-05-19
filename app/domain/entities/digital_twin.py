"""
Domain entity representing the core Digital Twin.

This entity aggregates and manages the state and configuration
of a patient's digital representation.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from app.domain.utils.datetime_utils import now_utc

# Assuming Patient entity exists or will be created
# from app.domain.entities.patient import Patient
# Remove BaseEntity inheritance for now
# from app.domain.entities.base_entity import BaseEntity


@dataclass
class DigitalTwinConfiguration:
    """Configuration settings specific to a digital twin."""

    simulation_granularity_hours: int = 1  # Default simulation step
    prediction_models_enabled: list[str] = field(
        default_factory=lambda: ["risk_relapse", "treatment_response"]
    )
    data_sources_enabled: list[str] = field(
        default_factory=lambda: ["actigraphy", "symptoms", "sessions"]
    )
    alert_thresholds: dict[str, float] = field(
        default_factory=dict
    )  # e.g., {"phq9_change": 5.0, "suicide_risk": 0.7}
    # Add other relevant configuration parameters


@dataclass
class DigitalTwinState:
    """Represents the current snapshot or aggregated state of the twin."""

    last_sync_time: datetime | None = None
    overall_risk_level: str | None = None  # e.g., 'low', 'moderate', 'high'
    dominant_symptoms: list[str] = field(default_factory=list)
    current_treatment_effectiveness: str | None = (
        None  # e.g., 'improving', 'stable', 'worsening'
    )
    # Add other relevant state indicators like predicted trajectory, adherence scores etc.
    predicted_phq9_trajectory: list[
        dict[str, Any]
    ] | None = None  # List of {"week": int, "score": float}


@dataclass
# class DigitalTwin(BaseEntity):
class DigitalTwin:
    """Core Digital Twin entity."""

    # Define non-default fields first
    patient_id: UUID
    # Define neurotransmitter baseline parameters needed for tests
    baseline_serotonin: float = 1.0
    baseline_dopamine: float = 1.0
    baseline_gaba: float = 1.0
    baseline_norepinephrine: float = 1.0
    # Define sensitivity parameters needed for tests
    cortisol_sensitivity: float = 0.5
    medication_sensitivity: float = 1.0
    therapy_sensitivity: float = 0.8
    # Define other fields, including ID with default
    id: UUID = field(default_factory=uuid4)  # Keep default factory
    configuration: DigitalTwinConfiguration = field(
        default_factory=DigitalTwinConfiguration
    )
    state: DigitalTwinState = field(default_factory=DigitalTwinState)
    created_at: datetime = field(default_factory=now_utc)
    last_updated: datetime = field(default_factory=now_utc)
    version: int = 1
    integration_summary: str | None = field(
        default=None
    )  # Added integration summary field

    def __post_init__(self):
        """Ensure created_at and last_updated are the same reference when first created."""
        # Make last_updated reference the same object as created_at
        if self.created_at is not None and self.last_updated is not None:
            object.__setattr__(self, "last_updated", self.created_at)

        # Validate neurotransmitter levels
        if (
            self.baseline_serotonin < 0
            or self.baseline_dopamine < 0
            or self.baseline_gaba < 0
            or self.baseline_norepinephrine < 0
        ):
            from app.domain.exceptions.base_exceptions import ValidationError

            raise ValidationError("Neurotransmitter baselines must be non-negative")

    def update_state(self, new_state_data: dict[str, Any]):
        """Update the twin's state based on new data."""
        for key, value in new_state_data.items():
            if hasattr(self.state, key):
                setattr(self.state, key, value)
        self.state.last_sync_time = now_utc()
        self.touch()

    def update_configuration(self, new_config_data: dict[str, Any]):
        """Update the twin's configuration."""
        for key, value in new_config_data.items():
            if hasattr(self.configuration, key):
                setattr(self.configuration, key, value)
        self.touch()

    def touch(self):
        """Update the last_updated timestamp and version."""
        self.last_updated = now_utc()
        self.version += 1

    # Ensure BaseEntity __post_init__ is called if it exists
    # def __post_init__(self):
    #     super().__post_init__() # Call BaseEntity's post_init
