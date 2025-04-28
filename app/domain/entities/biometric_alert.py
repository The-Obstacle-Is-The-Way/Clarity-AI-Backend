"""
Domain entity for Biometric Alerts.
"""
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Dict, Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, ConfigDict

from app.domain.entities.biometric_twin import BiometricDataPoint
from app.domain.entities.biometric_alert_rule import AlertPriority


class AlertStatusEnum(str, Enum):
    """Status of a biometric alert."""
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    MUTED = "muted"
    DISMISSED = "dismissed"
    
    def __str__(self) -> str:
        return self.value


class BiometricAlert(BaseModel):
    """Represents a biometric alert triggered by a rule."""
    id: UUID = Field(default_factory=uuid4, alias="alert_id")
    patient_id: UUID
    rule_id: UUID
    rule_name: str # Denormalized for easier display
    priority: AlertPriority
    status: AlertStatusEnum = AlertStatusEnum.NEW
    triggered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    data_point: BiometricDataPoint # The data point that triggered the alert
    message: str # Human-readable message describing the alert
    context: Optional[Dict[str, Any]] = None # Additional context (e.g., related events)
    
    # Tracking acknowledgment and resolution
    acknowledged: bool = False
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[UUID] = None # User ID
    acknowledged_notes: Optional[str] = None
    
    resolved: bool = False
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[UUID] = None # User ID
    resolved_notes: Optional[str] = None

    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Pydantic V2 configuration using ConfigDict
    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        validate_assignment=True,
        populate_by_name=True # Allows using 'alert_id' as input
    )

    def acknowledge(self, user_id: UUID, notes: Optional[str] = None):
        """Mark the alert as acknowledged."""
        if not self.acknowledged:
            self.acknowledged = True
            self.acknowledged_by = user_id
            self.acknowledged_at = datetime.now(timezone.utc)
            self.acknowledged_notes = notes
            self.status = AlertStatusEnum.ACKNOWLEDGED
            self.updated_at = self.acknowledged_at
            
    def resolve(self, user_id: UUID, notes: Optional[str] = None):
        """Mark the alert as resolved."""
        if not self.resolved:
            self.resolved = True
            self.resolved_by = user_id
            self.resolved_at = datetime.now(timezone.utc)
            self.resolved_notes = notes
            # Ensure it's acknowledged first if not already
            if not self.acknowledged:
                self.acknowledge(user_id, "Auto-acknowledged during resolution.")
            self.status = AlertStatusEnum.RESOLVED
            self.updated_at = self.resolved_at
