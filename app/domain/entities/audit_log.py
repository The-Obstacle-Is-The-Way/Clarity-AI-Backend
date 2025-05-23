"""
Audit Log domain entity.

This module defines the domain entity for audit logs, which represents
the core business concept of audit logging in a HIPAA-compliant system.
"""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AuditLog(BaseModel):
    """
    Domain entity representing an audit log entry.

    This entity encapsulates the core business concept of an audit log entry
    in a HIPAA-compliant healthcare system, tracking access to PHI and
    system events.
    """

    id: str | None = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: str
    actor_id: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    action: str
    status: str | None = None
    ip_address: str | None = None
    details: dict[str, Any] | None = None
    success: bool | None = None

    model_config = ConfigDict(arbitrary_types_allowed=True)

    @field_validator("timestamp")
    @classmethod
    def ensure_timezone(cls, v: datetime) -> datetime:
        """Ensure the timestamp has a timezone."""
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v

    def anonymize_phi(self) -> "AuditLog":
        """
        Create an anonymized version of this audit log for safe export.

        This ensures no PHI is included when exporting audit logs.

        Returns:
            AuditLog: Anonymized audit log
        """
        return AuditLog(
            id=self.id,
            timestamp=self.timestamp,
            event_type=self.event_type,
            actor_id=self.actor_id,  # User IDs are not PHI
            resource_type=self.resource_type,
            # Hash or mask resource IDs if they might contain PHI
            resource_id=f"***{self.resource_id[-4:]}" if self.resource_id else None,
            action=self.action,
            status=self.status,
            # IP addresses can be masked for privacy
            ip_address=".".join(self.ip_address.split(".")[:2] + ["*", "*"])
            if self.ip_address
            else None,
            # Strip any potential PHI from details
            details={
                k: v
                for k, v in (self.details or {}).items()
                if k not in ["phi", "patient_data", "medical_info"]
            },
            success=self.success,
        )


class AuditLogBatch(BaseModel):
    """
    Represents a batch of audit logs.

    Used for bulk operations and export/import.
    """

    logs: list[AuditLog]
    start_timestamp: datetime
    end_timestamp: datetime
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    total_count: int

    model_config = ConfigDict(arbitrary_types_allowed=True)

    @classmethod
    def create_from_logs(cls, logs: list[AuditLog]) -> "AuditLogBatch":
        """
        Create a batch from a list of audit logs.

        Args:
            logs: List of audit logs to include in the batch

        Returns:
            AuditLogBatch: The created batch
        """
        if not logs:
            return cls(
                logs=[],
                start_timestamp=datetime.now(timezone.utc),
                end_timestamp=datetime.now(timezone.utc),
                total_count=0,
            )

        # Sort logs by timestamp
        sorted_logs = sorted(logs, key=lambda log: log.timestamp)

        return cls(
            logs=sorted_logs,
            start_timestamp=sorted_logs[0].timestamp,
            end_timestamp=sorted_logs[-1].timestamp,
            total_count=len(logs),
        )
