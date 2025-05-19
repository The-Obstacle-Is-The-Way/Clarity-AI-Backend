"""
API models for audit logs.

This module defines the Pydantic models used for audit log API requests and responses.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, validator

from app.core.interfaces.services.audit_logger_interface import (
    AuditEventType,
)


class AuditLogResponseModel(BaseModel):
    """API model for audit log responses."""

    id: str
    timestamp: datetime
    event_type: str
    actor_id: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    action: str
    status: str | None = None
    ip_address: str | None = None
    details: dict[str, Any] | None = None

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": "7f9e4567-e89b-12d3-a456-426614174000",
                "timestamp": "2023-05-01T14:30:00Z",
                "event_type": "phi_accessed",
                "actor_id": "b5f8c1d2-3e4a-5b6c-7d8e-9f0a1b2c3d4e",
                "resource_type": "patient",
                "resource_id": "c7d8e9f0-a1b2-3c4d-5e6f-7a8b9c0d1e2f",
                "action": "view",
                "status": "success",
                "ip_address": "192.168.1.1",
                "details": {
                    "reason": "treatment",
                    "phi_fields": ["medications", "diagnoses"],
                },
            }
        },
    )


class AuditSearchRequest(BaseModel):
    """API model for audit log search requests."""

    filters: dict[str, Any] = Field(default_factory=dict)
    start_date: datetime | None = None
    end_date: datetime | None = None
    limit: int = Field(50, ge=1, le=100)
    offset: int = Field(0, ge=0)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "filters": {
                    "event_type": "phi_accessed",
                    "actor_id": "b5f8c1d2-3e4a-5b6c-7d8e-9f0a1b2c3d4e",
                    "resource_type": "patient",
                },
                "start_date": "2023-05-01T00:00:00Z",
                "end_date": "2023-05-31T23:59:59Z",
                "limit": 50,
                "offset": 0,
            }
        }
    )

    @validator("filters")
    def validate_filters(cls, v: dict[str, Any]) -> dict[str, Any]:
        """Validate that filters contain valid keys and values."""
        valid_keys = {
            "event_type",
            "actor_id",
            "resource_type",
            "resource_id",
            "action",
            "status",
            "ip_address",
        }

        # Ensure all keys are valid
        for key in v.keys():
            if key not in valid_keys:
                raise ValueError(f"Invalid filter key: {key}")

        # If event_type is provided, validate against AuditEventType
        if "event_type" in v:
            event_type = v["event_type"]
            if isinstance(event_type, str):
                try:
                    # Convert to AuditEventType if it's a valid enum value
                    v["event_type"] = AuditEventType(event_type)
                except ValueError:
                    # If not a valid enum value, validate it doesn't contain any SQL injection
                    if any(char in event_type for char in "';\"\\"):
                        raise ValueError(f"Invalid event_type value: {event_type}")
            elif isinstance(event_type, list):
                # If it's a list, validate each item
                valid_event_types = []
                for item in event_type:
                    try:
                        valid_event_types.append(AuditEventType(item))
                    except ValueError:
                        if any(char in item for char in "';\"\\"):
                            raise ValueError(
                                f"Invalid event_type value in list: {item}"
                            )
                        valid_event_types.append(item)
                v["event_type"] = valid_event_types

        return v


class SecurityDashboardResponse(BaseModel):
    """API model for security dashboard response."""

    statistics: dict[str, Any]
    recent_security_events: list[dict[str, Any]]
    recent_phi_access: list[dict[str, Any]]
    anomalies_detected: int
    time_range: dict[str, Any]

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "statistics": {
                    "total_logs": 1250,
                    "logs_by_event_type": {
                        "phi_accessed": 800,
                        "phi_modified": 200,
                        "login": 150,
                        "login_failed": 20,
                    },
                    "logs_by_outcome": {"success": 1200, "failure": 50},
                    "most_active_users": [
                        ["b5f8c1d2-3e4a-5b6c-7d8e-9f0a1b2c3d4e", 450],
                        ["e6f7a8b9-c0d1-2e3f-4a5b-6c7d8e9f0a1b", 300],
                    ],
                },
                "recent_security_events": [
                    {
                        "id": "7f9e4567-e89b-12d3-a456-426614174001",
                        "timestamp": "2023-05-01T14:30:00Z",
                        "event_type": "login_failed",
                        "actor_id": "b5f8c1d2-3e4a-5b6c-7d8e-9f0a1b2c3d4e",
                        "action": "login",
                        "status": "failure",
                    }
                ],
                "recent_phi_access": [
                    {
                        "id": "7f9e4567-e89b-12d3-a456-426614174002",
                        "timestamp": "2023-05-01T14:35:00Z",
                        "event_type": "phi_accessed",
                        "actor_id": "b5f8c1d2-3e4a-5b6c-7d8e-9f0a1b2c3d4e",
                        "resource_type": "patient",
                        "resource_id": "c7d8e9f0-a1b2-3c4d-5e6f-7a8b9c0d1e2f",
                        "action": "view",
                        "status": "success",
                    }
                ],
                "anomalies_detected": 2,
                "time_range": {
                    "start": "2023-04-24T00:00:00Z",
                    "end": "2023-05-01T00:00:00Z",
                    "days": 7,
                },
            }
        },
    )
