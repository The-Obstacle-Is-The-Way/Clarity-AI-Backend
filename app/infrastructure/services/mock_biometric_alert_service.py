"""
Mock Biometric Alert Service.

This module provides a mock implementation of the AlertServiceInterface
for testing and development purposes.
"""

import logging
import uuid
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.domain.entities.alert import AlertPriority, AlertStatus, AlertType
from app.core.interfaces.services.alert_service_interface import AlertServiceInterface

logger = logging.getLogger(__name__)


class MockBiometricAlertService(AlertServiceInterface):
    """Mock implementation of the AlertServiceInterface for testing."""

    def __init__(self):
        """Initialize the mock service."""
        self.alerts = {}
        self.patient_access = {}  # Map of provider_id -> set of patient_ids they can access

    async def get_alerts(
        self,
        patient_id: str | None = None,
        status: AlertStatus | None = None,
        priority: AlertPriority | None = None,
        alert_type: AlertType | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Get alerts with optional filtering."""
        filtered_alerts = []
        
        for alert_id, alert in self.alerts.items():
            # Apply filters
            if patient_id and alert.get("patient_id") != patient_id:
                continue
            if status and alert.get("status") != status:
                continue
            if priority and alert.get("priority") != priority:
                continue
            if alert_type and alert.get("alert_type") != alert_type:
                continue
            if start_date and alert.get("created_at", datetime.min) < start_date:
                continue
            if end_date and alert.get("created_at", datetime.max) > end_date:
                continue
            
            filtered_alerts.append(alert)
        
        # Apply pagination
        paginated = filtered_alerts[offset:offset+limit]
        return paginated

    async def get_alert_by_id(self, alert_id: str) -> dict[str, Any] | None:
        """Get a specific alert by ID."""
        return self.alerts.get(alert_id)

    async def create_alert(
        self,
        patient_id: str,
        alert_type: str,
        severity: AlertPriority,
        description: str,
        source_data: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[bool, str | None, str | None]:
        """Create a new alert."""
        alert_id = str(uuid.uuid4())
        now = datetime.now()
        
        alert = {
            "id": alert_id,
            "patient_id": patient_id,
            "alert_type": alert_type,
            "priority": severity,
            "description": description,
            "source_data": source_data or {},
            "metadata": metadata or {},
            "status": AlertStatus.NEW,
            "created_at": now,
            "updated_at": now,
        }
        
        self.alerts[alert_id] = alert
        return True, alert_id, None

    async def update_alert_status(
        self, alert_id: str, new_status: AlertStatus, updated_by: str
    ) -> bool:
        """Update the status of an alert."""
        if alert_id not in self.alerts:
            return False
            
        self.alerts[alert_id]["status"] = new_status
        self.alerts[alert_id]["updated_at"] = datetime.now()
        self.alerts[alert_id]["updated_by"] = updated_by
        return True

    async def validate_access(self, user_id: str, patient_id: str) -> bool:
        """Validate if a user has access to a patient's alerts."""
        # In mock implementation, allow access if the user is registered as having access
        if user_id in self.patient_access:
            return patient_id in self.patient_access[user_id]
        return False

    # Helper methods for testing
    def register_access(self, user_id: str, patient_id: str) -> None:
        """Register that a user has access to a patient's alerts."""
        if user_id not in self.patient_access:
            self.patient_access[user_id] = set()
        self.patient_access[user_id].add(patient_id)