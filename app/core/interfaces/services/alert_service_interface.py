"""
Alert service interface definition.

This module defines the abstract interface for clinical alert services
following clean architecture principles with proper separation of concerns.
Alerts are critical for clinical monitoring and intervention triggers.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from app.domain.entities.biometric_alert_rule import BiometricAlertRule


class AlertSeverity(str, Enum):
    """Alert severity levels for clinical alerts."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class AlertServiceInterface(ABC):
    """
    Abstract interface for clinical alert services.

    This interface defines the contract for operations related to generating,
    managing, and resolving clinical alerts, allowing for different implementations
    while maintaining a consistent interface throughout the application.
    """

    @abstractmethod
    async def create_alert(
        self,
        patient_id: str | UUID,
        alert_type: str,
        severity: AlertSeverity,
        description: str,
        source_data: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[bool, str | None, str | None]:
        """
        Create a new clinical alert for a patient.

        Args:
            patient_id: Unique identifier for the patient
            alert_type: Type of alert (e.g., 'biometric_threshold', 'medication_interaction')
            severity: Severity level of the alert
            description: Human-readable description of the alert
            source_data: Optional data that triggered the alert
            metadata: Optional additional metadata about the alert

        Returns:
            Tuple of (success, alert_id, error_message)
        """
        raise NotImplementedError

    @abstractmethod
    async def get_alerts(
        self,
        patient_id: str | UUID | None = None,
        provider_id: str | UUID | None = None,
        alert_type: str | None = None,
        severity: AlertSeverity | None = None,
        status: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 100,
        skip: int = 0,
    ) -> list[dict[str, Any]]:
        """
        Retrieve alerts with optional filtering.

        Args:
            patient_id: Optional patient identifier to filter by
            provider_id: Optional provider identifier to filter by
            alert_type: Optional alert type to filter by
            severity: Optional severity level to filter by
            status: Optional alert status to filter by
            start_time: Optional start of time range
            end_time: Optional end of time range
            limit: Maximum number of alerts to return
            skip: Number of alerts to skip

        Returns:
            List of alert records
        """
        raise NotImplementedError

    @abstractmethod
    async def update_alert_status(
        self,
        alert_id: str | UUID,
        status: str,
        resolution_notes: str | None = None,
        resolved_by: str | UUID | None = None,
    ) -> tuple[bool, str | None]:
        """
        Update the status of an alert.

        Args:
            alert_id: Unique identifier for the alert
            status: New status for the alert (e.g., 'acknowledged', 'resolved', 'escalated')
            resolution_notes: Optional notes about the resolution
            resolved_by: Optional identifier of the provider who resolved the alert

        Returns:
            Tuple of (success, error_message)
        """
        raise NotImplementedError

    @abstractmethod
    async def evaluate_biometric_data(
        self,
        patient_id: str | UUID,
        data_type: str,
        data_value: Any,
        timestamp: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """
        Evaluate biometric data against alert rules and generate alerts if needed.

        Args:
            patient_id: Unique identifier for the patient
            data_type: Type of biometric data
            data_value: The value to evaluate
            timestamp: Optional timestamp for the data point

        Returns:
            List of generated alerts (if any)
        """
        raise NotImplementedError

    @abstractmethod
    async def get_alert_summary(
        self, patient_id: str | UUID, start_time: datetime, end_time: datetime
    ) -> dict[str, Any]:
        """
        Get a summary of alerts for a patient within a time range.

        Args:
            patient_id: Unique identifier for the patient
            start_time: Start of time range
            end_time: End of time range

        Returns:
            Summary statistics about alerts
        """
        raise NotImplementedError

    @abstractmethod
    async def get_rule_by_id(self, rule_id: str) -> BiometricAlertRule | None:
        """Get a rule by its ID."""
        pass

    @abstractmethod
    async def create_rule(self, rule_data: BiometricAlertRule) -> BiometricAlertRule:
        """Create a new alert rule."""
        pass

    @abstractmethod
    async def update_rule(
        self, rule_id: str, rule_data: BiometricAlertRule
    ) -> BiometricAlertRule | None:
        """Update an existing alert rule."""
        pass

    @abstractmethod
    async def list_rules(
        self, user_id: str | None = None
    ) -> list[BiometricAlertRule]:
        """List alert rules, optionally filtered by user."""
        pass
