"""
Biometric service interface definition.

This module defines the abstract interface for biometric data processing
services following clean architecture principles with proper separation
between domain logic and implementation details.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any
from uuid import UUID


class BiometricServiceInterface(ABC):
    """
    Abstract interface for biometric data processing services.

    This interface defines the contract for operations related to biometric
    data processing, analysis, and storage, allowing different implementations
    while maintaining a consistent interface throughout the application.
    """

    @abstractmethod
    async def process_biometric_data(
        self,
        patient_id: str | UUID,
        data_type: str,
        data: dict[str, Any],
        timestamp: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[bool, str | None, str | None]:
        """
        Process incoming biometric data for a patient.

        Args:
            patient_id: Unique identifier for the patient
            data_type: Type of biometric data (e.g., 'heart_rate', 'activity')
            data: The biometric data payload
            timestamp: Optional timestamp for the data point
            metadata: Optional metadata about the data collection

        Returns:
            Tuple of (success, record_id, error_message)
        """
        raise NotImplementedError

    @abstractmethod
    async def get_biometric_data(
        self,
        patient_id: str | UUID,
        data_type: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 100,
        skip: int = 0,
    ) -> list[dict[str, Any]]:
        """
        Retrieve biometric data for a patient with optional filtering.

        Args:
            patient_id: Unique identifier for the patient
            data_type: Optional type of biometric data to filter by
            start_time: Optional start of time range
            end_time: Optional end of time range
            limit: Maximum number of records to return
            skip: Number of records to skip

        Returns:
            List of biometric data records
        """
        raise NotImplementedError

    @abstractmethod
    async def get_biometric_summary(
        self,
        patient_id: str | UUID,
        data_type: str,
        start_time: datetime,
        end_time: datetime,
        interval: str = "day",
    ) -> dict[str, Any]:
        """
        Get a summary of biometric data aggregated over time intervals.

        Args:
            patient_id: Unique identifier for the patient
            data_type: Type of biometric data to summarize
            start_time: Start of time range
            end_time: End of time range
            interval: Aggregation interval ('hour', 'day', 'week', 'month')

        Returns:
            Summary statistics and aggregated data points
        """
        raise NotImplementedError

    @abstractmethod
    async def analyze_trends(
        self,
        patient_id: str | UUID,
        data_type: str,
        start_time: datetime,
        end_time: datetime,
        analysis_type: str | None = None,
    ) -> dict[str, Any]:
        """
        Analyze trends in biometric data over time.

        Args:
            patient_id: Unique identifier for the patient
            data_type: Type of biometric data to analyze
            start_time: Start of time range
            end_time: End of time range
            analysis_type: Optional specific analysis to perform

        Returns:
            Analysis results including trends, patterns, and statistics
        """
        raise NotImplementedError

    @abstractmethod
    async def check_data_quality(
        self,
        patient_id: str | UUID,
        data_type: str,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> dict[str, Any]:
        """
        Check the quality of biometric data for a patient.

        Args:
            patient_id: Unique identifier for the patient
            data_type: Type of biometric data to check
            start_time: Optional start of time range
            end_time: Optional end of time range

        Returns:
            Quality metrics including completeness, consistency, and potential issues
        """
        raise NotImplementedError
