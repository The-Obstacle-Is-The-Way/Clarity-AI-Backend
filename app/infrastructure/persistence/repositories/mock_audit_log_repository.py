"""
Mock Audit Log Repository for Testing.

This module provides a mock implementation of the audit log repository
that doesn't require database access. This is primarily used for testing.
"""

from datetime import datetime
from typing import Any

from app.core.interfaces.repositories.audit_log_repository_interface import (
    IAuditLogRepository,
)
from app.domain.entities.audit_log import AuditLog


class MockAuditLogRepository(IAuditLogRepository):
    """
    Mock implementation of the audit log repository for testing.

    This repository stores audit logs in memory and doesn't interact with a database.
    """

    def __init__(self):
        """Initialize the mock repository with an empty logs collection."""
        self.logs: dict[str, AuditLog] = {}

    async def create(self, audit_log: AuditLog) -> str:
        """
        Store an audit log in memory.

        Args:
            audit_log: The audit log to store

        Returns:
            str: The ID of the stored audit log
        """
        log_id = audit_log.id
        self.logs[log_id] = audit_log
        return log_id

    async def get_by_id(self, log_id: str) -> AuditLog | None:
        """
        Retrieve an audit log by ID.

        Args:
            log_id: The ID of the audit log to retrieve

        Returns:
            Optional[AuditLog]: The audit log if found, None otherwise
        """
        return self.logs.get(log_id)

    async def search(
        self,
        filters: dict[str, Any] | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditLog]:
        """
        Search for audit logs based on filters.

        Args:
            filters: Filters to apply to the search
            start_time: Start time for time-range filtering
            end_time: End time for time-range filtering
            limit: Maximum number of results to return
            offset: Offset for pagination

        Returns:
            List[AuditLog]: List of matching audit logs
        """
        # Apply basic filtering
        results = list(self.logs.values())

        # Apply filters
        if filters:
            filtered_results = []
            for log in results:
                match = True
                for key, value in filters.items():
                    log_value = getattr(log, key, None)
                    if log_value != value:
                        match = False
                        break
                if match:
                    filtered_results.append(log)
            results = filtered_results

        # Apply time filtering
        if start_time:
            results = [log for log in results if log.timestamp >= start_time]
        if end_time:
            results = [log for log in results if log.timestamp <= end_time]

        # Apply pagination
        results = results[offset : offset + limit]

        return results

    async def get_statistics(
        self, start_time: datetime | None = None, end_time: datetime | None = None
    ) -> dict[str, Any]:
        """
        Get statistics about audit logs for the specified time period.

        Args:
            start_time: Start time for time-range filtering
            end_time: End time for time-range filtering

        Returns:
            Dict[str, Any]: Statistics about audit logs
        """
        # Filter logs by time period
        filtered_logs = list(self.logs.values())
        if start_time:
            filtered_logs = [log for log in filtered_logs if log.timestamp >= start_time]
        if end_time:
            filtered_logs = [log for log in filtered_logs if log.timestamp <= end_time]

        # Calculate basic statistics
        return {
            "total_logs": len(filtered_logs),
            "event_types": len(set(log.event_type for log in filtered_logs)),
            "users": len(set(log.actor_id for log in filtered_logs if log.actor_id)),
        }
