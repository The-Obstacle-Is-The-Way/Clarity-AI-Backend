"""
Interface for Audit Log Repository.

This module defines the interface for repository classes that handle 
HIPAA-compliant audit log persistence operations.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Dict, Optional, Any

from app.domain.entities.audit_log import AuditLog


class IAuditLogRepository(ABC):
    """
    Interface for audit log repositories.

    This interface follows the Interface Segregation Principle (ISP) from SOLID,
    defining the contract for repositories that handle audit log persistence.
    """

    @abstractmethod
    async def create(self, audit_log: AuditLog) -> str:
        """
        Create a new audit log entry.

        Args:
            audit_log: The audit log entry to create

        Returns:
            str: ID of the created audit log entry
        """
        pass

    @abstractmethod
    async def get_by_id(self, log_id: str) -> Optional[AuditLog]:
        """
        Retrieve an audit log entry by its ID.

        Args:
            log_id: ID of the audit log entry

        Returns:
            Optional[AuditLog]: The audit log entry if found, None otherwise
        """
        pass

    @abstractmethod
    async def search(
        self,
        filters: Optional[Dict[str, Any]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditLog]:
        """
        Search for audit log entries based on filters.

        Args:
            filters: Filters to apply to the search
            start_time: Start time for time-range filtering
            end_time: End time for time-range filtering
            limit: Maximum number of results to return
            offset: Offset for pagination

        Returns:
            List[AuditLog]: List of matching audit log entries
        """
        pass

    @abstractmethod
    async def get_statistics(
        self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Get statistics about audit logs for the specified time period.

        Args:
            start_time: Start time for time-range filtering
            end_time: End time for time-range filtering

        Returns:
            Dict[str, Any]: Statistics about audit logs
        """
        pass
