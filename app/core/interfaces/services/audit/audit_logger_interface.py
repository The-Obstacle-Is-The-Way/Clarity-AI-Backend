"""
Audit Logger Interface.

This module defines the interface for audit logging operations required 
for HIPAA compliance and security auditing purposes.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, Optional, Union
from uuid import UUID


class IAuditLogger(ABC):
    """
    Interface for audit logging operations.
    
    This interface encapsulates the functionality required for logging
    security and compliance-related events in accordance with HIPAA
    regulations and other security best practices.
    
    Implementations must ensure audit logs do not contain any PHI
    or sensitive data that would violate privacy requirements.
    """
    
    @abstractmethod
    async def log_auth_event(
        self,
        event_type: str,
        user_id: Optional[Union[str, UUID]] = None,
        success: bool = True,
        details: Optional[Dict[str, Any]] = None,
        timestamp: Optional[datetime] = None,
        request_id: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """
        Log an authentication or authorization related event.
        
        Args:
            event_type: Type of auth event (login, logout, token_refresh, etc.)
            user_id: ID of the user related to the event, if available
            success: Whether the auth action was successful
            details: Additional context about the event (NO PHI)
            timestamp: Event timestamp, defaults to current time if None
            request_id: ID of the associated request for correlation
            ip_address: IP address of the client, if available
            
        Returns:
            None
            
        Raises:
            AuditLogError: If logging fails
        """
        pass
    
    @abstractmethod
    async def log_data_access(
        self,
        data_type: str,
        action: str,
        user_id: Union[str, UUID],
        resource_id: Optional[Union[str, UUID]] = None,
        success: bool = True,
        reason: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        request_id: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """
        Log a data access event for auditing purposes.
        
        Args:
            data_type: Type of data accessed (patient, provider, etc.)
            action: Action performed (read, write, delete, etc.)
            user_id: ID of the user performing the access
            resource_id: ID of the resource being accessed (if applicable)
            success: Whether the access was successful
            reason: Reason for access or denial
            timestamp: Event timestamp, defaults to current time if None
            request_id: ID of the associated request for correlation
            ip_address: IP address of the client, if available
            
        Returns:
            None
            
        Raises:
            AuditLogError: If logging fails
        """
        pass
    
    @abstractmethod
    async def log_security_event(
        self,
        event_type: str,
        severity: str,
        details: Dict[str, Any],
        user_id: Optional[Union[str, UUID]] = None,
        timestamp: Optional[datetime] = None,
        request_id: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """
        Log a security event such as suspicious activity or system change.
        
        Args:
            event_type: Type of security event
            severity: Severity level (low, medium, high, critical)
            details: Details about the security event (NO PHI)
            user_id: ID of the related user, if applicable
            timestamp: Event timestamp, defaults to current time if None
            request_id: ID of the associated request for correlation
            ip_address: IP address of the client, if available
            
        Returns:
            None
            
        Raises:
            AuditLogError: If logging fails
        """
        pass
    
    @abstractmethod
    async def get_audit_logs(
        self,
        event_type: Optional[str] = None,
        user_id: Optional[Union[str, UUID]] = None,
        resource_id: Optional[Union[str, UUID]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Dict[str, Any]]:
        """
        Retrieve audit logs based on filter criteria.
        
        Args:
            event_type: Filter by event type
            user_id: Filter by user ID
            resource_id: Filter by resource ID
            start_time: Filter by start time
            end_time: Filter by end time
            limit: Maximum number of records to return
            offset: Offset for pagination
            
        Returns:
            List of audit log entries matching the criteria
            
        Raises:
            AuditLogError: If retrieval fails
        """
        pass