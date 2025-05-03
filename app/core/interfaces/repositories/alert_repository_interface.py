"""
Alert Repository Interface.

This module defines the interface for alert repositories following the repository pattern,
enabling clean architecture with proper separation between domain and infrastructure layers.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any

from app.core.domain.entities.alert import Alert, AlertStatus, AlertPriority, AlertType


class AlertRepositoryInterface(ABC):
    """
    Interface for alert repository implementations.
    
    This interface defines the contract for all alert repository implementations,
    ensuring HIPAA compliance through proper data handling, encryption, and access controls.
    """
    
    @abstractmethod
    async def create(self, alert: Alert) -> Alert:
        """
        Create a new alert record.
        
        Args:
            alert: Alert entity to create
            
        Returns:
            Created alert with generated ID
            
        Raises:
            ValueError: If alert data is invalid
        """
        pass
    
    @abstractmethod
    async def get_by_id(self, alert_id: str, user_id: str) -> Optional[Alert]:
        """
        Get an alert by its ID with access control.
        
        Args:
            alert_id: ID of the alert to retrieve
            user_id: ID of the user requesting access (for access control)
            
        Returns:
            Alert entity if found and access allowed, None otherwise
            
        Raises:
            AuthenticationError: If user does not have permission to access this alert
        """
        pass
    
    @abstractmethod
    async def update(self, alert: Alert) -> Alert:
        """
        Update an existing alert.
        
        Args:
            alert: Alert entity with updated data
            
        Returns:
            Updated alert entity
            
        Raises:
            ValueError: If alert not found or data invalid
            AuthenticationError: If user does not have permission to update
        """
        pass
    
    @abstractmethod
    async def delete(self, alert_id: str) -> bool:
        """
        Delete an alert by ID.
        
        Args:
            alert_id: ID of the alert to delete
            
        Returns:
            True if deleted successfully, False otherwise
        """
        pass
    
    @abstractmethod
    async def get_alerts(
        self,
        user_id: str,
        status: Optional[AlertStatus] = None,
        priority: Optional[AlertPriority] = None,
        alert_type: Optional[AlertType] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Alert]:
        """
        Get alerts with optional filtering.
        
        Args:
            user_id: ID of the user the alerts belong to
            status: Optional filter by alert status
            priority: Optional filter by alert priority
            alert_type: Optional filter by alert type
            start_date: Optional filter by start date (ISO format)
            end_date: Optional filter by end date (ISO format)
            limit: Maximum number of records to return
            offset: Number of records to skip
            
        Returns:
            List of alert entities matching criteria
        """
        pass
    
    @abstractmethod
    async def validate_access(self, user_id: str, subject_id: str) -> bool:
        """
        Validate if a user has access to a subject's alerts.
        
        Args:
            user_id: ID of the user requesting access
            subject_id: ID of the subject (patient) whose alerts are being accessed
            
        Returns:
            True if access is allowed, False otherwise
            
        Raises:
            AuthenticationError: If access is not allowed
        """
        pass
    
    @abstractmethod
    async def can_delete_alert(self, user_id: str, alert_id: str) -> bool:
        """
        Check if a user has permission to delete an alert.
        
        Args:
            user_id: ID of the user attempting deletion
            alert_id: ID of the alert to be deleted
            
        Returns:
            True if user can delete the alert, False otherwise
        """
        pass
