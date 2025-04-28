"""
BiometricAlertRepository interface.

This module defines the repository interface for BiometricAlert entities,
following the Repository pattern to abstract data access operations.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from uuid import UUID

from app.domain.services.biometric_event_processor import BiometricAlert, AlertPriority


class BiometricAlertRepository(ABC):
    """
    Repository interface for BiometricAlert entities.
    
    This abstract class defines the contract that any concrete repository
    implementation must follow for BiometricAlert data access operations.
    Handles persistence of alerts based on their acknowledged state.
    """
    
    @abstractmethod
    async def save(self, alert: BiometricAlert) -> BiometricAlert:
        """
        Save a biometric alert to the repository.
        
        Args:
            alert: The biometric alert to save
            
        Returns:
            The saved biometric alert with any updates (e.g., ID assignment)
            
        Raises:
            RepositoryError: If there's an error saving the alert
        """
        pass
    
    @abstractmethod
    async def get_by_id(self, alert_id: UUID | str) -> BiometricAlert | None:
        """
        Retrieve a biometric alert by its ID.
        
        Args:
            alert_id: ID of the alert to retrieve
            
        Returns:
            The biometric alert if found, None otherwise
            
        Raises:
            RepositoryError: If there's an error retrieving the alert
        """
        pass
    
    @abstractmethod
    async def get_by_patient_id(
        self,
        patient_id: UUID,
        acknowledged: bool | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        limit: int = 100,
        offset: int = 0
    ) -> list[BiometricAlert]:
        """
        Retrieve biometric alerts for a specific patient.
        
        Args:
            patient_id: ID of the patient
            acknowledged: Optional filter by acknowledged status (True/False)
            start_date: Optional start date for filtering
            end_date: Optional end date for filtering
            limit: Maximum number of alerts to return
            offset: Number of alerts to skip for pagination
            
        Returns:
            List of biometric alerts matching the criteria
            
        Raises:
            RepositoryError: If there's an error retrieving the alerts
        """
        pass
    
    @abstractmethod
    async def get_unacknowledged_alerts(
        self,
        priority: AlertPriority | None = None,
        patient_id: UUID | None = None,
        limit: int = 100,
        offset: int = 0
    ) -> list[BiometricAlert]:
        """
        Retrieve unacknowledged (active) biometric alerts.
        
        Args:
            priority: Optional filter by alert priority
            patient_id: Optional filter by patient ID
            limit: Maximum number of alerts to return
            offset: Number of alerts to skip for pagination
            
        Returns:
            List of active (unacknowledged) biometric alerts matching the criteria
            
        Raises:
            RepositoryError: If there's an error retrieving the alerts
        """
        pass
    
    @abstractmethod
    async def delete(self, alert_id: UUID | str) -> bool:
        """
        Delete a biometric alert from the repository.
        
        Args:
            alert_id: ID of the alert to delete
            
        Returns:
            True if the alert was deleted, False otherwise
            
        Raises:
            RepositoryError: If there's an error deleting the alert
        """
        pass
    
    @abstractmethod
    async def count_by_patient(
        self,
        patient_id: UUID,
        acknowledged: bool | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None
    ) -> int:
        """
        Count biometric alerts for a specific patient.
        
        Args:
            patient_id: ID of the patient
            acknowledged: Optional filter by acknowledged status (True/False)
            start_date: Optional start date for filtering
            end_date: Optional end date for filtering
            
        Returns:
            Number of alerts matching the criteria
            
        Raises:
            RepositoryError: If there's an error counting the alerts
        """
        pass