"""
Alert Repository Implementation.

This module provides the implementation of the alert repository interface,
ensuring HIPAA compliance and proper data handling for alerts.
"""

from datetime import datetime
from typing import Optional, Sequence

from sqlalchemy import select, between, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.domain.entities.alert import Alert, AlertPriority, AlertStatus, AlertType
from app.core.exceptions.auth_exceptions import AuthenticationError
from app.core.interfaces.repositories.alert_repository_interface import IAlertRepository
from app.core.interfaces.services.encryption_service_interface import IEncryptionService
from app.infrastructure.persistence.sqlalchemy.models.biometric_alert_model import Alert as AlertModel
from app.infrastructure.persistence.sqlalchemy.models.biometric_rule import AlertRule as AlertRuleModel
from app.infrastructure.models.user_model import UserModel


class AlertRepository(IAlertRepository):
    """
    Implementation of the alert repository interface.
    
    This repository handles CRUD operations for alerts with proper
    HIPAA compliance, including data encryption and access controls.
    """
    
    def __init__(self, db_session: AsyncSession, encryption_service: IEncryptionService):
        """
        Initialize the alert repository.
        
        Args:
            db_session: Database session for data access
            encryption_service: Service for encrypting sensitive data
        """
        self._db_session = db_session
        self._encryption_service = encryption_service
    
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
        # Create ORM model from domain entity
        alert_model = AlertModel(
            alert_type=alert.alert_type.value if isinstance(alert.alert_type, AlertType) else alert.alert_type,
            timestamp=alert.timestamp,
            status=alert.status.value if isinstance(alert.status, AlertStatus) else alert.status,
            priority=alert.priority.value if isinstance(alert.priority, AlertPriority) else alert.priority,
            message=self._encryption_service.encrypt(alert.message),  # Encrypt PHI
            data=self._encryption_service.encrypt_json(alert.data),  # Encrypt PHI
            user_id=alert.user_id,
            resolved_at=alert.resolved_at,
            resolution_notes=self._encryption_service.encrypt(alert.resolution_notes) if alert.resolution_notes else None
        )
        
        # Add to session and flush to get ID
        self._db_session.add(alert_model)
        await self._db_session.flush()
        
        # Update domain entity with generated ID
        alert.id = str(alert_model.id)
        
        return alert
    
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
        # Query for alert
        result = await self._db_session.execute(
            select(AlertModel).where(AlertModel.id == alert_id)
        )
        alert_model = result.scalars().first()
        
        if not alert_model:
            return None
            
        # Check access permissions
        if alert_model.user_id != user_id:
            # Check if user has provider access to this patient
            has_access = await self.validate_access(user_id, alert_model.user_id)
            if not has_access:
                raise AuthenticationError(f"User {user_id} does not have access to alert {alert_id}")
        
        # Convert to domain entity
        return self._to_domain_entity(alert_model)
    
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
        if not alert.id:
            raise ValueError("Alert ID is required for updates")
            
        # Query for existing alert
        result = await self._db_session.execute(
            select(AlertModel).where(AlertModel.id == alert.id)
        )
        alert_model = result.scalars().first()
        
        if not alert_model:
            raise ValueError(f"Alert with ID {alert.id} not found")
        
        # Update model fields
        alert_model.status = alert.status.value if isinstance(alert.status, AlertStatus) else alert.status
        alert_model.priority = alert.priority.value if isinstance(alert.priority, AlertPriority) else alert.priority
        alert_model.message = self._encryption_service.encrypt(alert.message)
        alert_model.data = self._encryption_service.encrypt_json(alert.data)
        alert_model.resolved_at = alert.resolved_at
        alert_model.resolution_notes = self._encryption_service.encrypt(alert.resolution_notes) if alert.resolution_notes else None
        
        # Flush changes
        await self._db_session.flush()
        
        return alert
    
    async def delete(self, alert_id: str) -> bool:
        """
        Delete an alert by ID.
        
        Args:
            alert_id: ID of the alert to delete
            
        Returns:
            True if deleted successfully, False otherwise
        """
        # Query for alert
        result = await self._db_session.execute(
            select(AlertModel).where(AlertModel.id == alert_id)
        )
        alert_model = result.scalars().first()
        
        if not alert_model:
            return False
        
        # Delete the alert
        await self._db_session.delete(alert_model)
        await self._db_session.flush()
        
        return True
    
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
    ) -> Sequence[Alert]:
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
        # Build query
        query = select(AlertModel).where(AlertModel.user_id == user_id)
        
        # Apply filters
        if status:
            status_value = status.value if isinstance(status, AlertStatus) else status
            query = query.where(AlertModel.status == status_value)
            
        if priority:
            priority_value = priority.value if isinstance(priority, AlertPriority) else priority
            query = query.where(AlertModel.priority == priority_value)
            
        if alert_type:
            alert_type_value = alert_type.value if isinstance(alert_type, AlertType) else alert_type
            query = query.where(AlertModel.alert_type == alert_type_value)
            
        if start_date and end_date:
            # Parse dates if they're strings
            start = datetime.fromisoformat(start_date) if isinstance(start_date, str) else start_date
            end = datetime.fromisoformat(end_date) if isinstance(end_date, str) else end_date
            query = query.where(between(AlertModel.timestamp, start, end))
        elif start_date:
            start = datetime.fromisoformat(start_date) if isinstance(start_date, str) else start_date
            query = query.where(AlertModel.timestamp >= start)
        elif end_date:
            end = datetime.fromisoformat(end_date) if isinstance(end_date, str) else end_date
            query = query.where(AlertModel.timestamp <= end)
            
        # Order by timestamp descending (newest first)
        query = query.order_by(desc(AlertModel.timestamp))
        
        # Apply pagination
        query = query.offset(offset).limit(limit)
        
        # Execute query
        result = await self._db_session.execute(query)
        alert_models = result.scalars().all()
        
        # Convert to domain entities
        return [self._to_domain_entity(model) for model in alert_models]
    
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
        # If user is accessing their own alerts, always allow
        if user_id == subject_id:
            return True
            
        # Check if user is a provider with access to this patient
        result = await self._db_session.execute(
            select(UserModel).where(UserModel.id == user_id)
        )
        user = result.scalars().first()
        
        if not user:
            raise AuthenticationError(f"User {user_id} not found")
            
        # TODO: Implement proper provider-patient relationship checking
        # For now, just check if user is a provider
        if user.role == "provider":
            return True
            
        raise AuthenticationError(f"User {user_id} does not have access to alerts for {subject_id}")
    
    async def can_delete_alert(self, user_id: str, alert_id: str) -> bool:
        """
        Check if a user has permission to delete an alert.
        
        Args:
            user_id: ID of the user attempting deletion
            alert_id: ID of the alert to be deleted
            
        Returns:
            True if user can delete the alert, False otherwise
        """
        # Query for alert
        result = await self._db_session.execute(
            select(AlertModel).where(AlertModel.id == alert_id)
        )
        alert_model = result.scalars().first()
        
        if not alert_model:
            return False
            
        # If user owns the alert, they can delete it
        if alert_model.user_id == user_id:
            return True
            
        # Check if user is a provider with access to this patient
        result = await self._db_session.execute(
            select(UserModel).where(UserModel.id == user_id)
        )
        user = result.scalars().first()
        
        if not user:
            return False
            
        # TODO: Implement proper provider-patient relationship checking
        # For now, just check if user is a provider
        return user.role == "provider"
    
    def _to_domain_entity(self, model: AlertModel) -> Alert:
        """
        Convert ORM model to domain entity.
        
        Args:
            model: ORM model
            
        Returns:
            Domain entity
        """
        # Decrypt sensitive data
        message = self._encryption_service.decrypt(model.message)
        data = self._encryption_service.decrypt_json(model.data)
        resolution_notes = self._encryption_service.decrypt(model.resolution_notes) if model.resolution_notes else None
        
        return Alert(
            id=str(model.id),
            alert_type=AlertType(model.alert_type),
            timestamp=model.timestamp,
            status=AlertStatus(model.status),
            priority=AlertPriority(model.priority),
            message=message,
            data=data,
            user_id=model.user_id,
            resolved_at=model.resolved_at,
            resolution_notes=resolution_notes
        )
