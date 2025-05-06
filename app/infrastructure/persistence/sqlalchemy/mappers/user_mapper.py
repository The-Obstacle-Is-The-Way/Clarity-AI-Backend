"""
User entity to SQLAlchemy model mapper.

This module provides bidirectional mapping between the domain User entity and
the SQLAlchemy User model, following clean architecture principles.
"""

from uuid import UUID

from app.domain.entities.user import User as DomainUser
from app.infrastructure.persistence.sqlalchemy.models.user import User as UserModel
from app.infrastructure.persistence.sqlalchemy.models.user import UserRole


class UserMapper:
    """
    Maps between domain User entities and SQLAlchemy User models.
    
    This follows the Adapter pattern to translate between domain and persistence layers,
    preserving clean architecture boundaries.
    """
    
    @staticmethod
    def to_domain(model: UserModel) -> DomainUser:
        """
        Convert a SQLAlchemy User model to a domain User entity.
        
        Args:
            model: SQLAlchemy User model instance
            
        Returns:
            Equivalent domain User entity
        """
        # Handle roles conversion - normalize from enum to string if needed
        roles = []
        if model.roles and isinstance(model.roles, list):
            roles = model.roles
        elif model.role:
            # Add the primary role if roles list is empty
            roles = [model.role.value]
            
        # Create domain entity from model attributes
        # Critical Fix: Map password_hash in model to hashed_password in domain entity
        return DomainUser(
            id=str(model.id),
            username=model.username,
            email=model.email,
            hashed_password=model.password_hash,  # Map password_hash to hashed_password
            is_active=model.is_active,
            is_verified=model.is_verified,
            email_verified=model.email_verified,
            roles=roles,
            role=model.role.value if model.role else None,
            first_name=model.first_name,
            last_name=model.last_name,
            created_at=model.created_at,
            updated_at=model.updated_at,
            last_login_at=model.last_login,  # Fix: Map last_login to last_login_at
            password_changed_at=model.password_changed_at,
            failed_login_attempts=model.failed_login_attempts,
            account_locked_until=model.account_locked_until,
            preferences=model.preferences
        )

    @staticmethod
    def to_persistence(entity: DomainUser) -> UserModel:
        """
        Convert a domain User entity to a SQLAlchemy User model.
        
        Args:
            entity: Domain User entity
            
        Returns:
            Equivalent SQLAlchemy User model for persistence
        """
        # Determine the UserRole enum from string value
        role = None
        if entity.role:
            try:
                role = UserRole(entity.role)
            except ValueError:
                # Default to PATIENT if role value isn't valid
                role = UserRole.PATIENT
                
        # Convert domain entity to model
        # Critical Fix: Map domain entity fields to SQLAlchemy model fields
        # - hashed_password in domain entity maps to password_hash in model
        # - last_login_at in domain entity maps to last_login in model
        model = UserModel(
            id=entity.id if isinstance(entity.id, UUID) else UUID(entity.id),
            username=entity.username,
            email=entity.email,
            password_hash=entity.hashed_password,  # Map hashed_password to password_hash
            is_active=entity.is_active,
            is_verified=entity.is_verified,
            email_verified=entity.email_verified,
            role=role,
            roles=[r for r in entity.roles if isinstance(r, str)],
            first_name=entity.first_name,
            last_name=entity.last_name,
            created_at=entity.created_at,
            updated_at=entity.updated_at,
            last_login=entity.last_login_at,  # Map last_login_at to last_login
            password_changed_at=entity.password_changed_at,
            failed_login_attempts=entity.failed_login_attempts,
            account_locked_until=entity.account_locked_until,
            preferences=entity.preferences
        )
        
        return model
        
    @staticmethod
    def update_persistence_model(model: UserModel, entity: DomainUser) -> UserModel:
        """
        Update an existing SQLAlchemy User model with values from a domain entity.
        
        This is used for partial updates when a full model replacement is not needed.
        
        Args:
            model: Existing SQLAlchemy User model to update
            entity: Domain User entity with new values
            
        Returns:
            Updated SQLAlchemy User model
        """
        # Only update fields that are not None in the entity
        if entity.username is not None:
            model.username = entity.username
            
        if entity.email is not None:
            model.email = entity.email
            
        # Critical Fix: Map hashed_password in domain entity to password_hash in model
        if entity.hashed_password is not None:
            model.password_hash = entity.hashed_password
            
        if entity.is_active is not None:
            model.is_active = entity.is_active
            
        if entity.is_verified is not None:
            model.is_verified = entity.is_verified
            
        if entity.email_verified is not None:
            model.email_verified = entity.email_verified
        
        if entity.role is not None:
            try:
                model.role = UserRole(entity.role)
            except ValueError:
                pass  # Keep existing role if new one is invalid
                
        if entity.roles:
            model.roles = [r for r in entity.roles if isinstance(r, str)]
            
        if entity.first_name is not None:
            model.first_name = entity.first_name
            
        if entity.last_name is not None:
            model.last_name = entity.last_name
            
        # Critical Fix: Map last_login_at in domain entity to last_login in model
        if entity.last_login_at is not None:
            model.last_login = entity.last_login_at
            
        if entity.preferences is not None:
            model.preferences = entity.preferences
            
        return model
