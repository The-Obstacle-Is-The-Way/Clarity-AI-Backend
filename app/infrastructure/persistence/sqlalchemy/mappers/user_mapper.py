"""
User entity to SQLAlchemy model mapper.

This module provides bidirectional mapping between the domain User entity and
the SQLAlchemy User model, following clean architecture principles.
"""

from uuid import UUID

from app.core.domain.entities.user import User as DomainUser
from app.core.domain.entities.user import UserRole as DomainUserRole
from app.infrastructure.persistence.sqlalchemy.models.user import User as UserModel
from app.infrastructure.persistence.sqlalchemy.models.user import UserRole as PersistenceUserRole


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
        if model is None:
            # Or raise an exception, depending on desired behavior for None input
            return None 

        # Convert roles from UserModel to a set of DomainUser UserRole enums
        domain_roles = set()
        if hasattr(model, 'roles') and model.roles:
            for role_in_model in model.roles:
                try:
                    # Assuming roles in model are string values or UserRole enum members from persistence layer
                    role_value = role_in_model.value if hasattr(role_in_model, 'value') else str(role_in_model)
                    domain_roles.add(DomainUserRole(role_value))
                except ValueError as e_role:
                    # Log or handle invalid role values from DB if necessary
                    print(f"Warning: Invalid role value '{role_in_model}' from DB for user {model.id}: {e_role}")
                    pass # Or raise, or assign a default role
        
        # Construct full_name
        full_name_parts = []
        if hasattr(model, 'first_name') and model.first_name:
            full_name_parts.append(model.first_name)
        if hasattr(model, 'last_name') and model.last_name:
            full_name_parts.append(model.last_name)
        full_name = " ".join(full_name_parts).strip()
        if not full_name and hasattr(model, 'username'): # Fallback to username if full_name is empty
            full_name = model.username

        # Create the domain entity using its constructor
        domain_user_data = {
            "id": model.id, # Assuming model.id is UUID
            "email": model.email if hasattr(model, 'email') else "",
            "username": model.username if hasattr(model, 'username') else "",
            "full_name": full_name,
            "password_hash": model.password_hash if hasattr(model, 'password_hash') else "",
            "roles": domain_roles,
        }
        # Add optional fields with defaults if they exist on the model
        if hasattr(model, 'created_at'):
            domain_user_data['created_at'] = model.created_at
        if hasattr(model, 'last_login'):
            domain_user_data['last_login'] = model.last_login
        if hasattr(model, 'mfa_enabled'):
            domain_user_data['mfa_enabled'] = model.mfa_enabled
        if hasattr(model, 'mfa_secret'):
            domain_user_data['mfa_secret'] = model.mfa_secret
        if hasattr(model, 'failed_login_attempts'): # Note: DomainUser calls this 'attempts'
            domain_user_data['attempts'] = model.failed_login_attempts
        # Add other fields like reset_token, reset_token_expires if they exist on UserModel

        # Instantiate DomainUser
        # Note: DomainUser's 'attempts' field might need mapping from 'failed_login_attempts'
        # if DomainUser field is 'attempts', and ORM is 'failed_login_attempts', then map explicitly
        # For now, assuming DomainUser takes these named args or they are handled by **domain_user_data

        # Temporary: map 'failed_login_attempts' from ORM to 'attempts' for DomainUser constructor
        # This is a common mismatch point needing explicit handling if names differ.
        # For this edit, we will assume the DomainUser constructor can take 'failed_login_attempts'
        # if it exists in domain_user_data, or that 'attempts' is the correct key there.
        # The DomainUser dataclass has 'attempts', so we should map to that.
        if 'failed_login_attempts' in domain_user_data:
            domain_user_data['attempts'] = domain_user_data.pop('failed_login_attempts')


        domain_user = DomainUser(**domain_user_data)

        # Set account_status based on ORM model.is_active
        if hasattr(model, 'is_active') and model.is_active is True:
            domain_user.activate()  # This sets domain_user.account_status
        elif hasattr(model, 'is_active') and model.is_active is False:
            domain_user.deactivate() # This sets domain_user.account_status
        # If model.is_active is None or not present, account_status remains its default (PENDING_VERIFICATION)
        
        return domain_user

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
                role = PersistenceUserRole(entity.role)
            except ValueError:
                # Default to PATIENT if role value isn't valid
                role = PersistenceUserRole.PATIENT
                
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
                model.role = PersistenceUserRole(entity.role)
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
