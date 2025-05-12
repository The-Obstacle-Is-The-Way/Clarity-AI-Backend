"""
User entity definition module.

This module defines the User entity as a domain object with its
attributes, behaviors, and invariants following Domain-Driven Design principles.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from uuid import UUID, uuid4

from app.core.utils.date_utils import utcnow


class UserRole(str, Enum):
    """Enum for available user roles within the system."""
    ADMIN = "admin"
    CLINICIAN = "clinician"
    RESEARCHER = "researcher"
    PATIENT = "patient"
    TECHNICIAN = "technician"


class UserStatus(str, Enum):
    """Enum for possible user account statuses."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING_VERIFICATION = "pending_verification"


@dataclass
class User:
    """
    User entity representing system users in the domain model.
    
    This class encapsulates the core attributes and behaviors of users
    in the system, enforcing business rules and invariants directly within
    the domain model according to Domain-Driven Design principles.
    
    Attributes:
        id: Unique identifier for the user
        email: Email address (unique within the system)
        username: Username (unique within the system)
        full_name: User's full name
        password_hash: Securely hashed password
        roles: Set of roles assigned to this user
        account_status: Current account status
        created_at: When the account was created
        last_login: When the user last logged in
        mfa_enabled: Whether multi-factor authentication is enabled
        attempts: Number of consecutive failed login attempts
    """
    email: str
    username: str
    full_name: str
    password_hash: str
    id: UUID = field(default_factory=uuid4)
    roles: set[UserRole] = field(default_factory=lambda: {UserRole.PATIENT})
    account_status: UserStatus = UserStatus.PENDING_VERIFICATION
    created_at: datetime = field(default_factory=utcnow)
    last_login: datetime | None = None
    mfa_enabled: bool = False
    mfa_secret: str | None = None
    attempts: int = 0
    reset_token: str | None = None
    reset_token_expires: datetime | None = None

    def __post_init__(self):
        """Validate the entity after initialization."""
        self._validate()
        
    def _validate(self):
        """
        Validate entity invariants.
        
        Raises:
            ValueError: If any invariants are violated
        """
        if not self.email:
            raise ValueError("Email cannot be empty")
        if not self.username:
            raise ValueError("Username cannot be empty")
        if not self.full_name:
            raise ValueError("Full name cannot be empty")
        if not self.password_hash:
            raise ValueError("Password hash cannot be empty")
        
    def has_role(self, role: UserRole) -> bool:
        """
        Check if the user has a specific role.
        
        Args:
            role: The role to check for
            
        Returns:
            True if the user has the role, False otherwise
        """
        return role in self.roles
        
    def add_role(self, role: UserRole) -> None:
        """
        Add a role to the user.
        
        Args:
            role: The role to add
        """
        self.roles.add(role)
        
    def remove_role(self, role: UserRole) -> None:
        """
        Remove a role from the user.
        
        Args:
            role: The role to remove
        """
        if role in self.roles and len(self.roles) > 1:
            self.roles.remove(role)
            
    def activate(self) -> None:
        """Activate the user account."""
        self.account_status = UserStatus.ACTIVE
        
    def deactivate(self) -> None:
        """Deactivate the user account."""
        self.account_status = UserStatus.INACTIVE
        
    def suspend(self) -> None:
        """Suspend the user account."""
        self.account_status = UserStatus.SUSPENDED
        
    def record_login(self) -> None:
        """Record a successful login."""
        self.last_login = utcnow()
        self.attempts = 0
        
    def record_login_attempt(self) -> None:
        """Record a failed login attempt."""
        self.attempts += 1
        
    def reset_attempts(self) -> None:
        """Reset the failed login attempt counter."""
        self.attempts = 0
        
    def enable_mfa(self, secret: str) -> None:
        """
        Enable multi-factor authentication.
        
        Args:
            secret: The MFA secret key
        """
        self.mfa_enabled = True
        self.mfa_secret = secret
        
    def disable_mfa(self) -> None:
        """Disable multi-factor authentication."""
        self.mfa_enabled = False
        self.mfa_secret = None
        
    def set_reset_token(self, token: str, expires: datetime) -> None:
        """
        Set a password reset token.
        
        Args:
            token: The reset token
            expires: When the token expires
        """
        self.reset_token = token
        self.reset_token_expires = expires
        
    def clear_reset_token(self) -> None:
        """Clear the password reset token."""
        self.reset_token = None
        self.reset_token_expires = None
        
    def is_reset_token_valid(self, token: str) -> bool:
        """
        Check if a reset token is valid.
        
        Args:
            token: The token to check
            
        Returns:
            True if the token matches and hasn't expired, False otherwise
        """
        if not self.reset_token or not self.reset_token_expires:
            return False
            
        if self.reset_token != token:
            return False
            
        return utcnow() < self.reset_token_expires
        
    @property
    def is_active(self) -> bool:
        """Whether the user account is active."""
        return self.account_status == UserStatus.ACTIVE
        
    @property
    def lockout_triggered(self) -> bool:
        """Whether the account should be locked due to too many failed attempts."""
        return self.attempts >= 5  # Configurable threshold