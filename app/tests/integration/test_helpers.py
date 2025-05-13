"""
Test Helper Utilities

This module provides helper utilities for testing, particularly focused on
authentication, database setup, and mocking common dependencies.
"""

import uuid
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Union

from fastapi import FastAPI, Depends
from jose import jwt
from unittest.mock import AsyncMock, MagicMock

from app.core.domain.entities.user import User, UserRole, UserStatus
from app.presentation.api.dependencies.auth import (
    get_current_user,
    get_current_active_user,
    require_admin_role,
    require_clinician_role,
)


logger = logging.getLogger(__name__)


class AuthBypass:
    """
    Helper class for bypassing authentication in tests
    
    This class provides methods for:
    1. Creating test users with specified roles
    2. Overriding authentication dependencies in FastAPI
    3. Generating valid JWT tokens for test users
    """
    
    def __init__(self):
        """Initialize the AuthBypass helper"""
        self.test_secret_key = "test_secret_key_for_testing_only"
        self.algorithm = "HS256"
        self._users = {}  # cache of users by role
        self._tokens = {}  # cache of tokens by user ID
        
        # Map of standard role UUIDs for consistent testing
        self.role_uuid_map = {
            UserRole.ADMIN: "00000000-0000-0000-0000-000000000001",
            UserRole.CLINICIAN: "00000000-0000-0000-0000-000000000002", 
            UserRole.PATIENT: "00000000-0000-0000-0000-000000000003",
            UserRole.RESEARCHER: "00000000-0000-0000-0000-000000000004",
        }
        
    def create_test_user(
        self, 
        role: Union[UserRole, str],
        user_id: Optional[Union[uuid.UUID, str]] = None,
        username: Optional[str] = None,
        email: Optional[str] = None,
        full_name: Optional[str] = None,
        account_status: Optional[UserStatus] = None,
    ) -> User:
        """
        Create a test user with the specified role
        
        Args:
            role: UserRole enum value or string role name
            user_id: Optional UUID for the user (generated if None)
            username: Optional username (generated if None)
            email: Optional email (generated if None)
            full_name: Optional full name (generated if None)
            account_status: Optional account status (defaults to ACTIVE)
            
        Returns:
            User: Test user with the specified role
        """
        # Convert string role to UserRole enum if needed
        if isinstance(role, str):
            try:
                role = UserRole(role.lower())
            except ValueError:
                logger.warning(f"Invalid role string: {role}, defaulting to PATIENT")
                role = UserRole.PATIENT
                
        # Generate user ID if not provided
        if user_id is None:
            # Use predictable UUIDs for standard roles
            user_id = uuid.UUID(self.role_uuid_map.get(role, str(uuid.uuid4())))
        elif isinstance(user_id, str):
            user_id = uuid.UUID(user_id)
            
        # Generate default values based on role
        role_name = role.name.lower()
        if username is None:
            username = f"test_{role_name}"
        if email is None:
            email = f"test.{role_name}@clarity.health"
        if full_name is None:
            full_name = f"Test {role_name.title()}"
        if account_status is None:
            account_status = UserStatus.ACTIVE
            
        # Create the user with consistent structure
        user = User(
            id=user_id,
            username=username,
            email=email,
            full_name=full_name,
            password_hash="$2b$12$TestPasswordHashForTestingOnly",
            roles={role},  # Always use a set for roles
            account_status=account_status
        )
        
        # Cache the user by role for later retrieval
        self._users[role] = user
        
        return user
        
    def get_user_by_role(self, role: Union[UserRole, str]) -> User:
        """
        Get or create a test user with the specified role
        
        Args:
            role: UserRole enum value or string role name
            
        Returns:
            User: Test user with the specified role
        """
        # Convert string role to UserRole enum if needed
        if isinstance(role, str):
            try:
                role = UserRole(role.lower())
            except ValueError:
                logger.warning(f"Invalid role string: {role}, defaulting to PATIENT")
                role = UserRole.PATIENT
                
        # Get cached user or create a new one
        user = self._users.get(role)
        if user is None:
            user = self.create_test_user(role)
            
        return user
        
    def create_token(
        self, 
        user_or_id: Union[User, uuid.UUID, str],
        roles: Optional[List[str]] = None,
        username: Optional[str] = None,
        email: Optional[str] = None,
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Create a JWT token for testing
        
        Args:
            user_or_id: User instance, UUID, or string UUID for the token subject
            roles: Optional list of role strings (extracted from user if None)
            username: Optional username (extracted from user if None)
            email: Optional email (extracted from user if None)
            expires_delta: Optional timedelta for token expiration
            
        Returns:
            str: JWT token
        """
        # Extract user ID and info if a User instance was provided
        user_id = None
        if isinstance(user_or_id, User):
            user = user_or_id
            user_id = user.id
            if username is None:
                username = user.username
            if email is None:
                email = user.email
            if roles is None and hasattr(user, 'roles'):
                # Convert roles from UserRole enum to strings
                roles = [role.value if hasattr(role, 'value') else str(role) for role in user.roles]
        else:
            # Handle UUID or string UUID
            if isinstance(user_or_id, str):
                user_id = uuid.UUID(user_or_id)
            else:
                user_id = user_or_id
                
        # Convert user_id to string
        user_id_str = str(user_id)
                
        # Set defaults for token fields
        roles = roles or ["patient"]
        expires = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=30))
        
        # Create token payload
        payload = {
            "sub": user_id_str,
            "username": username or f"user_{user_id_str[:8]}",
            "email": email or f"user_{user_id_str[:8]}@clarity.health",
            "roles": roles,
            "exp": int(expires.timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "jti": str(uuid.uuid4()),
            "iss": "test-issuer",
            "aud": "test-audience",
            "type": "access"
        }
        
        # Encode the token
        token = jwt.encode(payload, self.test_secret_key, algorithm=self.algorithm)
        
        # Cache the token
        self._tokens[user_id_str] = token
        
        return token
        
    def get_auth_headers(
        self, 
        user_or_role: Union[User, UserRole, str]
    ) -> Dict[str, str]:
        """
        Get authentication headers for a user or role
        
        Args:
            user_or_role: User instance, UserRole enum, or string role name
            
        Returns:
            Dict[str, str]: Headers dictionary with Authorization key
        """
        # Handle different types of input
        if isinstance(user_or_role, User):
            # Use the provided User instance
            user = user_or_role
        elif isinstance(user_or_role, UserRole):
            # Get or create a test user with this role
            user = self.get_user_by_role(user_or_role)
        elif isinstance(user_or_role, str):
            # Check if it's a role name
            try:
                role = UserRole(user_or_role.lower())
                user = self.get_user_by_role(role)
            except ValueError:
                # Treat as a user_id
                token = self.create_token(user_or_role)
                return {"Authorization": f"Bearer {token}"}
        else:
            # Default to patient role
            user = self.get_user_by_role(UserRole.PATIENT)
            
        # Get or create token
        token = self._tokens.get(str(user.id))
        if token is None:
            token = self.create_token(user)
            
        return {"Authorization": f"Bearer {token}"}
        
    def get_test_auth_header(self, role: str = "patient") -> Dict[str, str]:
        """
        Get a test authentication header with the specified role
        
        This is a shorthand for get_auth_headers with a role string,
        providing a quick way to get test headers.
        
        Args:
            role: Role name as string (admin, clinician, patient, researcher)
            
        Returns:
            Dict[str, str]: Headers dictionary with Authorization and X-Test-Auth-Bypass keys
        """
        # Get user ID for the role
        try:
            role_enum = UserRole(role.lower())
            user_id = self.role_uuid_map.get(role_enum, str(uuid.uuid4()))
        except ValueError:
            user_id = str(uuid.uuid4())
            
        # Return both Bearer token and X-Test-Auth-Bypass
        return {
            "Authorization": f"Bearer {self.create_token(user_id, roles=[role])}",
            "X-Test-Auth-Bypass": f"{role}:{user_id}"
        }
        
    def override_auth_dependencies(self, app: FastAPI, role: Union[UserRole, str] = UserRole.PATIENT):
        """
        Override authentication dependencies in a FastAPI app
        
        This overrides all common authentication dependencies with a
        function that returns a test user with the specified role.
        
        Args:
            app: FastAPI application instance
            role: UserRole enum or string role name for the test user
            
        Returns:
            dict: The original dependency_overrides dict (for restoration if needed)
        """
        # Convert string role to UserRole enum if needed
        if isinstance(role, str):
            try:
                role = UserRole(role.lower())
            except ValueError:
                logger.warning(f"Invalid role string: {role}, defaulting to PATIENT")
                role = UserRole.PATIENT
                
        # Get or create a test user with this role
        test_user = self.get_user_by_role(role)
        
        # Create an async function that returns the test user
        async def get_test_user():
            return test_user
        
        # Save original overrides
        original_overrides = app.dependency_overrides.copy()
        
        # Override all common auth dependencies
        app.dependency_overrides[get_current_user] = get_test_user
        app.dependency_overrides[get_current_active_user] = get_test_user
        
        # Role-specific dependencies - override only if the test user has that role
        roles = [r.value for r in test_user.roles]
        if UserRole.ADMIN.value in roles:
            app.dependency_overrides[require_admin_role] = get_test_user
        if UserRole.CLINICIAN.value in roles:
            app.dependency_overrides[require_clinician_role] = get_test_user
        if UserRole.PATIENT.value in roles:
            app.dependency_overrides[require_patient_role] = get_test_user
        if UserRole.RESEARCHER.value in roles:
            app.dependency_overrides[require_researcher_role] = get_test_user
            
        return original_overrides
        
    def restore_auth_dependencies(self, app: FastAPI, original_overrides: Dict[Any, Any]):
        """
        Restore original authentication dependencies
        
        Args:
            app: FastAPI application instance
            original_overrides: Original dependency_overrides dict from override_auth_dependencies
        """
        app.dependency_overrides = original_overrides
        
        
# Create a global auth_bypass instance for convenience
auth_bypass = AuthBypass() 