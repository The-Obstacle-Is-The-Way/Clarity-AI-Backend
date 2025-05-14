# Password Handler Interface

## Overview

The Password Handler Interface is a cornerstone of the Clarity AI Backend's security architecture, providing a clean abstraction for password hashing, verification, and security policy enforcement. This document outlines the design, implementation patterns, and security considerations for the password handling system according to clean architecture principles.

## Architectural Significance

In a healthcare-focused digital twin platform with HIPAA requirements, secure password management is critical. The `IPasswordHandler` interface represents a core security boundary that:

1. **Isolates Cryptographic Logic**: Keeps password hashing implementations separate from business logic
2. **Enables Security Updates**: Allows cryptographic algorithms to be upgraded without affecting other system components
3. **Enforces Consistent Security**: Provides a central implementation of password security policies
4. **Facilitates Testing**: Makes it possible to test authentication flows without cryptographic complexity

## Interface Definition

The `IPasswordHandler` interface is defined in the core layer and serves as a contract for password operations:

```python
from abc import ABC, abstractmethod
from typing import Dict, Optional, Tuple

class IPasswordHandler(ABC):
    """
    Interface for password management operations.
    
    This interface defines the contract for secure password handling,
    including hashing, verification, and policy enforcement.
    """
    
    @abstractmethod
    async def hash_password(self, password: str) -> str:
        """
        Hash a password using a secure algorithm with salt.
        
        Args:
            password: The plain text password to hash
            
        Returns:
            Secure hash of the password (including algorithm, salt, and hash parameters)
        """
        pass
    
    @abstractmethod
    async def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash.
        
        Args:
            plain_password: The plain text password to verify
            hashed_password: The hashed password to compare against
            
        Returns:
            True if the password matches, False otherwise
        """
        pass
    
    @abstractmethod
    async def password_meets_requirements(self, password: str) -> Tuple[bool, Optional[Dict[str, str]]]:
        """
        Check if a password meets security requirements.
        
        Args:
            password: The password to check
            
        Returns:
            Tuple containing:
              - Boolean indicating if password meets requirements
              - Dictionary of validation errors (if any, None otherwise)
        """
        pass
    
    @abstractmethod
    async def needs_rehash(self, hashed_password: str) -> bool:
        """
        Check if a password hash needs to be upgraded.
        
        This method determines if the hash was created with outdated
        algorithms or parameters and should be upgraded.
        
        Args:
            hashed_password: The existing password hash
            
        Returns:
            True if the password should be rehashed with current parameters
        """
        pass
    
    @abstractmethod
    async def generate_secure_password(self, length: int = 16) -> str:
        """
        Generate a cryptographically secure random password.
        
        Args:
            length: Length of the password to generate
            
        Returns:
            Secure random password meeting all requirements
        """
        pass
```

## Implementation Classes

### Standard Implementation

The concrete implementation of `IPasswordHandler` uses modern cryptographic libraries:

```python
from app.core.interfaces.security.password_handler_interface import IPasswordHandler
from app.core.config import Settings
import bcrypt
import re
import secrets
import string
from typing import Dict, Optional, Tuple

class PasswordHandler(IPasswordHandler):
    """
    Standard implementation of IPasswordHandler using bcrypt.
    
    This implementation enforces HIPAA-compliant password policies and
    uses bcrypt for secure password hashing with automatic salt generation.
    """
    
    def __init__(self, settings: Settings):
        """
        Initialize the password handler with application settings.
        
        Args:
            settings: Application settings containing password policy configuration
        """
        self._settings = settings
        
        # Define password policy parameters
        self._min_length = settings.PASSWORD_MIN_LENGTH
        self._require_uppercase = settings.PASSWORD_REQUIRE_UPPERCASE
        self._require_lowercase = settings.PASSWORD_REQUIRE_LOWERCASE
        self._require_digit = settings.PASSWORD_REQUIRE_DIGIT
        self._require_special = settings.PASSWORD_REQUIRE_SPECIAL
        self._max_attempts = settings.PASSWORD_MAX_ATTEMPTS
        self._bcrypt_rounds = settings.PASSWORD_BCRYPT_ROUNDS
        
    async def hash_password(self, password: str) -> str:
        """
        Hash a password using bcrypt with secure parameters.
        
        Args:
            password: The plain text password to hash
            
        Returns:
            Secure hash of the password
        """
        # Encode password to bytes (bcrypt requirement)
        password_bytes = password.encode('utf-8')
        
        # Generate salt with specified number of rounds
        salt = bcrypt.gensalt(rounds=self._bcrypt_rounds)
        
        # Hash the password with the salt
        hashed = bcrypt.hashpw(password_bytes, salt)
        
        # Return the hash as a string
        return hashed.decode('utf-8')
    
    async def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash using bcrypt.
        
        Args:
            plain_password: The plain text password to verify
            hashed_password: The hashed password to compare against
            
        Returns:
            True if the password matches, False otherwise
        """
        # Encode inputs to bytes (bcrypt requirement)
        plain_password_bytes = plain_password.encode('utf-8')
        hashed_password_bytes = hashed_password.encode('utf-8')
        
        # Use bcrypt's checkpw function for constant-time comparison
        try:
            return bcrypt.checkpw(plain_password_bytes, hashed_password_bytes)
        except (ValueError, TypeError):
            # If hash is invalid format, verification fails
            return False
    
    async def password_meets_requirements(self, password: str) -> Tuple[bool, Optional[Dict[str, str]]]:
        """
        Check if a password meets security requirements.
        
        Args:
            password: The password to check
            
        Returns:
            Tuple containing:
              - Boolean indicating if password meets requirements
              - Dictionary of validation errors (if any, None otherwise)
        """
        errors = {}
        
        # Check length
        if len(password) < self._min_length:
            errors["length"] = f"Password must be at least {self._min_length} characters"
        
        # Check for uppercase letters
        if self._require_uppercase and not re.search(r'[A-Z]', password):
            errors["uppercase"] = "Password must contain at least one uppercase letter"
        
        # Check for lowercase letters
        if self._require_lowercase and not re.search(r'[a-z]', password):
            errors["lowercase"] = "Password must contain at least one lowercase letter"
        
        # Check for digits
        if self._require_digit and not re.search(r'\d', password):
            errors["digit"] = "Password must contain at least one digit"
        
        # Check for special characters
        if self._require_special and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors["special"] = "Password must contain at least one special character"
        
        # Check for common passwords (simplified version - real implementation would use a larger dictionary)
        common_passwords = ["password", "123456", "qwerty", "admin", "welcome"]
        if password.lower() in common_passwords:
            errors["common"] = "Password is too common and easily guessed"
        
        # Return result
        if errors:
            return (False, errors)
        return (True, None)
    
    async def needs_rehash(self, hashed_password: str) -> bool:
        """
        Check if a password hash needs to be upgraded.
        
        Args:
            hashed_password: The existing password hash
            
        Returns:
            True if the password should be rehashed with current parameters
        """
        try:
            # The bcrypt version is encoded in the hash string
            # Extract the number of rounds from the hash
            hashed_bytes = hashed_password.encode('utf-8')
            current_rounds = int(hashed_bytes.split(b'$')[2])
            
            # If the hash uses fewer rounds than current setting, it needs rehash
            return current_rounds < self._bcrypt_rounds
        except (IndexError, ValueError):
            # If we can't parse the hash, treat it as needing rehash
            return True
    
    async def generate_secure_password(self, length: int = 16) -> str:
        """
        Generate a cryptographically secure random password.
        
        Args:
            length: Length of the password to generate
            
        Returns:
            Secure random password meeting all requirements
        """
        # Use at least the minimum length
        final_length = max(length, self._min_length)
        
        # Define character sets
        uppercase_chars = string.ascii_uppercase
        lowercase_chars = string.ascii_lowercase
        digit_chars = string.digits
        special_chars = "!@#$%^&*(),.?\":{}|<>"
        
        # Ensure all requirements are met
        password = [
            secrets.choice(uppercase_chars),
            secrets.choice(lowercase_chars),
            secrets.choice(digit_chars),
            secrets.choice(special_chars)
        ]
        
        # Fill remaining length with random characters from all sets
        all_chars = uppercase_chars + lowercase_chars + digit_chars + special_chars
        for _ in range(final_length - 4):
            password.append(secrets.choice(all_chars))
        
        # Shuffle the password characters
        shuffled_password = list(password)
        secrets.SystemRandom().shuffle(shuffled_password)
        
        return ''.join(shuffled_password)
```

### Testing Implementation

For testing purposes, a simplified implementation can be used:

```python
class MockPasswordHandler(IPasswordHandler):
    """
    Mock implementation of IPasswordHandler for testing.
    
    This implementation provides predictable behavior for testing
    without actual cryptographic operations.
    """
    
    async def hash_password(self, password: str) -> str:
        """Simple mock hashing that isn't secure, for testing only."""
        # Add a prefix to identify this as a mock hash
        return f"MOCK_HASH:{password}"
    
    async def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Simple mock verification that isn't secure, for testing only."""
        if hashed_password.startswith("MOCK_HASH:"):
            # Extract original password from hash
            original = hashed_password[len("MOCK_HASH:"):]
            return original == plain_password
        return False
    
    async def password_meets_requirements(self, password: str) -> Tuple[bool, Optional[Dict[str, str]]]:
        """Simple requirements check for testing."""
        if len(password) < 8:
            return (False, {"length": "Password must be at least 8 characters"})
        return (True, None)
    
    async def needs_rehash(self, hashed_password: str) -> bool:
        """Always return False for testing."""
        return False
    
    async def generate_secure_password(self, length: int = 16) -> str:
        """Generate a deterministic password for testing."""
        return "TestPassword123!"
```

## Dependency Injection

The Password Handler is provided through FastAPI's dependency injection system:

```python
from fastapi import Depends
from app.core.interfaces.security.password_handler_interface import IPasswordHandler
from app.infrastructure.security.password.password_handler import PasswordHandler
from app.core.config import get_settings, Settings

async def get_password_handler(
    settings: Settings = Depends(get_settings)
) -> IPasswordHandler:
    """
    Dependency provider for Password Handler.
    
    Args:
        settings: Application settings
    
    Returns:
        IPasswordHandler implementation
    """
    return PasswordHandler(settings)
```

## Usage in Authentication Flow

The Password Handler is used throughout the authentication system:

### User Registration

```python
@router.post("/register", response_model=UserResponse)
async def register_user(
    user_data: UserCreateRequest,
    user_service: UserService = Depends(get_user_service),
    password_handler: IPasswordHandler = Depends(get_password_handler),
    audit_logger: IAuditLogger = Depends(get_audit_logger)
):
    """Register a new user with secure password handling."""
    
    # Validate password against security policy
    meets_requirements, errors = await password_handler.password_meets_requirements(user_data.password)
    
    if not meets_requirements:
        # Return detailed validation errors
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Password does not meet security requirements", "errors": errors}
        )
    
    # Hash the password
    hashed_password = await password_handler.hash_password(user_data.password)
    
    # Create user with hashed password
    try:
        user = await user_service.create_user(
            username=user_data.username,
            email=user_data.email,
            hashed_password=hashed_password,
            role=user_data.role
        )
        
        # Log the successful registration
        await audit_logger.log_security_event(
            "user_registered",
            {"user_id": str(user.id), "username": user.username}
        )
        
        return user
        
    except UserExistsError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User with this username or email already exists"
        )
```

### User Authentication

```python
class UserService:
    """Service for user management operations."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        password_handler: IPasswordHandler,
        audit_logger: IAuditLogger
    ):
        """Initialize the user service."""
        self._user_repository = user_repository
        self._password_handler = password_handler
        self._audit_logger = audit_logger
    
    async def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """
        Authenticate a user with username/password.
        
        Args:
            username: User's username or email
            password: User's password
            
        Returns:
            User object if authentication is successful, None otherwise
        """
        # Get user by username or email
        user = await self._user_repository.get_by_username_or_email(username)
        
        if not user:
            return None
        
        # Verify password
        is_valid = await self._password_handler.verify_password(password, user.hashed_password)
        
        if not is_valid:
            # Log failed login attempt
            await self._audit_logger.log_security_event(
                "login_failed",
                {"user_id": str(user.id), "reason": "invalid_password"}
            )
            return None
        
        # Check if password hash needs to be upgraded
        if await self._password_handler.needs_rehash(user.hashed_password):
            # Generate new hash with current settings
            new_hash = await self._password_handler.hash_password(password)
            
            # Update user's password hash
            user.hashed_password = new_hash
            await self._user_repository.update(user)
            
            # Log hash upgrade
            await self._audit_logger.log_security_event(
                "password_hash_upgraded",
                {"user_id": str(user.id)}
            )
        
        return user
```

### Password Reset

```python
@router.post("/reset-password")
async def reset_password(
    reset_data: PasswordResetRequest,
    password_handler: IPasswordHandler = Depends(get_password_handler),
    user_service: UserService = Depends(get_user_service),
    audit_logger: IAuditLogger = Depends(get_audit_logger)
):
    """Reset user password using a reset token."""
    
    # Validate password against security policy
    meets_requirements, errors = await password_handler.password_meets_requirements(reset_data.new_password)
    
    if not meets_requirements:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Password does not meet security requirements", "errors": errors}
        )
    
    # Verify reset token and get user
    try:
        user = await user_service.verify_reset_token(reset_data.token)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token"
            )
        
        # Hash the new password
        hashed_password = await password_handler.hash_password(reset_data.new_password)
        
        # Update the user's password
        await user_service.update_password(user.id, hashed_password)
        
        # Log the password reset
        await audit_logger.log_security_event(
            "password_reset",
            {"user_id": str(user.id)}
        )
        
        return {"message": "Password has been reset successfully"}
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
```

## HIPAA Compliance Considerations

The Password Handler enforces HIPAA requirements for authentication:

1. **Complex Passwords**: Enforces complexity requirements for password strength
2. **Failed Attempts**: Supports tracking failed login attempts (through integration with authentication service)
3. **Password Expiration**: Supports password expiration policies through the application service layer
4. **Secure Hashing**: Uses industry-standard bcrypt algorithm with configurable work factor
5. **Automatic Upgrades**: Identifies and upgrades password hashes when cryptographic standards change

## Testing

To test password handling capabilities:

```python
import pytest
from app.infrastructure.security.password.password_handler import PasswordHandler
from app.core.config import Settings

@pytest.fixture
def password_handler():
    """Provide a password handler for testing."""
    test_settings = Settings(
        PASSWORD_MIN_LENGTH=8,
        PASSWORD_REQUIRE_UPPERCASE=True,
        PASSWORD_REQUIRE_LOWERCASE=True,
        PASSWORD_REQUIRE_DIGIT=True,
        PASSWORD_REQUIRE_SPECIAL=True,
        PASSWORD_BCRYPT_ROUNDS=4  # Lower rounds for faster tests
    )
    return PasswordHandler(test_settings)

async def test_password_hashing(password_handler):
    """Test that password hashing works correctly."""
    password = "SecurePassword123!"
    hashed = await password_handler.hash_password(password)
    
    # Hash should be different from original password
    assert hashed != password
    
    # Verification should succeed
    assert await password_handler.verify_password(password, hashed) is True
    
    # Verification with wrong password should fail
    assert await password_handler.verify_password("WrongPassword", hashed) is False

async def test_password_requirements(password_handler):
    """Test password requirements checking."""
    # Valid password
    valid, errors = await password_handler.password_meets_requirements("SecurePassword123!")
    assert valid is True
    assert errors is None
    
    # Too short
    valid, errors = await password_handler.password_meets_requirements("Short1!")
    assert valid is False
    assert "length" in errors
    
    # Missing uppercase
    valid, errors = await password_handler.password_meets_requirements("lowercase123!")
    assert valid is False
    assert "uppercase" in errors
```

## Migration Strategy

To implement the Password Handler interface:

1. Define the interface in the core layer
2. Create the bcrypt implementation in the infrastructure layer
3. Update the user service to use the password handler
4. Add password validation to registration and password reset flows
5. Update authentication to include hash upgrading when needed

## Security Considerations

The password handler implements several security best practices:

1. **Salt Generation**: Each password hash includes a unique salt
2. **Work Factor**: Configurable work factor to balance security and performance
3. **Timing Attacks**: Uses constant-time comparison for verification
4. **Hash Upgrades**: Supports detecting and upgrading outdated hash algorithms
5. **Secure Random Generation**: Uses cryptographically secure random generators

## Conclusion

The Password Handler Interface is a foundational security component for the Clarity AI Backend that ensures consistent and secure handling of passwords throughout the application. By following clean architecture principles and HIPAA requirements, this interface provides a robust foundation for user authentication while maintaining flexibility for future security enhancements.
