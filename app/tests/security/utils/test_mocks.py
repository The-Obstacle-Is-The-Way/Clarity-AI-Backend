"""
Mock objects for security-related testing.

This module provides mock implementations for various security components
to be used in unit tests, ensuring isolation from real security services.
"""

from unittest.mock import MagicMock
import uuid

# Mock Encryption Service
from app.infrastructure.security.encryption.base_encryption_service import BaseEncryptionService
import base64
from cryptography.fernet import Fernet, InvalidToken

class MockEncryptionService(BaseEncryptionService):
    """A proper mock implementation of BaseEncryptionService for testing.
    
    This mock actually encrypts and decrypts data using Fernet with a fixed test key,
    making it suitable for unit tests that need real encryption/decryption behavior.
    """
    VERSION_PREFIX = "v1:"
    
    def __init__(self, direct_key=None, previous_key=None):
        """Initialize with a test encryption key if none is provided."""
        # Use a fixed test key if none provided - this is for testing only
        self._direct_key = direct_key or 'YDK6UZeOqpHeiU33a3HVt_FWdVh9Z2LtQZZU-C1LD1E='
        self._direct_previous_key = previous_key
        self._cipher = None
        self._previous_cipher = None
        
    def encrypt(self, value):
        """Encrypt a value using the cipher."""
        if value is None:
            return None
        
        # Special case: empty strings remain empty as per test expectations
        if value == "" or (isinstance(value, bytes) and len(value) == 0):
            return ""
            
        try:
            if isinstance(value, str):
                value_bytes = value.encode()
            elif isinstance(value, bytes):
                value_bytes = value
            else:
                value_bytes = str(value).encode()
                
            encrypted_bytes = self.cipher.encrypt(value_bytes)
            return f"{self.VERSION_PREFIX}{encrypted_bytes.decode()}"
            
        except Exception as e:
            return f"encryption_error: {str(e)}"
            
    def decrypt(self, encrypted_value):
        """Decrypt a value using the cipher."""
        if encrypted_value is None:
            return None
            
        if not isinstance(encrypted_value, str):
            return str(encrypted_value)
            
        if not encrypted_value.startswith(self.VERSION_PREFIX):
            return encrypted_value
            
        try:
            encrypted_data = encrypted_value[len(self.VERSION_PREFIX):].encode()
            decrypted_bytes = self.cipher.decrypt(encrypted_data)
            return decrypted_bytes.decode()
        except Exception:
            # For tests, return a predictable value on error
            return "decrypted_data"
            
    def encrypt_dict(self, data):
        """Encrypt string values in a dictionary."""
        if not data:
            return {}
            
        encrypted_data = {}
        for key, value in data.items():
            if isinstance(value, str):
                encrypted_data[key] = self.encrypt(value)
            else:
                encrypted_data[key] = value
        return encrypted_data
        
    def decrypt_dict(self, data):
        """Decrypt encrypted string values in a dictionary."""
        if not data:
            return {}
            
        decrypted_data = {}
        for key, value in data.items():
            if isinstance(value, str) and value.startswith(self.VERSION_PREFIX):
                decrypted_data[key] = self.decrypt(value)
            else:
                decrypted_data[key] = value
        return decrypted_data
        
    def encrypt_field(self, value):
        """Alias for encrypt method."""
        return self.encrypt(value)
        
    def decrypt_field(self, encrypted_value):
        """Alias for decrypt method."""
        return self.decrypt(encrypted_value)

# Mock Auth Service
class MockAuthService:
    def __init__(self):
        self.create_token = MagicMock(return_value="mock_token")
        self.validate_token = MagicMock(return_value={"user_id": "test_user", "roles": ["user"]})
        self.has_role = MagicMock(return_value=True)
        self.refresh_token = MagicMock(return_value={"access_token": "new_mock_token", "refresh_token": "new_refresh_token"})

# Mock RBAC Service
class MockRBACService:
    def __init__(self):
        def check_permission_logic(permission, roles=None):
            if roles is None:
                return permission in ["read:own_data", "read:patient_data"]
            return True
        self.check_permission = MagicMock(side_effect=check_permission_logic)
        self.add_role_permission = MagicMock()

# Mock Audit Logger
class MockAuditLogger:
    def __init__(self):
        self.log_phi_access = MagicMock()
        self.log_access_attempt = MagicMock()

# Mock Database Session
class MockDBSession:
    def __init__(self):
        self.commit = MagicMock()
        self.rollback = MagicMock()
        self.add = MagicMock()
        self.query = MagicMock()

# Mock Async Database Session
class MockAsyncSession:
    def __init__(self):
        self.commit = MagicMock()
        self.rollback = MagicMock()
        self.add = MagicMock()
        self.query = MagicMock()

# Mock Patient Model
class MockPatient:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

# Mock PHI Detection Service
class MockPHIDetection:
    def __init__(self):
        self.detect_phi = MagicMock(return_value={'has_phi': False, 'redacted_text': 'redacted'})

# Mock Role-Based Access Control
class RoleBasedAccessControl:
    """
    Mock implementation of RoleBasedAccessControl for testing.
    """
    def __init__(self):
        self._roles = {}
        self.check_access = MagicMock(return_value=True)
        self.filter_data = MagicMock(return_value={'filtered_data': 'mocked'})

    def add_role(self, role: str):
        if role not in self._roles:
            self._roles[role] = set()

    def add_permission_to_role(self, role: str, permission: str) -> bool:
        if role in self._roles:
            self._roles[role].add(permission)
            return True
        return False

    def add_role_permission(self, role: str, permission: str) -> bool:
        """
        Add a permission to a role. Added for compatibility with tests.
        
        Args:
            role: The role to add permission to
            permission: The permission to add
            
        Returns:
            bool: True if added successfully
        """
        return self.add_permission_to_role(role, permission)

    def has_permission(self, role: str, permission: str) -> bool:
        return role in self._roles and permission in self._roles[role]

# Mock Entity Factory
class MockEntityFactory:
    def __init__(self):
        self._entities = {}
        self.create_patient = MagicMock(return_value=MockPatient())
        self.create_user = MagicMock(return_value={'id': 'test_user', 'roles': ['user']})

    def create(self, entity_type, **kwargs):
        entity_id = str(uuid.uuid4())
        entity = {"id": entity_id, "type": entity_type, **kwargs}
        self._entities[entity_id] = entity
        return entity

    def get(self, entity_id):
        return self._entities.get(entity_id)

# Mock PHI Auditor
class MockPHIAuditor:
    def __init__(self, app_dir=None):
        self.run_audit = MagicMock(return_value=True)
        self.generate_report = MagicMock(return_value='{"summary": {"issues_found": 0}}')
        self.findings = {"code_phi": [], "api_security": [], "configuration_issues": [], "logging_issues": []}

# Mock PHI Audit Result
class MockPHIAuditResult:
    def __init__(self, file_path=None):
        self.file_path = file_path
        self.phi_detected = []
        self.is_allowed = False

# Mock PHI Redaction Service
class PHIRedactionService:
    def __init__(self):
        self.redact_phi = MagicMock(return_value="[REDACTED]")
        self.detect_phi = MagicMock(return_value=[])
        self.redact = MagicMock(return_value="[REDACTED]")
        self.sanitize = self._sanitize
        self.sanitize_text = MagicMock(return_value="[PHI SANITIZED]")
        
    def _sanitize(self, data, sensitivity="high", replacement=None):
        """A robust mock implementation that actually sanitizes PHI in nested data structures"""
        if data is None:
            return None
        
        # String sanitization with special patterns
        if isinstance(data, str):
            # Define PHI patterns to match and sanitize
            phi_patterns = [
                (r'\b\d{3}-\d{2}-\d{4}\b', "[REDACTED SSN]"),  # SSN
                (r'\b\d{3}-\d{3}-\d{4}\b', "[REDACTED PHONE]"),  # Phone
                (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', "[REDACTED EMAIL]"),  # Email
                (r'\b\d{1,5}\s+[\w\s]+(?:Avenue|Lane|Road|Boulevard|Drive|Street|Ave|Dr|Rd|Blvd|Ln|St)\b', "[REDACTED ADDRESS]"),  # Address
                (r'\b(?:SensitiveName|Secret)\w*\b', "[REDACTED NAME]")  # Sample sensitive names
            ]
            
            result = data
            for pattern, replacement_text in phi_patterns:
                import re
                result = re.sub(pattern, replacement_text, result)
            return result
            
        # Dictionary sanitization
        elif isinstance(data, dict):
            sanitized = {}
            for k, v in data.items():
                # Special handling for known PHI fields
                if k.lower() in ('ssn', 'social_security_number', 'email', 'phone', 'address', 'first_name', 'last_name'):
                    sanitized[k] = f"[REDACTED {k.upper()}]" if isinstance(v, str) else self._sanitize(v, sensitivity, replacement)
                else:
                    sanitized[k] = self._sanitize(v, sensitivity, replacement)
            return sanitized
            
        # List/tuple/set sanitization
        elif isinstance(data, (list, tuple, set)):
            sanitized = [self._sanitize(item, sensitivity, replacement) for item in data]
            if isinstance(data, tuple):
                return tuple(sanitized)
            elif isinstance(data, set):
                return set(sanitized)
            return sanitized
            
        # Non-sanitizable types
        return data

# Mock Logger
class MockLogger:
    def __init__(self):
        self.info = MagicMock()
        self.warning = MagicMock()
        self.error = MagicMock()
        self.debug = MagicMock()
        self.critical = MagicMock()
        
    def __call__(self, *args, **kwargs):
        # Allow the logger to be called directly for compatibility
        self.info(*args, **kwargs)
        return self
        
    # Support for audit features
    def audit(self, *args, **kwargs):
        self.info(*args, **kwargs)
        self.warning(*args, **kwargs)  # Ensure warning is called for audit tests
        return self
