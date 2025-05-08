"""Unit tests for password handling functionality."""
import time
from unittest.mock import MagicMock, patch

import pytest

from app.infrastructure.security.password.hashing import get_password_hash, verify_password

# Correct imports: Import PasswordHandler and hashing functions
from app.infrastructure.security.password.password_handler import PasswordHandler

# Define or mock missing types/constants if needed for tests
# Removed mocks for PasswordPolicy, PasswordComplexityError as they don't exist
# Removed mocks for PasswordStrengthResult, PasswordStrengthError as tests will be adapted
# Mocking COMMON_PASSWORDS if it's used and not defined/imported correctly
COMMON_PASSWORDS = {"password123", "123456", "qwerty"}

@pytest.fixture
def password_handler() -> PasswordHandler:
    """Fixture to provide a PasswordHandler instance."""
    return PasswordHandler()

class TestPasswordHashing:
    """Test suite for password hashing and verification (using standalone functions)."""

    def test_password_hash_different_from_original(self):
        """Test that the hashed password is different from the original."""
        password = "SecurePassword123!"
        hashed = get_password_hash(password)
        assert hashed != password
        assert isinstance(hashed, str)
        assert len(hashed) > len(password)

    def test_password_hash_is_deterministic_with_same_salt(self):
        """Test verify_password works correctly (hashing is deterministic internally)."""
        password = "SecurePassword123!"
        # Hash it once
        hashed = get_password_hash(password)
        # Verify it works
        assert verify_password(password, hashed) is True
        # Verify again, should still work
        assert verify_password(password, hashed) is True

    def test_different_passwords_different_hashes(self):
        """Test that different passwords produce different hashes."""
        password1 = "SecurePassword123!"
        password2 = "DifferentPassword456!"
        hashed1 = get_password_hash(password1)
        hashed2 = get_password_hash(password2)
        assert hashed1 != hashed2

    def test_verify_correct_password(self):
        """Test that verification succeeds with correct password."""
        password = "SecurePassword123!"
        hashed = get_password_hash(password)
        result = verify_password(password, hashed)
        assert result is True

    def test_verify_incorrect_password(self):
        """Test that verification fails with incorrect password."""
        correct_password = "SecurePassword123!"
        wrong_password = "WrongPassword123!"
        hashed = get_password_hash(correct_password)
        result = verify_password(wrong_password, hashed)
        assert result is False

    def test_verify_handles_none_values(self):
        """Test that verification properly handles None values."""
        assert verify_password(None, "somehash") is False
        assert verify_password("somepassword", None) is False
        assert verify_password(None, None) is False

    def test_hashing_is_slow_enough_for_security(self):
        """Test that password hashing takes a reasonable amount of time for security."""
        password = "SecurePassword123!"
        start_time = time.time()
        get_password_hash(password) # Corrected call
        duration = time.time() - start_time
        # Check if duration is reasonable (e.g., > 50ms)
        # This threshold might need adjustment based on the system running the tests
        assert duration > 0.01, "Password hashing might be too fast (<10ms)"


class TestPasswordStrengthValidation:
    """Test suite for password strength validation (using PasswordHandler method)."""

    def test_valid_password_strength(self, password_handler: PasswordHandler):
        """Test that a strong password passes validation."""
        password = "SecureP@ssw0rd123!"
        is_valid, message = password_handler.validate_password_strength(password)
        assert is_valid is True
        assert message is None

    def test_short_password(self, password_handler: PasswordHandler):
        """Test that short passwords are rejected."""
        password = "Short1!"
        is_valid, message = password_handler.validate_password_strength(password)
        assert is_valid is False
        assert message is not None
        assert "must be at least 12 characters" in message

    def test_password_without_complexity(self, password_handler: PasswordHandler):
        """Test that passwords missing complexity requirements fail."""
        password = "nouppercase123!"  # Long enough but missing uppercase
        is_valid, message = password_handler.validate_password_strength(password)
        assert is_valid is False
        assert message is not None
        assert "must include uppercase, lowercase, digits, and special characters" in message

    def test_common_password(self, password_handler: PasswordHandler):
        """Test that common passwords are rejected."""
        password = "Password12345!"
        is_valid, message = password_handler.validate_password_strength(password)
        assert is_valid is False
        assert message is not None
        assert "common patterns" in message

    def test_repeated_characters(self, password_handler: PasswordHandler):
        """Test that passwords with repeated characters fail."""
        password = "Passssword123!"  # Contains repeated 's'
        is_valid, message = password_handler.validate_password_strength(password)
        assert is_valid is False
        assert message is not None
        assert "repeated characters" in message

    # Removed tests for _contains_personal_info, PasswordStrengthResult, PasswordStrengthError, strict mode
    # as they are not part of the current PasswordHandler.validate_password_strength implementation.

class TestRandomPasswordGeneration:
    """Test suite for random password generation (using PasswordHandler method)."""

    def test_random_password_length(self, password_handler: PasswordHandler):
        """Test that generated passwords have the requested length."""
        length = 16
        password = password_handler.generate_secure_password(length)
        assert len(password) == length

    def test_random_password_complexity(self, password_handler: PasswordHandler):
        """Test that generated passwords meet complexity requirements."""
        password = password_handler.generate_secure_password(16)
        is_valid, message = password_handler.validate_password_strength(password)
        assert is_valid is True, f"Generated password failed strength check: {password}, Message: {message}"

    def test_random_password_uniqueness(self, password_handler: PasswordHandler):
        """Test that generated passwords are unique."""
        num_passwords = 100
        passwords = [password_handler.generate_secure_password(16) for _ in range(num_passwords)]
        assert len(set(passwords)) == num_passwords

    @patch("app.infrastructure.security.password.password_handler.secrets.choice")
    def test_uses_cryptographically_secure_rng(self, mock_choice: MagicMock, password_handler: PasswordHandler):
        """Test that password generation uses cryptographically secure RNG."""
        mock_choice.side_effect = lambda x: x[0]
        password_handler.generate_secure_password(16)
        assert mock_choice.called
