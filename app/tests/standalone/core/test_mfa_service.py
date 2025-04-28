"""
Tests for the MFA service.

This module contains tests for the Multi-Factor Authentication (MFA) service, 
which includes TOTP (Time-based One-Time Password), SMS, and Email authentication methods.
"""

import pytest
from unittest.mock import MagicMock, patch
import base64
import qrcode
from io import BytesIO
import time
from app.infrastructure.security.auth.mfa_service import (
    MFAService, 
    MFAStrategyFactory, 
    TOTPStrategy, 
    SMSStrategy, 
    EmailStrategy,
    MFAType,
    MFAVerificationException,
    MFASetupException
)

class BaseSecurityTest:
    pass

@pytest.fixture
def mfa_service():
    """Fixture to provide an instance of MFAService with mocked dependencies."""
    # Mock settings to avoid AttributeError
    mock_settings = MagicMock()
    mock_settings.MFA_SECRET_KEY = "mock_mfa_secret"
    mock_settings.MFA_ISSUER_NAME = "MockIssuer"
    
    with patch('app.infrastructure.security.auth.mfa_service.settings', mock_settings):
        service = MFAService()
        yield service

class TestMFAService(BaseSecurityTest):
    """Test suite for the MFAService class."""

    def test_generate_secret_key(self, mfa_service):
        """Test that a secret key is generated correctly."""
        secret_key = mfa_service.generate_secret_key()
        assert isinstance(secret_key, str)
        assert len(secret_key) > 0

    @patch('pyotp.TOTP')
    @pytest.mark.standalone()
    def test_verify_totp_valid(self, mock_totp, mfa_service):
        """Test verifying a valid TOTP code using patching."""
        mock_totp_instance = mock_totp.return_value
        mock_totp_instance.verify.return_value = True
        result = mfa_service.verify_totp("ABCDEFGH", "123456")
        assert result is True
        mock_totp_instance.verify.assert_called_once_with("123456")

    @patch('pyotp.TOTP')
    @pytest.mark.standalone()
    def test_verify_totp_invalid(self, mock_totp, mfa_service):
        """Test verifying an invalid TOTP code using patching."""
        mock_totp_instance = mock_totp.return_value
        mock_totp_instance.verify.return_value = False
        result = mfa_service.verify_totp("ABCDEFGH", "123456")
        assert result is False
        mock_totp_instance.verify.assert_called_once_with("123456")

    @patch('random.choice')
    @pytest.mark.standalone()
    def test_generate_verification_code(self, mock_choice, mfa_service):
        """Test generating a verification code."""
        mock_choice.side_effect = lambda digits: digits[0]
        code = mfa_service.generate_verification_code(6)
        assert len(code) == 6
        assert code == "000000"

    @patch('time.time')
    @pytest.mark.standalone()
    def test_setup_sms_mfa(self, mock_time, mfa_service):
        """Test setting up SMS MFA."""
        mock_time.return_value = 1000
        with patch.object(mfa_service, 'generate_verification_code', return_value="123456"):
            result = mfa_service.setup_sms_mfa("user123", "+1234567890")
            assert result["phone_number"] == "+1234567890"
            assert result["verification_code"] == "123456"
            assert result["expires_at"] == 1300
            assert result["mfa_type"] == MFAType.SMS.value

    @patch('time.time')
    @pytest.mark.standalone()
    def test_setup_email_mfa(self, mock_time, mfa_service):
        """Test setting up email MFA."""
        mock_time.return_value = 1000
        with patch.object(mfa_service, 'generate_verification_code', return_value="12345678"):
            result = mfa_service.setup_email_mfa("user123", "test@example.com")
            assert result["email"] == "test@example.com"
            assert result["verification_code"] == "12345678"
            assert result["expires_at"] == 1300
            assert result["mfa_type"] == MFAType.EMAIL.value

    @patch('time.time')
    @pytest.mark.standalone()
    def test_verify_code_valid(self, mock_time, mfa_service):
        """Test verifying a valid code."""
        mock_time.return_value = 1000
        result = mfa_service.verify_code("123456", "123456", 1300)
        assert result is True

    @patch('time.time')
    @pytest.mark.standalone()
    def test_verify_code_expired(self, mock_time, mfa_service):
        """Test verifying an expired code."""
        mock_time.return_value = 1500
        result = mfa_service.verify_code("123456", "123456", 1300)
        assert result is False

    @patch('time.time')
    @pytest.mark.standalone()
    def test_verify_code_invalid(self, mock_time, mfa_service):
        """Test verifying an invalid code."""
        mock_time.return_value = 1000
        result = mfa_service.verify_code("123456", "654321", 1300)
        assert result is False

    @patch('uuid.uuid4')
    @pytest.mark.standalone()
    def test_get_backup_codes(self, mock_uuid, mfa_service):
        """Test generating backup codes."""
        # Configure the mock provided by @patch directly
        mock_uuid.return_value.__str__.return_value = "abcdef12-3456-7890-abcd-ef1234567890"
        
        codes = mfa_service.get_backup_codes(3)
        assert len(codes) == 3
        assert all(len(code) == 10 for code in codes)

    @pytest.mark.standalone()
    def test_hash_backup_code(self, mfa_service):
        """Test hashing a backup code."""
        hashed_code = mfa_service.hash_backup_code("ABCDEF1234")
        assert isinstance(hashed_code, str)
        assert len(hashed_code) > 0

    @pytest.mark.standalone()
    def test_verify_backup_code_valid(self, mfa_service):
        """Test verifying a valid backup code."""
        hashed_code = mfa_service.hash_backup_code("ABCDEF1234")
        result = mfa_service.verify_backup_code("ABCDEF1234", [hashed_code])
        assert result is True

    @pytest.mark.standalone()
    def test_verify_backup_code_invalid(self, mfa_service):
        """Test verifying an invalid backup code."""
        hashed_code = mfa_service.hash_backup_code("ABCDEF1234")
        result = mfa_service.verify_backup_code("ZYXWVU9876", [hashed_code])
        assert result is False

class TestMFAStrategyFactory:
    """Tests for the MFAStrategyFactory class."""

    @pytest.mark.standalone()
    def test_create_totp_strategy(self, mfa_service):
        """Test creating a TOTP strategy."""
        strategy = MFAStrategyFactory.create_strategy(MFAType.TOTP, mfa_service)
        assert isinstance(strategy, TOTPStrategy)

    @pytest.mark.standalone()
    def test_create_sms_strategy(self, mfa_service):
        """Test creating an SMS strategy."""
        strategy = MFAStrategyFactory.create_strategy(MFAType.SMS, mfa_service)
        assert isinstance(strategy, SMSStrategy)

    @pytest.mark.standalone()
    def test_create_email_strategy(self, mfa_service):
        """Test creating an email strategy."""
        strategy = MFAStrategyFactory.create_strategy(MFAType.EMAIL, mfa_service)
        assert isinstance(strategy, EmailStrategy)

    @pytest.mark.standalone()
    def test_create_invalid_strategy(self, mfa_service):
        """Test creating an invalid strategy."""
        with pytest.raises(ValueError):
            MFAStrategyFactory.create_strategy("invalid", mfa_service)

class TestTOTPStrategy:
    """Tests for the TOTPStrategy class."""

    @pytest.fixture
    def totp_strategy(self, mfa_service):
        """Fixture for TOTP strategy."""
        return TOTPStrategy(mfa_service)

    @patch.object(MFAService, 'setup_totp')
    @pytest.mark.standalone()
    def test_setup(self, mock_setup_totp, totp_strategy):
        """Test setting up TOTP."""
        mock_setup_totp.return_value = {
            "secret_key": "ABCDEFGH",
            "qr_code_base64": "base64_encoded_qr_code",
            "provisioning_uri": "otpauth://totp/MockIssuer:test%40example.com?secret=ABCDEFGH&issuer=MockIssuer",
            "mfa_type": MFAType.TOTP.value
        }
        # Pass email as keyword argument
        result = totp_strategy.setup("user123", email="test@example.com")
        assert result == mock_setup_totp.return_value
        mock_setup_totp.assert_called_once_with("user123", "test@example.com")

    @pytest.mark.standalone()
    def test_setup_missing_email(self, totp_strategy):
        """Test setting up TOTP without an email."""
        with pytest.raises(MFASetupException):
            # Call without email kwarg
            totp_strategy.setup("user123") 

    @patch.object(MFAService, 'verify_totp')
    @pytest.mark.standalone()
    def test_verify(self, mock_verify_totp, totp_strategy):
        """Test verifying TOTP."""
        mock_verify_totp.return_value = True
        # Pass args as keywords
        result = totp_strategy.verify(secret_key="ABCDEFGH", code="123456")
        assert result is True
        mock_verify_totp.assert_called_once_with("ABCDEFGH", "123456")

    @pytest.mark.standalone()
    def test_verify_missing_parameters(self, totp_strategy):
        """Test verifying TOTP without required parameters."""
        with pytest.raises(MFAVerificationException):
            # Missing secret_key
            totp_strategy.verify(code="123456")

        with pytest.raises(MFAVerificationException):
            # Missing code
            totp_strategy.verify(secret_key="ABCDEFGH")

class TestSMSStrategy:
    """Tests for the SMSStrategy class."""

    @pytest.fixture
    def sms_strategy(self, mfa_service):
        """Fixture for SMS strategy."""
        return SMSStrategy(mfa_service)

    @patch.object(MFAService, 'setup_sms_mfa')
    @pytest.mark.standalone()
    def test_setup(self, mock_setup_sms, sms_strategy):
        """Test setting up SMS MFA."""
        mock_setup_sms.return_value = {
            "phone_number": "+1234567890",
            "verification_code": "123456",
            "expires_at": 1300,
            "mfa_type": MFAType.SMS.value
        }
        # Pass phone_number as keyword
        result = sms_strategy.setup("user123", phone_number="+1234567890")
        assert result == mock_setup_sms.return_value
        mock_setup_sms.assert_called_once_with("user123", "+1234567890")

    @pytest.mark.standalone()
    def test_setup_missing_phone_number(self, sms_strategy):
        """Test setting up SMS MFA without a phone number."""
        with pytest.raises(MFASetupException):
            sms_strategy.setup("user123")

    @patch.object(MFAService, 'verify_code')
    @pytest.mark.standalone()
    def test_verify(self, mock_verify_code, sms_strategy):
        """Test verifying SMS code."""
        mock_verify_code.return_value = True
        # Pass args as keywords
        result = sms_strategy.verify(code="123456", expected_code="123456", expires_at=1300)
        assert result is True
        mock_verify_code.assert_called_once_with("123456", "123456", 1300)

    @pytest.mark.standalone()
    def test_verify_missing_parameters(self, sms_strategy):
        """Test verifying SMS code without required parameters."""
        with pytest.raises(MFAVerificationException):
            # Missing code
            sms_strategy.verify(expected_code="123456", expires_at=1300)

        with pytest.raises(MFAVerificationException):
            # Missing expected_code
            sms_strategy.verify(code="123456", expires_at=1300)

        with pytest.raises(MFAVerificationException):
            # Missing expires_at
            sms_strategy.verify(code="123456", expected_code="123456")

class TestEmailStrategy:
    """Tests for the EmailStrategy class."""

    @pytest.fixture
    def email_strategy(self, mfa_service):
        """Fixture for Email strategy."""
        return EmailStrategy(mfa_service)

    @patch.object(MFAService, 'setup_email_mfa')
    @pytest.mark.standalone()
    def test_setup(self, mock_setup_email, email_strategy):
        """Test setting up email MFA."""
        mock_setup_email.return_value = {
            "email": "test@example.com",
            "verification_code": "12345678",
            "expires_at": 1300,
            "mfa_type": MFAType.EMAIL.value
        }
        # Pass email as keyword
        result = email_strategy.setup("user123", email="test@example.com")
        assert result == mock_setup_email.return_value
        mock_setup_email.assert_called_once_with("user123", "test@example.com")

    @pytest.mark.standalone()
    def test_setup_missing_email(self, email_strategy):
        """Test setting up email MFA without an email."""
        with pytest.raises(MFASetupException):
            email_strategy.setup("user123")

    @patch.object(MFAService, 'verify_code')
    @pytest.mark.standalone()
    def test_verify(self, mock_verify_code, email_strategy):
        """Test verifying email code."""
        mock_verify_code.return_value = True
        # Pass args as keywords
        result = email_strategy.verify(code="12345678", expected_code="12345678", expires_at=1300)
        assert result is True
        mock_verify_code.assert_called_once_with("12345678", "12345678", 1300)

    @pytest.mark.standalone()
    def test_verify_missing_parameters(self, email_strategy):
        """Test verifying email code without required parameters."""
        with pytest.raises(MFAVerificationException):
            # Missing code
            email_strategy.verify(expected_code="12345678", expires_at=1300)

        with pytest.raises(MFAVerificationException):
            # Missing expected_code
            email_strategy.verify(code="12345678", expires_at=1300)

        with pytest.raises(MFAVerificationException):
            # Missing expires_at
            email_strategy.verify(code="12345678", expected_code="12345678")