"""
Tests for the MFA service.
"""

from unittest.mock import MagicMock, patch

import pytest

# Updated import path
from app.infrastructure.security.auth.mfa_service import (
    EmailStrategy,
    MFAService,
    MFASetupException,
    MFAStrategyFactory,
    MFAType,
    MFAVerificationException,
    SMSStrategy,
    TOTPStrategy,
)

# Assuming settings might be needed, import or mock appropriately
# from app.core.config import settings # Example if needed


@pytest.fixture
def mfa_service():
    """Fixture for MFA service."""
    # Mock settings if MFAService relies on them during init
    # For this example, pass config directly
    service = MFAService(
        secret_key="test_secret_key_32_bytes_long!", # Ensure sufficient length
        issuer_name="Novamind Psychiatry",
        totp_digits=6,
        totp_interval=30,
        sms_code_length=6,
        email_code_length=8,
        verification_timeout_seconds=300
    )
    return service

# Removed misplaced decorator @pytest.mark.db_required()
class TestMFAService:
    """Tests for the MFAService class."""

    def test_generate_secret_key(self, mfa_service: MFAService):
        """Test generating a secret key."""
        secret_key = mfa_service.generate_secret_key()
        assert isinstance(secret_key, str)
        assert len(secret_key) >= 16 # Default pyotp length

    @patch('pyotp.TOTP')
    @patch('qrcode.QRCode')
    def test_setup_totp(self, mock_qrcode: MagicMock, mock_totp: MagicMock, mfa_service: MFAService):
        """Test setting up TOTP."""
        mock_totp_instance = MagicMock()
        mock_totp_instance.provisioning_uri.return_value = "otpauth://totp/Novamind%20Psychiatry:test%40example.com?secret=ABCDEFGH&issuer=Novamind%20Psychiatry"
        mock_totp.return_value = mock_totp_instance

        mock_qrcode_instance = MagicMock()
        mock_img = MagicMock()
        mock_img.save = MagicMock()
        mock_qrcode_instance.make_image.return_value = mock_img
        mock_qrcode.return_value = mock_qrcode_instance

        with patch.object(mfa_service, 'generate_secret_key', return_value="JBSWY3DPEHPK3PXP"):
            result = mfa_service.setup_totp("user123", "test@example.com")

            assert result["secret_key"] == "JBSWY3DPEHPK3PXP"
            assert "qr_code_base64" in result
            assert "provisioning_uri" in result
            assert result["mfa_type"] == MFAType.TOTP.value
            mock_totp.assert_called_once_with("JBSWY3DPEHPK3PXP", digits=6, interval=30)
            mock_totp_instance.provisioning_uri.assert_called_once_with(name="test@example.com", issuer_name="Novamind Psychiatry")
            mock_qrcode.assert_called_once()
            mock_qrcode_instance.add_data.assert_called_once()
            mock_qrcode_instance.make_image.assert_called_once()
            mock_img.save.assert_called_once()

    @patch('pyotp.TOTP')
    def test_verify_totp_valid(self, mock_totp: MagicMock, mfa_service: MFAService):
        """Test verifying a valid TOTP code."""
        mock_totp_instance = MagicMock()
        mock_totp_instance.verify.return_value = True
        mock_totp.return_value = mock_totp_instance
        secret_key = "JBSWY3DPEHPK3PXP"
        result = mfa_service.verify_totp(secret_key, "123456")
        assert result is True
        mock_totp.assert_called_once_with(secret_key, digits=6, interval=30)
        mock_totp_instance.verify.assert_called_once_with("123456")

    @patch('pyotp.TOTP')
    def test_verify_totp_invalid(self, mock_totp: MagicMock, mfa_service: MFAService):
        """Test verifying an invalid TOTP code."""
        mock_totp_instance = MagicMock()
        mock_totp_instance.verify.return_value = False
        mock_totp.return_value = mock_totp_instance
        secret_key = "JBSWY3DPEHPK3PXP"
        result = mfa_service.verify_totp(secret_key, "654321")
        assert result is False
        mock_totp.assert_called_once_with(secret_key, digits=6, interval=30)
        mock_totp_instance.verify.assert_called_once_with("654321")

    @patch('random.choice')
    def test_generate_verification_code(self, mock_choice: MagicMock, mfa_service: MFAService):
        """Test generating a verification code."""
        mock_choice.return_value = '1'
        code = mfa_service.generate_verification_code(6)
        assert len(code) == 6
        assert code == "111111"

    @patch('time.time')
    def test_setup_sms_mfa(self, mock_time: MagicMock, mfa_service: MFAService):
        """Test setting up SMS MFA."""
        current_time = 1000.0
        mock_time.return_value = current_time
        with patch.object(mfa_service, 'generate_verification_code', return_value="123456") as mock_generate:
            result = mfa_service.setup_sms_mfa("user123", "+1234567890")
            assert result["phone_number"] == "+1234567890"
            assert result["verification_code"] == "123456"
            assert result["expires_at"] == current_time + mfa_service.verification_timeout_seconds
            assert result["mfa_type"] == MFAType.SMS.value
            mock_generate.assert_called_once_with(mfa_service.sms_code_length)

    @patch('time.time')
    def test_setup_email_mfa(self, mock_time: MagicMock, mfa_service: MFAService):
        """Test setting up email MFA."""
        current_time = 1000.0
        mock_time.return_value = current_time
        with patch.object(mfa_service, 'generate_verification_code', return_value="12345678") as mock_generate:
            result = mfa_service.setup_email_mfa("user123", "test@example.com")
            assert result["email"] == "test@example.com"
            assert result["verification_code"] == "12345678"
            assert result["expires_at"] == current_time + mfa_service.verification_timeout_seconds
            assert result["mfa_type"] == MFAType.EMAIL.value
            mock_generate.assert_called_once_with(mfa_service.email_code_length)

    @patch('time.time')
    def test_verify_code_valid(self, mock_time: MagicMock, mfa_service: MFAService):
        """Test verifying a valid code."""
        mock_time.return_value = 1200.0 # Before expiration
        result = mfa_service.verify_code("123456", "123456", 1300.0)
        assert result is True

    @patch('time.time')
    def test_verify_code_expired(self, mock_time: MagicMock, mfa_service: MFAService):
        """Test verifying an expired code."""
        mock_time.return_value = 1500.0 # After expiration
        result = mfa_service.verify_code("123456", "123456", 1300.0)
        assert result is False

    @patch('time.time')
    def test_verify_code_invalid(self, mock_time: MagicMock, mfa_service: MFAService):
        """Test verifying an invalid code."""
        mock_time.return_value = 1000.0
        result = mfa_service.verify_code("123456", "654321", 1300.0)
        assert result is False

    @patch('uuid.uuid4')
    def test_get_backup_codes(self, mock_uuid: MagicMock, mfa_service: MFAService):
        """Test generating backup codes."""
        mock_uuid.side_effect = [MagicMock(hex="abcdef1234"), MagicMock(hex="1234abcdef"), MagicMock(hex="fedcba4321")]
        codes = mfa_service.get_backup_codes(3)
        assert len(codes) == 3
        assert all(len(code) == 10 for code in codes)
        assert codes == ["ABCDEF1234", "1234ABCDEF", "FEDCBA4321"]

    def test_hash_backup_code(self, mfa_service: MFAService):
        """Test hashing a backup code."""
        code = "ABCDEF1234"
        hashed_code = mfa_service.hash_backup_code(code)
        assert isinstance(hashed_code, str)
        assert len(hashed_code) > 0
        assert hashed_code != code
        hashed_code2 = mfa_service.hash_backup_code(code)
        assert hashed_code == hashed_code2

    def test_verify_backup_code_valid(self, mfa_service: MFAService):
        """Test verifying a valid backup code."""
        code = "ABCDEF1234"
        hashed_code = mfa_service.hash_backup_code(code)
        stored_hashes = ["some_other_hash", hashed_code, "another_hash"]
        result = mfa_service.verify_backup_code(code, stored_hashes)
        assert result is True

    def test_verify_backup_code_invalid(self, mfa_service: MFAService):
        """Test verifying an invalid backup code."""
        hashed_code = mfa_service.hash_backup_code("ABCDEF1234")
        stored_hashes = ["some_other_hash", hashed_code, "another_hash"]
        result = mfa_service.verify_backup_code("ZYXWVU9876", stored_hashes)
        assert result is False

    def test_verify_backup_code_not_in_list(self, mfa_service: MFAService):
        """Test verifying a backup code not present in the stored list."""
        stored_hashes = ["hash1", "hash2"]
        result = mfa_service.verify_backup_code("ABCDEF1234", stored_hashes)
        assert result is False


class TestMFAStrategyFactory:
    """Tests for the MFAStrategyFactory class."""

    def test_create_totp_strategy(self, mfa_service: MFAService):
        """Test creating a TOTP strategy."""
        strategy = MFAStrategyFactory.create_strategy(MFAType.TOTP, mfa_service)
        assert isinstance(strategy, TOTPStrategy)

    def test_create_sms_strategy(self, mfa_service: MFAService):
        """Test creating an SMS strategy."""
        strategy = MFAStrategyFactory.create_strategy(MFAType.SMS, mfa_service)
        assert isinstance(strategy, SMSStrategy)

    def test_create_email_strategy(self, mfa_service: MFAService):
        """Test creating an email strategy."""
        strategy = MFAStrategyFactory.create_strategy(MFAType.EMAIL, mfa_service)
        assert isinstance(strategy, EmailStrategy)

    def test_create_invalid_strategy(self, mfa_service: MFAService):
        """Test creating an invalid strategy."""
        with pytest.raises(ValueError, match="Unsupported MFA type"):
            MFAStrategyFactory.create_strategy("invalid_type", mfa_service)


class TestTOTPStrategy:
    """Tests for the TOTPStrategy class."""

    def test_setup(self, mfa_service: MFAService):
        """Test setting up TOTP."""
        strategy = TOTPStrategy(mfa_service)
        with patch.object(mfa_service, 'setup_totp', return_value={"result": "success"}) as mock_setup:
            result = strategy.setup(user_id="user123", email="test@example.com")
            assert result == {"result": "success"}
            mock_setup.assert_called_once_with("user123", "test@example.com")

    def test_setup_missing_email(self, mfa_service: MFAService):
        """Test setting up TOTP without an email."""
        strategy = TOTPStrategy(mfa_service)
        with pytest.raises(MFASetupException, match="Email is required for TOTP setup"):
            strategy.setup(user_id="user123")

    def test_verify(self, mfa_service: MFAService):
        """Test verifying TOTP."""
        strategy = TOTPStrategy(mfa_service)
        with patch.object(mfa_service, 'verify_totp', return_value=True) as mock_verify:
            result = strategy.verify(secret_key="ABCDEFGH", code="123456")
            assert result is True
            mock_verify.assert_called_once_with("ABCDEFGH", "123456")

    def test_verify_missing_parameters(self, mfa_service: MFAService):
        """Test verifying TOTP without required parameters."""
        strategy = TOTPStrategy(mfa_service)
        with pytest.raises(MFAVerificationException, match="Missing required parameters: secret_key, code"):
            strategy.verify()


class TestSMSStrategy:
    """Tests for the SMSStrategy class."""

    def test_setup(self, mfa_service: MFAService):
        """Test setting up SMS MFA."""
        strategy = SMSStrategy(mfa_service)
        with patch.object(mfa_service, 'setup_sms_mfa', return_value={"result": "success"}) as mock_setup:
            result = strategy.setup(user_id="user123", phone_number="+1234567890")
            assert result == {"result": "success"}
            mock_setup.assert_called_once_with("user123", "+1234567890")

    def test_setup_missing_phone_number(self, mfa_service: MFAService):
        """Test setting up SMS MFA without a phone number."""
        strategy = SMSStrategy(mfa_service)
        with pytest.raises(MFASetupException, match="Phone number is required for SMS setup"):
            strategy.setup(user_id="user123")

    def test_verify(self, mfa_service: MFAService):
        """Test verifying SMS code."""
        strategy = SMSStrategy(mfa_service)
        with patch.object(mfa_service, 'verify_code', return_value=True) as mock_verify:
            result = strategy.verify(
                code="123456",
                expected_code="123456",
                expires_at=1300.0
            )
            assert result is True
            mock_verify.assert_called_once_with("123456", "123456", 1300.0)

    def test_verify_missing_parameters(self, mfa_service: MFAService):
        """Test verifying SMS code without required parameters."""
        strategy = SMSStrategy(mfa_service)
        with pytest.raises(MFAVerificationException, match="Missing required parameters: code, expected_code, expires_at"):
            strategy.verify()


class TestEmailStrategy:
    """Tests for the EmailStrategy class."""

    def test_setup(self, mfa_service: MFAService):
        """Test setting up email MFA."""
        strategy = EmailStrategy(mfa_service)
        with patch.object(mfa_service, 'setup_email_mfa', return_value={"result": "success"}) as mock_setup:
            result = strategy.setup(user_id="user123", email="test@example.com")
            assert result == {"result": "success"}
            mock_setup.assert_called_once_with("user123", "test@example.com")

    def test_setup_missing_email(self, mfa_service: MFAService):
        """Test setting up email MFA without an email."""
        strategy = EmailStrategy(mfa_service)
        with pytest.raises(MFASetupException, match="Email is required for Email setup"):
            strategy.setup(user_id="user123")

    def test_verify(self, mfa_service: MFAService):
        """Test verifying email code."""
        strategy = EmailStrategy(mfa_service)
        with patch.object(mfa_service, 'verify_code', return_value=True) as mock_verify:
            result = strategy.verify(
                code="12345678",
                expected_code="12345678",
                expires_at=1300.0
            )
            assert result is True
            mock_verify.assert_called_once_with("12345678", "12345678", 1300.0)

    def test_verify_missing_parameters(self, mfa_service: MFAService):
        """Test verifying email code without required parameters."""
        strategy = EmailStrategy(mfa_service)
        with pytest.raises(MFAVerificationException, match="Missing required parameters: code, expected_code, expires_at"):
            strategy.verify()
