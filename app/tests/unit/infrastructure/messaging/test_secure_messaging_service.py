"""
Tests for the Secure Messaging Service.
"""

import time
import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Corrected import
from app.infrastructure.messaging.secure_messaging_service import (
    MessageDecryptionException,
    MessageNotFoundException,
    MessagePriority,
    MessageStatus,
    MessageType,
    SecureMessagingException,
    SecureMessagingService,
)
from app.infrastructure.security.encryption.base_encryption_service import BaseEncryptionService

# Assuming EncryptionService exists for type hinting/mocking
# Assuming BaseRepository exists for type hinting/mocking


@pytest.fixture
def encryption_service():
    """Fixture for encryption service."""
    service = MagicMock(spec=BaseEncryptionService)
    service.encrypt_field.side_effect = lambda x: f"encrypted_{x}"
    # Corrected decrypt_field side effect
    service.decrypt_field.side_effect = lambda x: x.replace("encrypted_", "") if isinstance(x, str) else x
    return service

@pytest.fixture
def message_repository():
    """Fixture for message repository."""
    repository = AsyncMock() # Removed spec for non-existent BaseRepository
    # Make save return the object passed to it
    async def save_side_effect(msg):
        return msg
    repository.save = AsyncMock(side_effect=save_side_effect)
    repository.get_by_id = AsyncMock(return_value=None) # Default to not found
    return repository

@pytest.fixture
def key_pair():
    """Fixture for RSA key pair."""
    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Get the public key
    public_key = private_key.public_key()

    # Serialize the keys
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_bytes, public_key_bytes

@pytest.fixture
def secure_messaging_service(encryption_service):
    """Fixture for secure messaging service."""
    return SecureMessagingService(
        encryption_service=encryption_service,
        key_size=2048,
        symmetric_key_ttl_seconds=86400
    )

# Corrected class definition and indentation
@pytest.mark.venv_only() # Assuming venv_only is a valid marker
class TestSecureMessagingService:
    """Tests for the SecureMessagingService class."""

    def test_generate_key_pair(self, secure_messaging_service):
        """Test generating a key pair."""
        private_key, public_key = secure_messaging_service.generate_key_pair()

        # Check that the keys are bytes
        assert isinstance(private_key, bytes)
        assert isinstance(public_key, bytes)

        # Check that the keys are PEM-encoded
        assert private_key.startswith(b"-----BEGIN PRIVATE KEY-----")
        assert private_key.endswith(b"-----END PRIVATE KEY-----\n")
        assert public_key.startswith(b"-----BEGIN PUBLIC KEY-----")
        assert public_key.endswith(b"-----END PUBLIC KEY-----\n")

    def test_encrypt_decrypt_symmetric_key(
        self, secure_messaging_service, key_pair): # Added colon
        """Test encrypting and decrypting a symmetric key."""
        private_key_bytes, public_key_bytes = key_pair

        # Generate a symmetric key
        symmetric_key = Fernet.generate_key()

        # Encrypt the symmetric key
        encrypted_key = secure_messaging_service._encrypt_symmetric_key( # Corrected call
            symmetric_key=symmetric_key,
            recipient_public_key=public_key_bytes
        )

        # Decrypt the symmetric key
        decrypted_key = secure_messaging_service._decrypt_symmetric_key( # Corrected call
            encrypted_key=encrypted_key,
            private_key=private_key_bytes
        )

        # Check that the decrypted key matches the original
        assert decrypted_key == symmetric_key

    def test_encrypt_decrypt_message(self, secure_messaging_service):
        """Test encrypting and decrypting a message."""
        # Generate a symmetric key
        symmetric_key = Fernet.generate_key()

        # Original message
        original_message = "This is a test message with PHI: Patient John Doe has anxiety."

        # Encrypt the message
        encrypted_message = secure_messaging_service._encrypt_message( # Corrected call
            message=original_message,
            symmetric_key=symmetric_key
        )

        # Decrypt the message
        decrypted_message = secure_messaging_service._decrypt_message( # Corrected call
            encrypted_message=encrypted_message,
            symmetric_key=symmetric_key
        )

        # Check that the decrypted message matches the original
        assert decrypted_message == original_message

    def test_encrypt_message_for_recipient(
        self, secure_messaging_service, key_pair): # Added colon
        """Test encrypting a message for a recipient."""
        _, public_key_bytes = key_pair

        # Original message
        original_message = "This is a test message with PHI: Patient John Doe has anxiety."

        # Encrypt the message for the recipient
        message_package = secure_messaging_service.encrypt_message_for_recipient( # Corrected call
            message=original_message,
            recipient_public_key=public_key_bytes
        )

        # Check the message package structure
        assert "encrypted_message" in message_package
        assert "encrypted_key" in message_package
        assert "timestamp" in message_package
        assert "expires_at" in message_package

        # Check that the timestamp and expiration are valid
        current_time = int(time.time())
        assert message_package["timestamp"] <= current_time
        assert message_package["expires_at"] > current_time
        assert message_package["expires_at"] == message_package["timestamp"] + 86400

    def test_decrypt_message(self, secure_messaging_service, key_pair):
        """Test decrypting a message."""
        private_key_bytes, public_key_bytes = key_pair

        # Original message
        original_message = "This is a test message with PHI: Patient John Doe has anxiety."

        # Encrypt the message for the recipient
        message_package = secure_messaging_service.encrypt_message_for_recipient( # Corrected call
            message=original_message,
            recipient_public_key=public_key_bytes
        )

        # Decrypt the message
        decrypted_message = secure_messaging_service.decrypt_message( # Corrected call
            message_package=message_package,
            private_key=private_key_bytes
        )

        # Check that the decrypted message matches the original
        assert decrypted_message == original_message

    def test_decrypt_expired_message(
        self, secure_messaging_service, key_pair): # Added colon
        """Test decrypting an expired message."""
        private_key_bytes, public_key_bytes = key_pair

        # Original message
        original_message = "This is a test message with PHI: Patient John Doe has anxiety."

        # Encrypt the message for the recipient
        message_package = secure_messaging_service.encrypt_message_for_recipient( # Corrected call
            message=original_message,
            recipient_public_key=public_key_bytes
        )

        # Set the expiration to the past
        message_package["expires_at"] = int(time.time()) - 3600

        # Try to decrypt the expired message
        with pytest.raises(MessageDecryptionException):
            secure_messaging_service.decrypt_message( # Corrected call
                message_package=message_package,
                private_key=private_key_bytes
            )

    def test_create_message(
        self,
        secure_messaging_service,
        key_pair,
        encryption_service): # Added colon
        """Test creating a message."""
        _, public_key_bytes = key_pair

        # Create a message
        message = secure_messaging_service.create_message( # Corrected call
            sender_id="sender123",
            recipient_id="recipient456",
            subject="Test Subject",
            content="This is a test message with PHI: Patient John Doe has anxiety.",
            recipient_public_key=public_key_bytes,
            message_type=MessageType.TEXT,
            priority=MessagePriority.NORMAL
        )

        # Check the message structure
        assert "id" in message
        assert "sender_id" in message
        assert "recipient_id" in message
        assert "subject" in message
        assert "encrypted_package" in message
        assert "message_type" in message
        assert "priority" in message
        assert "status" in message
        assert "created_at" in message
        assert "updated_at" in message
        assert "expires_at" in message
        assert "has_attachments" in message

        # Check the message values
        assert message["sender_id"] == "sender123"
        assert message["recipient_id"] == "recipient456"
        # Check encrypted subject
        assert message["subject"] == "encrypted_Test Subject"
        assert message["message_type"] == MessageType.TEXT.value
        assert message["priority"] == MessagePriority.NORMAL.value
        assert message["status"] == MessageStatus.DRAFT.value
        assert message["has_attachments"] is False

        # Check that the encryption service was called for the subject
        encryption_service.encrypt_field.assert_called_once_with(
            "Test Subject"
        )

    def test_create_message_with_attachments(
        self, secure_messaging_service, key_pair): # Added colon
        """Test creating a message with attachments."""
        _, public_key_bytes = key_pair

        # Create attachments
        attachments = [ # Corrected list definition
            {
                "id": str(uuid.uuid4()),
                "name": "test.pdf",
                "content_type": "application/pdf",
                "size": 1024,
                "encrypted_content": "encrypted_content_here"  # Assume content is pre-encrypted
            }
        ]

        # Create a message with attachments
        message = secure_messaging_service.create_message( # Corrected call
            sender_id="sender123",
            recipient_id="recipient456",
            subject="Test Subject",
            content="This is a test message with attachments.",
            recipient_public_key=public_key_bytes,
            message_type=MessageType.DOCUMENT,
            priority=MessagePriority.HIGH,
            attachments=attachments
        )

        # Check that the message has attachments
        assert message["has_attachments"] is True
        assert "attachments" in message
        assert message["attachments"] == attachments
        assert message["message_type"] == MessageType.DOCUMENT.value
        assert message["priority"] == MessagePriority.HIGH.value

    @pytest.mark.asyncio
    async def test_send_message(
        self,
        secure_messaging_service,
        key_pair,
        message_repository): # Added colon
        """Test sending a message."""
        _, public_key_bytes = key_pair

        # Create a message
        message = secure_messaging_service.create_message( # Corrected call
            sender_id="sender123",
            recipient_id="recipient456",
            subject="Test Subject",
            content="This is a test message.",
            recipient_public_key=public_key_bytes
        )

        # Send the message
        sent_message = await secure_messaging_service.send_message( # Corrected call
            message=message,
            message_repository=message_repository
        )

        # Check that the message status was updated
        assert sent_message["status"] == MessageStatus.SENT.value
        assert "sent_at" in sent_message
        assert sent_message["updated_at"] == sent_message["sent_at"]

        # Check that the repository was called
        message_repository.save.assert_called_once()

    @pytest.mark.asyncio
    async def test_mark_as_delivered(
        self,
        secure_messaging_service,
        message_repository): # Added colon
        """Test marking a message as delivered."""
        # Create a mock message
        message_id = str(uuid.uuid4()) # Removed extra comma
        message = {
            "id": message_id,
            "status": MessageStatus.SENT.value,
            "updated_at": int(time.time())
        }

        # Set up the repository to return the message
        message_repository.get_by_id.return_value = message

        # Mark the message as delivered
        delivered_message = await secure_messaging_service.mark_as_delivered( # Corrected call
            message_id=message_id,
            message_repository=message_repository
        )

        # Check that the message status was updated
        assert delivered_message["status"] == MessageStatus.DELIVERED.value
        assert "delivered_at" in delivered_message
        assert delivered_message["updated_at"] == delivered_message["delivered_at"]

        # Check that the repository was called
        message_repository.get_by_id.assert_called_once_with(message_id)
        message_repository.save.assert_called_once()

    @pytest.mark.asyncio
    async def test_mark_as_delivered_not_found(
        self, secure_messaging_service, message_repository): # Added colon
        """Test marking a non-existent message as delivered."""
        # Set up the repository to return None
        message_repository.get_by_id.return_value = None

        # Try to mark a non-existent message as delivered
        with pytest.raises(MessageNotFoundException):
            await secure_messaging_service.mark_as_delivered( # Corrected call
                message_id="nonexistent",
                message_repository=message_repository
            )

    @pytest.mark.asyncio
    async def test_mark_as_read(
        self,
        secure_messaging_service,
        message_repository): # Added colon
        """Test marking a message as read."""
        # Create a mock message
        message_id = str(uuid.uuid4()) # Removed extra comma
        message = {
            "id": message_id,
            "status": MessageStatus.DELIVERED.value,
            "updated_at": int(time.time())
        }

        # Set up the repository to return the message
        message_repository.get_by_id.return_value = message

        # Mark the message as read
        read_message = await secure_messaging_service.mark_as_read( # Corrected call
            message_id=message_id,
            message_repository=message_repository
        )

        # Check that the message status was updated
        assert read_message["status"] == MessageStatus.READ.value
        assert "read_at" in read_message
        assert read_message["updated_at"] == read_message["read_at"]

        # Check that the repository was called
        message_repository.get_by_id.assert_called_once_with(message_id)
        message_repository.save.assert_called_once()

    @pytest.mark.asyncio
    async def test_mark_as_read_not_found(
        self, secure_messaging_service, message_repository): # Added colon
        """Test marking a non-existent message as read."""
        # Set up the repository to return None
        message_repository.get_by_id.return_value = None

        # Try to mark a non-existent message as read
        with pytest.raises(MessageNotFoundException):
            await secure_messaging_service.mark_as_read( # Corrected call
                message_id="nonexistent",
                message_repository=message_repository
            )

    @pytest.mark.asyncio
    async def test_delete_message(
        self,
        secure_messaging_service,
        message_repository): # Added colon
        """Test deleting a message."""
        # Create a mock message
        sender_id = "sender123"
        message_id = str(uuid.uuid4()) # Removed extra comma
        message = {
            "id": message_id,
            "sender_id": sender_id,
            "recipient_id": "recipient456",
            "status": MessageStatus.READ.value,
            "updated_at": int(time.time())
        }

        # Set up the repository to return the message
        message_repository.get_by_id.return_value = message

        # Delete the message
        deleted_message = await secure_messaging_service.delete_message( # Corrected call
            message_id=message_id,
            user_id=sender_id,
            message_repository=message_repository
        )

        # Check that the message status was updated
        assert deleted_message["status"] == MessageStatus.DELETED.value
        assert "deleted_at" in deleted_message
        assert "deleted_by" in deleted_message
        assert deleted_message["deleted_by"] == sender_id
        assert deleted_message["updated_at"] == deleted_message["deleted_at"]

        # Check that the repository was called
        message_repository.get_by_id.assert_called_once_with(message_id)
        message_repository.save.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_message_not_found(
        self, secure_messaging_service, message_repository): # Added colon
        """Test deleting a non-existent message."""
        # Set up the repository to return None
        message_repository.get_by_id.return_value = None

        # Try to delete a non-existent message
        with pytest.raises(MessageNotFoundException):
            await secure_messaging_service.delete_message( # Corrected call
                message_id="nonexistent",
                user_id="user123",
                message_repository=message_repository
            )

    @pytest.mark.asyncio
    async def test_delete_message_unauthorized(
        self, secure_messaging_service, message_repository): # Added colon
        """Test deleting a message by an unauthorized user."""
        # Create a mock message
        sender_id = "sender123"
        message_id = str(uuid.uuid4())
        message = {
            "id": message_id,
            "sender_id": sender_id,
            "recipient_id": "recipient456",
            "status": MessageStatus.READ.value,
            "updated_at": int(time.time())
        }

        # Set up the repository to return the message
        message_repository.get_by_id.return_value = message

        # Try to delete the message with a different user ID
        unauthorized_user_id = "unauthorized_user"
        with pytest.raises(SecureMessagingException): # Expecting a general exception
            await secure_messaging_service.delete_message(
                message_id=message_id,
                user_id=unauthorized_user_id,
                message_repository=message_repository
            )

        # Check that save was not called
        message_repository.save.assert_not_called()
