# app/application/interfaces/notification_service.py
# Interface for notification services
# Following Dependency Inversion Principle and ensuring HIPAA compliance

from abc import ABC, abstractmethod
from typing import Any
from uuid import UUID


class NotificationService(ABC):
    """
    Interface for notification services
    This follows the Interface Segregation Principle by providing focused interfaces
    All implementations must ensure HIPAA compliance for PHI
    """

    @abstractmethod
    async def send_appointment_reminder(
        self, recipient_id: UUID, appointment_data: dict[str, Any]
    ) -> bool:
        """
        Send an appointment reminder notification

        Args:
            recipient_id: UUID of the recipient
            appointment_data: Dictionary containing appointment details
                              (Must NOT include PHI beyond minimum necessary)

        Returns:
            Boolean indicating success or failure

        Raises:
            ValueError: If recipient doesn't exist or data is invalid
        """
        pass

    @abstractmethod
    async def send_secure_message(
        self, recipient_id: UUID, message_content: str, sender_id: UUID
    ) -> bool:
        """
        Send a secure message notification

        Args:
            recipient_id: UUID of the recipient
            message_content: Content of the message (Must be encrypted)
            sender_id: UUID of the sender

        Returns:
            Boolean indicating success or failure

        Raises:
            ValueError: If recipient doesn't exist or data is invalid
        """
        pass

    @abstractmethod
    async def get_notification_preferences(self, user_id: UUID) -> dict[str, Any]:
        """
        Get notification preferences for a user

        Args:
            user_id: UUID of the user

        Returns:
            Dictionary containing notification preferences

        Raises:
            ValueError: If user doesn't exist
        """
        pass
