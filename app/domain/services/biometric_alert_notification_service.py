"""
Biometric Alert Notification Service for the Digital Twin Psychiatry Platform.

This service implements the AlertObserver interface to send HIPAA-compliant
notifications when biometric alerts are generated. It supports multiple
notification channels (SMS, email, in-app) and ensures PHI is properly
sanitized in all communications.
"""

from enum import Enum
from typing import Any

from app.domain.interfaces.alert_observer import AlertObserver
from app.domain.repositories.biometric_alert_repository import BiometricAlertRepository
from app.domain.services.biometric_event_processor import AlertPriority, BiometricAlert


class NotificationChannel(Enum):
    """
    Notification channels for biometric alerts.
    
    These channels define how notifications are delivered to recipients.
    """
    SMS = "sms"
    EMAIL = "email"
    IN_APP = "in_app"
    PUSH = "push"


class BiometricAlertNotificationService(AlertObserver):
    """
    Service for sending HIPAA-compliant notifications for biometric alerts.
    
    This service implements the AlertObserver interface to receive notifications
    when new biometric alerts are generated. It then sends appropriate
    notifications to clinical staff based on alert priority and configured
    preferences.
    """
    
    def __init__(
        self,
        alert_repository: BiometricAlertRepository,
        notification_service_provider: Any  # This would be a concrete notification service
    ) -> None:
        """
        Initialize the BiometricAlertNotificationService.
        
        Args:
            alert_repository: Repository for storing and retrieving alerts
            notification_service_provider: Service for sending notifications
        """
        self.alert_repository = alert_repository
        self.notification_service = notification_service_provider
    
    async def notify_alert(self, alert: BiometricAlert) -> None:
        """
        Notify clinical staff of a new biometric alert.
        
        This method is called by the BiometricEventProcessor when a new
        alert is generated. It determines the appropriate notification
        channels and recipients based on the alert priority and sends
        HIPAA-compliant notifications.
        
        Args:
            alert: The biometric alert to notify about
        """
        # Determine notification channels based on priority
        channels = self._get_channels_for_priority(alert.priority)
        
        # Get recipients for this alert
        recipients = await self._get_alert_recipients(alert)
        
        # Send notifications through each channel
        for channel in channels:
            await self._send_notification(alert, channel, recipients)
    
    def _get_channels_for_priority(self, priority: AlertPriority) -> list[NotificationChannel]:
        """
        Determine appropriate notification channels based on alert priority.
        
        Args:
            priority: Priority level of the alert
            
        Returns:
            List of notification channels to use
        """
        if priority == AlertPriority.URGENT:
            # Urgent alerts use all available channels
            return [
                NotificationChannel.SMS,
                NotificationChannel.EMAIL,
                NotificationChannel.IN_APP,
                NotificationChannel.PUSH
            ]
        elif priority == AlertPriority.WARNING:
            # Warning alerts use email, in-app, and push
            return [
                NotificationChannel.EMAIL,
                NotificationChannel.IN_APP,
                NotificationChannel.PUSH
            ]
        else:  # INFORMATIONAL
            # Informational alerts use in-app only
            return [NotificationChannel.IN_APP]
    
    async def _get_alert_recipients(self, alert: BiometricAlert) -> list[dict[str, Any]]:
        """
        Determine recipients for an alert notification.
        
        Args:
            alert: The biometric alert to notify about
            
        Returns:
            List of recipient information dictionaries
        """
        # In a real implementation, this would query a provider-patient
        # relationship database to determine which providers should be
        # notified about this patient's alerts
        
        # For now, we'll return a mock recipient list
        return [
            {
                "provider_id": "00000000-0000-0000-0000-000000000000",
                "name": "Primary Provider",
                "email": "provider@example.com",
                "phone": "+15555555555",
                "notification_preferences": {
                    "sms": True,
                    "email": True,
                    "in_app": True,
                    "push": True
                }
            }
        ]
    
    async def _send_notification(
        self,
        alert: BiometricAlert,
        channel: NotificationChannel,
        recipients: list[dict[str, Any]]
    ) -> None:
        """
        Send a notification through a specific channel.
        
        Args:
            alert: The biometric alert to notify about
            channel: The notification channel to use
            recipients: List of recipients to notify
        """
        # Filter recipients based on their preferences
        filtered_recipients = [
            r for r in recipients
            if r["notification_preferences"].get(channel.value, False)
        ]
        
        if not filtered_recipients:
            return
        
        # Create a HIPAA-compliant message
        message = self._create_hipaa_compliant_message(alert, channel)
        
        # Send through the appropriate channel
        if channel == NotificationChannel.SMS:
            await self._send_sms_notifications(message, filtered_recipients)
        elif channel == NotificationChannel.EMAIL:
            await self._send_email_notifications(message, filtered_recipients, alert)
        elif channel == NotificationChannel.IN_APP:
            await self._send_in_app_notifications(message, filtered_recipients, alert)
        elif channel == NotificationChannel.PUSH:
            await self._send_push_notifications(message, filtered_recipients)
    
    def _create_hipaa_compliant_message(
        self,
        alert: BiometricAlert,
        channel: NotificationChannel
    ) -> str:
        """
        Create a HIPAA-compliant message for a notification.
        
        This method ensures that no PHI is included in the notification
        message, following HIPAA guidelines for secure communications.
        
        Args:
            alert: The biometric alert to create a message for
            channel: The notification channel the message will be sent through
            
        Returns:
            A HIPAA-compliant notification message
        """
        # For SMS, create a minimal message with no PHI
        if channel == NotificationChannel.SMS:
            return (
                f"SECURE: {alert.priority.value.upper()} biometric alert detected. "
                f"Please log in to the secure portal for details."
            )
        
        # For other channels, we can include more information but still no PHI
        return (
            f"SECURE: {alert.priority.value.upper()} biometric alert detected.\n\n"
            f"Alert Type: {alert.alert_type}\n"
            f"Time: {alert.created_at.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            f"Please log in to the secure portal to view details and take action."
        )
    
    async def _send_sms_notifications(
        self,
        message: str,
        recipients: list[dict[str, Any]]
    ) -> None:
        """
        Send SMS notifications to recipients.
        
        Args:
            message: The notification message
            recipients: List of recipients to notify
        """
        for recipient in recipients:
            if "phone" in recipient:
                await self.notification_service.send_sms(
                    recipient["phone"],
                    message
                )
    
    async def _send_email_notifications(
        self,
        message: str,
        recipients: list[dict[str, Any]],
        alert: BiometricAlert
    ) -> None:
        """
        Send email notifications to recipients.
        
        Args:
            message: The notification message
            recipients: List of recipients to notify
            alert: The biometric alert to notify about
        """
        subject = f"SECURE: {alert.priority.value.upper()} Biometric Alert"
        
        for recipient in recipients:
            if "email" in recipient:
                await self.notification_service.send_email(
                    recipient["email"],
                    subject,
                    message,
                    {
                        "alert_id": str(alert.alert_id),
                        "priority": alert.priority.value,
                        "created_at": alert.created_at.isoformat()
                    }
                )
    
    async def _send_in_app_notifications(
        self,
        message: str,
        recipients: list[dict[str, Any]],
        alert: BiometricAlert
    ) -> None:
        """
        Send in-app notifications to recipients.
        
        Args:
            message: The notification message
            recipients: List of recipients to notify
            alert: The biometric alert to notify about
        """
        for recipient in recipients:
            if "provider_id" in recipient:
                await self.notification_service.send_in_app_notification(
                    recipient["provider_id"],
                    message,
                    {
                        "alert_id": str(alert.alert_id),
                        "priority": alert.priority.value,
                        "type": "biometric_alert",
                        "created_at": alert.created_at.isoformat()
                    }
                )
    
    async def _send_push_notifications(
        self,
        message: str,
        recipients: list[dict[str, Any]]
    ) -> None:
        """
        Send push notifications to recipients.
        
        Args:
            message: The notification message
            recipients: List of recipients to notify
        """
        for recipient in recipients:
            if "provider_id" in recipient:
                await self.notification_service.send_push_notification(
                    recipient["provider_id"],
                    "Biometric Alert",
                    message
                )