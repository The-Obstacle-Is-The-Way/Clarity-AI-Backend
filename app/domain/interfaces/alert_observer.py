"""
Alert Observer Interface for the Digital Twin Psychiatry Platform.

This module defines the AlertObserver interface, which implements the Observer
pattern for the biometric alert system. Observers are notified when new alerts
are generated, allowing for flexible handling of alerts by different components.
"""

from abc import ABC, abstractmethod

from app.domain.services.biometric_event_processor import BiometricAlert


class AlertObserver(ABC):
    """
    Interface for observers of biometric alerts.

    Classes implementing this interface can register to be notified
    when new biometric alerts are generated. This follows the Observer
    pattern to decouple alert generation from alert handling.
    """

    @abstractmethod
    async def notify_alert(self, alert: BiometricAlert) -> None:
        """
        Notify the observer of a new biometric alert.

        Args:
            alert: The biometric alert that was generated
        """
        pass


class AlertSubject(ABC):
    """
    Interface for subjects that generate biometric alerts.

    Classes implementing this interface can register observers to be notified
    when new alerts are generated. This follows the Observer pattern to
    decouple alert generation from alert handling.
    """

    @abstractmethod
    def register_observer(self, observer: AlertObserver) -> None:
        """
        Register a new observer to be notified of alerts.

        Args:
            observer: The observer to register
        """
        pass

    @abstractmethod
    def remove_observer(self, observer: AlertObserver) -> None:
        """
        Remove an observer from the notification list.

        Args:
            observer: The observer to remove
        """
        pass

    @abstractmethod
    async def notify_observers(self, alert: BiometricAlert) -> None:
        """
        Notify all registered observers of a new alert.

        Args:
            alert: The biometric alert to notify observers about
        """
        pass
