"""
Exception classes related to appointment operations.

This module defines exceptions raised during appointment scheduling, cancellation,
and other appointment-related operations.
"""

from typing import Any

from app.domain.exceptions.base_exceptions import BaseApplicationError


class AppointmentError(BaseApplicationError):
    """Base class for appointment-related exceptions."""

    def __init__(
        self, message: str = "Appointment operation failed", *args: Any, **kwargs: Any
    ) -> None:
        super().__init__(message, *args, **kwargs)


class InvalidAppointmentStateError(AppointmentError):
    """Raised when an operation is attempted on an appointment in an invalid state."""

    def __init__(
        self,
        message: str = "Invalid appointment state for the requested operation",
        current_state: str | None = None,
        required_state: str | None = None,
        appointment_id: str | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        if current_state and required_state:
            message = f"{message}: current state is '{current_state}', required state is '{required_state}'"
        if appointment_id:
            message = f"{message} for appointment {appointment_id}"
        super().__init__(message, *args, **kwargs)
        self.current_state = current_state
        self.required_state = required_state
        self.appointment_id = appointment_id


class InvalidAppointmentTimeError(AppointmentError):
    """Raised when an invalid appointment time is specified."""

    def __init__(
        self, message: str = "Invalid appointment time", *args: Any, **kwargs: Any
    ) -> None:
        super().__init__(message, *args, **kwargs)


class AppointmentConflictError(AppointmentError):
    """Raised when there is a scheduling conflict with another appointment."""

    def __init__(
        self,
        message: str = "Appointment scheduling conflict",
        conflicting_appointment_id: str | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        if conflicting_appointment_id:
            message = f"{message} with appointment {conflicting_appointment_id}"
        super().__init__(message, *args, **kwargs)
        self.conflicting_appointment_id = conflicting_appointment_id


class AppointmentNotFoundError(AppointmentError):
    """Raised when an appointment cannot be found."""

    def __init__(
        self,
        message: str = "Appointment not found",
        appointment_id: str | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        if appointment_id:
            message = f"Appointment with ID {appointment_id} not found"
        super().__init__(message, *args, **kwargs)
        self.appointment_id = appointment_id


class AppointmentCancellationError(AppointmentError):
    """Raised when an appointment cannot be cancelled."""

    def __init__(
        self,
        message: str = "Cannot cancel appointment",
        appointment_id: str | None = None,
        reason: str | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        if appointment_id and reason:
            message = f"Cannot cancel appointment {appointment_id}: {reason}"
        elif appointment_id:
            message = f"Cannot cancel appointment {appointment_id}"
        super().__init__(message, *args, **kwargs)
        self.appointment_id = appointment_id
        self.reason = reason


class AppointmentReschedulingError(AppointmentError):
    """Raised when an appointment cannot be rescheduled."""

    def __init__(
        self,
        message: str = "Cannot reschedule appointment",
        appointment_id: str | None = None,
        reason: str | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        if appointment_id and reason:
            message = f"Cannot reschedule appointment {appointment_id}: {reason}"
        elif appointment_id:
            message = f"Cannot reschedule appointment {appointment_id}"
        super().__init__(message, *args, **kwargs)
        self.appointment_id = appointment_id
        self.reason = reason
