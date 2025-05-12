"""
Exception classes specific to appointment-related operations.

This module defines exceptions for common appointment errors, such as
invalid states, time conflicts, and other appointment-specific conditions.
"""

from app.domain.exceptions.base_exceptions import ValidationError, BusinessRuleError

class InvalidAppointmentStateError(ValidationError):
    """Exception raised for invalid appointment state transitions."""
    def __init__(self, message: str = "Invalid appointment state transition"):
        super().__init__(message)

class InvalidAppointmentTimeError(ValidationError):
    """Exception raised for invalid appointment times (e.g., past date)."""
    def __init__(self, message: str = "Invalid appointment time"):
        super().__init__(message)

class AppointmentConflictError(ValidationError):
    """Raised when attempting to create or move an appointment that conflicts with an existing one."""
    def __init__(self, message: str = "The requested appointment time conflicts with an existing appointment"):
        super().__init__(message)
        
class AppointmentNotFoundError(BusinessRuleError):
    """Raised when an appointment is not found."""
    def __init__(self, appointment_id: str):
        message = f"Appointment with ID {appointment_id} not found"
        super().__init__(message)
        self.appointment_id = appointment_id
        
class AppointmentCancellationError(BusinessRuleError):
    """Raised when an appointment cannot be cancelled."""
    def __init__(self, message: str = "Appointment cannot be cancelled"):
        super().__init__(message)
        
class AppointmentReschedulingError(BusinessRuleError):
    """Raised when an appointment cannot be rescheduled."""
    def __init__(self, message: str = "Appointment cannot be rescheduled"):
        super().__init__(message) 