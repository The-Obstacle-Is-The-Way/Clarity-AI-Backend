"""
Exception classes for patient-related domain operations.

These exceptions represent domain-specific error conditions and are independent
of any infrastructure or application framework.
"""

from typing import Any


class PatientError(Exception):
    """Base exception class for all patient-related errors."""

    def __init__(
        self,
        message: str = "An error occurred with patient operation",
        *args: Any,
        **kwargs: Any
    ) -> None:
        """
        Initialize a PatientError exception.

        Args:
            message: Human-readable error message describing the patient operation error
            *args: Additional positional arguments for extensibility
            **kwargs: Additional keyword arguments for extensibility
        """
        self.message = message
        super().__init__(message, *args, **kwargs)


class PatientNotFoundError(PatientError):
    """Exception raised when a patient cannot be found."""

    def __init__(self, patient_id: str, *args: Any, **kwargs: Any) -> None:
        """
        Initialize a PatientNotFoundError exception.

        Args:
            patient_id: The ID of the patient that could not be found
            *args: Additional positional arguments for extensibility
            **kwargs: Additional keyword arguments for extensibility
        """
        self.patient_id = patient_id
        message = f"Patient with ID '{patient_id}' not found"
        super().__init__(message, *args, **kwargs)


class PatientValidationError(PatientError):
    """Exception raised when patient data fails validation."""

    def __init__(
        self,
        message: str = "Invalid patient data",
        field: str | None = None,
        *args: Any,
        **kwargs: Any
    ) -> None:
        """
        Initialize a PatientValidationError exception.

        Args:
            message: Human-readable error message describing the validation failure
            field: Optional field name that failed validation
            *args: Additional positional arguments for extensibility
            **kwargs: Additional keyword arguments for extensibility
        """
        self.field = field
        if field:
            message = f"Invalid patient data: field '{field}' {message}"
        super().__init__(message, *args, **kwargs)


class PatientAlreadyExistsError(PatientError):
    """Exception raised when attempting to create a patient that already exists."""

    def __init__(self, patient_id: str, *args: Any, **kwargs: Any) -> None:
        """
        Initialize a PatientAlreadyExistsError exception.

        Args:
            patient_id: The ID of the patient that already exists
            *args: Additional positional arguments for extensibility
            **kwargs: Additional keyword arguments for extensibility
        """
        self.patient_id = patient_id
        message = f"Patient with ID '{patient_id}' already exists"
        super().__init__(message, *args, **kwargs)


class PatientOperationError(PatientError):
    """Exception raised when a patient operation fails due to a system error."""

    def __init__(
        self,
        operation: str,
        message: str = "Operation failed",
        *args: Any,
        **kwargs: Any
    ) -> None:
        """
        Initialize a PatientOperationError exception.

        Args:
            operation: The name of the patient operation that failed
            message: Human-readable error message describing the operation failure
            *args: Additional positional arguments for extensibility
            **kwargs: Additional keyword arguments for extensibility
        """
        self.operation = operation
        message = f"Patient {operation} operation failed: {message}"
        super().__init__(message, *args, **kwargs)
