"""
Exception classes for patient-related domain operations.

These exceptions represent domain-specific error conditions and are independent
of any infrastructure or application framework.
"""


class PatientError(Exception):
    """Base exception class for all patient-related errors."""

    def __init__(self, message: str = "An error occurred with patient operation"):
        self.message = message
        super().__init__(self.message)


class PatientNotFoundError(PatientError):
    """Exception raised when a patient cannot be found."""

    def __init__(self, patient_id: str):
        self.patient_id = patient_id
        message = f"Patient with ID '{patient_id}' not found"
        super().__init__(message)


class PatientValidationError(PatientError):
    """Exception raised when patient data fails validation."""

    def __init__(self, message: str = "Invalid patient data", field: str | None = None):
        self.field = field
        if field:
            message = f"Invalid patient data: field '{field}' {message}"
        super().__init__(message)


class PatientAlreadyExistsError(PatientError):
    """Exception raised when attempting to create a patient that already exists."""

    def __init__(self, patient_id: str):
        self.patient_id = patient_id
        message = f"Patient with ID '{patient_id}' already exists"
        super().__init__(message)


class PatientOperationError(PatientError):
    """Exception raised when a patient operation fails due to a system error."""

    def __init__(self, operation: str, message: str = "Operation failed"):
        self.operation = operation
        message = f"Patient {operation} operation failed: {message}"
        super().__init__(message)
