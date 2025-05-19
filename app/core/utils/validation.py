"""
Core Validation Utilities.

This module provides core data validation utilities.
PHI detection logic has been moved to infrastructure.
"""

import re
from typing import Any


def validate_us_phone(phone_number: str) -> bool:
    """
    Validate if a string is a properly formatted US phone number.

    Args:
        phone_number: Phone number string to validate

    Returns:
        True if valid US phone number, False otherwise
    """
    # Remove any non-digit characters for validation
    digits_only = re.sub(r"\D", "", phone_number)

    # US phone numbers should have 10 digits (or 11 with country code 1)
    return len(digits_only) == 10 or (
        len(digits_only) == 11 and digits_only.startswith("1")
    )


def validate_ssn(ssn: str) -> bool:
    """
    Validate if a string could be a Social Security Number format.
    Note: This performs a basic format check, not a validity check against issued SSNs.

    Args:
        ssn: String to validate as SSN format

    Returns:
        True if the format matches ###-##-#### or #########, False otherwise
    """
    # Basic regex for SSN format (###-##-#### or #########)
    ssn_pattern = re.compile(r"^\d{3}-?\d{2}-?\d{4}$")
    return bool(ssn_pattern.match(ssn))


def validate_email(email: str) -> bool:
    """
    Validate if a string is a plausible email address format.

    Args:
        email: String to validate

    Returns:
        True if the format looks like an email address, False otherwise
    """
    # Standard email regex pattern
    email_pattern = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    return bool(email_pattern.match(email))


def validate_date_of_birth(dob: str) -> bool:
    """
    Validate if a string matches common date formats (e.g., MM/DD/YYYY, YYYY-MM-DD).
    Note: This is a basic format check, not a logical date validation.

    Args:
        dob: String to validate as a date format

    Returns:
        True if the format matches common date patterns, False otherwise
    """
    # Regex for common date formats (MM/DD/YYYY, YYYY-MM-DD, MM-DD-YYYY, YYYY/MM/DD)
    date_pattern = re.compile(
        r"^(\d{1,2}[/.-]\d{1,2}[/.-]\d{4}|\d{4}[/.-]\d{1,2}[/.-]\d{1,2})$"
    )
    return bool(date_pattern.match(dob))


# Example basic input validation function
def validate_non_empty_string(value: Any, field_name: str) -> str:
    """
    Validates that a value is a non-empty string.

    Args:
        value: The value to validate.
        field_name: The name of the field being validated (for error messages).

    Returns:
        The validated string value.

    Raises:
        ValueError: If the value is not a string or is empty/whitespace.
    """
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string.")
    if not value.strip():
        raise ValueError(f"{field_name} cannot be empty or contain only whitespace.")
    return value.strip()
