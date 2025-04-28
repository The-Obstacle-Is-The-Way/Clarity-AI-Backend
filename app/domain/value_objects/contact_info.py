# app/domain/value_objects/contact_info.py
"""Contact information value object."""

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ContactInfo:
    """Value object for contact information."""
    
    email: str
    phone: str
    preferred_contact_method: str | None = None
    
    def __post_init__(self) -> None:
        """Validate contact information."""
        self._validate_email(self.email)
        self._validate_phone(self.phone)
        
        if self.preferred_contact_method and self.preferred_contact_method not in [
            "email",
            "phone",
        ]:
            raise ValueError(
                "Preferred contact method must be either 'email' or 'phone'"
            )
    
    @staticmethod
    def _validate_email(email: str) -> None:
        """Validate email format."""
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, email):
            raise ValueError("Invalid email format")
    
    @staticmethod
    def _validate_phone(phone: str) -> None:
        """Validate phone number format."""
        # Remove any non-digit characters
        digits = re.sub(r"\D", "", phone)
        if len(digits) < 10:
            raise ValueError("Phone number must have at least 10 digits")
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "email": self.email,
            "phone": self.phone
        }
