"""Emergency contact value object."""

from dataclasses import dataclass
from typing import Dict, Optional, Union

from app.domain.value_objects.address import Address


@dataclass(frozen=True)
class EmergencyContact:
    """
    Immutable value object for a patient's emergency contact.
    
    Contains PHI that must be handled according to HIPAA regulations.
    """
    
    name: str
    relationship: str
    phone: str
    email: Optional[str] = None
    address: Optional[Union[Address, Dict]] = None
    
    def __post_init__(self) -> None:
        """Validate emergency contact data."""
        if not self.name:
            raise ValueError("Name cannot be empty")
        
        if not self.relationship:
            raise ValueError("Relationship cannot be empty")
        
        if not self.phone:
            raise ValueError("Phone number cannot be empty")
        
        # Basic phone validation
        digits = ''.join(filter(str.isdigit, self.phone))
        if len(digits) < 10:
            raise ValueError("Invalid phone number format")
        
        # Basic email validation if provided
        if self.email and "@" not in self.email:
            raise ValueError("Invalid email format")
        
        # Convert address dict to Address object if needed
        if self.address and isinstance(self.address, dict):
            object.__setattr__(self, "address", Address(**self.address))
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        # Handle address which could be Address object or None
        address_dict = None
        if self.address:
            if hasattr(self.address, 'to_dict'):
                # It's an Address object
                address_dict = self.address.to_dict()
            elif isinstance(self.address, dict):
                # It's already a dict
                address_dict = self.address
        
        return {
            "name": self.name,
            "relationship": self.relationship,
            "phone": self.phone,
            "email": self.email,
            "address": address_dict
        }
