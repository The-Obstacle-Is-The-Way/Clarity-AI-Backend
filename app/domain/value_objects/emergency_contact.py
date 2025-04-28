"""Emergency contact value object."""

from dataclasses import dataclass

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
    email: str | None = None
    address: Address | None = None
    
    def __post_init__(self) -> None:
        """Validate emergency contact data."""
        if not self.name:
            raise ValueError("Emergency contact name is required")
        
        if not self.relationship:
            raise ValueError("Relationship to patient is required")
        
        if not self.phone:
            raise ValueError("Emergency contact phone is required")
        
        # Basic phone validation
        digits = ''.join(filter(str.isdigit, self.phone))
        if len(digits) < 10:
            raise ValueError("Phone number must have at least 10 digits")
    
    def to_dict(self) -> dict:
        """Convert to dictionary with PHI masking."""
        # Handle address which could be Address object, dict, or None
        address_dict = None
        if self.address:
            if hasattr(self.address, 'to_dict'):
                # It's an Address object
                address_dict = self.address.to_dict()
            elif isinstance(self.address, dict):
                # It's already a dict
                address_dict = self.address
        
        return {
            "name": "[REDACTED]",  # PHI masked
            "relationship": self.relationship,
            "phone": "[REDACTED]",  # PHI masked
            "email": "[REDACTED]" if self.email else None,  # PHI masked
            "address": address_dict
        }
