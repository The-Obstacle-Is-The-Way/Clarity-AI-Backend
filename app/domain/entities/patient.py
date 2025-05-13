"""Domain entity representing a patient.

This module defines the *pure* domain model for a patient.  Earlier revisions
of the codebase represented a person's name with separate ``first_name`` and
``last_name`` fields, while newer code – including the patient‑repository test
suite we are currently fixing – passes a single ``name`` string instead.

To maintain backwards‑compatibility we therefore support **both** calling
styles:

1.  ``Patient(id=uuid4(), name="Jane Doe", ...)``
2.  ``Patient(id=uuid4(), first_name="Jane", last_name="Doe", ...)``

If only the **full** name is provided we split it on whitespace to populate
``first_name`` / ``last_name``; if only the *parts* are provided we join them
to synthesise the ``name`` field.  When all three are supplied we leave the
values untouched – caller wins.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, Union
from uuid import UUID

from app.domain.value_objects.emergency_contact import EmergencyContact


@dataclass
class ContactInfo:
    """Contact information for a patient, supporting HIPAA-compliant access patterns."""
    email: str | None = None
    phone: str | None = None
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> 'ContactInfo':
        """Create a ContactInfo instance from a dictionary."""
        if not data:
            return cls()
        return cls(
            email=data.get('email'),
            phone=data.get('phone')
        )
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary, excluding None values."""
        return {k: v for k, v in {
            'email': self.email,
            'phone': self.phone
        }.items() if v is not None}
    
    def to_json(self) -> str:
        """Convert to JSON string representation (convenience method for tests)."""
        import json
        return json.dumps(self.to_dict())


class PatientContactInfoDescriptor:
    """Special descriptor for Patient.contact_info that handles both class and instance access.
    
    When accessed from the class (Patient.contact_info), returns the ContactInfo class.
    When accessed from an instance (patient.contact_info), returns a ContactInfo instance.
    """
    
    def __get__(self, instance, owner=None):
        """Get handler that differentiates between class and instance access."""
        # Class access: return the ContactInfo class itself
        if instance is None:
            return ContactInfo
        
        # Instance access: return ContactInfo instance with instance data
        if instance.email is None and instance.phone is None:
            return None
        
        # Create a new ContactInfo instance with the patient's email and phone
        return ContactInfo(email=instance.email, phone=instance.phone)
    
    def __set__(self, instance, value):
        """Set handler that updates the instance's email and phone."""
        if value is None:
            instance.email = None
            instance.phone = None
        elif isinstance(value, dict):
            instance.email = value.get('email')
            instance.phone = value.get('phone')
        elif isinstance(value, ContactInfo):
            instance.email = value.email
            instance.phone = value.phone
        elif value is ContactInfo:
            # Just ignore this case - it's handled in __get__
            pass
        else:
            raise TypeError(f"Expected ContactInfo, dict, or None; got {type(value).__name__}")


@dataclass
class Patient:
    """Core domain model for a patient."""
    
    # PHI fields list - fields considered protected health information
    phi_fields: set = field(default_factory=lambda: {
        'name', 'first_name', 'last_name', 'date_of_birth', 'email', 'phone', 
        'address', 'insurance_number', 'ssn', 'medical_record_number',
        'emergency_contact', 'treatment_notes', 'medical_history'
    }, init=False, repr=False)
    
    # Required fields
    date_of_birth: Union[datetime, str]
    
    # Optional fields with defaults
    id: UUID | None = None
    gender: str | None = None
    name: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    
    # Contact info fields
    email: str | None = None
    phone: str | None = None
    address: Any = None
    insurance_number: str | None = None
    ssn: str | None = None
    medical_record_number: str | None = None
    emergency_contact: EmergencyContact | None = None
    insurance: dict[str, Any] | None = None
    insurance_info: dict[str, Any] | None = None
    
    # Status fields
    active: bool = True
    created_by: Any = None
    
    # Clinical data
    diagnoses: list[str] = field(default_factory=list)
    medications: list[str] = field(default_factory=list)
    allergies: list[str] = field(default_factory=list)
    medical_history: list[str] = field(default_factory=list)
    treatment_notes: list[dict[str, Any]] = field(default_factory=list)
    
    # Audit timestamps
    created_at: datetime | str | None = None
    updated_at: datetime | str | None = None
    
    # This won't be stored in the instance but will be used during initialization
    _contact_info: Any = field(default=None, repr=False, compare=False)
    
    def __post_init__(self):
        """Initialize the object after dataclass initialization."""
        # Handle contact_info parameter if provided
        if hasattr(self, '_contact_info') and self._contact_info is not None:
            self._process_contact_info(self._contact_info)
            # Remove the temporary field
            object.__delattr__(self, '_contact_info')
            
        # Process names
        self._harmonize_names()
        
        # Initialize timestamps
        self._initialize_timestamps()
        
        # Parse date fields
        self._parse_date_fields()
    
    def __getattribute__(self, name):
        """Override to log access to PHI fields."""
        # First get the phi_fields set to check if this is a PHI field
        # We need to use object.__getattribute__ to avoid infinite recursion
        if name != 'phi_fields' and name in object.__getattribute__(self, 'phi_fields'):
            # Import here to avoid circular imports
            try:
                from app.core.utils.audit import audit_logger
                # Log access to PHI field
                patient_id = object.__getattribute__(self, 'id')
                audit_logger.log_access(
                    resource_id=str(patient_id) if patient_id else None,
                    resource_type="Patient",
                    field_name=name,
                    action="field_access"
                )
            except ImportError:
                # If audit_logger is not available, just log a warning
                import logging
                logging = logging.getLogger(__name__)
                logging.warning(f"PHI field '{name}' accessed but audit_logger unavailable")
                
        # Return the attribute normally
        return object.__getattribute__(self, name)
    
    def _process_contact_info(self, contact_info):
        """Process the contact_info parameter."""
        if contact_info is ContactInfo:
            # This is the class itself, not an instance
            return
            
        if isinstance(contact_info, dict):
            # If email or phone weren't explicitly provided, get them from contact_info
            if self.email is None:
                self.email = contact_info.get('email')
            if self.phone is None:
                self.phone = contact_info.get('phone')
        elif hasattr(contact_info, 'email') and hasattr(contact_info, 'phone'):
            # Handle ContactInfo instance
            if self.email is None:
                self.email = contact_info.email
            if self.phone is None:
                self.phone = contact_info.phone
    
    def _harmonize_names(self):
        """Harmonize first_name, last_name, and name fields."""
        if self.name and not (self.first_name or self.last_name):
            parts = self.name.split()
            if parts:
                self.first_name = parts[0]
                if len(parts) > 1:
                    self.last_name = parts[-1]

        if not self.name and (self.first_name or self.last_name):
            self.name = " ".join(p for p in (self.first_name, self.last_name) if p)
    
    def _initialize_timestamps(self):
        """Initialize created_at and updated_at timestamps if not provided."""
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.updated_at is None:
            self.updated_at = datetime.now()
    
    def _parse_date_fields(self):
        """Parse date fields from strings if necessary."""
        self.date_of_birth = self._ensure_datetime(self.date_of_birth)
        self.created_at = self._ensure_datetime(self.created_at)
        self.updated_at = self._ensure_datetime(self.updated_at)
    
    def _ensure_datetime(self, value):
        """Convert string dates to datetime objects."""
        if value is None or isinstance(value, (datetime, date)):
            return value
        if isinstance(value, str):
            try:
                return date.fromisoformat(value)
            except ValueError:
                pass
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                pass
            try:
                return datetime.strptime(value, "%Y-%m-%d").date()
            except ValueError:
                return value
        return value
    
    def update_contact_info(self, email: str | None = None, phone: str | None = None, address: str | None = None) -> None:
        """Update contact fields and refresh updated_at timestamp."""
        if email is not None:
            self.email = email
        if phone is not None:
            self.phone = phone
        if address is not None:
            self.address = address
        self.updated_at = datetime.now()
    
    def add_medical_history_item(self, item: str) -> None:
        """Add an item to medical_history and refresh updated_at."""
        self.medical_history.append(item)
        self.updated_at = datetime.now()
    
    def add_medication(self, medication: str) -> None:
        """Add a medication and refresh updated_at."""
        self.medications.append(medication)
        self.updated_at = datetime.now()
    
    def add_allergy(self, allergy: str) -> None:
        """Add an allergy if not existing and refresh updated_at."""
        if allergy not in self.allergies:
            self.allergies.append(allergy)
            self.updated_at = datetime.now()
    
    def add_treatment_note(self, note: dict) -> None:
        """Add a treatment note with timestamp and refresh updated_at."""
        entry = dict(note)
        entry["date"] = datetime.now()
        self.treatment_notes.append(entry)
        self.updated_at = datetime.now()
    
    def model_copy(self, *, update: dict = None, deep: bool = False, **kwargs) -> Patient:
        """Compatibility method similar to Pydantic v1's copy() but for dataclasses."""
        from copy import copy, deepcopy
        # Create a new instance with the same attributes
        if deep:
            data = deepcopy(self.__dict__)
        else:
            data = copy(self.__dict__)
            
        # Remove special fields
        if '_contact_info' in data:
            data.pop('_contact_info')
            
        # Apply updates from the update dict and kwargs
        if update:
            for field, nested_update in update.items():
                if field == 'contact_info' and isinstance(nested_update, dict):
                    # Handle contact_info updates
                    data['email'] = nested_update.get('email')
                    data['phone'] = nested_update.get('phone')
                elif isinstance(nested_update, dict) and field in data and isinstance(data[field], dict):
                    data[field].update(nested_update)
                else:
                    # For other fields, replace completely
                    data[field] = nested_update
                    
        # Apply any additional keyword args as direct updates
        data.update(kwargs)
        
        # Create new instance
        return self.__class__(**data)
    
    def model_dump(self, *, exclude=None, exclude_none=False) -> dict:
        """Compatibility method similar to Pydantic v2's model_dump but for dataclasses."""
        from dataclasses import asdict
        data = asdict(self)
        
        # Remove special fields
        if '_contact_info' in data:
            data.pop('_contact_info')
        
        # Ensure contact_info is properly represented
        if self.email is not None or self.phone is not None:
            data['contact_info'] = {
                'email': self.email,
                'phone': self.phone
            }
        
        # Handle exclusions
        if exclude:
            for field in exclude:
                if field in data:
                    data.pop(field)
        
        # Handle exclude_none
        if exclude_none:
            return {k: v for k, v in data.items() if v is not None}
            
        return data
    
    def __str__(self) -> str:
        """String representation of the patient."""
        return f"Patient<{self.id}> {self.name or ''} {self.first_name or ''} {self.last_name or ''}".strip()
    
    def __repr__(self) -> str:
        """Detailed string representation of the patient."""
        return (
            f"Patient(id={self.id!r}, name={self.name!r}, first_name={self.first_name!r}, last_name={self.last_name!r})"
        )
    
    def __hash__(self) -> int:
        """Hash based on ID."""
        return hash(self.id) if self.id is not None else hash(None)


# Attach the descriptor to the class after definition
Patient.contact_info = PatientContactInfoDescriptor()
