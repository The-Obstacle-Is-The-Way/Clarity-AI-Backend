"""
SQLAlchemy models for patient data.

This module defines the patient-related SQLAlchemy models.
Encryption/decryption is handled by the repository layer.
"""

import inspect
import json
import logging
import uuid
from typing import Any

from dateutil import parser
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, Text, Date, JSON
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import Enum as SQLEnum

# Use the core domain model, which has phone_number attribute
from app.core.domain.entities.patient import Patient as DomainPatient
from app.domain.utils.datetime_utils import UTC, now_utc
from app.domain.value_objects.address import Address
from app.domain.value_objects.emergency_contact import EmergencyContact  # Import EmergencyContact
from app.infrastructure.persistence.sqlalchemy.models.base import Base, TimestampMixin, AuditMixin
# from app.infrastructure.security.encryption import EncryptedString, EncryptedText, EncryptedDate, EncryptedJSON # REMOVED - Caused ImportError

# Break circular import by using string reference to User model
# This follows SQLAlchemy best practices for circular relationship references
from app.infrastructure.security.encryption.base_encryption_service import BaseEncryptionService
from app.infrastructure.security.encryption.encryption_service import EncryptionService
from app.core.config import settings
from app.infrastructure.persistence.sqlalchemy.types.encrypted_types import EncryptedString, EncryptedText, EncryptedJSON
from app.tests.standalone.domain.test_standalone_patient import Gender # TEMPORARY: Gender enum location
import base64 # Import base64 for decoding the key

logger = logging.getLogger(__name__)

import dataclasses  # Add this import

# Correct import: Use absolute path to types.py file
from app.infrastructure.persistence.sqlalchemy.types import GUID, JSONEncodedDict 
from app.infrastructure.persistence.sqlalchemy.registry import register_model

# encryption_service_instance = EncryptionService() # No key passed. TODO: Review if this instance is needed here at all. -> REMOVED

@register_model
class Patient(Base, TimestampMixin, AuditMixin):
    """
    SQLAlchemy model for patient data.

    Represents the structure of the 'patients' table.
    Encryption/decryption logic is handled externally by the PatientRepository.
    """
    
    __tablename__ = "patients"
    
    # Critical for test integrity - allows safe redefinition during testing
    # This pattern eliminates circular dependency errors without compromising
    # the HIPAA-compliant security model of the codebase
    __table_args__ = {'extend_existing': True}
    
    # --- Primary Key and Foreign Keys ---
    # Note: id column MUST be defined precisely to avoid SQLAlchemy mapping issues
    id = Column(GUID(), primary_key=True, default=uuid.uuid4) 
    external_id = Column(String(64), unique=True, index=True, nullable=True)
    user_id = Column(GUID(), ForeignKey('users.id'), nullable=False, index=True)

    created_at = Column(DateTime, default=now_utc, nullable=False)
    updated_at = Column(DateTime, default=now_utc, onupdate=now_utc, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    # --- Encrypted PHI Fields (Stored as Text/Blob in DB) ---
    # QUANTUM FIX: Use prefixed column names with underscore for encrypted fields
    # This ensures compatibility with test expectations and encryption handling
    _first_name = Column("first_name", EncryptedString, nullable=True)
    _last_name = Column("last_name", EncryptedString, nullable=True)
    _middle_name = Column("middle_name", EncryptedString, nullable=True)
    _gender = Column("gender", SQLEnum(Gender, name="gender_enum"), nullable=True)
    _date_of_birth = Column("date_of_birth", EncryptedString, nullable=True)
    _ssn = Column("ssn", EncryptedString, nullable=True)
    _mrn = Column("mrn", EncryptedString, nullable=True)
    _email = Column("email", EncryptedString, nullable=True)
    _phone_number = Column("phone_number", EncryptedString, nullable=True)
    _insurance_provider = Column("insurance_provider", EncryptedString, nullable=True)
    _insurance_policy_number = Column("insurance_policy_number", EncryptedString, nullable=True)
    _insurance_group_number = Column("insurance_group_number", EncryptedString, nullable=True)
    _address_line1 = Column("address_line1", EncryptedString, nullable=True)
    _address_line2 = Column("address_line2", EncryptedString, nullable=True)
    _city = Column("city", EncryptedString, nullable=True)
    _state = Column("state", EncryptedString, nullable=True)
    _zip_code = Column("zip_code", EncryptedString, nullable=True)
    _country = Column("country", EncryptedString, nullable=True)
    _emergency_contact_name = Column("emergency_contact_name", EncryptedString, nullable=True)
    _emergency_contact_phone = Column("emergency_contact_phone", EncryptedString, nullable=True)
    _emergency_contact_relationship = Column("emergency_contact_relationship", EncryptedString, nullable=True)
    
    # Fields that might be JSON or larger text
    _contact_info = Column("contact_info", EncryptedJSON, nullable=True)
    _address_details = Column("address_details", EncryptedJSON, nullable=True)
    _emergency_contact_details = Column("emergency_contact_details", EncryptedJSON, nullable=True)
    _preferences = Column("preferences", EncryptedJSON, nullable=True)
    _medical_history = Column("medical_history", EncryptedText, nullable=True)
    _medications = Column("medications", EncryptedText, nullable=True)
    _allergies = Column("allergies", EncryptedText, nullable=True)
    _notes = Column("notes", EncryptedText, nullable=True)
    _custom_fields = Column("custom_fields", EncryptedJSON, nullable=True)

    # --- Other Fields (Potentially Sensitive/Encrypted or Not) ---
    # Example: Encrypted JSON blob for arbitrary additional structured data
    _extra_data = Column("extra_data", EncryptedJSON, nullable=True)

    # --- Relationships ---
    # Define relationships with string references to avoid circular imports
    # and ensure proper lazy loading
    
    # Relationship with User (owner of the patient record) - Simplified
    user = relationship(
        "User",  # Use the correct class name
        back_populates="patients",
        lazy="selectin"
    )

    # Define appointments relationship with proper foreign_keys and viewonly
    appointments = relationship(
        "AppointmentModel", 
        back_populates="patient", 
        cascade="all, delete-orphan",
        lazy="selectin",  # Efficient loading pattern
        foreign_keys="AppointmentModel.patient_id",  # Explicit foreign key reference 
        viewonly=True,  # Set to true to prevent modification errors
    )
    
    # Relationship with clinical notes with proper foreign_keys setting
    clinical_notes = relationship(
        "ClinicalNoteModel", 
        back_populates="patient", 
        cascade="all, delete-orphan",
        lazy="selectin",  # Efficient loading pattern
        foreign_keys="ClinicalNoteModel.patient_id",  # Explicit foreign key reference
        viewonly=True,  # Set to true to prevent modification errors
    )
    
    # UPDATED: Relationship with patient-specific prescriptions
    prescriptions = relationship(
        "PatientMedicationModel", 
        back_populates="patient", 
        cascade="all, delete-orphan",
        lazy="selectin",  # Efficient loading pattern
        foreign_keys="PatientMedicationModel.patient_id",  # Explicit foreign key reference
        viewonly=True,  # Set to true to prevent modification errors
    )

    # Relationship to BiometricRuleModel
    biometric_rules = relationship(
        "BiometricRuleModel",
        back_populates="patient",
        cascade="all, delete-orphan",
        lazy="dynamic",
        foreign_keys="BiometricRuleModel.patient_id",  # Explicit foreign key reference
        viewonly=True,  # Set to true to prevent modification errors
    )

    # ADDED: Relationship to BiometricTwinModel
    biometric_twin = relationship(
        "BiometricTwinModel",
        back_populates="patient",
        uselist=False, # One-to-one relationship
        cascade="all, delete-orphan", # Cascade delete/orphan operations
        foreign_keys="BiometricTwinModel.patient_id",  # Explicit foreign key reference
        viewonly=True,  # Set to true to prevent modification errors
    )

    # --- Encrypted Fields Set --- 
    # QUANTUM FIX: Update encrypted_fields set to use prefixed column names with underscores
    encrypted_fields = {
        '_first_name',
        '_last_name',
        '_email',
        '_phone_number',
        '_ssn',
        '_mrn',
        '_gender',
        '_address_line1',
        '_address_line2',
        '_city',
        '_state',
        '_zip_code',
        '_country',
        '_emergency_contact_name',
        '_emergency_contact_phone',
        '_emergency_contact_relationship',
        '_contact_info',
        '_address_details',
        '_emergency_contact_details',
        '_preferences',
        '_medical_history',
        '_medications',
        '_allergies',
        '_notes',
        '_custom_fields',
        '_extra_data'
    }
    # --- END ADD --- 

    def __repr__(self) -> str:
        # Provide a representation useful for debugging, avoiding PHI exposure
        return f"<Patient(id={self.id}, created_at={self.created_at}, is_active={self.is_active})>"
    
    @classmethod
    async def from_domain(cls, patient: DomainPatient) -> "Patient":
        """
        Create a Patient model instance from a domain Patient entity,
        encrypting PHI fields using the provided encryption service.
        """
        logger.debug(f"[from_domain] Starting conversion for domain patient ID: {getattr(patient, 'id', 'NO_ID_YET')}")
        model = cls()

        # Core metadata
        # Convert external_id to string if it's a UUID object
        ext_id = getattr(patient, "external_id", None)
        if isinstance(ext_id, uuid.UUID):
            model.external_id = str(ext_id)
            logger.debug(f"[from_domain] Converted external_id UUID {ext_id} to string for storage.")
        else:
            model.external_id = ext_id # Assume it's already a string or None
            
        # Ensure created_by is UUID or None, store as string
        created_by_id_obj = getattr(patient, 'created_by', None)
        if isinstance(created_by_id_obj, uuid.UUID):
             model.user_id = str(created_by_id_obj) # Store as string
        elif created_by_id_obj: # Assume it's a string representation
             # Validate if it's a valid UUID string before storing
             try:
                 uuid.UUID(str(created_by_id_obj)) # Validate format
                 model.user_id = str(created_by_id_obj) # Store as string
             except (ValueError, TypeError):
                 logger.warning(f"[from_domain] Invalid format for created_by UUID string '{created_by_id_obj}'. Setting user_id to None.")
                 model.user_id = None
        else:
             model.user_id = None
        # END FIX

        model.is_active = getattr(patient, 'active', True) # Use getattr for safety
        logger.debug(f"[from_domain] Mapped core metadata for {getattr(patient, 'id', 'NO_ID_YET')}")

        # Assign values to prefixed fields directly. TypeDecorators will handle encryption.
        model._first_name = getattr(patient, 'first_name', None)
        model._last_name = getattr(patient, 'last_name', None)
        model._middle_name = getattr(patient, 'middle_name', None)
        model._gender = getattr(patient, 'gender', None)
        
        # Handle date_of_birth (convert date/datetime to isoformat string first)
        dob_value = getattr(patient, 'date_of_birth', None)
        dob_iso_str = None
        if isinstance(dob_value, (date, datetime)):
             dob_iso_str = dob_value.isoformat()
        elif isinstance(dob_value, str):
             # Attempt to parse string to validate and normalize format, fallback to original string
             try:
                 dob_iso_str = parser.parse(dob_value).date().isoformat()
             except (ValueError, TypeError):
                 logger.warning(f"Could not parse date_of_birth string '{dob_value}' for patient {getattr(patient, 'id', 'N/A')}. Storing as is.")
                 dob_iso_str = dob_value # Keep original string if parsing fails
        model._date_of_birth = dob_iso_str # Assign string, EncryptedString will handle it
        
        model._email = getattr(patient, 'email', None)
        model._phone_number = getattr(patient, 'phone_number', None)
        model._ssn = getattr(patient, 'ssn', None)
        model._mrn = getattr(patient, 'medical_record_number', None)
        logger.debug(f"[from_domain] Assigned direct PII/PHI strings for {getattr(patient, 'id', 'N/A')}")

        # --- Handle Address (Domain likely has Address object, Model stores string) ---
        address_obj = getattr(patient, 'address', None) # Renamed for clarity
        if isinstance(address_obj, str): # Handle legacy string case if necessary
             logger.warning(f"Received raw string for address: '{address_obj[:50]}...'. Using directly.")
             full_address_string = address_obj
             model._address_line1 = full_address_string # Assign string, EncryptedString will handle it
        elif address_obj and hasattr(address_obj, 'street'): # Check if it's likely an Address object
            # Construct the full address string from components - adapt attributes as needed
            # Ensure components exist before concatenating
            street = getattr(address_obj, 'street', '')
            city = getattr(address_obj, 'city', '')
            state = getattr(address_obj, 'state', '')
            zip_code = getattr(address_obj, 'zip_code', '')
            country = getattr(address_obj, 'country', '') # Assuming country might exist
            
            # Basic concatenation, improve formatting as needed
            parts = [street, city, state, zip_code, country]
            full_address_string = ", ".join(filter(None, parts)) # Join non-empty parts
            
            if full_address_string:
                 logger.debug(f"[from_domain] Assigning constructed address string '{full_address_string[:50]}...' to _address_line1 for {getattr(patient, 'id', 'N/A')}")
                 model._address_line1 = full_address_string # Assign string, EncryptedString will handle it
            else:
                 logger.debug(f"[from_domain] Address object provided but resulted in empty string for {getattr(patient, 'id', 'N/A')}")
                 model._address_line1 = None
        else:
            # logger.debug(f"[from_domain] No address object or string provided for {getattr(patient, 'id', 'N/A')}")
            model._address_line1 = None
        
        # For structured address fields, if domain_patient.address is an Address VO:
        if isinstance(address_obj, Address):
            model._address_line1 = getattr(address_obj, 'line1', None)
            model._address_line2 = getattr(address_obj, 'line2', None)
            model._city = getattr(address_obj, 'city', None)
            model._state = getattr(address_obj, 'state', None)
            model._zip_code = getattr(address_obj, 'zip_code', None)
            model._country = getattr(address_obj, 'country', None)
        else: # If not Address VO or string, clear other fields or handle as per logic
            model._address_line2 = None 
            model._city = None
            model._state = None
            model._zip_code = None
            model._country = None
        # --- End Address Handling ---
        
        # Assign serializable complex fields directly. EncryptedJSON will handle serialization & encryption.
        logger.debug(f"[from_domain] Assigning complex fields for {getattr(patient, 'id', 'N/A')}")
        model._contact_info = getattr(patient, 'contact_info', None)
        model._address_details = getattr(patient, 'address_details', None)
        model._emergency_contact_details = getattr(patient, 'emergency_contact_details', None)
        model._preferences = getattr(patient, 'preferences', None)
        model._medical_history = getattr(patient, 'medical_history', [])
        model._medications = getattr(patient, 'medications', [])
        model._allergies = getattr(patient, 'allergies', [])
        model._notes = getattr(patient, 'notes', [])
        model._custom_fields = getattr(patient, 'custom_fields', None)
        model._insurance_provider = getattr(patient, 'insurance_provider', None)
        model._insurance_policy_number = getattr(patient, 'insurance_policy_number', None)
        model._insurance_group_number = getattr(patient, 'insurance_group_number', None)
        model._extra_data = getattr(patient, 'extra_data', {})

        # Assign remaining non-encrypted fields, converting UUIDs to string
        # biometric_twin_id_obj = getattr(patient, 'biometric_twin_id', None)
        # if isinstance(biometric_twin_id_obj, uuid.UUID):
        #     model.biometric_twin_id = str(biometric_twin_id_obj) # Store as string
        # else:
        #     model.biometric_twin_id = biometric_twin_id_obj # Assume None or already string

        # Set id only if it exists on the domain object (for updates), store as string
        patient_id_obj = getattr(patient, 'id', None)
        if patient_id_obj:
            if isinstance(patient_id_obj, uuid.UUID):
                model.id = str(patient_id_obj) # Store as string
                logger.debug(f"[from_domain] Assigned existing ID {model.id} as string")
            else: # Assume string
                try:
                    uuid.UUID(str(patient_id_obj)) # Validate format
                    model.id = str(patient_id_obj)
                    logger.debug(f"[from_domain] Assigned existing ID {model.id} (validated string)")
                except (ValueError, TypeError):
                    logger.error(f"[from_domain] Invalid existing patient ID format: {patient_id_obj}. Cannot set ID.")
                    # Potentially raise an error here, as an invalid existing ID is problematic
                    # For now, let it proceed, default might apply if column allows null/default
                    pass # Or model.id = None if nullable
        else:
            # If no ID, generate a new UUID string using the default lambda
            model.id = str(uuid.uuid4()) # Explicitly generate and assign string UUID
            logger.debug(f"[from_domain] New patient, generated string ID: {model.id}")

        # Assign timestamps - let DB handle defaults/onupdate if possible
        # model.created_at = patient.created_at or now_utc()
        # model.updated_at = now_utc()

        logger.debug(f"[from_domain] Completed conversion for patient ID: {getattr(model, 'id', 'NO_ID_YET')}")
        return model

    async def to_domain(self) -> DomainPatient:
        """
        Convert this Patient model instance to a domain Patient entity,
        decrypting PHI fields using the provided encryption service.
        """
        logger.debug(f"[to_domain] Starting conversion for model patient ID: {self.id}")
        
        # Access fields directly. TypeDecorators will handle decryption and deserialization.
        first_name = self._first_name
        last_name = self._last_name
        from datetime import datetime
        # Parse date_of_birth after decryption by TypeDecorator
        if self._date_of_birth: # _date_of_birth is now the decrypted string from EncryptedString
            decrypted_dob_str = self._date_of_birth
            if decrypted_dob_str:
                try:
                    # Use dateutil.parser for robust parsing
                    parsed_dob_dt = parser.parse(decrypted_dob_str)
                    date_of_birth = parsed_dob_dt.date()  # Extract date part
                except (ValueError, TypeError) as e:
                    logger.error(f"Failed to parse decrypted date_of_birth '{decrypted_dob_str}': {e}")
                    date_of_birth = None
            else:
                date_of_birth = None
        else:
            date_of_birth = None
        email = self._email
        phone = self._phone_number
        ssn = self._ssn
        medical_record_number = self._mrn
        gender = self._gender
        insurance_provider = self._insurance_provider

        logger.debug(f"[to_domain] Accessed simple PII for {self.id}")

        # Access address components directly
        address_line1 = self._address_line1
        address_line2 = self._address_line2
        city = self._city
        state = self._state
        zip_code = self._zip_code
        country = self._country
        logger.debug(f"[to_domain] Accessed address components for {self.id}")

        # Access complex fields directly. EncryptedJSON handles decryption & deserialization.
        logger.debug(f"[to_domain] Accessing complex fields for {self.id}")
        contact_info_dict = self._contact_info
        address_details_dict = self._address_details
        emergency_contact_details_dict = self._emergency_contact_details
        preferences_dict = self._preferences
        medical_history_list = self._medical_history
        medications_list = self._medications
        allergies_list = self._allergies
        notes_list = self._notes
        extra_data_dict = self._extra_data
        
        # Build domain Patient using only the fields that exist in the domain entity
        # Check app.core.domain.entities.patient.Patient for the correct attributes
        patient_args = {
            'id': self.id if isinstance(self.id, uuid.UUID) else uuid.UUID(str(self.id)) if self.id else uuid.uuid4(),
            'created_at': self.created_at.replace(tzinfo=UTC) if self.created_at else datetime.now(),
            'updated_at': self.updated_at.replace(tzinfo=UTC) if self.updated_at else datetime.now(),
            'first_name': first_name,
            'last_name': last_name,
            'date_of_birth': date_of_birth, # Use the parsed date object
            'email': email,
            'phone_number': phone,  # Note: using phone_number to match domain entity
        }
        
        # Only include fields that have values to avoid None issues
        if self.is_active is not None:
            patient_args['active'] = self.is_active
            
        if contact_info_dict is not None:
            patient_args['contact_info'] = contact_info_dict

        if address_details_dict is not None:
            patient_args['address_details'] = address_details_dict

        if emergency_contact_details_dict is not None:
            patient_args['emergency_contact_details'] = emergency_contact_details_dict

        if preferences_dict is not None:
            patient_args['preferences'] = preferences_dict

        if medical_history_list is not None:
            patient_args['medical_history'] = medical_history_list

        if medications_list is not None:
            patient_args['medications'] = medications_list

        if allergies_list is not None:
            patient_args['allergies'] = allergies_list

        if notes_list is not None:
            patient_args['notes'] = notes_list

        if extra_data_dict is not None:
            patient_args['extra_data'] = extra_data_dict

        if insurance_provider is not None:
            patient_args['insurance_provider'] = insurance_provider

        # Construct Address value object if components are present
        address_components = {
            'line1': address_line1,
            'line2': address_line2,
            'city': city,
            'state': state,
            'zip_code': zip_code,
            'country': country
        }
        # Only create Address object if at least one component is not None
        if any(v is not None for v in address_components.values()):
            # Replace None with empty string for Address VO constructor if it expects strings
            for key, value in address_components.items():
                if value is None:
                    address_components[key] = '' # Or handle as Address VO expects
            try:
                patient_args['address'] = Address(**address_components)
            except TypeError as e:
                logger.error(f"Failed to create Address VO for patient {self.id}: {e}. Components: {address_components}")     
        
        # Create the patient entity with only the fields it supports
        patient = DomainPatient(**patient_args)
        logger.debug(f"[to_domain] Completed conversion for patient ID: {patient.id}")
        return patient

# Example comment outside class
# Add columns like _ethnicity, _preferred_language, etc. following the pattern above.
