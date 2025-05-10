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
from datetime import date, datetime

from dateutil import parser
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, Text, Date as SQLDate, JSON
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import Enum as SQLEnum

# Use the core domain model, which has phone_number attribute
from app.core.domain.entities.patient import Patient as DomainPatient
from app.domain.utils.datetime_utils import UTC, now_utc
from app.domain.value_objects.address import Address
from app.domain.value_objects.emergency_contact import EmergencyContact
from app.core.domain.enums import Gender # Corrected Gender import
from app.infrastructure.persistence.sqlalchemy.models.base import Base, TimestampMixin, AuditMixin
# from app.infrastructure.security.encryption import EncryptedString, EncryptedText, EncryptedDate, EncryptedJSON # REMOVED - Caused ImportError

# Break circular import by using string reference to User model
# This follows SQLAlchemy best practices for circular relationship references
from app.infrastructure.security.encryption.base_encryption_service import BaseEncryptionService
from app.infrastructure.security.encryption.encryption_service import EncryptionService
from app.core.config import settings
from app.infrastructure.persistence.sqlalchemy.types.encrypted_types import EncryptedString, EncryptedText, EncryptedJSON
# from app.tests.standalone.domain.test_standalone_patient import Gender # TEMPORARY: Gender enum location # This line will be removed
import base64 # Import base64 for decoding the key

logger = logging.getLogger(__name__)

import dataclasses  # Add this import

# Correct import: Use absolute path to types.py file
from app.infrastructure.persistence.sqlalchemy.types import GUID, JSONEncodedDict 
from app.infrastructure.persistence.sqlalchemy.registry import register_model

# Instantiate the global encryption service instance for TypeDecorators
# BaseEncryptionService (parent of EncryptionService) handles its own key loading
# (e.g., from ENCRYPTION_MASTER_KEY env var or auto-generates).
encryption_service_instance = EncryptionService()

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
    id = Column(GUID(), primary_key=True, default=uuid.uuid4, nullable=False, index=True) 
    external_id = Column(String(64), unique=True, index=True, nullable=True)
    user_id = Column(GUID(), ForeignKey("users.id"), index=True, nullable=True)

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
        Create a Patient model instance from a domain Patient entity.
        """
        logger.debug(f"[from_domain] Starting conversion for domain patient ID: {getattr(patient, 'id', 'NO_ID_YET')}")
        model = cls()

        # Core metadata - Fields guaranteed by DomainPatient
        model.id = getattr(patient, 'id', uuid.uuid4()) # Ensure UUID
        if not isinstance(model.id, uuid.UUID):
            try:
                model.id = uuid.UUID(str(model.id))
            except ValueError:
                logger.error(f"Invalid ID format for patient: {model.id}. Generating new UUID.")
                model.id = uuid.uuid4()
                
        model.external_id = str(getattr(patient, 'external_id', None)) if getattr(patient, 'external_id', None) is not None else None
        # user_id should be set based on who is creating/owning this record.
        # DomainPatient doesn't have user_id, but PatientModel requires it (FK).
        # This needs to be passed or set contextually. For now, assume it might come via created_by.
        created_by_uuid = getattr(patient, 'created_by', None) # DomainPatient might not have this
        if isinstance(created_by_uuid, uuid.UUID):
            model.user_id = created_by_uuid
        elif isinstance(created_by_uuid, str):
            try:
                model.user_id = uuid.UUID(created_by_uuid)
            except ValueError:
                logger.warning(f"Invalid created_by UUID string: {created_by_uuid}. user_id will be None.")
                model.user_id = None # Or handle as error if user_id is non-nullable and no default
        else:
            model.user_id = None # Fallback if not provided or invalid type
            
        # model.created_at = getattr(patient, 'created_at', now_utc()) # Let DB handle default
        # model.updated_at = getattr(patient, 'updated_at', now_utc()) # Let DB handle default/onupdate
        model.is_active = getattr(patient, 'active', getattr(patient, 'is_active', True)) # 'active' or 'is_active'

        # Basic PII - fields in DomainPatient
        model._first_name = getattr(patient, 'first_name', None)
        model._last_name = getattr(patient, 'last_name', None)
        model._email = getattr(patient, 'email', None)
        model._phone_number = getattr(patient, 'phone_number', None)
        
        dob_value = getattr(patient, 'date_of_birth', None)
        if isinstance(dob_value, (date, datetime)):
            model._date_of_birth = dob_value.isoformat()
        elif isinstance(dob_value, str):
            try: model._date_of_birth = parser.parse(dob_value).date().isoformat()
            except: model._date_of_birth = dob_value # Store as is if unparseable
        else:
            model._date_of_birth = None

        # Extended PII - fields NOT in core DomainPatient, use getattr with None default
        model._middle_name = getattr(patient, 'middle_name', None)
        model._gender = getattr(patient, 'gender', None) # DomainPatient doesn't have gender
        model._ssn = getattr(patient, 'social_security_number_lve', None) # Corrected to use _lve from DomainPatient
        model._mrn = getattr(patient, 'medical_record_number_lve', None) # Corrected to use _lve from DomainPatient

        # Insurance Info - NOT in core DomainPatient
        model._insurance_provider = getattr(patient, 'insurance_provider', None)
        model._insurance_policy_number = getattr(patient, 'insurance_policy_number', None)
        model._insurance_group_number = getattr(patient, 'insurance_group_number', None)

        # Address components - NOT directly in core DomainPatient (it has Address VO in contact_info or as separate field)
        # For PatientModel's direct address string fields, attempt to get from patient.address VO if it exists.
        address_vo = getattr(patient, 'address', None)
        if isinstance(address_vo, Address):
            model._address_line1 = getattr(address_vo, 'line1', None)
            model._address_line2 = getattr(address_vo, 'line2', None)
            model._city = getattr(address_vo, 'city', None)
            model._state = getattr(address_vo, 'state', None)
            model._zip_code = getattr(address_vo, 'zip_code', None) # or postal_code
            model._country = getattr(address_vo, 'country', None)
        else: # Clear them if no proper Address VO
            model._address_line1 = None
            model._address_line2 = None
            model._city = None
            model._state = None
            model._zip_code = None
            model._country = None

        # Emergency Contact components - NOT in core DomainPatient (it has EmergencyContact VO)
        emergency_contact_vo = getattr(patient, 'emergency_contact', None)
        if isinstance(emergency_contact_vo, EmergencyContact):
            model._emergency_contact_name = getattr(emergency_contact_vo, 'name', None)
            model._emergency_contact_phone = getattr(emergency_contact_vo, 'phone', None)
            model._emergency_contact_relationship = getattr(emergency_contact_vo, 'relationship', None)
            # Assign the VO instance directly; EncryptedJSON will serialize it
            model._emergency_contact_details = emergency_contact_vo
        else:
            model._emergency_contact_name = None
            model._emergency_contact_phone = None
            model._emergency_contact_relationship = None
            model._emergency_contact_details = None

        # Complex / JSON / Text fields - use getattr and then str() for EncryptedText
        # EncryptedJSON fields can take the direct object if it's serializable or None.
        # For EncryptedText/EncryptedJSON that store serialized complex types, use json.dumps.

        contact_info_vo = getattr(patient, 'contact_info', None)
        # Assign the Pydantic model instance directly; EncryptedJSON will serialize it
        model._contact_info = contact_info_vo

        address_vo_from_domain = getattr(patient, 'address', None)
        # Assign the VO instance directly; EncryptedJSON will serialize it
        model._address_details = address_vo_from_domain

        preferences_val = getattr(patient, 'preferences', None)
        model._preferences = preferences_val # EncryptedJSON handles dict serialization
        
        # For EncryptedText fields that store JSON strings of complex Python objects:
        def _serialize_to_json_string(value: Any) -> str | None:
            if value is None:
                return None
            try:
                return json.dumps(value)
            except TypeError:
                logger.warning(f"Could not JSON serialize value for model: {value}. Storing as string repr.")
                return str(value) # Fallback, though ideally this shouldn't happen for expected list/dict types

        model._medical_history = _serialize_to_json_string(getattr(patient, 'medical_history', None))
        model._medications = _serialize_to_json_string(getattr(patient, 'medications', None))
        model._allergies = _serialize_to_json_string(getattr(patient, 'allergies', None))
        
        notes_val = getattr(patient, 'notes', None) # Assuming notes is a simple string
        model._notes = str(notes_val) if notes_val is not None else None

        model._custom_fields = getattr(patient, 'custom_fields', None) # EncryptedJSON handles dict serialization
        model._extra_data = getattr(patient, 'extra_data', None) # EncryptedJSON handles dict serialization

        logger.debug(f"[from_domain] Completed conversion for patient model ID: {model.id}")
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
        # emergency_contact_details_dict will be automatically deserialized by EncryptedJSON if it was stored as JSON
        # The DomainPatient model expects a field named 'emergency_contact' that can take a dict.
        raw_emergency_contact_details = self._emergency_contact_details
        preferences_dict = self._preferences
        
        # Parse list-like fields from their string representation after decryption
        medical_history_list_str = self._medical_history
        medications_list_str = self._medications
        allergies_list_str = self._allergies
        
        notes_list = self._notes # Assuming notes is intended to be a simple string or handled as such by EncryptedText
        extra_data_dict = self._extra_data
        
        def _parse_json_string_to_list(json_str: str | None, field_name: str) -> list | None:
            if json_str is None:
                return None
            try:
                return json.loads(json_str)
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse {field_name} for patient {self.id} from JSON string: '{json_str}'")
                return None # Or an empty list: [] ? Or raise error?

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

        # Pass the deserialized dict from _emergency_contact_details to 'emergency_contact' field for DomainPatient
        if raw_emergency_contact_details is not None:
            patient_args['emergency_contact'] = raw_emergency_contact_details 

        if preferences_dict is not None:
            patient_args['preferences'] = preferences_dict

        parsed_medical_history = _parse_json_string_to_list(medical_history_list_str, "medical_history")
        if parsed_medical_history is not None:
            patient_args['medical_history'] = parsed_medical_history

        parsed_medications = _parse_json_string_to_list(medications_list_str, "medications")
        if parsed_medications is not None:
            patient_args['medications'] = parsed_medications

        parsed_allergies = _parse_json_string_to_list(allergies_list_str, "allergies")
        if parsed_allergies is not None:
            patient_args['allergies'] = parsed_allergies

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
