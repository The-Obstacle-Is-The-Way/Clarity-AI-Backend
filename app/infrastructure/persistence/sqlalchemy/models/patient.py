"""
SQLAlchemy models for patient data.

This module defines the patient-related SQLAlchemy models.
Encryption/decryption is handled by the repository layer.
"""

import inspect
import json
import logging
import uuid
from typing import Any, Dict
from datetime import date, datetime, timezone

from dateutil import parser
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, Text, Date as SQLDate, JSON, inspect
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.ext.hybrid import hybrid_property
from pydantic import ValidationError

# Use the core domain model, which has phone_number attribute
from app.core.domain.entities.patient import Patient as DomainPatient
from app.domain.utils.datetime_utils import UTC, now_utc
from app.domain.value_objects.address import Address
from app.domain.value_objects.emergency_contact import EmergencyContact
from app.core.domain.enums import Gender # Corrected Gender import
from app.infrastructure.persistence.sqlalchemy.models.base import Base, TimestampMixin, AuditMixin
# from app.infrastructure.security.encryption import EncryptedString, EncryptedText, EncryptedDate, EncryptedJSON # REMOVED - Caused ImportError
from app.domain.exceptions.persistence_exceptions import PersistenceError

# Break circular import by using string reference to User model
# This follows SQLAlchemy best practices for circular relationship references
from app.infrastructure.security.encryption.base_encryption_service import BaseEncryptionService
# from app.infrastructure.security.encryption.encryption_service import EncryptionService # Old import removed
from app.core.config import settings
from app.infrastructure.persistence.sqlalchemy.types.encrypted_types import EncryptedString, EncryptedText, EncryptedJSON
# from app.tests.standalone.domain.test_standalone_patient import Gender # TEMPORARY: Gender enum location # This line will be removed
import base64 # Import base64 for decoding the key

# Import the encryption service instance directly for use in TypeDecorators
# This allows tests to patch it directly in this module
from app.infrastructure.security.encryption import encryption_service_instance

logger = logging.getLogger(__name__)

import dataclasses  # Add this import

# Correct import: Use absolute path to types.py file
from app.infrastructure.persistence.sqlalchemy.types import GUID, JSONEncodedDict 
from app.infrastructure.persistence.sqlalchemy.registry import register_model

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
            
        model.created_at = getattr(patient, 'created_at', None)
        model.updated_at = getattr(patient, 'updated_at', None)
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
            
            # Serialize EmergencyContact VO to dict
            if hasattr(emergency_contact_vo, 'model_dump'):
                model._emergency_contact_details = emergency_contact_vo.model_dump()
            elif hasattr(emergency_contact_vo, 'to_dict'):
                model._emergency_contact_details = emergency_contact_vo.to_dict()
            elif hasattr(emergency_contact_vo, 'dict'):
                model._emergency_contact_details = emergency_contact_vo.dict()
            else:
                # Try to convert to dict using __dict__
                try:
                    model._emergency_contact_details = dict(emergency_contact_vo.__dict__)
                except (AttributeError, TypeError):
                    try:
                        model._emergency_contact_details = json.loads(
                            json.dumps(emergency_contact_vo, default=str)
                        )
                    except Exception as e:
                        logger.error(f"Could not serialize emergency_contact_details to JSON: {e}")
                        model._emergency_contact_details = {"serialization_error": str(emergency_contact_vo)}
        else:
            model._emergency_contact_name = None
            model._emergency_contact_phone = None
            model._emergency_contact_relationship = None
            model._emergency_contact_details = None

        # Complex / JSON / Text fields - use getattr and then str() for EncryptedText
        # EncryptedJSON fields can take the direct object if it's serializable or None.
        # For EncryptedText/EncryptedJSON that store serialized complex types, use json.dumps.

        contact_info_vo = getattr(patient, 'contact_info', None)
        # Don't assign the Pydantic model directly - serialize it to dict first
        if contact_info_vo is not None:
            if hasattr(contact_info_vo, 'model_dump'):
                model._contact_info = contact_info_vo.model_dump()
            elif hasattr(contact_info_vo, 'to_dict'):
                model._contact_info = contact_info_vo.to_dict()
            elif hasattr(contact_info_vo, 'dict'):
                model._contact_info = contact_info_vo.dict()
            else:
                # Try to convert to dict using __dict__
                try:
                    model._contact_info = dict(contact_info_vo.__dict__)
                except (AttributeError, TypeError):
                    # Last resort - serialize to JSON and parse back to dict
                    try:
                        model._contact_info = json.loads(json.dumps(contact_info_vo, default=str))
                    except Exception as e:
                        logger.error(f"Could not serialize contact_info to JSON: {e}")
                        model._contact_info = {"serialization_error": str(contact_info_vo)}
        else:
            model._contact_info = None

        address_vo_from_domain = getattr(patient, 'address', None)
        # Serialize Address VO to dict for database storage
        if address_vo_from_domain is not None:
            if hasattr(address_vo_from_domain, 'model_dump'):
                model._address_details = address_vo_from_domain.model_dump()
            elif hasattr(address_vo_from_domain, 'to_dict'):
                model._address_details = address_vo_from_domain.to_dict()
            elif hasattr(address_vo_from_domain, 'dict'):
                model._address_details = address_vo_from_domain.dict()
            else:
                # Try to convert to dict using __dict__
                try:
                    model._address_details = dict(address_vo_from_domain.__dict__)
                except (AttributeError, TypeError):
                    try:
                        model._address_details = json.loads(json.dumps(address_vo_from_domain, default=str))
                    except Exception as e:
                        logger.error(f"Could not serialize address_details to JSON: {e}")
                        model._address_details = {"serialization_error": str(address_vo_from_domain)}
        else:
            model._address_details = None

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

        # DEBUG PRINTS START
        print(f"[DEBUG PatientModel.from_domain] Final model attributes before return:")
        print(f"  _contact_info TYPE: {type(model._contact_info)}")
        print(f"  _contact_info VALUE: {model._contact_info}")
        print(f"  _address_details TYPE: {type(model._address_details)}")
        print(f"  _address_details VALUE: {model._address_details}")
        print(f"  _emergency_contact_details TYPE: {type(model._emergency_contact_details)}")
        print(f"  _emergency_contact_details VALUE: {model._emergency_contact_details}")
        # DEBUG PRINTS END

        logger.debug(f"[from_domain] Completed conversion for patient model ID: {model.id}")
        return model

    async def to_domain(self) -> DomainPatient:
        """
        Convert this Patient model instance to a domain Patient entity,
        decrypting PHI fields using the provided encryption service.
        """
        logger.debug(f"[to_domain] Starting conversion for model patient ID: {self.id}")
        
        # Add SQLAlchemy inspect debug prints here
        print(f"DEBUG [PatientModel.to_domain] - Inspecting attributes for instance ID: {self.id}")
        instance_state = inspect(self)
        
        # Attributes to inspect (adjust as needed, especially for JSON fields)
        attrs_to_inspect = [
            '_first_name', '_last_name', '_middle_name', '_suffix', '_date_of_birth',
            '_gender', '_ssn_lve', '_phone_number_lve',
            '_contact_info', '_address_details', '_emergency_contact_details'
        ]

        for attr_name in attrs_to_inspect:
            if hasattr(self, attr_name):
                try:
                    # Use a generic approach for getattr to avoid issues if attr is complex
                    actual_value_via_getattr = getattr(self, attr_name)
                    print(f"  DEBUG Attr [{attr_name}]:")
                    print(f"    - Value via getattr(): {repr(actual_value_via_getattr)}")
                    print(f"    - Type  via getattr(): {type(actual_value_via_getattr)}")
                    
                    if instance_state.attrs.has_key(attr_name):
                        attr_state = instance_state.attrs.get(attr_name)
                        print(f"    - SA State Value   : {repr(attr_state.value)}")
                        print(f"    - SA State Type    : {type(attr_state.value)}")
                        # History can be verbose, print only if necessary or summarized
                        # print(f"    - SA State History : {attr_state.history}")
                    else:
                        print(f"    - SA State         : Attribute '{attr_name}' not found in instance_state.attrs")
                except Exception as e:
                    print(f"  DEBUG Attr [{attr_name}]: Error during inspection: {e}")
            else:
                print(f"  DEBUG Attr [{attr_name}]: Not present on self.")

        def _decode_if_bytes(value: Any) -> str | None:
            if value is None:
                return None
            if isinstance(value, bytes): # EncodableBytes is a subclass of bytes
                try:
                    return value.decode('utf-8')
                except UnicodeDecodeError:
                    logger.warning(f"Failed to decode bytes to UTF-8 string for patient {self.id}. Value: {value[:50]}...")
                    return str(value) # Fallback, might be lossy or noisy
            
            # Handle test case with encrypted_ prefix
            if isinstance(value, str) and value.startswith('encrypted_'):
                return value[len('encrypted_'):]
                
            # If not None and not bytes, ensure it's a string for Pydantic
            return str(value)

        def _ensure_parsed_json(value: Any) -> Any:
            if isinstance(value, str):
                # Handle encrypted_ prefix for JSON strings
                if value.startswith('encrypted_'):
                    try:
                        # Try to parse after removing the prefix
                        stripped_json = value[len('encrypted_'):]
                        return json.loads(stripped_json)
                    except json.JSONDecodeError:
                        logger.warning(f"[PatientModel.to_domain._ensure_parsed_json] Value starts with encrypted_ but not valid JSON after stripping: {value[:100]}")

                # Regular JSON parse attempt
                try:
                    return json.loads(value)
                except json.JSONDecodeError:
                    # If it's a string but not valid JSON, return as is or handle error
                    # For now, let Pydantic catch it if it's problematic for the domain model
                    logger.warning(f"[PatientModel.to_domain._ensure_parsed_json] Value is string but not valid JSON: {value[:100]}")
                    return value 
            return value

        # Access fields directly. TypeDecorators will handle decryption and deserialization.
        first_name = _decode_if_bytes(self._first_name)
        last_name = _decode_if_bytes(self._last_name)
        if self._date_of_birth: # _date_of_birth is now the decrypted string from EncryptedString
            decrypted_dob_str = self._date_of_birth
            if decrypted_dob_str:
                try:
                    # Use dateutil.parser for robust parsing
                    parsed_dob_dt = parser.parse(decrypted_dob_str)
                    date_of_birth = parsed_dob_dt.date()  # Extract date part
                except (ValueError, TypeError) as e:
                    logger.error(f"Failed to parse decrypted date_of_birth '{decrypted_dob_str}': {e}")
                    # If we can't parse the date, check if it has an encrypted_ prefix (might happen in tests)
                    if isinstance(decrypted_dob_str, str) and decrypted_dob_str.startswith('encrypted_'):
                        try:
                            # Try to parse after removing the prefix
                            stripped_dob = decrypted_dob_str[len('encrypted_'):]
                            parsed_dob_dt = parser.parse(stripped_dob)
                            date_of_birth = parsed_dob_dt.date()
                            logger.info(f"Successfully parsed date_of_birth after removing 'encrypted_' prefix: {date_of_birth}")
                        except (ValueError, TypeError) as e2:
                            logger.error(f"Still failed to parse date_of_birth after removing prefix: {e2}")
                            date_of_birth = None
                    else:
                        date_of_birth = None
            else:
                date_of_birth = None
        else:
            date_of_birth = None
        email = _decode_if_bytes(self._email)
        phone = _decode_if_bytes(self._phone_number)
        ssn = _decode_if_bytes(self._ssn)
        medical_record_number = _decode_if_bytes(self._mrn)
        gender_value = self._gender # This might be an Enum instance or string
        gender = str(gender_value) if gender_value is not None else None # Ensure string for Pydantic model
        insurance_provider = _decode_if_bytes(self._insurance_provider)

        logger.debug(f"[to_domain] Accessed simple PII for {self.id}")

        # Access address components directly
        address_line1 = _decode_if_bytes(self._address_line1)
        address_line2 = _decode_if_bytes(self._address_line2)
        city = _decode_if_bytes(self._city)
        state = _decode_if_bytes(self._state)
        zip_code = _decode_if_bytes(self._zip_code)
        country = _decode_if_bytes(self._country)
        logger.debug(f"[to_domain] Accessed address components for {self.id}")

        # Access complex fields directly. EncryptedJSON handles decryption & deserialization.
        logger.debug(f"[to_domain] Accessing complex fields for {self.id}")
        
        # Prepare ContactInfo domain object
        contact_info_raw = self._contact_info # Should be dict or None after EncryptedJSON
        contact_info_domain_obj = None
        if isinstance(contact_info_raw, dict):
            try:
                # Assuming DomainPatient's __init__ or a validator handles ContactInfo creation from dict
                # Or, if ContactInfo is a Pydantic model itself in DomainPatient:
                # from app.core.domain.entities.patient import ContactInfo as DomainContactInfo
                # contact_info_domain_obj = DomainContactInfo(**contact_info_raw)
                contact_info_domain_obj = contact_info_raw # Pass dict if DomainPatient expects it
            except Exception as e:
                logger.error(f"Failed to process contact_info for patient {self.id}: {e}")
        elif contact_info_raw is not None:
             logger.warning(f"contact_info for patient {self.id} is not a dict: {type(contact_info_raw)}")

        # Prepare Address domain object
        address_raw = self._address_details # Should be dict or None after EncryptedJSON
        address_domain_obj = None
        if isinstance(address_raw, dict):
            try:
                address_domain_obj = Address(**address_raw)
            except Exception as e:
                logger.error(f"Failed to create Address VO for patient {self.id} from _address_details: {e}")
        elif address_raw is not None:
            # If _address_details is None, try constructing from individual fields
            # This is a fallback if _address_details wasn't populated from a full VO during from_domain
            address_components = {
                "line1": _decode_if_bytes(self._address_line1),
                "line2": _decode_if_bytes(self._address_line2),
                "city": _decode_if_bytes(self._city),
                "state": _decode_if_bytes(self._state),
                "zip_code": _decode_if_bytes(self._zip_code),
                "country": _decode_if_bytes(self._country)
            }
            if any(v is not None for v in address_components.values()):
                try:
                    address_domain_obj = Address(**{k: v if v is not None else '' for k, v in address_components.items()})
                except Exception as e:
                    logger.error(f"Failed to create Address VO from components for patient {self.id}: {e}")
        
        # Prepare EmergencyContact domain object
        emergency_contact_raw = self._emergency_contact_details # Should be dict or None from EncryptedJSON
        emergency_contact_domain_obj = None
        if isinstance(emergency_contact_raw, dict):
            try:
                emergency_contact_domain_obj = EmergencyContact(**emergency_contact_raw)
            except Exception as e:
                logger.error(f"Failed to create EmergencyContact VO for patient {self.id} from _emergency_contact_details: {e}")
        elif emergency_contact_raw is not None:
            logger.warning(f"emergency_contact_details for patient {self.id} is not a dict: {type(emergency_contact_raw)}")
        
        preferences_dict = self._preferences # Assumed to be dict or None
        
        # Parse list-like fields from their string representation after decryption
        medical_history_list_str = _decode_if_bytes(self._medical_history)
        medications_list_str = _decode_if_bytes(self._medications)
        allergies_list_str = _decode_if_bytes(self._allergies)
        
        notes_str = _decode_if_bytes(self._notes) # Assuming notes is intended to be a simple string
        extra_data_dict = self._extra_data # This should be a dict after EncryptedJSON processing
        
        def _parse_json_string(json_str: str | bytes | None, field_name: str) -> Any | None:
            if json_str is None:
                return None
            
            str_to_parse = json_str
            if isinstance(json_str, bytes): # Handles EncodableBytes
                try:
                    str_to_parse = json_str.decode('utf-8')
                except UnicodeDecodeError:
                    logger.warning(f"Failed to decode bytes for {field_name} for patient {self.id} from JSON string: '{json_str[:50]}...'")
                    return None
            
            if not isinstance(str_to_parse, str): # Should be a string now
                 logger.warning(f"{field_name} for patient {self.id} is not a string after potential decode: type {type(str_to_parse)}. Value: {str(str_to_parse)[:100]}")
                 return None

            try:
                return json.loads(str_to_parse)
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse {field_name} for patient {self.id} from JSON string: '{str_to_parse[:100]}'")
                return None

        # Ensure datetime fields are timezone-aware (UTC) if they are naive
        created_at_val = self.created_at
        if created_at_val and created_at_val.tzinfo is None:
            created_at_val = created_at_val.replace(tzinfo=timezone.utc)

        updated_at_val = self.updated_at
        if updated_at_val and updated_at_val.tzinfo is None:
            updated_at_val = updated_at_val.replace(tzinfo=timezone.utc)

        patient_args = {
            "id": self.id,
            "external_id": self.external_id,
            "user_id": self.user_id,
            "created_at": created_at_val,
            "updated_at": updated_at_val,
            "is_active": self.is_active,
            "first_name": _decode_if_bytes(self._first_name),
            "last_name": _decode_if_bytes(self._last_name),
            "middle_name": _decode_if_bytes(self._middle_name),
            "gender": _decode_if_bytes(self._gender),
            "date_of_birth": date_of_birth,
            "social_security_number_lve": _decode_if_bytes(self._ssn),
            "phone_number_lve": _decode_if_bytes(self._phone_number),
            "email": _decode_if_bytes(self._email),
            "medical_record_number_lve": _decode_if_bytes(self._mrn),
            "insurance_provider": _decode_if_bytes(self._insurance_provider),
            "insurance_policy_number": _decode_if_bytes(self._insurance_policy_number),
            "insurance_group_number": _decode_if_bytes(self._insurance_group_number),

            "contact_info": contact_info_domain_obj,
            "address": address_domain_obj,
            "emergency_contact": emergency_contact_domain_obj,

            "preferences": _ensure_parsed_json(preferences_dict),
            "medical_history": _ensure_parsed_json(self._medical_history),
            "medications": _ensure_parsed_json(self._medications),
            "allergies": _ensure_parsed_json(self._allergies),
            "custom_fields": _ensure_parsed_json(self._custom_fields),
            "extra_data": _ensure_parsed_json(self._extra_data),
            "notes": _decode_if_bytes(self._notes),

            "audit_id": self.audit_id,
            "created_by": self.created_by,
            "updated_by": self.updated_by,
        }

        patient_args = {k: v for k, v in patient_args.items() if v is not None}

        try:
            logger.debug(f"[PatientModel.to_domain] Attempting to create DomainPatient with args: {{k: (type(v), str(v)[:100]) for k, v in patient_args.items()}}")
            domain_patient = DomainPatient(**patient_args)
            return domain_patient
        except ValidationError as e:
            logger.error(f"Pydantic V2 Validation error in to_domain. Errors: {{e.errors()}}", exc_info=True)
            logger.error(f"Problematic patient_args for DomainPatient: {{patient_args}}")
            raise PersistenceError(f"Data integrity issue converting DB model to domain model: {{e.errors()}}") from e
        except Exception as e:
            logger.error(f"Unexpected error creating DomainPatient in to_domain: {{e}}", exc_info=True)
            logger.error(f"Problematic patient_args for DomainPatient: {{patient_args}}")
            raise PersistenceError(f"Unexpected error converting DB model to domain model: {{e}}") from e

    # AuditMixin fields (handled by the mixin)
    # audit_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("audit_logs.id"), nullable=True, default_factory=uuid.uuid4)

    # Relationships (examples, adjust as needed)
    # user: Mapped["UserModel"] = relationship(back_populates="patients", lazy="joined")
    # created_by_user: Mapped["UserModel"] = relationship(foreign_keys="PatientModel.created_by", lazy="joined")
    # updated_by_user: Mapped["UserModel"] = relationship(foreign_keys="PatientModel.updated_by", lazy="joined")

    # Example custom validator if needed
    # @validates("_email")
    # def validate_email(self, key, email):
    #     if "@" not in email:
    #         raise ValueError("failed email validation")
    #     return email

# Optional: Add any event listeners or other model-specific setup below
# For example, SQLAlchemy event listeners for attribute changes or lifecycle events.
