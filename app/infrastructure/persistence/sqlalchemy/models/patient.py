"""
SQLAlchemy models for patient data.

This module defines the patient-related SQLAlchemy models.
Encryption/decryption is handled by the repository layer.
"""

import uuid
from app.domain.utils.datetime_utils import now_utc, UTC
from typing import Any, Dict, List, Optional, Union, cast
import json
import inspect
from dateutil import parser

import sqlalchemy as sa
from sqlalchemy import Column, String, Text, DateTime, Boolean, Integer, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.infrastructure.persistence.sqlalchemy.models.base import Base
from .user import User # Import User model
from app.infrastructure.security.encryption.base_encryption_service import BaseEncryptionService
from app.domain.value_objects.address import Address as AddressVO # Corrected import for AddressVO
from app.domain.value_objects.contact_info import ContactInfo as ContactInfoVO # Import ContactInfo
from app.domain.value_objects.name import Name as NameVO # Import Name
from app.domain.value_objects.emergency_contact import EmergencyContact # Import EmergencyContact
from app.domain.entities.patient import Patient as DomainPatient # Re-add this import

import logging
logger = logging.getLogger(__name__)

import dataclasses  # Add this import

class Patient(Base):
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
    
    # --- Core Identification and Metadata ---
    # Store UUIDs as String(36) for SQLite compatibility
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    # external_id could be from an EMR or other system
    external_id = Column(String(64), unique=True, index=True, nullable=True)
    # Foreign key to the associated user account (if applicable)
    # Use string reference "users.id"
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True, index=True)

    created_at = Column(DateTime, default=now_utc, nullable=False)
    updated_at = Column(DateTime, default=now_utc, onupdate=now_utc, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    # --- Encrypted PHI Fields (Stored as Text/Blob in DB) ---
    # QUANTUM FIX: Use prefixed column names with underscore for encrypted fields
    # This ensures compatibility with test expectations and encryption handling
    _first_name = Column("first_name", Text, nullable=True)
    _last_name = Column("last_name", Text, nullable=True)
    # Storing DOB as encrypted text is common for flexibility, though dedicated date types exist
    _dob = Column("date_of_birth", Text, nullable=True)
    _email = Column("email", Text, nullable=True)
    _phone = Column("phone", Text, nullable=True)
    # Legacy generic address storage removed in favor of structured address fields
    _medical_record_number = Column("medical_record_number", Text, nullable=True)
    # Use Text for potentially long encrypted JSON strings or large text fields
    _ssn = Column("ssn", Text, nullable=True)
    _insurance_number = Column("insurance_number", Text, nullable=True)
    _medical_history = Column("medical_history", Text, nullable=True)  # Assumed stored as encrypted JSON list/text
    _medications = Column("medications_data", Text, nullable=True)      # Encrypted medications data stored as JSON list/text
    _allergies = Column("allergies", Text, nullable=True)        # Assumed stored as encrypted JSON list/text
    _treatment_notes = Column("treatment_notes", Text, nullable=True)  # Assumed stored as encrypted JSON list/text
    _gender = Column("gender", Text, nullable=True)           # Encrypted gender identity/expression

    # --- Other Fields (Potentially Sensitive/Encrypted or Not) ---
    # Example: Encrypted JSON blob for arbitrary additional structured data
    _extra_data = Column("extra_data", Text, nullable=True)
    # Structured address fields
    _address_line1 = Column("address_line1", Text, nullable=True)
    _address_line2 = Column("address_line2", Text, nullable=True)
    _city = Column("city", Text, nullable=True)
    _state = Column("state", Text, nullable=True)
    _postal_code = Column("postal_code", Text, nullable=True)
    _country = Column("country", Text, nullable=True)

    # Emergency contact 
    _emergency_contact = Column("emergency_contact", Text, nullable=True)
    # Add insurance_info field expected by the test
    _insurance_info = Column("insurance_info", Text, nullable=True) # Uncommenting for proper access

    # --- Relationships ---
    # Simplify relationship definitions to use direct references where possible

    # user = relationship(
    #     "User", 
    #     back_populates="patients",
    #     # foreign_keys='Patient.user_id', # Use string definition - Try removing explicit foreign_keys if SQLAlchemy can infer
    #     primaryjoin='User.id == Patient.user_id' # Use string definition - Try removing explicit primaryjoin
    # ) 
    # Let SQLAlchemy infer the join condition based on ForeignKey
    user = relationship("User", back_populates="patients") 

    # appointments = relationship(
    #     "AppointmentModel",
    #     back_populates="patient",
    #     cascade="all, delete-orphan",
    #     foreign_keys="[AppointmentModel.patient_id]" # Explicitly define the foreign key - Simplify this
    # )
    # Assuming AppointmentModel has a patient_id ForeignKey backref defined
    # Import AppointmentModel at the top if not already imported
    # from .appointment import AppointmentModel # Example import
    appointments = relationship("AppointmentModel", back_populates="patient", cascade="all, delete-orphan")

    # clinical_notes = relationship("ClinicalNoteModel", back_populates="patient", cascade="all, delete-orphan", remote_side="ClinicalNoteModel.patient_id")
    # Assuming ClinicalNoteModel has patient_id ForeignKey and backref
    # from .clinical_note import ClinicalNoteModel # Example import
    clinical_notes = relationship("ClinicalNoteModel", back_populates="patient", cascade="all, delete-orphan")

    # medication_records = relationship("MedicationModel", back_populates="patient", cascade="all, delete-orphan", remote_side="MedicationModel.patient_id")
    # Assuming MedicationModel has patient_id ForeignKey and backref
    # from .medication import MedicationModel # Example import
    medication_records = relationship("MedicationModel", back_populates="patient", cascade="all, delete-orphan")

    # --- END Relationship Simplification ---

    # Digital twin relationships
    # Store as String(36) for SQLite compatibility
    biometric_twin_id = Column(String(36), nullable=True)

    # --- Encrypted Fields Set --- 
    # QUANTUM FIX: Update encrypted_fields set to use prefixed column names with underscores
    encrypted_fields = {
        '_first_name',
        '_last_name',
        '_email',
        '_phone',
        '_ssn',
        '_medical_record_number',
        '_gender',
        '_address_line1',
        '_address_line2',
        '_city',
        '_state',
        '_postal_code',
        '_country',
        '_emergency_contact',  # Stored as encrypted JSON string
        '_insurance_number',   # Stored as encrypted string
        '_medical_history',    # Stored as encrypted JSON string (list)
        '_medications',        # Stored as encrypted JSON string (list)
        '_allergies',          # Stored as encrypted JSON string (list)
        '_treatment_notes',    # Stored as encrypted JSON string (list)
        '_extra_data'          # Stored as encrypted JSON string (dict/list)
    }
    # --- END ADD --- 

    def __repr__(self) -> str:
        # Provide a representation useful for debugging, avoiding PHI exposure
        return f"<Patient(id={self.id}, created_at={self.created_at}, is_active={self.is_active})>"
    
    @classmethod
    async def from_domain(cls, patient: DomainPatient, encryption_service: BaseEncryptionService) -> "Patient":
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
             except (ValueError, TypeError) as e:
                 logger.warning(f"[from_domain] Invalid format for created_by UUID string '{created_by_id_obj}'. Setting user_id to None.")
                 model.user_id = None
        else:
             model.user_id = None
        # END FIX

        model.is_active = getattr(patient, 'active', True) # Use getattr for safety
        logger.debug(f"[from_domain] Mapped core metadata for {getattr(patient, 'id', 'NO_ID_YET')}")

        # --- Encryption Helpers ---
        def _encrypt(value: Optional[Any], field_name: str) -> Optional[bytes]: # Added field_name for logging
            """Encrypts a value (assumed stringifiable), returns bytes or None."""
            if value is None:
                # logger.debug(f"_encrypt: Value for '{field_name}' is None, returning None.")
                return None
            try:
                value_str = str(value) # Ensure it's a string
                logger.debug(f"_encrypt: Attempting to encrypt '{field_name}': '{value_str[:50]}...'") # Log value before encryption
                # Ensure encryption_service is available and encrypt is synchronous or async
                if hasattr(encryption_service, 'encrypt'):
                    encrypted_result = encryption_service.encrypt(value_str.encode('utf-8'))
                    # Handle potential awaitable
                    if inspect.isawaitable(encrypted_result):
                         # This helper shouldn't be called with async encrypt, use _encrypt_serializable or direct await
                         logger.error(f"_encrypt: Called with async encryption service for '{field_name}'. Use await directly.")
                         return None # Or raise error
                    encrypted = encrypted_result
                    
                    if not isinstance(encrypted, bytes):
                        logger.warning(f"_encrypt: Encryption service did not return bytes for '{field_name}'. Type: {type(encrypted)}. Attempting encode.")
                        # Attempt to encode if it's string-like, otherwise log error
                        try:
                             encrypted = str(encrypted).encode('utf-8')
                        except Exception:
                             logger.error(f"_encrypt: Failed to encode non-bytes encryption result for '{field_name}'.")
                             return None
                             
                    logger.debug(f"_encrypt: Successfully encrypted '{field_name}'.")
                    return encrypted
                else:
                    logger.error(f"_encrypt: encryption_service has no 'encrypt' method for field '{field_name}'.")
                    return None # Or raise an error
            except Exception as e:
                logger.error(f"_encrypt: Failed to encrypt '{field_name}' ('{str(value)[:50]}...'): {e}", exc_info=True)
                return None # Return None or re-raise specific exception

        async def _encrypt_serializable(data: Optional[Any], field_name: str) -> Optional[bytes]: # Added field_name
            """Serializes data to JSON string then encrypts, returns bytes or None."""
            if data is None:
                # logger.debug(f"_encrypt_serializable: Data for '{field_name}' is None, returning None.")
                return None
            try:
                 # Handle Pydantic models, dataclasses, dicts, lists, primitives
                 if hasattr(data, 'model_dump'): # Pydantic V2+
                     data_dict = data.model_dump()
                 elif dataclasses.is_dataclass(data) and not isinstance(data, type):
                     data_dict = dataclasses.asdict(data)
                 elif isinstance(data, (dict, list)):
                      data_dict = data # Already serializable
                 elif isinstance(data, (str, int, float, bool)):
                      data_dict = data # Primitives are serializable
                 else:
                     # Attempt to convert others to string as a fallback
                     logger.warning(f"Attempting string conversion for non-standard type {type(data)} before JSON serialization for field '{field_name}'.")
                     data_dict = str(data)
                
                 json_str = json.dumps(data_dict)
                 logger.debug(f"_encrypt_serializable: Attempting to encrypt '{field_name}': JSON='{json_str[:100]}...'") # Log JSON before encrypt
                 # Call the service's encrypt method with the JSON string (sync or async)
                 result = encryption_service.encrypt(json_str)
                 if inspect.isawaitable(result):
                     encrypted_bytes = await result
                 else:
                     encrypted_bytes = result
                
                 if not isinstance(encrypted_bytes, bytes):
                      logger.warning(f"_encrypt_serializable: Encryption service did not return bytes for '{field_name}'. Type: {type(encrypted_bytes)}. Attempting encode.")
                      try:
                           encrypted_bytes = str(encrypted_bytes).encode('utf-8')
                      except Exception:
                           logger.error(f"_encrypt_serializable: Failed to encode non-bytes encryption result for '{field_name}'.")
                           return None
                          
                 logger.debug(f"_encrypt_serializable: Successfully encrypted '{field_name}'.")
                 return encrypted_bytes
            except TypeError as e:
                logger.error(f"Failed to serialize/encrypt '{field_name}': {e} (Data type: {type(data)})", exc_info=True)
                return None
        # --- End Encryption Helpers ---

        from datetime import date, datetime
        # Assign values to prefixed fields, passing field name for logging
        model._first_name = _encrypt(getattr(patient, 'first_name', None), '_first_name')
        model._last_name = _encrypt(getattr(patient, 'last_name', None), '_last_name')
        
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
        model._dob = _encrypt(dob_iso_str, '_dob')
        
        model._email = _encrypt(getattr(patient, 'email', None), '_email')
        model._phone = _encrypt(getattr(patient, 'phone', None), '_phone')
        model._ssn = _encrypt(getattr(patient, 'ssn', None), '_ssn')
        model._medical_record_number = _encrypt(getattr(patient, 'medical_record_number', None), '_medical_record_number')
        model._gender = _encrypt(getattr(patient, 'gender', None), '_gender')
        model._insurance_number = _encrypt(getattr(patient, 'insurance_number', None), '_insurance_number')
        logger.debug(f"[from_domain] Encrypted direct PII/PHI strings for {getattr(patient, 'id', 'N/A')}")

        # --- Handle Address (Domain likely has Address object, Model stores string) ---
        address_obj = getattr(patient, 'address', None) # Renamed for clarity
        if isinstance(address_obj, str): # Handle legacy string case if necessary
             logger.warning(f"Received raw string for address: '{address_obj[:50]}...'. Using directly.")
             full_address_string = address_obj
             model._address_line1 = _encrypt(full_address_string, '_address_line1')
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
                 logger.debug(f"[from_domain] Encrypting constructed address string '{full_address_string[:50]}...' into _address_line1 for {getattr(patient, 'id', 'N/A')}")
                 model._address_line1 = _encrypt(full_address_string, '_address_line1')
            else:
                 logger.debug(f"[from_domain] Address object provided but resulted in empty string for {getattr(patient, 'id', 'N/A')}")
                 model._address_line1 = None
        else:
            # logger.debug(f"[from_domain] No address object or string provided for {getattr(patient, 'id', 'N/A')}")
            model._address_line1 = None
        
        # Ensure other address components in model are explicitly None if not handled above
        # These might be populated if the Address object has corresponding fields and logic is added
        model._address_line2 = None 
        model._city = None
        model._state = None
        model._postal_code = None
        model._country = None
        # --- End Address Handling ---\
        
        # Encrypt serializable complex fields
        logger.debug(f"[from_domain] Encrypting complex fields for {getattr(patient, 'id', 'N/A')}")
        # Use await for async helper function, pass field name for logging
        model._emergency_contact = await _encrypt_serializable(getattr(patient, 'emergency_contact', None), '_emergency_contact')
        model._medical_history = await _encrypt_serializable(getattr(patient, 'medical_history', []), '_medical_history') # Use getattr with default
        model._medications = await _encrypt_serializable(getattr(patient, 'medications', []), '_medications') 
        model._allergies = await _encrypt_serializable(getattr(patient, 'allergies', []), '_allergies')
        model._treatment_notes = await _encrypt_serializable(getattr(patient, 'treatment_notes', []), '_treatment_notes')
        model._extra_data = await _encrypt_serializable(getattr(patient, 'extra_data', {}), '_extra_data') 
        model._insurance_info = await _encrypt_serializable(getattr(patient, 'insurance_info', None), '_insurance_info') 

        # Assign remaining non-encrypted fields, converting UUIDs to string
        biometric_twin_id_obj = getattr(patient, 'biometric_twin_id', None)
        if isinstance(biometric_twin_id_obj, uuid.UUID):
            model.biometric_twin_id = str(biometric_twin_id_obj) # Store as string
        else:
            model.biometric_twin_id = biometric_twin_id_obj # Assume None or already string

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

    async def to_domain(self, encryption_service: BaseEncryptionService) -> DomainPatient:
        """
        Convert this Patient model instance to a domain Patient entity,
        decrypting PHI fields using the provided encryption service.
        """
        logger.debug(f"[to_domain] Starting conversion for model patient ID: {self.id}")
        
        # --- Decryption Helpers ---
        async def _decrypt(encrypted_value: Optional[bytes]) -> Optional[str]:
            """Decrypts bytes value, returns string or None."""
            if encrypted_value is None:
                return None
            try:
                result = encryption_service.decrypt(encrypted_value)
                # Support both sync and async decrypt
                if inspect.isawaitable(result):
                    return await result
                return result
            except Exception as e:
                logger.error(f"Decryption failed for patient {self.id}: {e}", exc_info=True)
                # Return None on decryption failure
                return None

        # Decrypt necessary fields
        first_name = await _decrypt(self._first_name)
        last_name = await _decrypt(self._last_name)
        from datetime import date, datetime
        # Decrypt and parse date_of_birth
        if self._dob:
            decrypted_dob_str = await _decrypt(self._dob)
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
        email = await _decrypt(self._email)
        phone = await _decrypt(self._phone)
        ssn = await _decrypt(self._ssn)
        medical_record_number = await _decrypt(self._medical_record_number)
        gender = await _decrypt(self._gender)
        insurance_number = await _decrypt(self._insurance_number)

        logger.debug(f"[to_domain] Decrypted simple PII for {self.id}")

        # Decrypt only the address string stored in _address_line1
        decrypted_address_str = await _decrypt(self._address_line1)
        logger.debug(f"[to_domain] Decrypted address string for {self.id}: {decrypted_address_str[:50] if decrypted_address_str else 'None'}...")

        # Decrypt complex fields using the appropriate helper
        logger.debug(f"[to_domain] Decrypting complex fields for {self.id}")
        decrypted_emergency_contact = await _decrypt(self._emergency_contact)
        emergency_contact_obj = EmergencyContact(**json.loads(decrypted_emergency_contact)) if decrypted_emergency_contact else None
        
        decrypted_medical_history = await _decrypt(self._medical_history)
        decrypted_medications = await _decrypt(self._medications)
        decrypted_allergies = await _decrypt(self._allergies)
        decrypted_treatment_notes = await _decrypt(self._treatment_notes)
        decrypted_extra_data = await _decrypt(self._extra_data)
        
        # QUANTUM FIX: Decrypt insurance_info
        decrypted_insurance_info = await _decrypt(self._insurance_info) # Assuming dict

        # Build domain Patient using correct types expected by the dataclass
        patient = DomainPatient(
            id=self.id,
            external_id=self.external_id,
            created_by=self.user_id,
            active=self.is_active,
            # Assign name components
            first_name=first_name,
            last_name=last_name,
            date_of_birth=date_of_birth, # Use the parsed date object
            # Assign contact components
            email=email,
            phone=phone,
            ssn=ssn,
            medical_record_number=medical_record_number,
            gender=gender,
            insurance_number=insurance_number,
            # Assign the decrypted address string
            address=decrypted_address_str, 
            emergency_contact=emergency_contact_obj,
            medical_history=decrypted_medical_history or [], # Default to empty list
            medications=decrypted_medications or [],
            allergies=decrypted_allergies or [],
            treatment_notes=decrypted_treatment_notes or [],
            extra_data=decrypted_extra_data or {}, # Default to empty dict
            biometric_twin_id=self.biometric_twin_id,
            created_at=self.created_at.replace(tzinfo=UTC) if self.created_at else None,
            updated_at=self.updated_at.replace(tzinfo=UTC) if self.updated_at else None,
            insurance_info=decrypted_insurance_info,
            # name and contact_info handled by __post_init__ or descriptor
        )
        logger.debug(f"[to_domain] Completed conversion for patient ID: {patient.id}")
        return patient

# Example comment outside class
# Add columns like _ethnicity, _preferred_language, etc. following the pattern above.
