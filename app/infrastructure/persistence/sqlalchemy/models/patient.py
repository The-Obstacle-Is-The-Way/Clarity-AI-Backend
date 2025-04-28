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
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # external_id could be from an EMR or other system
    external_id = Column(String(64), unique=True, index=True, nullable=True)
    # Foreign key to the associated user account (if applicable)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)

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

    user = relationship("User", back_populates="patients") # Define relationship to User (Ensuring no foreign_keys here)
    # --- Relationships ---
    # Complete unified relationship graph with proper cascades for referential integrity
    appointments = relationship(
        "AppointmentModel",
        back_populates="patient",
        cascade="all, delete-orphan",
        foreign_keys="[AppointmentModel.patient_id]" # Explicitly define the foreign key
    )
    clinical_notes = relationship("ClinicalNoteModel", back_populates="patient", cascade="all, delete-orphan", remote_side="ClinicalNoteModel.patient_id")
    # Rename relationship to avoid conflict
    medication_records = relationship("MedicationModel", back_populates="patient", cascade="all, delete-orphan", remote_side="MedicationModel.patient_id")
    
    # Digital twin relationships
    biometric_twin_id = Column(UUID(as_uuid=True), nullable=True)

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
        model.external_id = getattr(patient, "external_id", None)
        model.user_id = patient.created_by
        model.is_active = patient.active
        logger.debug(f"[from_domain] Mapped core metadata for {patient.id}")

        # --- Encryption Helpers ---
        def _encrypt(value: Optional[str]) -> Optional[bytes]:
            """Encrypts a string value, returns bytes or None."""
            if value is None:
                return None
            try:
                value_str = str(value) # Ensure it's a string
                # Ensure encryption_service is available and encrypt is synchronous
                if hasattr(encryption_service, 'encrypt') and callable(encryption_service.encrypt):
                    encrypted = encryption_service.encrypt(value_str.encode('utf-8'))
                    logger.debug(f"_encrypt: Successfully encrypted value starting with '{value_str[:10]}...'. Encrypted type: {type(encrypted)} len: {len(encrypted) if encrypted else 0}")
                    return encrypted
                else:
                    logger.error("_encrypt: encryption_service.encrypt is not available or not callable.")
                    return None # Or raise an error
            except Exception as e:
                logger.error(f"_encrypt: Failed to encrypt value starting with '{str(value)[:10]}...': {e}", exc_info=True)
                return None # Return None or re-raise specific exception

        async def _encrypt_serializable(data: Optional[Any]) -> Optional[bytes]:
            """Serializes data to JSON string then encrypts, returns bytes or None."""
            if data is None:
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
                    logger.warning(f"Attempting string conversion for non-standard type {type(data)} before JSON serialization.")
                    data_dict = str(data) 

                json_str = json.dumps(data_dict)
                # Call the service's encrypt method with the JSON string (sync or async)
                result = encryption_service.encrypt(json_str)
                if inspect.isawaitable(result):
                    encrypted_bytes = await result
                else:
                    encrypted_bytes = result
                return encrypted_bytes
            except TypeError as e:
                logger.error(f"Failed to serialize/encrypt data: {e} (Data type: {type(data)})", exc_info=True)
                return None
        # --- End Encryption Helpers ---

        from datetime import date, datetime
        # Assign values to prefixed fields
        model._first_name = _encrypt(patient.first_name)
        model._last_name = _encrypt(patient.last_name)
        
        # Handle date_of_birth (convert date/datetime to isoformat string first)
        dob_value = None
        if isinstance(patient.date_of_birth, (date, datetime)):
             dob_value = patient.date_of_birth.isoformat()
        elif isinstance(patient.date_of_birth, str):
             dob_value = patient.date_of_birth # Assume already string
        model._dob = _encrypt(dob_value)
        
        model._email = _encrypt(patient.email)
        model._phone = _encrypt(patient.phone)
        model._ssn = _encrypt(patient.ssn)
        model._medical_record_number = _encrypt(patient.medical_record_number)
        model._gender = _encrypt(patient.gender)
        model._insurance_number = _encrypt(patient.insurance_number)
        logger.debug(f"[from_domain] Encrypted direct PII/PHI strings for {patient.id}")

        # Encrypt address component fields
        model._address_line1 = _encrypt(patient.address)
        # Nullify other address components as they are not in the domain model
        model._address_line2 = None
        model._city = None
        model._state = None
        model._postal_code = None
        model._country = None
        logger.debug(f"[from_domain] Encrypted address string for {patient.id}")

        model._emergency_contact = await _encrypt_serializable(patient.emergency_contact)
        model._medical_history = await _encrypt_serializable(patient.medical_history)
        model._medications = await _encrypt_serializable(patient.medications)
        model._allergies = await _encrypt_serializable(patient.allergies)
        model._treatment_notes = await _encrypt_serializable(patient.treatment_notes)
        model._extra_data = await _encrypt_serializable(patient.extra_data if hasattr(patient, 'extra_data') else None)
        logger.debug(f"[from_domain] Encrypted complex/JSON fields for {patient.id}")

        logger.debug(f"[from_domain] Conversion complete for {patient.id}. Returning model.")
        return model

    async def to_domain(self, encryption_service: BaseEncryptionService) -> DomainPatient:
        """
        Convert a Patient model instance to a domain Patient entity,
        decrypting PHI fields.
        """
        logger.debug(f"[to_domain] Starting conversion for model patient ID: {self.id}")

        # Helper for decryption
        async def _decrypt(encrypted_value: Optional[str]) -> Optional[str]:
            """Decrypt a value, handling sync or async decrypt methods."""
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

        # Helper for decryption and JSON parsing with type validation
        async def _decrypt_and_parse_json(
            attr_name: str, 
            expected_type: type # Expect list or dict
        ) -> Optional[Union[dict, list]]:
            decrypted_json_str = await _decrypt(getattr(self, attr_name, None))
            if not decrypted_json_str:
                # logger.debug(f"[to_domain:_decrypt_and_parse_json] No encrypted data for {attr_name} for patient {self.id}")
                return None  # Return None if no encrypted data
            
            try:
                parsed_data = json.loads(decrypted_json_str)
                # Validate type
                if isinstance(parsed_data, expected_type):
                    # logger.debug(f"[to_domain:_decrypt_and_parse_json] Parsed {attr_name} for patient {self.id} as expected type {expected_type}")
                    return parsed_data
                else:
                    logger.warning(
                        f"Parsed JSON for {attr_name} patient {self.id} is not of expected type {expected_type}. Got {type(parsed_data)}. Returning default."
                    )
                    # Return None, let the caller handle default (e.g., `or []`)
                    return None 
            except (json.JSONDecodeError, TypeError) as e:
                logger.warning(f"Failed to parse decrypted JSON for {attr_name} patient {self.id}: {e}", exc_info=True)
                # Return None on parsing failure
                return None

        try:
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

            # --- Updated Address Handling --- 
            # Decrypt only the address string stored in _address_line1
            address_str = await _decrypt(self._address_line1)
            logger.debug(f"[to_domain] Decrypted address string for {self.id}: {address_str}")

            # Decrypt and reconstruct EmergencyContact
            emergency_contact_json_str = await _decrypt(self._emergency_contact)
            emergency_contact_obj: Optional[EmergencyContact] = None
            if emergency_contact_json_str:
                try:
                    emergency_contact_dict = json.loads(emergency_contact_json_str)
                    emergency_contact_obj = EmergencyContact(**emergency_contact_dict)
                    logger.debug(f"[to_domain] Reconstructed EmergencyContact for {self.id}: {emergency_contact_obj}")
                except (json.JSONDecodeError, TypeError) as e:
                    logger.warning(f"Failed to parse or instantiate EmergencyContact for patient {self.id}: {e}", exc_info=True)
            else:
                logger.debug(f"[to_domain] No emergency contact data found or decrypted for {self.id}")

            # Decrypt and parse JSON list/dict fields, ensuring correct type
            medical_history = await _decrypt_and_parse_json('_medical_history', expected_type=list)
            medications = await _decrypt_and_parse_json('_medications', expected_type=list)
            allergies = await _decrypt_and_parse_json('_allergies', expected_type=list)
            treatment_notes = await _decrypt_and_parse_json('_treatment_notes', expected_type=list) # Expecting list[dict]

            logger.debug(f"[to_domain] Decrypted complex fields for {self.id}")

            # Prepare contact_info dictionary
            contact_info_dict = {}
            if email: contact_info_dict['email'] = email
            if phone: contact_info_dict['phone'] = phone

            # Build domain Patient using correct types expected by the dataclass
            patient = DomainPatient(
                id=self.id,
                date_of_birth=date_of_birth, # Type: date | None
                gender=gender,               # Type: str | None
                # Pass individual name components, __post_init__ handles full name
                first_name=first_name,       # Type: str | None
                last_name=last_name,         # Type: str | None
                # Pass contact dict and individual components, __post_init__ handles consolidation
                contact_info=contact_info_dict, # Type: dict[str, Any]
                email=email,                 # Type: str | None
                phone=phone,                 # Type: str | None
                # Pass formatted address string
                address=address_str,         # Type: str | None
                insurance_number=insurance_number, # Type: str | None
                ssn=ssn,                     # Type: str | None
                medical_record_number=medical_record_number, # Type: str | None
                emergency_contact=emergency_contact_obj, # Type: EmergencyContact | None
                # insurance=None, # Let default factory handle
                insurance_info=None, # Pass None explicitly
                active=self.is_active,       # Type: bool
                created_by=self.user_id,     # Type: Any
                # diagnoses=None, # Let default factory handle
                medications=medications or [], # Type: list[str]
                allergies=allergies or [],     # Type: list[str]
                medical_history=medical_history or [], # Type: list[str]
                treatment_notes=treatment_notes or [], # Type: list[dict[str, Any]]
                created_at=self.created_at,  # Type: datetime | None
                updated_at=self.updated_at   # Type: datetime | None
                # NOTE: 'name' field is deliberately omitted, handled by __post_init__
            )
            logger.debug(f"[to_domain] Successfully created DomainPatient for {self.id}")
            return patient

        except Exception as e:
            logger.error(f"Error converting Patient model {self.id} to domain: {e}", exc_info=True)
            raise  # Re-raise the error to be handled by the caller (repository)

# Example comment outside class
# Add columns like _ethnicity, _preferred_language, etc. following the pattern above.
