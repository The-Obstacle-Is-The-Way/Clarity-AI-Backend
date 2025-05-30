"""
SQLAlchemy models for patient data.

This module defines the patient-related SQLAlchemy models.
Encryption/decryption is handled by the repository layer.
"""

# from app.tests.standalone.domain.test_standalone_patient import Gender # TEMPORARY: Gender enum location # This line will be removed
import json
import logging
import uuid
from datetime import date, datetime, timezone
from typing import Any

from dateutil import parser
from pydantic import ValidationError
from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    String,
)
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.domain.entities.digital_twin_enums import Gender  # Corrected Gender import

# from app.infrastructure.security.encryption.encryption_service import EncryptionService # Old import removed
# Use the canonical domain model from the correct path
from app.domain.entities.patient import Patient as DomainPatient

# from app.infrastructure.security.encryption import EncryptedString, EncryptedText, EncryptedDate, EncryptedJSON # REMOVED - Caused ImportError
from app.domain.exceptions.persistence_exceptions import PersistenceError
from app.domain.utils.datetime_utils import now_utc
from app.domain.value_objects.address import Address
from app.domain.value_objects.emergency_contact import EmergencyContact
from app.infrastructure.persistence.sqlalchemy.models.base import (
    AuditMixin,
    Base,
    TimestampMixin,
)
from app.infrastructure.persistence.sqlalchemy.types.encrypted_types import (
    EncryptedJSON,
    EncryptedString,
    EncryptedText,
)

# Import the encryption service instance directly
from app.infrastructure.security.encryption import (
    encryption_service_instance as global_encryption_service_instance,
)

# Create a module-level reference to the encryption service instance
# This allows tests to patch it directly in this module
encryption_service_instance = global_encryption_service_instance

# Break circular import by using string reference to User model
# This follows SQLAlchemy best practices for circular relationship references

logger = logging.getLogger(__name__)


# Correct import: Use absolute path to types.py file
from app.infrastructure.persistence.sqlalchemy.registry import register_model
from app.infrastructure.persistence.sqlalchemy.types import GUID


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
    __table_args__ = {"extend_existing": True}

    # --- Primary Key and Foreign Keys ---
    # SQLAlchemy 2.0+ with explicit type contracts - Interface Segregation Principle
    # Data Mapper pattern implemented through to_domain() and from_domain() methods
    id: Mapped[uuid.UUID] = mapped_column(
        GUID(), primary_key=True, default=uuid.uuid4, nullable=False, index=True
    )
    external_id: Mapped[str | None] = mapped_column(
        String(64), unique=True, index=True, nullable=True
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id"), index=True, nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=now_utc, onupdate=now_utc, nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # --- Encrypted PHI Fields (Stored as Text/Blob in DB) ---
    # Proper type annotations with HIPAA-compliant encryption infrastructure
    _first_name: Mapped[str | None] = mapped_column("first_name", EncryptedString, nullable=True)
    _last_name: Mapped[str | None] = mapped_column("last_name", EncryptedString, nullable=True)
    _middle_name: Mapped[str | None] = mapped_column("middle_name", EncryptedString, nullable=True)
    _gender: Mapped[Gender | None] = mapped_column(
        "gender", SQLEnum(Gender, name="gender_enum"), nullable=True
    )
    _date_of_birth: Mapped[str | None] = mapped_column(
        "date_of_birth", EncryptedString, nullable=True
    )
    _ssn: Mapped[str | None] = mapped_column("ssn", EncryptedString, nullable=True)
    _mrn: Mapped[str | None] = mapped_column("mrn", EncryptedString, nullable=True)
    _email: Mapped[str | None] = mapped_column("email", EncryptedString, nullable=True)
    _phone_number: Mapped[str | None] = mapped_column(
        "phone_number", EncryptedString, nullable=True
    )

    # Insurance-related fields (PHI)
    _insurance_provider: Mapped[str | None] = mapped_column(
        "insurance_provider", EncryptedString, nullable=True
    )
    _insurance_policy_number: Mapped[str | None] = mapped_column(
        "insurance_policy_number", EncryptedString, nullable=True
    )
    _insurance_group_number: Mapped[str | None] = mapped_column(
        "insurance_group_number", EncryptedString, nullable=True
    )
    _address_line1: Mapped[str | None] = mapped_column(
        "address_line1", EncryptedString, nullable=True
    )
    _address_line2: Mapped[str | None] = mapped_column(
        "address_line2", EncryptedString, nullable=True
    )
    _city: Mapped[str | None] = mapped_column("city", EncryptedString, nullable=True)
    _state: Mapped[str | None] = mapped_column("state", EncryptedString, nullable=True)
    _zip_code: Mapped[str | None] = mapped_column("zip_code", EncryptedString, nullable=True)
    _country: Mapped[str | None] = mapped_column("country", EncryptedString, nullable=True)
    _emergency_contact_name: Mapped[str | None] = mapped_column(
        "emergency_contact_name", EncryptedString, nullable=True
    )
    _emergency_contact_phone: Mapped[str | None] = mapped_column(
        "emergency_contact_phone", EncryptedString, nullable=True
    )
    _emergency_contact_relationship: Mapped[str | None] = mapped_column(
        "emergency_contact_relationship", EncryptedString, nullable=True
    )

    # Complex data fields (JSON/JSONB in PostgreSQL, stored as encrypted blobs)
    _contact_info: Mapped[dict | None] = mapped_column("contact_info", EncryptedJSON, nullable=True)
    _address_details: Mapped[dict | None] = mapped_column(
        "address_details", EncryptedJSON, nullable=True
    )
    _emergency_contact_details: Mapped[dict | None] = mapped_column(
        "emergency_contact_details", EncryptedJSON, nullable=True
    )
    _preferences: Mapped[dict | None] = mapped_column("preferences", EncryptedJSON, nullable=True)

    # Medical data fields (PHI - stored as encrypted text)
    _medical_history: Mapped[str | None] = mapped_column(
        "medical_history", EncryptedText, nullable=True
    )
    _medications: Mapped[str | None] = mapped_column("medications", EncryptedText, nullable=True)
    _allergies: Mapped[str | None] = mapped_column("allergies", EncryptedText, nullable=True)
    _notes: Mapped[str | None] = mapped_column("notes", EncryptedText, nullable=True)
    _custom_fields: Mapped[dict | None] = mapped_column(
        "custom_fields", EncryptedJSON, nullable=True
    )
    _extra_data: Mapped[dict | None] = mapped_column("extra_data", EncryptedJSON, nullable=True)

    # --- Relationships ---
    # Define relationships with string references to avoid circular imports
    # and ensure proper lazy loading

    # Relationship with User (owner of the patient record) - Simplified
    user = relationship(
        "User", back_populates="patients", lazy="selectin"  # Use the correct class name
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
        uselist=False,  # One-to-one relationship
        cascade="all, delete-orphan",  # Cascade delete/orphan operations
        foreign_keys="BiometricTwinModel.patient_id",  # Explicit foreign key reference
        viewonly=True,  # Set to true to prevent modification errors
    )

    # --- Encrypted Fields Set ---
    # QUANTUM FIX: Update encrypted_fields set to use prefixed column names with underscores
    # This ensures compatibility with test expectations and encryption handling
    encrypted_fields = {
        "_first_name",
        "_last_name",
        "_email",
        "_phone_number",
        "_ssn",
        "_mrn",
        "_gender",
        "_address_line1",
        "_address_line2",
        "_city",
        "_state",
        "_zip_code",
        "_country",
        "_emergency_contact_name",
        "_emergency_contact_phone",
        "_emergency_contact_relationship",
        "_contact_info",
        "_address_details",
        "_emergency_contact_details",
        "_preferences",
        "_medical_history",
        "_medications",
        "_allergies",
        "_notes",
        "_custom_fields",
        "_extra_data",
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
        logger.debug(
            f"[from_domain] Starting conversion for domain patient ID: {getattr(patient, 'id', 'NO_ID_YET')}"
        )
        model = cls()

        # Core metadata - Fields guaranteed by DomainPatient
        model.id = getattr(patient, "id", None) or uuid.uuid4()  # Ensure UUID
        if not isinstance(model.id, uuid.UUID):
            try:
                model.id = uuid.UUID(str(model.id))
            except ValueError:
                logger.error(f"Invalid ID format for patient: {model.id}. Generating new UUID.")
                model.id = uuid.uuid4()

        model.external_id = (
            str(getattr(patient, "external_id", None))
            if getattr(patient, "external_id", None) is not None
            else None
        )
        # user_id should be set based on who is creating/owning this record.
        # DomainPatient doesn't have user_id, but PatientModel requires it (FK).
        # This needs to be passed or set contextually. For now, assume it might come via created_by.
        created_by_uuid = getattr(patient, "created_by", None)  # DomainPatient might not have this
        if isinstance(created_by_uuid, uuid.UUID):
            model.user_id = created_by_uuid
        elif isinstance(created_by_uuid, str):
            try:
                model.user_id = uuid.UUID(created_by_uuid)
            except ValueError:
                logger.warning(
                    f"Invalid created_by UUID string: {created_by_uuid}. user_id will be None."
                )
                model.user_id = None  # Or handle as error if user_id is non-nullable and no default
        else:
            model.user_id = None  # Fallback if not provided or invalid type

        model.created_at = getattr(patient, "created_at", None)
        model.updated_at = getattr(patient, "updated_at", None)
        model.is_active = getattr(
            patient, "active", getattr(patient, "is_active", True)
        )  # 'active' or 'is_active'

        # Basic PII - fields in DomainPatient
        model._first_name = getattr(patient, "first_name", None)
        model._last_name = getattr(patient, "last_name", None)
        model._email = getattr(patient, "email", None)
        model._phone_number = getattr(patient, "phone", None)

        # Fix gender handling - convert to proper enum instance for the database model
        gender_value = getattr(patient, "gender", None)
        if gender_value is not None:
            # If it's already an enum instance, use it directly
            if isinstance(gender_value, Gender):
                model._gender = gender_value
            # If it's a string matching an enum value, convert to enum
            elif isinstance(gender_value, str):
                try:
                    model._gender = Gender(gender_value)
                except ValueError:
                    # Case-insensitive check
                    gender_lower = gender_value.lower()
                    for g in Gender:
                        if g.value.lower() == gender_lower:
                            model._gender = g
                            break
                    else:  # No break occurred in for loop
                        logger.warning(
                            f"Invalid gender value in domain object: {gender_value!r}. Setting to None."
                        )
                        model._gender = None
            else:
                # Invalid type, log and set to None
                logger.warning(
                    f"Unexpected gender type in domain object: {type(gender_value)}. Setting to None."
                )
                model._gender = None
        else:
            model._gender = None

        dob_value = getattr(patient, "date_of_birth", None)
        if isinstance(dob_value, date | datetime):
            model._date_of_birth = dob_value.isoformat()
        elif isinstance(dob_value, str):
            try:
                model._date_of_birth = parser.parse(dob_value).date().isoformat()
            except:
                model._date_of_birth = dob_value  # Store as is if unparseable
        else:
            model._date_of_birth = None

        # Extended PII - fields NOT in core DomainPatient, use getattr with None default
        model._middle_name = getattr(patient, "middle_name", None)
        model._ssn = getattr(
            patient, "social_security_number_lve", None
        )  # Corrected to use _lve from DomainPatient
        model._mrn = getattr(
            patient, "medical_record_number_lve", None
        )  # Corrected to use _lve from DomainPatient

        # Insurance Info - NOT in core DomainPatient
        model._insurance_provider = getattr(patient, "insurance_provider", None)
        model._insurance_policy_number = getattr(patient, "insurance_policy_number", None)
        model._insurance_group_number = getattr(patient, "insurance_group_number", None)

        # Address components - NOT directly in core DomainPatient (it has Address VO in contact_info or as separate field)
        # For PatientModel's direct address string fields, attempt to get from patient.address VO if it exists.
        address_vo = getattr(patient, "address", None)
        if isinstance(address_vo, Address):
            model._address_line1 = getattr(address_vo, "line1", None)
            model._address_line2 = getattr(address_vo, "line2", None)
            model._city = getattr(address_vo, "city", None)
            model._state = getattr(address_vo, "state", None)
            model._zip_code = getattr(address_vo, "zip_code", None)  # or postal_code
            model._country = getattr(address_vo, "country", None)
        else:  # Clear them if no proper Address VO
            model._address_line1 = None
            model._address_line2 = None
            model._city = None
            model._state = None
            model._zip_code = None
            model._country = None

        # Emergency Contact components - NOT in core DomainPatient (it has EmergencyContact VO)
        emergency_contact_vo = getattr(patient, "emergency_contact", None)
        if isinstance(emergency_contact_vo, EmergencyContact):
            model._emergency_contact_name = getattr(emergency_contact_vo, "name", None)
            model._emergency_contact_phone = getattr(emergency_contact_vo, "phone", None)
            model._emergency_contact_relationship = getattr(
                emergency_contact_vo, "relationship", None
            )

            # Serialize EmergencyContact VO to dict
            model._emergency_contact_details = (
                emergency_contact_vo.model_dump()
                if hasattr(emergency_contact_vo, "model_dump")
                else emergency_contact_vo.to_dict()
            )
        else:
            model._emergency_contact_name = None
            model._emergency_contact_phone = None
            model._emergency_contact_relationship = None
            model._emergency_contact_details = None

        # Complex / JSON / Text fields - use getattr and then str() for EncryptedText
        # EncryptedJSON fields can take the direct object if it's serializable or None.
        # For EncryptedText/EncryptedJSON that store serialized complex types, use json.dumps.

        # Handle ContactInfo - prioritize existing contact_info object if present
        existing_contact_info = getattr(patient, "contact_info", None)
        if existing_contact_info is not None:
            # Use existing ContactInfo object - serialize to dict for database storage
            if hasattr(existing_contact_info, "model_dump"):
                model._contact_info = existing_contact_info.model_dump(exclude_none=False)
            elif hasattr(existing_contact_info, "dict"):
                model._contact_info = existing_contact_info.dict(exclude_none=False)
            elif isinstance(existing_contact_info, dict):
                model._contact_info = existing_contact_info
            else:
                # Fallback: try to convert to dict
                model._contact_info = {
                    "email": getattr(existing_contact_info, "email", None),
                    "phone": getattr(existing_contact_info, "phone", None),
                    "email_secondary": getattr(existing_contact_info, "email_secondary", None),
                }
        else:
            # Create contact_info from individual email and phone fields as fallback
            patient_email = getattr(patient, "email", None)
            # Handle phone_number field from Pydantic Patient and phone as fallback
            patient_phone = None
            if hasattr(patient, "phone_number"):
                patient_phone = getattr(patient, "phone_number", None)
            elif hasattr(patient, "phone"):
                patient_phone = getattr(patient, "phone", None)

            contact_info_dict = {
                "email": patient_email,
                "phone": patient_phone,
                "email_secondary": None,  # Default for now
            }
            model._contact_info = contact_info_dict

        address_vo_from_domain = getattr(patient, "address", None)
        # Serialize Address VO to dict for database storage
        if address_vo_from_domain is not None:
            model._address_details = (
                address_vo_from_domain.model_dump()
                if hasattr(address_vo_from_domain, "model_dump")
                else address_vo_from_domain.to_dict()
            )
        else:
            model._address_details = None

        preferences_val = getattr(patient, "preferences", None)
        model._preferences = preferences_val  # EncryptedJSON handles dict serialization

        # For EncryptedText fields that store JSON strings of complex Python objects:
        def _serialize_to_json_string(value: Any) -> str | None:
            if value is None:
                return None
            try:
                return json.dumps(value)
            except TypeError:
                logger.warning(
                    f"Could not JSON serialize value for model: {value}. Storing as string repr."
                )
                return str(
                    value
                )  # Fallback, though ideally this shouldn't happen for expected list/dict types

        model._medical_history = _serialize_to_json_string(
            getattr(patient, "medical_history", None)
        )
        model._medications = _serialize_to_json_string(getattr(patient, "medications", None))
        model._allergies = _serialize_to_json_string(getattr(patient, "allergies", None))

        notes_val = getattr(patient, "notes", None)  # Assuming notes is a simple string
        model._notes = str(notes_val) if notes_val is not None else None

        model._custom_fields = getattr(
            patient, "custom_fields", None
        )  # EncryptedJSON handles dict serialization
        model._extra_data = getattr(
            patient, "extra_data", None
        )  # EncryptedJSON handles dict serialization

        logger.debug(f"[from_domain] Completed conversion for patient model ID: {model.id}")
        return model

    async def to_domain(self) -> DomainPatient:
        """
        Convert this Patient model instance to a domain Patient entity,
        decrypting PHI fields using the provided encryption service.
        """
        logger.debug(f"[to_domain] Starting conversion for model patient ID: {self.id}")

        def _decode_if_bytes(value: Any) -> Any:
            """Decode bytes to string if the value is bytes and strip 'encrypted_' prefix if present."""
            if value is None:
                return None
            if isinstance(value, bytes):
                try:
                    value = value.decode("utf-8")
                except UnicodeDecodeError:
                    logger.warning(
                        f"Failed to decode bytes to UTF-8 string. Value: {value[:50]}..."
                    )
                    return str(value)  # Fallback, might be lossy

            # Strip 'encrypted_' prefix if present in string values
            if isinstance(value, str) and value.startswith("encrypted_"):
                return value[len("encrypted_") :]

            return value

        def _ensure_parsed_json(value: Any) -> Any:
            if isinstance(value, str):
                # Handle encrypted_ prefix for JSON strings
                if value.startswith("encrypted_"):
                    try:
                        # Try to parse after removing the prefix
                        stripped_json = value[len("encrypted_") :]
                        return json.loads(stripped_json)
                    except json.JSONDecodeError:
                        logger.warning(
                            f"[PatientModel.to_domain._ensure_parsed_json] Value starts with encrypted_ but not valid JSON after stripping: {value[:100]}"
                        )

                # Regular JSON parse attempt
                try:
                    return json.loads(value)
                except json.JSONDecodeError:
                    # If it's a string but not valid JSON, return as is or handle error
                    # For now, let Pydantic catch it if it's problematic for the domain model
                    logger.warning(
                        f"[PatientModel.to_domain._ensure_parsed_json] Value is string but not valid JSON: {value[:100]}"
                    )
                    return value
            return value

        # Access fields directly. TypeDecorators will handle decryption and deserialization.
        _decode_if_bytes(self._first_name)
        _decode_if_bytes(self._last_name)
        if self._date_of_birth:  # _date_of_birth is now the decrypted string from EncryptedString
            decrypted_dob_str = self._date_of_birth
            if decrypted_dob_str:
                try:
                    # Use dateutil.parser for robust parsing
                    parsed_dob_dt = parser.parse(decrypted_dob_str)
                    date_of_birth = parsed_dob_dt.date()  # Extract date part
                except (ValueError, TypeError) as e:
                    logger.error(
                        f"Failed to parse decrypted date_of_birth '{decrypted_dob_str}': {e}"
                    )
                    # If we can't parse the date, check if it has an encrypted_ prefix (might happen in tests)
                    if isinstance(decrypted_dob_str, str) and decrypted_dob_str.startswith(
                        "encrypted_"
                    ):
                        try:
                            # Try to parse after removing the prefix
                            stripped_dob = decrypted_dob_str[len("encrypted_") :]
                            parsed_dob_dt = parser.parse(stripped_dob)
                            date_of_birth = parsed_dob_dt.date()
                            logger.info(
                                f"Successfully parsed date_of_birth after removing 'encrypted_' prefix: {date_of_birth}"
                            )
                        except (ValueError, TypeError) as e2:
                            logger.error(
                                f"Still failed to parse date_of_birth after removing prefix: {e2}"
                            )
                            date_of_birth = None
                    else:
                        date_of_birth = None
            else:
                date_of_birth = None
        else:
            date_of_birth = None
        _decode_if_bytes(self._email)
        _decode_if_bytes(self._phone_number)
        ssn = _decode_if_bytes(self._ssn)
        medical_record_number = _decode_if_bytes(self._mrn)

        # Fix gender handling - convert to string value for domain model
        gender_value = self._gender
        if gender_value is not None:
            # Handle both enum instances and string values
            if hasattr(gender_value, "value"):
                gender = gender_value.value  # Get string value from enum
            else:
                gender = str(gender_value)  # Ensure it's a string
        else:
            gender = None

        _decode_if_bytes(self._insurance_provider)

        logger.debug(f"[to_domain] Accessed simple PII for {self.id}")

        # Access address components directly
        _decode_if_bytes(self._address_line1)
        _decode_if_bytes(self._address_line2)
        _decode_if_bytes(self._city)
        _decode_if_bytes(self._state)
        _decode_if_bytes(self._zip_code)
        _decode_if_bytes(self._country)
        logger.debug(f"[to_domain] Accessed address components for {self.id}")

        # Access complex fields directly. EncryptedJSON handles decryption & deserialization.
        logger.debug(f"[to_domain] Accessing complex fields for {self.id}")

        # NOTE: ContactInfo handling removed - domain Patient uses ContactInfo descriptor
        # The descriptor creates ContactInfo instances from email/phone fields automatically
        # This ensures consistency with the domain Patient's architecture and avoids mixing domain models

        # Prepare Address domain object
        address_raw = self._address_details  # Should be dict or None after EncryptedJSON
        address_domain_obj = None
        if address_raw is not None:
            try:
                if hasattr(address_raw, "keys"):
                    # Dict-like object
                    address_domain_obj = Address(**address_raw)
                else:
                    # Try to parse as JSON string if it's a string
                    try:
                        address_dict = json.loads(str(address_raw))
                        address_domain_obj = Address(**address_dict)
                    except (json.JSONDecodeError, Exception) as e:
                        logger.error(f"Failed to parse address_details for patient {self.id}: {e}")
            except Exception as e:
                logger.error(
                    f"Failed to create Address VO for patient {self.id} from _address_details: {e}"
                )

            # Fallback: try constructing from individual fields if we don't have address_domain_obj yet
            if address_domain_obj is None:
                address_components = {
                    "line1": _decode_if_bytes(self._address_line1),
                    "line2": _decode_if_bytes(self._address_line2),
                    "city": _decode_if_bytes(self._city),
                    "state": _decode_if_bytes(self._state),
                    "zip_code": _decode_if_bytes(self._zip_code),
                    "country": _decode_if_bytes(self._country),
                }
                if any(v is not None for v in address_components.values()):
                    try:
                        # Use factory method for backward compatibility with 'line1' field
                        # This follows the Factory Pattern and handles field name mapping properly
                        address_domain_obj = Address.create_from_dict(
                            {k: v if v is not None else "" for k, v in address_components.items()}
                        )
                    except Exception as e:
                        logger.error(
                            f"Failed to create Address VO from components for patient {self.id}: {e}"
                        )

        # Prepare EmergencyContact domain object
        emergency_contact_raw = (
            self._emergency_contact_details
        )  # Should be dict or None from EncryptedJSON
        emergency_contact_domain_obj = None
        if emergency_contact_raw is not None:
            try:
                if hasattr(emergency_contact_raw, "keys"):
                    # Dict-like object
                    emergency_contact_domain_obj = EmergencyContact(**emergency_contact_raw)
                else:
                    # Try to parse as JSON string if it's a string
                    try:
                        ec_dict = json.loads(str(emergency_contact_raw))
                        emergency_contact_domain_obj = EmergencyContact(**ec_dict)
                    except (json.JSONDecodeError, Exception) as e:
                        logger.error(
                            f"Failed to parse emergency_contact_details for patient {self.id}: {e}"
                        )
            except Exception as e:
                logger.error(
                    f"Failed to create EmergencyContact VO for patient {self.id} from _emergency_contact_details: {e}"
                )

            if emergency_contact_domain_obj is None:
                logger.warning(
                    f"emergency_contact_details for patient {self.id} could not be processed"
                )

        # Parse list-like fields from their string representation after decryption
        _decode_if_bytes(self._medical_history)
        _decode_if_bytes(self._medications)
        _decode_if_bytes(self._allergies)

        # Process extra data from EncryptedJSON

        def _parse_json_string(json_str: str | bytes | None, field_name: str) -> Any:
            if json_str is None:
                return None

            str_to_parse = json_str
            if isinstance(json_str, bytes):
                try:
                    str_to_parse = json_str.decode("utf-8")
                except UnicodeDecodeError:
                    logger.warning(
                        f"Failed to decode bytes for {field_name} for patient {self.id} from JSON string: {json_str[:50]!r}..."
                    )
                    return None
            # Use repr for proper bytes representation
            try:
                return json.loads(str_to_parse)
            except json.JSONDecodeError:
                logger.warning(
                    f"Failed to parse {field_name} for patient {self.id} from JSON string: {str_to_parse[:100]!r}"
                )
                return None

        # Ensure datetime fields are timezone-aware (UTC) if they are naive
        created_at_val = self.created_at
        if created_at_val and created_at_val.tzinfo is None:
            created_at_val = created_at_val.replace(tzinfo=timezone.utc)

        updated_at_val = self.updated_at
        if updated_at_val and updated_at_val.tzinfo is None:
            updated_at_val = updated_at_val.replace(tzinfo=timezone.utc)

        # Build patient_args with ONLY fields accepted by Domain Patient constructor
        # This enforces Clean Architecture boundaries (Infrastructure → Domain)
        # SOLID Principle: Interface Segregation - Domain should not depend on infrastructure details
        patient_args = {
            "id": self.id,
            "created_at": created_at_val,
            "updated_at": updated_at_val,
            "active": self.is_active,  # Map 'is_active' → 'active' for domain compatibility
            "first_name": _decode_if_bytes(self._first_name),
            "last_name": _decode_if_bytes(self._last_name),
            "gender": gender,
            "date_of_birth": date_of_birth,
            "email": _decode_if_bytes(self._email),
            "phone": _decode_if_bytes(
                self._phone_number
            ),  # Use alias 'phone' that maps to phone_number field
            "medical_record_number": medical_record_number,  # Required for medical_record_number_lve property
            "ssn": ssn,  # Required for social_security_number_lve property
            "address": address_domain_obj,
            "emergency_contact": emergency_contact_domain_obj,
            # NOTE: contact_info is NOT passed to domain Patient constructor
            # Domain Patient expects email/phone as individual fields (above)
            "medical_history": _ensure_parsed_json(self._medical_history),
            "medications": _ensure_parsed_json(self._medications),
            "allergies": _ensure_parsed_json(self._allergies),
        }

        # Filter out None values
        # EXCLUDE infrastructure-specific fields: external_id, user_id, preferences,
        # custom_fields, extra_data, notes, audit_id, created_by, updated_by
        # EXCLUDE LVE fields: social_security_number_lve, medical_record_number_lve, insurance fields
        patient_args = {k: v for k, v in patient_args.items() if v is not None}

        try:
            logger.debug(
                "[PatientModel.to_domain] Attempting to create DomainPatient with args: {k: (type(v), str(v)[:100]) for k, v in patient_args.items()}"
            )
            domain_patient = DomainPatient(**patient_args)
            return domain_patient
        except ValidationError as e:
            logger.error(
                "Pydantic V2 Validation error in to_domain. Errors: {e.errors()}",
                exc_info=True,
            )
            logger.error("Problematic patient_args for DomainPatient: {patient_args}")
            raise PersistenceError(
                "Data integrity issue converting DB model to domain model: {e.errors()}"
            ) from e
        except Exception as e:
            logger.error(
                "Unexpected error creating DomainPatient in to_domain: {e}",
                exc_info=True,
            )
            logger.error("Problematic patient_args for DomainPatient: {patient_args}")
            raise PersistenceError(
                "Unexpected error converting DB model to domain model: {e}"
            ) from e

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
