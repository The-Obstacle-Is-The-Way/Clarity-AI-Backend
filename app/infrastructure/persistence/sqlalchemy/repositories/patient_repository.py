"""
SQLAlchemy implementation of Patient repository for the Novamind Digital Twin platform.

This module provides a concrete implementation of the patient repository
interface using SQLAlchemy for database operations.
"""
import dataclasses
import inspect
import json
import traceback
import uuid
from dataclasses import fields
from datetime import date, datetime, timezone
from typing import Any
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import PersistenceError  # ADD THIS IMPORT

# Import the custom logger function
from app.core.utils.logging import get_logger
from app.infrastructure.security.audit.audit import AuditLogger
from app.domain.entities.patient import Patient as PatientEntity
from app.domain.value_objects.address import Address

# The ContactInfoDescriptor in the Patient domain entity now properly handles
# both class-level access (PatientEntity.contact_info) and instance-level access (patient.contact_info)
# with a clean architectural pattern
from app.infrastructure.persistence.sqlalchemy.models.patient import (
    Patient as PatientModel,  # Alias model
)

# Use the custom logger
logger = get_logger(__name__)

class PatientRepositoryFactory:
    def __call__(self, db_session=None, db_session_factory=None, **kwargs):
        """Factory method to create PatientRepository instances.
        
        Supports both direct db_session and db_session_factory approaches.
        
        Args:
            db_session: An async SQLAlchemy session.
            db_session_factory: A factory function that returns db_session instances.
            **kwargs: Additional arguments to pass to the repository.
            
        Returns:
            PatientRepository: A configured repository instance.
        """
        if db_session:
            return PatientRepository(db_session=db_session, **kwargs)
        elif db_session_factory:
            return PatientRepository(db_session_factory=db_session_factory, **kwargs)
        else:
            raise ValueError("Either db_session or db_session_factory must be provided")


class PatientRepository:
    """
    SQLAlchemy implementation of the patient repository interface.
    
    This class is responsible for translating between domain entities
    and database models, and for performing database operations.
    """

    def __init__(self, 
                 db_session: AsyncSession | None = None, 
                 db_session_factory = None, 
                 uow_session: AsyncSession | None = None,
                 user_context: dict[str, Any] | None = None, 
                 **_):
        """
        Initialize the repository with a database session, a session factory, or a UoW-managed session.
        
        Args:
            db_session: An async SQLAlchemy session (for standalone use).
            db_session_factory: A callable that returns an AsyncSession (for standalone use).
            uow_session: An async SQLAlchemy session provided by a Unit of Work.
            user_context: Dictionary holding user context (e.g., user_id).
        """
        self.db_session = db_session
        self.db_session_factory = db_session_factory
        self.uow_session = uow_session
        
        # Ensure at least one session providing mechanism is available
        if not self.db_session and not self.db_session_factory and not self.uow_session:
            raise ValueError("Either db_session, db_session_factory, or uow_session must be provided")
            
        self.user_context = user_context or {}
        self.logger = logger

    async def _with_session(self, operation):
        """Execute an operation with session management, prioritizing UoW session."""
        if self.uow_session is not None:
            # UoW manages the session lifecycle (commit/rollback)
            return await operation(self.uow_session)
        elif self.db_session is not None:
            # Standalone session, assume lifecycle managed externally or simple ops
            # This path might need review if used for complex transactions standalone.
            # For UoW, this branch should ideally not be hit if uow_session is always provided.
            return await operation(self.db_session)
        elif self.db_session_factory is not None:
            # Create a new session from the factory and manage its lifecycle for this operation
            session = self.db_session_factory()
            try:
                # For standalone factory use, we must commit/rollback here.
                result = await operation(session)
                await session.commit() # Commit on success
                return result
            except Exception:
                await session.rollback() # Rollback on error
                raise
            finally:
                await session.close()
        else:
            self.logger.error("No database session, factory, or UoW session available for PatientRepository.")
            raise RuntimeError("No database session or factory available") # Changed from RepositoryException for clarity

    async def create(self, patient_entity: PatientEntity, context: dict | None = None) -> PatientEntity | None:
        """Creates a new patient record in the database from a PatientEntity."""
        self.logger.debug(f"Attempting to create patient with entity ID: {patient_entity.id} with context: {context}")

        async def _create_operation(session: AsyncSession) -> PatientEntity | None: 
            try:
                # Convert domain entity to SQLAlchemy model instance
                # This now relies on TypeDecorators in PatientModel for encryption
                patient_model = await PatientModel.from_domain(patient_entity) # REMOVED encryption_service
                
                # DEBUG PRINTS START
                print(f"[DEBUG PatientRepository.create] PatientModel instance before session.add:")
                print(f"  _contact_info TYPE: {type(patient_model._contact_info)}")
                print(f"  _contact_info VALUE: {patient_model._contact_info}")
                print(f"  _address_details TYPE: {type(patient_model._address_details)}")
                print(f"  _address_details VALUE: {patient_model._address_details}")
                print(f"  _emergency_contact_details TYPE: {type(patient_model._emergency_contact_details)}")
                print(f"  _emergency_contact_details VALUE: {patient_model._emergency_contact_details}")
                # DEBUG PRINTS END

                session.add(patient_model)
                await session.flush()  # Flush to get ID and process defaults/triggers
                await session.refresh(patient_model) # Refresh to get any DB-generated values

                self.logger.info(f"Successfully created patient with DB ID: {patient_model.id}")
                
                # Convert back to domain entity using the model's to_domain method
                # This now relies on TypeDecorators in PatientModel for decryption
                created_entity = await patient_model.to_domain() # REMOVED encryption_service
                return created_entity
            except ValidationError as e: # This is pydantic.ValidationError (should be PydanticV2ValidationError)
                await session.rollback()
                # self.logger.error(f"Pydantic V2 Validation Error during patient creation: {e.errors()}", exc_info=True)
                # Re-raise as PersistenceError, including Pydantic V2 error details for clarity
                # The detail here will be a list of dicts from e.errors()
                raise PersistenceError(f"Pydantic V2 Validation Error: {e.errors()}", original_exception=e)
            except IntegrityError as e:
                await session.rollback()
                self.logger.error(f"Integrity error creating patient: {e}", exc_info=True)
                # Consider specific error messages based on e.details or e.orig
                raise PersistenceError(f"Patient already exists or data integrity violation: {e}") from e
            except SQLAlchemyError as e:
                await session.rollback()
                self.logger.error(f"Database error creating patient: {e}", exc_info=True)
                raise PersistenceError("A database error occurred while creating the patient.") from e
            except Exception as e:
                await session.rollback()
                self.logger.error(f"Unexpected error creating patient: {e}", exc_info=True)
                raise PersistenceError("An unexpected error occurred while creating the patient.") from e

        return await self._with_session(_create_operation)

    async def get_by_id(self, patient_id: str | UUID, context: dict | None = None) -> PatientEntity | None:
        """Retrieves a patient by their ID."""
        self.logger.debug(f"Attempting to retrieve patient with ID: {patient_id}")
        async def _get_by_id_operation(session):
            # Ensure patient_id is a UUID object if it was passed as a string
            if isinstance(patient_id, str):
                try:
                    patient_uuid = UUID(patient_id)
                except ValueError:
                    self.logger.warning(f"Invalid UUID string provided: {patient_id}")
                    return None
            else:
                patient_uuid = patient_id

            stmt = select(PatientModel).where(PatientModel.id == patient_uuid)
            result = await session.execute(stmt)
            patient_model = result.scalars().one_or_none()

            if patient_model:
                self.logger.debug(f"Patient model found for ID {patient_uuid}. Converting to domain entity.")
                # Convert model to domain entity using the model's to_domain method
                # This now relies on TypeDecorators in PatientModel for decryption
                patient_entity = await patient_model.to_domain() # REMOVED encryption_service
                return patient_entity
            else:
                self.logger.debug(f"No patient model found for ID {patient_uuid}.")
                return None
        
        return await self._with_session(_get_by_id_operation)

    async def get_all(self, limit: int = 50, offset: int = 0, context: dict | None = None) -> list[PatientEntity]:
        """Retrieves all patients with pagination."""
        self.logger.debug(f"Attempting to retrieve all patients with limit={limit}, offset={offset}")
        async def _get_all_operation(session):
            stmt = select(PatientModel).limit(limit).offset(offset)
            result = await session.execute(stmt)
            patient_models = result.scalars().all()
            
            patient_entities = []
            for model in patient_models:
                # Convert model to domain entity using the model's to_domain method
                entity = await model.to_domain() # REMOVED encryption_service
                patient_entities.append(entity)
            
            self.logger.debug(f"Retrieved {len(patient_entities)} patient entities.")
            return patient_entities

        return await self._with_session(_get_all_operation)

    async def update(self, patient_id: uuid.UUID, patient_entity: PatientEntity, context: dict | None = None) -> PatientEntity | None:
        """Updates an existing patient record from a PatientEntity."""
        self.logger.debug(f"Attempting to update patient with ID: {patient_id} using entity ID: {patient_entity.id} with context: {context}")

        # Prepare data for DB update, mapping domain fields to model fields
        # This is a simplified example; a more robust solution might involve a dedicated mapper.
        update_data_for_model = {}
        domain_dict = patient_entity.model_dump(exclude_unset=True, exclude_none=True)

        field_map = {
            "first_name": "_first_name",
            "last_name": "_last_name",
            "middle_name": "_middle_name",
            "email": "_email",
            "phone_number": "_phone_number",
            "date_of_birth": "_date_of_birth", # Ensure this is handled as string for EncryptedString
            "gender": "_gender", # Ensure this is stored as per model's expectation (e.g., enum value)
            "medical_record_number_lve": "_mrn",
            "social_security_number_lve": "_ssn",
            "insurance_provider_lve": "_insurance_provider",
            "insurance_policy_number_lve": "_insurance_policy_number",
            "insurance_group_number_lve": "_insurance_group_number",
            "address_line1_lve": "_address_line1",
            "address_line2_lve": "_address_line2",
            "city_lve": "_city",
            "state_lve": "_state",
            "zip_code_lve": "_zip_code",
            "country_lve": "_country",
            "emergency_contact_name_lve": "_emergency_contact_name",
            "emergency_contact_phone_lve": "_emergency_contact_phone",
            "emergency_contact_relationship_lve": "_emergency_contact_relationship",
            # Direct attributes (not LVE or specially mapped)
            "is_active": "is_active", # This is directly on PatientModel
            # Potentially other fields like preferences, notes, etc.
        }

        for domain_key, model_key in field_map.items():
            if domain_key in domain_dict:
                value = domain_dict[domain_key]
                # Special handling for date/enum if necessary before encryption or storage
                if domain_key == "date_of_birth" and isinstance(value, date):
                    value = value.isoformat() # Convert date to string
                elif domain_key == "gender" and hasattr(value, 'value'):
                    value = value.value # Get enum value if it's an enum object
                update_data_for_model[model_key] = value
        
        # Include any fields that are not in the map but directly match model attributes
        for key, value in domain_dict.items():
            if key not in field_map and not key.endswith('_lve'): # Avoid re-adding LVEs or mapped fields
                 if not hasattr(PatientModel, key) and hasattr(PatientModel, f"_{key}"): # check if it's a private version
                     if f"_{key}" not in update_data_for_model: # and not already mapped
                         update_data_for_model[f"_{key}"] = value
                 elif hasattr(PatientModel, key): # direct match
                     if key not in update_data_for_model: # and not already mapped
                         update_data_for_model[key] = value

        if not update_data_for_model:
            self.logger.warning(f"No updatable fields found for patient ID: {patient_id} from entity: {patient_entity}")
            # Optionally, could return the patient as is, or raise an error/return None
            # For now, let's try to retrieve and return the existing patient if no updates are made.
            async with self._with_session(lambda session: session.get(PatientModel, patient_id)) as db_patient:
                return await db_patient.to_domain() if db_patient else None

        async def _update_operation(session: AsyncSession) -> PatientEntity | None:
            self.logger.debug(f"Executing update for patient ID: {patient_id} with model data: {update_data_for_model}")
            stmt = select(PatientModel).where(PatientModel.id == patient_id)
            result = await session.execute(stmt)
            db_patient = result.scalar_one_or_none()

            if db_patient:
                updated_fields_for_log = []
                for key, value in update_data_for_model.items(): # Use the mapped data
                    if hasattr(db_patient, key):
                        setattr(db_patient, key, value)
                        updated_fields_for_log.append(key)
                    else:
                        self.logger.warning(f"Attribute {key} not found on PatientModel during update for patient ID: {patient_id}")
                
                if not updated_fields_for_log:
                    self.logger.info(f"No fields were actually updated for patient ID: {patient_id} based on provided data.")
                    # No actual DB changes, so no commit needed, just return current state
                    return await db_patient.to_domain()

                db_patient.updated_at = datetime.now(timezone.utc) # Ensure updated_at is set
                # self.logger.info(f"Patient with ID: {db_patient.id} updated. Changed fields: {updated_fields_for_log}. Context: {context}")
                # Log a more generic success message, actual fields can be in audit log if needed
                self.logger.info(f"Successfully updated patient data for DB ID: {db_patient.id}. Context: {context}")
                
                try:
                    await session.commit()
                    await session.refresh(db_patient) # Refresh to get any DB-generated changes
                    # self.logger.debug(f"Successfully committed update for patient ID: {db_patient.id}")
                    return await db_patient.to_domain()
                except IntegrityError as e:
                    await session.rollback()
                    self.logger.error(f"IntegrityError during update for patient ID: {patient_id}. Error: {e}")
                    raise PersistenceError(f"Data integrity issue updating patient: {e}") from e
                except Exception as e:
                    await session.rollback()
                    self.logger.error(f"Unexpected error during update for patient ID: {patient_id}. Error: {e}")
                    raise PersistenceError(f"Unexpected issue updating patient: {e}") from e
            else:
                self.logger.warning(f"Patient with ID: {patient_id} not found for update.")
                return None

        return await self._with_session(_update_operation)

    async def delete(self, patient_id: str | UUID, context: dict | None = None) -> bool:
        """Deletes a patient by their ID.
        
        Args:
            patient_id: The ID of the patient to delete (can be str or UUID).
            context: Optional context dictionary.

        Returns:
            bool: True if deletion was successful, False otherwise.
        """
        self.logger.debug(f"Attempting to delete patient with ID: {patient_id}")
        
        # Ensure patient_id is a UUID object if it was passed as a string
        if isinstance(patient_id, str):
            try:
                patient_uuid = UUID(patient_id)
            except ValueError:
                self.logger.warning(f"Invalid UUID string provided for deletion: {patient_id}")
                return False # Or raise an error, depending on desired behavior for invalid ID format
        elif isinstance(patient_id, UUID):
            patient_uuid = patient_id
        else:
            self.logger.error(f"Invalid patient_id type for deletion: {type(patient_id)}")
            return False # Or raise TypeError

        async def _delete_operation(session: AsyncSession) -> bool:
            try:
                stmt = select(PatientModel).where(PatientModel.id == patient_uuid)
                result = await session.execute(stmt)
                patient_model = result.scalars().one_or_none()
                
                if patient_model:
                    await session.delete(patient_model)
                    await session.flush()
                    logger.info(f"Successfully deleted patient with ID {patient_id}")
                    return True
                else:
                    logger.warning(f"Patient with ID {patient_id} not found for deletion.")
                    return False
            except IntegrityError as e:
                logger.error(f"Database integrity error deleting patient ID {patient_id}: {e}", exc_info=True)
                return False
            except SQLAlchemyError as e:
                logger.error(f"Database error deleting patient ID {patient_id}: {e}", exc_info=True)
                return False
            except Exception as e:
                logger.error(f"Unexpected error deleting patient ID {patient_id}: {e}", exc_info=True)
                return False
        
        return await self._with_session(_delete_operation)

    async def get_by_email(self, email: str) -> PatientEntity | None:
        """Retrieve a patient by their email address."""
        self.logger.debug(f"Attempting to retrieve patient by email: {email}")

        async def _get_by_email_operation(session: AsyncSession) -> PatientEntity | None:
            try:
                # Assuming email is stored in a JSONB field, adjust query as needed.
                # This query is an example and might need to match your exact model structure.
                # If email is a top-level encrypted field, the query would be different.
                # For TypeDecorator on a simple PatientModel._email:
                # stmt = select(PatientModel).where(PatientModel._email == email)
                # For JSONB 'contact_info' -> 'email':
                stmt = select(PatientModel).where(PatientModel._email == email)
                
                result = await session.execute(stmt)
                patient_model = result.scalars().one_or_none()

                if patient_model:
                    self.logger.debug(f"Patient model found for email {email}. Converting to domain entity.")
                    # Convert model to domain entity using the model's to_domain method
                    patient_entity = await patient_model.to_domain() # REMOVED encryption_service
                    return patient_entity
                else:
                    self.logger.debug(f"No patient model found for email {email}.")
                    return None
            except SQLAlchemyError as e:
                self.logger.error(f"Database error retrieving patient by email {email}: {e}", exc_info=True)
                # Consider raising PersistenceError or returning None based on desired contract
                raise PersistenceError(f"Database error retrieving patient by email {email}.") from e
            except Exception as e: # Catch broader exceptions after specific ones
                self.logger.error(f"Unexpected error retrieving patient by email {email}: {e}", exc_info=True)
                raise PersistenceError(f"Unexpected error retrieving patient by email {email}.") from e
        
        return await self._with_session(_get_by_email_operation)


class PatientRepositoryFactory:
    # TODO: Implement factory logic if needed, or remove if unused.
    pass # Add pass to make the class definition valid

# Export alias to maintain backward compatibility with names used in UnitOfWorkFactory
PatientRepositoryImpl = PatientRepository
