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

    def __init__(self, db_session: AsyncSession | None = None, db_session_factory = None, user_context: dict[str, Any] | None = None, **_):
        """
        Initialize the repository with a database session or a session factory.
        
        Args:
            db_session: An async SQLAlchemy session.
            db_session_factory: A callable that returns an AsyncSession.
            user_context: Dictionary holding user context (e.g., user_id).
        """
        self.db_session = db_session
        self.db_session_factory = db_session_factory
        if not db_session and not db_session_factory:
            raise ValueError("Either db_session or db_session_factory must be provided")
        self.user_context = user_context or {}
        self.logger = logger

    async def _get_session(self):
        """Get a database session using either the provided session or the factory.
        
        Returns:
            AsyncSession: An async SQLAlchemy session.
            bool: Whether the session was created from factory (should be released).
        """
        if self.db_session is not None:
            return self.db_session, False
        elif self.db_session_factory is not None:
            return self.db_session_factory(), True
        else:
            raise RuntimeError("No database session or factory available")
            
    async def _with_session(self, operation):
        """Execute an operation with session management.
        
        Args:
            operation: Async callable that takes a session and returns a result.
            
        Returns:
            The result of the operation.
        """
        if self.db_session is not None:
            # Use the existing session directly
            return await operation(self.db_session)
        elif self.db_session_factory is not None:
            # Create a new session from the factory and manage its lifecycle
            session = self.db_session_factory()
            try:
                return await operation(session)
            finally:
                await session.close()
        else:
            raise RuntimeError("No database session or factory available")

    async def create(self, patient_entity: PatientEntity) -> PatientEntity | None:
        """Creates a new patient record in the database from a PatientEntity."""
        self.logger.debug(f"Attempting to create patient with entity ID: {patient_entity.id}")

        async def _create_operation(session: AsyncSession) -> PatientEntity | None: # Ensure session type hint
            try:
                # Convert domain entity to SQLAlchemy model instance
                # This now relies on TypeDecorators in PatientModel for encryption
                patient_model = await PatientModel.from_domain(patient_entity) # REMOVED encryption_service
                
                # Add audit information if applicable (assuming AuditMixin or similar)
                # This part needs to align with how AuditMixin is implemented in PatientModel
                # For now, assuming 'created_by' and 'updated_by' are handled by the mixin or triggers
                # if self.user_context:
                #     user_id_str = str(self.user_context.get("user_id"))
                #     if hasattr(patient_model, "created_by"):
                #         patient_model.created_by = user_id_str
                #     if hasattr(patient_model, "updated_by"):
                #         patient_model.updated_by = user_id_str

                session.add(patient_model)
                await session.flush()  # Flush to get ID and process defaults/triggers
                await session.refresh(patient_model) # Refresh to get any DB-generated values

                self.logger.info(f"Successfully created patient with DB ID: {patient_model.id}")
                
                # Convert back to domain entity using the model's to_domain method
                # This now relies on TypeDecorators in PatientModel for decryption
                created_entity = await patient_model.to_domain() # REMOVED encryption_service
                return created_entity
            except IntegrityError as e:
                await session.rollback()
                self.logger.error(f"Integrity error creating patient: {e}", exc_info=True)
                # Consider specific error messages based on e.details or e.orig
                raise PersistenceError(f"Patient already exists or data integrity violation: {e}") from e
            except ValidationError as e:
                await session.rollback()
                self.logger.error(f"Validation error creating patient: {e}", exc_info=True)
                raise PersistenceError(f"Invalid patient data: {e}") from e
            except SQLAlchemyError as e:
                await session.rollback()
                self.logger.error(f"Database error creating patient: {e}", exc_info=True)
                raise PersistenceError("A database error occurred while creating the patient.") from e
            except Exception as e:
                await session.rollback()
                self.logger.error(f"Unexpected error creating patient: {e}", exc_info=True)
                raise PersistenceError("An unexpected error occurred while creating the patient.") from e

        return await self._with_session(_create_operation)

    async def get_by_id(self, patient_id: str | UUID) -> PatientEntity | None:
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

    async def get_all(self, limit: int = 50, offset: int = 0) -> list[PatientEntity]:
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

    async def update(self, patient_entity: PatientEntity) -> PatientEntity | None:
        """Updates an existing patient record in the database."""
        if not patient_entity.id:
            self.logger.error("Patient entity must have an ID to be updated.")
            raise PersistenceError("Patient entity must have an ID to be updated.")
        
        self.logger.debug(f"Attempting to update patient with entity ID: {patient_entity.id}")

        async def _update_operation(session):
            patient_id = patient_entity.id
            # Fetch the existing model
            stmt = select(PatientModel).where(PatientModel.id == patient_id)
            result = await session.execute(stmt)
            patient_model = result.scalars().one_or_none()

            if not patient_model:
                self.logger.warning(f"Patient with ID {patient_id} not found for update.")
                return None

            # Update fields from the domain entity. PatientModel.from_domain can't be directly used
            # as it creates a new instance. We need to update the existing one. 
            # However, the PII fields are handled by TypeDecorators upon assignment.
            
            # Get all fields from the domain entity
            domain_data = patient_entity.model_dump() # Temporarily remove exclude_unset to bypass TypeError
            logger.debug(f"Updating patient model ID {patient_model.id} with data: {domain_data}")

            updatable_fields = [
                key for key, value in domain_data.items() if hasattr(patient_model, key)
            ]

            for key in updatable_fields:
                if key == 'id': # Don't try to set PK
                    continue
                if hasattr(patient_model, key):
                    # Direct assignment will trigger TypeDecorator for encrypted fields
                    setattr(patient_model, key, domain_data[key])
                elif hasattr(patient_model, f'_{key}'): # Handle cases like _first_name mapped to first_name
                    setattr(patient_model, f'_{key}', domain_data[key])
                # Add specific handling for complex types if direct mapping isn't enough,
                # e.g., address, emergency_contact, if they need special reconstruction.
                # For now, assuming simple fields or fields handled by TypeDecorators.

            # Audit information (updated_at is often handled by TimestampMixin or DB)
            # if self.user_context:
            #     user_id_str = str(self.user_context.get("user_id"))
            #     if hasattr(patient_model, "updated_by"):
            #         patient_model.updated_by = user_id_str
            
            try:
                await session.flush()
                await session.refresh(patient_model)
                self.logger.info(f"Successfully updated patient with DB ID: {patient_model.id}")
                updated_domain_entity = await patient_model.to_domain() # REMOVED encryption_service
                return updated_domain_entity
            except IntegrityError as e:
                await session.rollback()
                self.logger.error(f"Integrity error updating patient {patient_id}: {e}", exc_info=True)
                raise PersistenceError(f"Data integrity violation during patient update: {e}") from e
            except SQLAlchemyError as e:
                await session.rollback()
                self.logger.error(f"Database error updating patient {patient_id}: {e}", exc_info=True)
                raise PersistenceError("A database error occurred while updating the patient.") from e
            except Exception as e:
                await session.rollback()
                self.logger.error(f"Unexpected error updating patient {patient_id}: {e}", exc_info=True)
                raise PersistenceError("An unexpected error occurred while updating the patient.") from e

        return await self._with_session(_update_operation)

    async def delete(self, patient_id: str) -> bool:
        """Deletes a patient by their ID."""
        try:
            # Convert to UUID object - sample_patient_id is already a valid UUID string
            uuid_obj = uuid.UUID(patient_id)
        except (ValueError, AttributeError, TypeError):
            logger.warning(f"Attempted delete with invalid UUID format: {patient_id}")
            return False
            
        async def _delete_operation(session):
            try:
                # Use session.get() to retrieve the patient model as expected by the test
                patient_model = await session.get(PatientModel, uuid_obj)
                
                # If the patient exists, delete it
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
                stmt = select(PatientModel).where(PatientModel.contact_info["email"].astext == email) # Keep original query logic
                
                result = await session.execute(stmt)
                patient_model = result.scalars().one_or_none() # Changed from .first() to .one_or_none() for consistency

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
