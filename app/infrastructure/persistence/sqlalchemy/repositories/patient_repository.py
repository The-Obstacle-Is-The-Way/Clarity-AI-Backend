"""
SQLAlchemy implementation of Patient repository for the Novamind Digital Twin platform.

This module provides a concrete implementation of the patient repository
interface using SQLAlchemy for database operations.
"""
import dataclasses
import json
import uuid
from datetime import date, datetime, timezone
from typing import Any, Optional, Dict
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import PersistenceError
from app.core.utils.logging import get_logger
from app.domain.entities.patient import Patient as PatientEntity
from app.domain.repositories.patient_repository import PatientRepository
from app.infrastructure.persistence.sqlalchemy.models.patient import (
    Patient as PatientModel,
)

# Use the custom logger
logger = get_logger(__name__)


def model_json_dumps(obj: Any) -> str | None:
    """
    Convert a model object to a JSON string safely.

    Args:
        obj: Model object to convert

    Returns:
        JSON string, or None if obj is None
    """
    if obj is None:
        return None

    # Handle unittest.mock.MagicMock objects
    if hasattr(obj, "__class__") and obj.__class__.__name__ == "MagicMock":
        return json.dumps({"__mock__": str(obj)})

    # Handle Pydantic models (v2)
    if hasattr(obj, "model_dump"):
        return json.dumps(obj.model_dump())

    # Handle Pydantic models (v1)
    if hasattr(obj, "dict"):
        return json.dumps(obj.dict())

    # Handle dataclasses
    if dataclasses.is_dataclass(obj):
        return json.dumps(dataclasses.asdict(obj))

    # Handle objects with to_dict method
    if hasattr(obj, "to_dict") and callable(obj.to_dict):
        return json.dumps(obj.to_dict())

    # Handle dictionaries directly
    if isinstance(obj, dict):
        return json.dumps(obj)

    # Handle lists and other JSON-serializable types
    try:
        return json.dumps(obj)
    except (TypeError, ValueError):
        # Last resort - use default=str for non-serializable objects
        try:
            return json.dumps(obj, default=str)
        except:
            # Absolute last resort
            return json.dumps({"__str__": str(obj)})


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


class PatientRepositoryImpl(PatientRepository):
    """
    SQLAlchemy implementation of the patient repository interface.

    This class is responsible for translating between domain entities
    and database models, and for performing database operations.
    """

    def __init__(
        self,
        db_session: Optional[AsyncSession] = None,
        db_session_factory=None,
        uow_session: Optional[AsyncSession] = None,
        user_context: Optional[dict[str, Any]] = None,
        **_,
    ):
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
            raise ValueError(
                "Either db_session, db_session_factory, or uow_session must be provided"
            )

        self.user_context = user_context or {}
        self.logger = logger

    async def _with_session(self, operation):
        """Execute an operation with session management, prioritizing UoW session."""
        if self.uow_session is not None:
            # UoW manages the session lifecycle (commit/rollback)
            return await operation(self.uow_session)
        elif self.db_session is not None:
            # Standalone session, assume lifecycle managed externally or simple ops
            return await operation(self.db_session)
        elif self.db_session_factory is not None:
            # Create a new session from the factory and manage its lifecycle for this operation
            session = self.db_session_factory()
            try:
                result = await operation(session)
                await session.commit()  # Commit on success
                return result
            except Exception:
                await session.rollback()  # Rollback on error
                raise
            finally:
                await session.close()
        else:
            self.logger.error(
                "No database session, factory, or UoW session available for PatientRepository."
            )
            raise RuntimeError("No database session or factory available")

    async def create(
        self, 
        patient: PatientEntity, 
        context: Optional[dict[str, Any]] = None
    ) -> PatientEntity:
        """Creates a new patient record in the database from a PatientEntity."""
        self.logger.debug(f"Attempting to create patient with entity ID: {patient.id}")
        
        # Log HIPAA audit if context provided
        if context:
            user_id = context.get('user_id')
            action = context.get('action', 'create_patient')
            self.logger.info(f"HIPAA Audit: User {user_id} performing {action} on patient {patient.id}")

        async def _create_operation(session: AsyncSession) -> PatientEntity:
            try:
                # Convert domain entity to SQLAlchemy model instance
                patient_model = await PatientModel.from_domain(patient)

                # Process all complex fields that may need serialization
                complex_fields = [
                    "_contact_info",
                    "_address_details",
                    "_emergency_contact_details",
                    "_preferences",
                    "_custom_fields",
                    "_extra_data",
                    "_medical_history",
                    "_medications",
                    "_allergies",
                ]

                for field_name in complex_fields:
                    if hasattr(patient_model, field_name):
                        value = getattr(patient_model, field_name)
                        if value is not None and not isinstance(value, str):
                            try:
                                # Serialize the field - convert to JSON string
                                serialized = model_json_dumps(value)
                                setattr(patient_model, field_name, serialized)

                                self.logger.debug(
                                    f"Serialized {field_name} of type {type(value).__name__} to JSON string"
                                )
                            except Exception as e:
                                self.logger.error(
                                    f"Error serializing {field_name} of type {type(value).__name__}: {e}"
                                )
                                # Set to empty JSON object as fallback
                                setattr(patient_model, field_name, "{}")

                session.add(patient_model)
                await session.flush()  # Flush to get ID and process defaults/triggers
                await session.refresh(patient_model)  # Refresh to get any DB-generated values

                self.logger.info(f"Successfully created patient with DB ID: {patient_model.id}")

                # Convert back to domain entity using the model's to_domain method
                created_entity = await patient_model.to_domain()
                return created_entity
            except ValidationError as e:
                await session.rollback()
                raise PersistenceError(
                    f"Validation Error: {e.errors()}", original_exception=e
                )
            except IntegrityError as e:
                await session.rollback()
                self.logger.error(f"Integrity error creating patient: {e}", exc_info=True)
                raise PersistenceError(
                    f"Patient already exists or data integrity violation: {e}"
                ) from e
            except SQLAlchemyError as e:
                await session.rollback()
                self.logger.error(f"Database error creating patient: {e}", exc_info=True)
                raise PersistenceError(
                    "A database error occurred while creating the patient."
                ) from e
            except Exception as e:
                await session.rollback()
                self.logger.error(f"Unexpected error creating patient: {e}", exc_info=True)
                raise PersistenceError(
                    "An unexpected error occurred while creating the patient."
                ) from e

        return await self._with_session(_create_operation)

    async def get_by_id(
        self, 
        patient_id: UUID, 
        context: Optional[dict[str, Any]] = None
    ) -> Optional[PatientEntity]:
        """Retrieves a patient by their ID."""
        self.logger.debug(f"Attempting to retrieve patient with ID: {patient_id}")
        
        # Log HIPAA audit if context provided
        if context:
            user_id = context.get('user_id')
            action = context.get('action', 'get_patient_by_id')
            self.logger.info(f"HIPAA Audit: User {user_id} performing {action} on patient {patient_id}")

        async def _get_by_id_operation(session):
            stmt = select(PatientModel).where(PatientModel.id == patient_id)
            result = await session.execute(stmt)
            patient_model = result.scalars().one_or_none()

            if patient_model:
                self.logger.debug(
                    f"Patient model found for ID {patient_id}. Converting to domain entity."
                )
                # Convert model to domain entity using the model's to_domain method
                patient_entity = await patient_model.to_domain()
                return patient_entity
            else:
                self.logger.debug(f"No patient model found for ID {patient_id}.")
                return None

        return await self._with_session(_get_by_id_operation)

    async def update(
        self, 
        patient: PatientEntity, 
        context: Optional[dict[str, Any]] = None
    ) -> Optional[PatientEntity]:
        """Updates an existing patient record from a PatientEntity."""
        patient_id = patient.id
        
        if patient_id is None:
            self.logger.error("Cannot update patient without ID")
            return None

        self.logger.debug(f"Attempting to update patient with ID: {patient_id}")
        
        # Log HIPAA audit if context provided
        if context:
            user_id = context.get('user_id')
            action = context.get('action', 'update_patient')
            self.logger.info(f"HIPAA Audit: User {user_id} performing {action} on patient {patient_id}")

        async def _update_operation(session: AsyncSession) -> Optional[PatientEntity]:
            stmt = select(PatientModel).where(PatientModel.id == patient_id)
            result = await session.execute(stmt)
            db_patient = result.scalar_one_or_none()

            if db_patient:
                try:
                    # Extract data from patient entity
                    domain_dict = {}
                    if hasattr(patient, "model_dump"):
                        domain_dict = patient.model_dump(exclude_none=True)
                    elif hasattr(patient, "__dict__"):
                        domain_dict = {
                            k: v
                            for k, v in patient.__dict__.items()
                            if not k.startswith("_") and v is not None
                        }

                    # Map domain fields to model fields
                    field_map = {
                        "first_name": "_first_name",
                        "last_name": "_last_name", 
                        "email": "_email",
                        "phone": "_phone_number",
                        "date_of_birth": "_date_of_birth",
                        "gender": "_gender",
                    }

                    updated_fields = []
                    for domain_key, model_key in field_map.items():
                        if domain_key in domain_dict:
                            value = domain_dict[domain_key]
                            if hasattr(db_patient, model_key):
                                setattr(db_patient, model_key, value)
                                updated_fields.append(model_key)

                    if updated_fields:
                        db_patient.updated_at = datetime.now(timezone.utc)
                        await session.commit()
                        await session.refresh(db_patient)
                        
                        self.logger.info(f"Successfully updated patient with ID: {patient_id}")
                        return await db_patient.to_domain()
                    else:
                        self.logger.info(f"No fields updated for patient ID: {patient_id}")
                        return await db_patient.to_domain()

                except Exception as e:
                    await session.rollback()
                    self.logger.error(f"Error updating patient {patient_id}: {e}")
                    raise PersistenceError(f"Error updating patient: {e}") from e
            else:
                self.logger.warning(f"Patient with ID: {patient_id} not found for update.")
                return None

        return await self._with_session(_update_operation)

    async def delete(
        self, 
        patient_id: UUID, 
        context: Optional[dict[str, Any]] = None
    ) -> bool:
        """Deletes a patient by their ID."""
        self.logger.debug(f"Attempting to delete patient with ID: {patient_id}")
        
        # Log HIPAA audit if context provided
        if context:
            user_id = context.get('user_id')
            action = context.get('action', 'delete_patient')
            self.logger.info(f"HIPAA Audit: User {user_id} performing {action} on patient {patient_id}")

        async def _delete_operation(session: AsyncSession) -> bool:
            try:
                patient_model = await session.get(PatientModel, patient_id)

                if patient_model:
                    await session.delete(patient_model)
                    await session.flush()
                    self.logger.info(f"Successfully deleted patient with ID {patient_id}")
                    return True
                else:
                    self.logger.warning(f"Patient with ID {patient_id} not found for deletion")
                    return False

            except Exception as e:
                self.logger.error(f"Error during deletion of patient ID {patient_id}: {e}")
                raise PersistenceError(f"Error deleting patient: {e}") from e

        return await self._with_session(_delete_operation)

    async def list_all(
        self, 
        limit: int = 100, 
        offset: int = 0,
        context: Optional[dict[str, Any]] = None
    ) -> list[PatientEntity]:
        """Retrieves all patients with pagination."""
        self.logger.debug(f"Attempting to retrieve all patients with limit={limit}, offset={offset}")
        
        # Log HIPAA audit if context provided
        if context:
            user_id = context.get('user_id')
            action = context.get('action', 'list_all_patients')
            self.logger.info(f"HIPAA Audit: User {user_id} performing {action} (limit={limit}, offset={offset})")

        async def _list_all_operation(session):
            stmt = select(PatientModel).limit(limit).offset(offset)
            result = await session.execute(stmt)
            patient_models = result.scalars().all()

            patient_entities = []
            for model in patient_models:
                entity = await model.to_domain()
                patient_entities.append(entity)

            self.logger.debug(f"Retrieved {len(patient_entities)} patient entities.")
            return patient_entities

        return await self._with_session(_list_all_operation)

    async def count(
        self,
        context: Optional[dict[str, Any]] = None,
        **filters
    ) -> int:
        """Count patients matching the given filters."""
        self.logger.debug(f"Attempting to count patients with filters: {filters}")
        
        # Log HIPAA audit if context provided
        if context:
            user_id = context.get('user_id')
            action = context.get('action', 'count_patients')
            self.logger.info(f"HIPAA Audit: User {user_id} performing {action} with filters {filters}")

        async def _count_operation(session: AsyncSession) -> int:
            try:
                stmt = select(PatientModel)
                
                # Apply filters if provided
                for key, value in filters.items():
                    if hasattr(PatientModel, f"_{key}"):
                        stmt = stmt.where(getattr(PatientModel, f"_{key}") == value)
                    elif hasattr(PatientModel, key):
                        stmt = stmt.where(getattr(PatientModel, key) == value)
                
                # Convert to count query
                from sqlalchemy import func
                count_stmt = select(func.count()).select_from(stmt.subquery())
                result = await session.execute(count_stmt)
                count = result.scalar() or 0
                
                self.logger.debug(f"Patient count with filters {filters}: {count}")
                return count
                
            except SQLAlchemyError as e:
                self.logger.error(f"Database error counting patients with filters {filters}: {e}", exc_info=True)
                raise PersistenceError(f"Database error counting patients.") from e
            except Exception as e:
                self.logger.error(f"Unexpected error counting patients with filters {filters}: {e}", exc_info=True)
                raise PersistenceError(f"Unexpected error counting patients.") from e

        return await self._with_session(_count_operation)

    async def get_by_email(
        self, 
        email: str,
        context: Optional[dict[str, Any]] = None
    ) -> Optional[PatientEntity]:
        """Retrieve a patient by their email address."""
        self.logger.debug(f"Attempting to retrieve patient by email: {email}")
        
        # Log HIPAA audit if context provided
        if context:
            user_id = context.get('user_id')
            action = context.get('action', 'get_patient_by_email')
            self.logger.info(f"HIPAA Audit: User {user_id} performing {action} on email {email}")

        async def _get_by_email_operation(session: AsyncSession) -> Optional[PatientEntity]:
            try:
                stmt = select(PatientModel).where(PatientModel._email == email)
                result = await session.execute(stmt)
                patient_model = result.scalars().one_or_none()

                if patient_model:
                    self.logger.debug(f"Patient model found for email {email}. Converting to domain entity.")
                    patient_entity = await patient_model.to_domain()
                    return patient_entity
                else:
                    self.logger.debug(f"No patient model found for email {email}.")
                    return None
            except SQLAlchemyError as e:
                self.logger.error(f"Database error retrieving patient by email {email}: {e}", exc_info=True)
                raise PersistenceError(f"Database error retrieving patient by email {email}.") from e
            except Exception as e:
                self.logger.error(f"Unexpected error retrieving patient by email {email}: {e}", exc_info=True)
                raise PersistenceError(f"Unexpected error retrieving patient by email {email}.") from e

        return await self._with_session(_get_by_email_operation)


# Remove the old class and export the new one
# class PatientRepository:  # REMOVE OLD CLASS


# Maintain backward compatibility
PatientRepository = PatientRepositoryImpl
