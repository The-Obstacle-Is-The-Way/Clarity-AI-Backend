# app/infrastructure/persistence/sqlalchemy/repositories/digital_twin_repository.py
# Placeholder for digital twin repository implementation

import json
import logging
from datetime import datetime
from typing import Any
from uuid import UUID

import sqlalchemy
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.domain.entities.digital_twin import (
    DigitalTwin,
    DigitalTwinConfiguration,
    DigitalTwinState,
)
from app.domain.repositories.digital_twin_repository import DigitalTwinRepository

# Import the SQLAlchemy model
from app.infrastructure.persistence.sqlalchemy.models.digital_twin import (
    DigitalTwinModel,
)

logger = logging.getLogger(__name__)


class DigitalTwinRepositoryImpl(DigitalTwinRepository):
    """Concrete SQLAlchemy implementation of the DigitalTwinRepository."""

    def __init__(self, session: AsyncSession):
        """Initialize the repository with an async session."""
        self.session = session

    def _to_model(self, entity: DigitalTwin) -> DigitalTwinModel:
        """Convert domain entity to SQLAlchemy model."""
        return DigitalTwinModel(
            id=str(entity.id),
            patient_id=str(entity.patient_id),
            created_at=entity.created_at,
            updated_at=entity.last_updated,  # Map domain's last_updated
            version=entity.version,
            configuration_json=self._serialize_config(entity.configuration),
            state_json=self._serialize_state(entity.state),
        )

    def _to_entity(self, model: DigitalTwinModel) -> DigitalTwin:
        """Convert SQLAlchemy model to domain entity."""
        return DigitalTwin(
            id=model.id if isinstance(model.id, UUID) else UUID(str(model.id)),
            patient_id=model.patient_id if isinstance(model.patient_id, UUID) else UUID(str(model.patient_id)),
            created_at=model.created_at,
            last_updated=model.updated_at,  # Map model's updated_at
            version=model.version,
            configuration=self._deserialize_config(model.configuration_json),
            state=self._deserialize_state(model.state_json),
        )

    def _serialize_config(self, config: DigitalTwinConfiguration) -> dict[str, Any]:
        """Serialize Configuration dataclass to JSON-compatible dict."""
        # Convert dataclass to dict
        return config.__dict__

    def _deserialize_config(self, config_json: dict | None) -> DigitalTwinConfiguration:
        """Deserialize JSON dict to Configuration dataclass."""
        if config_json is None:
            return DigitalTwinConfiguration()  # Return default if no data
        return DigitalTwinConfiguration(**config_json)

    def _serialize_state(self, state: DigitalTwinState) -> dict[str, Any]:
        """Serialize State dataclass to JSON-compatible dict."""
        # Convert dataclass to dict, handling datetime if necessary
        state_dict = state.__dict__.copy()
        if state_dict.get("last_sync_time"):
            state_dict["last_sync_time"] = state_dict["last_sync_time"].isoformat()
        # Handle potential non-serializable predicted_phq9_trajectory
        if state_dict.get("predicted_phq9_trajectory"):
            try:
                json.dumps(state_dict["predicted_phq9_trajectory"])
            except TypeError:
                logger.warning(
                    "predicted_phq9_trajectory contains non-serializable data, skipping."
                )
                state_dict["predicted_phq9_trajectory"] = None
        return state_dict

    def _deserialize_state(self, state_json: dict | None) -> DigitalTwinState:
        """Deserialize JSON dict to State dataclass."""
        if state_json is None:
            return DigitalTwinState()  # Return default if no data
        # Handle datetime deserialization
        if state_json.get("last_sync_time"):
            try:
                state_json["last_sync_time"] = datetime.fromisoformat(state_json["last_sync_time"])
            except (TypeError, ValueError):
                logger.warning("Could not parse last_sync_time from JSON, setting to None.")
                state_json["last_sync_time"] = None
        return DigitalTwinState(**state_json)

    async def add(self, digital_twin: DigitalTwin) -> DigitalTwin:
        """Add a new digital twin to the database."""
        model = self._to_model(digital_twin)
        self.session.add(model)
        try:
            await self.session.flush()
            await self.session.refresh(model)  # Refresh to get DB defaults if any
            logger.info(f"Successfully added DigitalTwin with ID: {model.id}")
            return self._to_entity(model)
        except sqlalchemy.exc.IntegrityError as e:
            await self.session.rollback()
            logger.error(f"Error adding DigitalTwin: {e}", exc_info=True)
            # Re-raise a more specific domain exception if needed
            raise
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Unexpected error adding DigitalTwin: {e}", exc_info=True)
            raise

    async def get_by_id(self, entity_id: str | UUID) -> DigitalTwin | None:
        """Get a digital twin by its unique ID."""
        # Convert to UUID if string provided, maintain SQLAlchemy compatibility
        twin_id = UUID(entity_id) if isinstance(entity_id, str) else entity_id
        stmt = select(DigitalTwinModel).where(DigitalTwinModel.id == str(twin_id))
        result = await self.session.execute(stmt)
        model = result.scalar_one_or_none()
        if model:
            return self._to_entity(model)
        return None

    async def get_by_patient_id(self, patient_id: UUID) -> DigitalTwin | None:
        """Get a digital twin by the patient's ID."""
        stmt = select(DigitalTwinModel).where(DigitalTwinModel.patient_id == str(patient_id))
        result = await self.session.execute(stmt)
        model = result.scalar_one_or_none()
        if model:
            return self._to_entity(model)
        return None

    async def update(self, digital_twin: DigitalTwin) -> DigitalTwin:
        """Update an existing digital twin."""
        model = await self.session.get(DigitalTwinModel, str(digital_twin.id))
        if not model:
            logger.warning(f"DigitalTwin with ID {digital_twin.id} not found for update.")
            raise ValueError(
                f"DigitalTwin with ID {digital_twin.id} not found"
            )  # Or a custom domain exception

        # Update fields from the entity
        model.updated_at = digital_twin.last_updated
        model.version = digital_twin.version
        model.configuration_json = self._serialize_config(digital_twin.configuration)
        model.state_json = self._serialize_state(digital_twin.state)

        try:
            await self.session.flush()
            await self.session.refresh(model)
            logger.info(f"Successfully updated DigitalTwin with ID: {model.id}")
            return self._to_entity(model)
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Error updating DigitalTwin ID {model.id}: {e}", exc_info=True)
            raise

    async def delete(self, entity_id: str | UUID) -> bool:
        """Delete a digital twin by its ID."""
        # Convert to UUID if string provided, maintain SQLAlchemy compatibility
        twin_id = UUID(entity_id) if isinstance(entity_id, str) else entity_id
        model = await self.session.get(DigitalTwinModel, str(twin_id))
        if model:
            await self.session.delete(model)
            await self.session.flush()
            logger.info(f"Successfully deleted DigitalTwin with ID: {twin_id}")
            return True
        logger.warning(f"DigitalTwin with ID {twin_id} not found for deletion.")
        return False

    async def list_all(self, skip: int = 0, limit: int = 100) -> list[DigitalTwin]:
        """List all digital twins with pagination."""
        stmt = select(DigitalTwinModel).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        models = result.scalars().all()
        return [self._to_entity(model) for model in models]


# Export alias for UnitOfWorkFactory compatibility
SQLAlchemyDigitalTwinRepository = DigitalTwinRepositoryImpl
