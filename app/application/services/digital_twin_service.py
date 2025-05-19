"""
Application Service for Digital Twin operations.

This service orchestrates the use cases related to managing digital twins,
interacting with repositories and potentially other domain services.
"""
import logging
from uuid import UUID

# Import domain entities and repository interfaces
from app.domain.entities.digital_twin import DigitalTwin
from app.domain.repositories.digital_twin_repository import DigitalTwinRepository

logger = logging.getLogger(__name__)


class DigitalTwinApplicationService:
    """Provides application-level operations for Digital Twins."""

    def __init__(self, digital_twin_repository: DigitalTwinRepository):
        # Inject necessary repositories and potentially other services
        self.repo = digital_twin_repository
        # self.digital_twin_service = digital_twin_service # Removed incorrect injection
        logger.info("DigitalTwinApplicationService initialized.")

    async def create_twin(
        self, patient_id: UUID, initial_config: dict | None = None
    ) -> DigitalTwin:
        """Creates a new digital twin for a patient."""
        logger.info(f"Attempting to create digital twin for patient {patient_id}")
        existing = await self.repo.get_by_patient_id(patient_id)
        if existing:
            logger.warning(f"Digital twin already exists for patient {patient_id}")
            # Depending on policy, could return existing or raise error
            # For now, let's return the existing one
            return existing
            # raise ValueError(f"Digital twin already exists for patient {patient_id}")

        twin = DigitalTwin(patient_id=patient_id)
        if initial_config:
            # Apply initial configuration safely
            twin.update_configuration(initial_config)

        created_twin = await self.repo.create(twin)
        logger.info(f"Successfully created digital twin {created_twin.id} for patient {patient_id}")
        return created_twin

    async def get_twin_by_patient_id(self, patient_id: UUID) -> DigitalTwin | None:
        """Retrieves a digital twin by patient ID."""
        logger.debug(f"Retrieving digital twin for patient {patient_id}")
        return await self.repo.get_by_patient_id(patient_id)

    async def update_twin_configuration(
        self, patient_id: UUID, config_data: dict
    ) -> DigitalTwin | None:
        """Updates the configuration of a specific digital twin."""
        logger.info(f"Updating configuration for digital twin of patient {patient_id}")
        twin = await self.repo.get_by_patient_id(patient_id)
        if not twin:
            logger.warning(f"Digital twin not found for patient {patient_id} during config update")
            return None

        twin.update_configuration(config_data)
        updated_twin = await self.repo.update(twin)
        if updated_twin:
            logger.info(f"Successfully updated configuration for digital twin {updated_twin.id}")
        else:
            logger.error(f"Failed to persist configuration update for twin of patient {patient_id}")
        return updated_twin

    # Add more methods for other use cases:
    # - update_twin_state(patient_id, state_data)
    # - delete_twin(patient_id)
    # - trigger_twin_sync(patient_id)
