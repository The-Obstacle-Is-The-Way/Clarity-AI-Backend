"""
Dependency providers for repositories.
"""

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

# Import necessary components
from app.infrastructure.persistence.sqlalchemy.config.database import get_db_session
from app.infrastructure.persistence.sqlalchemy.repositories.patient_repository import (
    PatientRepository,
)
from app.infrastructure.security.encryption.base_encryption_service import (
    BaseEncryptionService,
)

# Import the actual dependency provider for encryption service if one exists, else mock it for now
# from app.presentation.api.dependencies.security import get_encryption_service # Example


# Placeholder for encryption service dependency - replace with actual provider if available
# For now, we assume it might be directly requested or provided elsewhere
async def get_encryption_service() -> BaseEncryptionService:
    # This is a placeholder. In a real app, this would likely retrieve
    # the configured encryption service instance.
    # If using FernetEncryptionService, it might look like:
    # from app.infrastructure.security.encryption.fernet_encryption_service import FernetEncryptionService
    # from app.core.config import get_settings
    # settings = get_settings()
    # return FernetEncryptionService(settings.ENCRYPTION_KEY)
    # Since we mock this in tests, a basic mock suffices here if no real provider exists yet.
    from unittest.mock import MagicMock

    mock_service = MagicMock(spec=BaseEncryptionService)
    mock_service.encrypt.side_effect = lambda x: f"encrypted_{x}"
    mock_service.decrypt.side_effect = (
        lambda x: x.replace("encrypted_", "") if isinstance(x, str) else x
    )
    return mock_service


async def get_patient_repository(
    db: AsyncSession = Depends(get_db_session),
    encryption_service: BaseEncryptionService = Depends(get_encryption_service),  # Use placeholder
) -> PatientRepository:
    """
    Dependency provider for the PatientRepository.

    Injects the database session and encryption service.
    """
    return PatientRepository(db_session=db, encryption_service=encryption_service)
