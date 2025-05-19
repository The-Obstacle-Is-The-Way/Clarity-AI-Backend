"""
Factory functions for in-memory repository implementations.
"""

from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.repositories.memory.biometric_alert_template_repository_mock import (
    MockBiometricAlertTemplateRepository,
)


def get_mock_biometric_alert_template_repository(session: AsyncSession):
    """
    Factory function for creating MockBiometricAlertTemplateRepository instances.

    Args:
        session: SQLAlchemy AsyncSession instance

    Returns:
        A new MockBiometricAlertTemplateRepository instance
    """
    return MockBiometricAlertTemplateRepository(session)
