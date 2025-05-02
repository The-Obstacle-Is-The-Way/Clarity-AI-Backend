"""
Package for application-level dependency helpers.

This package contains FastAPI dependency modules (database, services,
authentication, rate limiting, etc.) under their own files. Sub-modules
can be imported directly:

    from app.presentation.api.dependencies.rate_limiter import RateLimitDependency
    from app.presentation.api.dependencies.auth import get_current_user

For database interactions, use `get_db_session` for database interactions.
The session is configured via `app.config.settings`.

Design Principles:
    - Dependency Injection: Provides repository instances via FastAPI's Depends.
    - Decoupling: Abstracts data access implementation details.
    - Testability: Allows easy mocking/overriding of dependencies in tests.
"""

# No legacy backward-compat shims here - sub-modules live under this package.

from fastapi import Depends

from app.domain.repositories.biometric_alert_rule_repository import BiometricAlertRuleRepository
# Removed unused domain repositories
# from app.domain.repositories.patient_repository import PatientRepository 

from app.infrastructure.persistence.sqlalchemy.config.database import (
    DBSessionDep,
    get_db_session,
)
# Removed unused infra repositories
# from app.infrastructure.persistence.sqlalchemy.repositories.user_repository import SQLAlchemyUserRepository
# from app.infrastructure.persistence.sqlalchemy.repositories.patient_repository import SQLAlchemyPatientRepository
from app.infrastructure.persistence.sqlalchemy.repositories.biometric_rule_repository import (
    SQLAlchemyBiometricRuleRepository,
)


__all__ = [
    "DBSessionDep",
    "get_db_session",
    "get_rule_repository",
]


def get_rule_repository(
    session: DBSessionDep = Depends(get_db_session),
) -> BiometricAlertRuleRepository:
    """Dependency provider for BiometricRuleRepository."""
    return SQLAlchemyBiometricRuleRepository(session=session)

# Placeholder for other potential dependencies
# e.g., get_user_repository, get_patient_repository etc.
