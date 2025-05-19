"""
Unified Database Test Fixtures

This module provides a complete set of pytest fixtures and utilities for
database testing, combining transaction management, dependency injection,
and test data generation capabilities into a single cohesive module.
"""

import asyncio
import os
from collections.abc import AsyncGenerator
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.core.dependencies.database import get_session
from app.infrastructure.persistence.sqlalchemy.models.base import Base

# Test database URL from environment or default to a test PostgreSQL DB
TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://postgres:postgres@localhost:15432/novamind_test",
)

# Create a test engine with appropriate settings
test_engine = create_async_engine(
    TEST_DATABASE_URL,
    echo=False,
    poolclass=NullPool,
    connect_args={"server_settings": {"jit": "off"}},  # Disable JIT for tests
)

# Create a session factory for tests
TestSessionLocal = async_sessionmaker(
    test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session")
async def setup_database() -> AsyncGenerator[None, None]:
    """
    Set up the test database once per test session.

    This fixture creates all tables defined in SQLAlchemy models,
    then drops them when the test session is complete.
    """
    async with test_engine.begin() as conn:
        # Create all tables
        await conn.run_sync(Base.metadata.create_all)

    yield

    # Clean up after tests
    async with test_engine.begin() as conn:
        # Drop all tables
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def db_session(setup_database) -> AsyncGenerator[AsyncSession, None]:
    """
    Create a new database session for a test.

    This fixture creates a new database session for each test that uses it.
    The session is rolled back after the test completes, ensuring test isolation.
    """
    async with TestSessionLocal() as session:
        # Start a transaction
        transaction = await session.begin()
        try:
            yield session
        finally:
            # Roll back the transaction
            await transaction.rollback()
            await session.close()


@pytest_asyncio.fixture(scope="function")
async def override_get_session(db_session: AsyncSession, dependency_overrides: dict) -> None:
    """
    Overrides the 'get_session' dependency for the FastAPI app using the
    standard dependency_overrides mechanism.

    Yields the test database session instance for the duration of a test.
    """

    async def _override_get_session_func() -> AsyncGenerator[AsyncSession, None]:
        """The actual function that will replace get_session during tests."""
        yield db_session

    # Add the override to the dictionary
    # The key is the original dependency function (get_session)
    # The value is the function to use instead (_override_get_session_func)
    dependency_overrides[get_session] = _override_get_session_func


class TestDataFactory:
    """Factory for creating test data."""

    @staticmethod
    def create_patient_data(count: int = 1) -> list[dict[str, Any]]:
        """Create test patient data."""
        patients = []
        for i in range(1, count + 1):
            patients.append(
                {
                    "id": f"test-patient-{i}",
                    "name": f"Test Patient {i}",
                    "date_of_birth": "1990-01-01",
                    "gender": "male" if i % 2 == 0 else "female",
                    "contact_info": {
                        "email": f"patient{i}@example.com",
                        "phone": f"555-000-{i:04d}",
                    },
                    "medical_record_number": f"MRN{i:06d}",
                    "created_at": "2024-01-01T00:00:00",
                    "updated_at": "2024-01-01T00:00:00",
                }
            )
        return patients

    @staticmethod
    def create_clinician_data(count: int = 1) -> list[dict[str, Any]]:
        """Create test clinician data."""
        clinicians = []
        for i in range(1, count + 1):
            clinicians.append(
                {
                    "id": f"test-clinician-{i}",
                    "name": f"Dr. Test Clinician {i}",
                    "specialty": "Psychiatry" if i % 3 == 0 else "Psychology",
                    "license_number": f"LIC{i:06d}",
                    "contact_info": {
                        "email": f"clinician{i}@example.com",
                        "phone": f"555-111-{i:04d}",
                    },
                    "created_at": "2024-01-01T00:00:00",
                    "updated_at": "2024-01-01T00:00:00",
                }
            )
        return clinicians

    @staticmethod
    def create_user_data(count: int = 1) -> list[dict[str, Any]]:
        """Create test user data."""
        users = []
        for i in range(1, count + 1):
            users.append(
                {
                    "id": f"test-user-{i}",
                    "username": f"testuser{i}",
                    "email": f"user{i}@example.com",
                    "hashed_password": "hashed_test_password",
                    "is_active": True,
                    "role": "user" if i % 3 != 0 else "admin",
                    "created_at": "2024-01-01T00:00:00",
                    "updated_at": "2024-01-01T00:00:00",
                }
            )
        return users


# Context manager for transaction-based testing
class TransactionalTestContext:
    """Context manager for transaction-based testing."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def __aenter__(self):
        """Begin a nested transaction."""
        self.transaction = await self.session.begin_nested()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Roll back the transaction."""
        await self.transaction.rollback()


# Factory for creating transactional test contexts
@pytest.fixture
def transactional_test(db_session: AsyncSession):
    """Provide a transactional context for tests."""

    def _transactional_test():
        return TransactionalTestContext(db_session)

    return _transactional_test


# NOTE: Removed redundant get_test_settings function.
# Test settings should now be obtained via app.core.config.settings.get_settings()
