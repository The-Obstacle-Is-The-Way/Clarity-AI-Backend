from sqlalchemy import Column, Enum
from sqlalchemy.types import Text, DateTime
"""
Test Database Initializer

This module provides a standardized, production-quality approach to database initialization
for integration tests. It ensures consistent table creation and foreign key relationships,
regardless of the actual database schema state.

Features:
1. In-memory SQLite database with foreign keys enabled for fast test execution
2. Complete test schema based on *actual* application models
3. Predefined test user accounts with consistent UUIDs for reliable foreign keys
4. Proper transaction handling and rollback after each test
5. Helper functions for creating test data
"""

import uuid
import logging
import asyncio
import json
import random
from datetime import datetime, timezone, date
from typing import AsyncGenerator, List, Dict, Any, Optional, Union

# Import REAL application models and Base
from app.infrastructure.persistence.sqlalchemy.models.base import Base
from app.infrastructure.persistence.sqlalchemy.models.user import User as UserModel, UserRole
from app.infrastructure.persistence.sqlalchemy.models.patient import Patient as PatientModel

from sqlalchemy import Column, String, Boolean, Integer, ForeignKey, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.dialects.postgresql import UUID as PostgresUUID # Use Postgres UUID for type hint consistency if needed
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.future import select


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# REMOVE TestBase definition
# TestBase = declarative_base()

# Define standard test user IDs for consistent foreign keys
TEST_USER_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
TEST_CLINICIAN_ID = uuid.UUID("00000000-0000-0000-0000-000000000002")

# REMOVE Test User Model definition
# class TestUser(TestBase): ...

# REMOVE Test Patient Model definition
# class TestPatient(TestBase): ...


async def create_test_users(session: AsyncSession) -> None:
    """Create standard test users in the database if they don't already exist."""

    # Check if test users exist using the real UserModel
    result = await session.execute(select(UserModel).where(
        UserModel.id.in_([TEST_USER_ID, TEST_CLINICIAN_ID])
    ))
    existing_users = result.scalars().all()
    existing_ids = {user.id for user in existing_users} # Use a set for faster lookups

    # Create test patient user if not exists using the real UserModel
    if TEST_USER_ID not in existing_ids:
        test_user = UserModel(
            id=TEST_USER_ID,
            username="testuser",
            email="test.user@novamind.ai",
            password_hash="$2b$12$EixZaYVK1fsbw1ZfbX3RU.II9.eGCwJoF1732K/i54e9QaJIX3fOC", # Example hash for 'password'
            is_active=True,
            is_verified=True,
            email_verified=True,
            role=UserRole.PATIENT, # Use the actual Enum
            first_name="Test",
            last_name="User",
            created_at=datetime.now(timezone.utc), # Use datetime objects
            updated_at=datetime.now(timezone.utc),
            password_changed_at=datetime.now(timezone.utc)
        )
        session.add(test_user)

    # Create test clinician user if not exists using the real UserModel
    if TEST_CLINICIAN_ID not in existing_ids:
        test_clinician = UserModel(
            id=TEST_CLINICIAN_ID,
            username="testclinician",
            email="test.clinician@novamind.ai",
            password_hash="$2b$12$EixZaYVK1fsbw1ZfbX3RU.II9.eGCwJoF1732K/i54e9QaJIX3fOC", # Example hash for 'password'
            is_active=True,
            is_verified=True,
            email_verified=True,
            role=UserRole.CLINICIAN, # Use the actual Enum
            first_name="Test",
            last_name="Clinician",
            created_at=datetime.now(timezone.utc), # Use datetime objects
            updated_at=datetime.now(timezone.utc),
            password_changed_at=datetime.now(timezone.utc)
        )
        session.add(test_clinician)

    try:
        await session.commit() # Commit changes if users were added
        logger.info(f"Test users initialized with IDs: {TEST_USER_ID}, {TEST_CLINICIAN_ID}")
    except Exception as e:
        logger.error(f"Error committing test users: {e}")
        await session.rollback()


async def get_test_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Create a test database session with all tables created using REAL models
    and test users inserted.

    This provides an isolated transactional session for each test.
    """
    # Use an in-memory SQLite database for testing
    DATABASE_URL = "sqlite+aiosqlite:///:memory:"
    engine = create_async_engine(DATABASE_URL, echo=False, future=True)

    # Use the metadata from the *real* Base
    async with engine.begin() as conn:
        # Enable foreign key support for SQLite
        await conn.execute(text("PRAGMA foreign_keys=ON;"))
        # Create tables based on the real application models
        await conn.run_sync(Base.metadata.create_all)

    # Create a sessionmaker
    TestSessionLocal = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )

    # Create a new session
    async with TestSessionLocal() as session:
        try:
            # Create test users within the session context
            await create_test_users(session)

            # Begin transaction for the test
            await session.begin()
            yield session
            # Rollback transaction after test completes
            await session.rollback()
        except Exception as e:
            logger.error(f"Error during test database session setup/teardown: {e}")
            await session.rollback() # Ensure rollback on error
            raise # Re-raise the exception
        finally:
            # Ensure the session is closed
            await session.close()

    # Dispose of the engine after the session is done
    # Note: For in-memory SQLite with function scope, disposing might discard the DB state prematurely.
    # Let's comment this out.
    # await engine.dispose()


# Optional: Keep helper function to create test patients if needed,
# but ensure it uses the real PatientModel or PatientDomain entity
# This example assumes PatientDomain is used for consistency
from app.domain.entities.patient import Patient as PatientDomain
from app.domain.value_objects.name import Name
from app.domain.value_objects.contact_info import ContactInfo
from app.infrastructure.persistence.sqlalchemy.repositories.patient_repository import PatientRepository # Import real repo if needed for creation logic
from app.infrastructure.security.encryption.base_encryption_service import BaseEncryptionService # Import if needed


async def create_test_patient_domain(
    user_id: Optional[uuid.UUID] = None,
    first_name: str = "Test",
    last_name: str = "Patient",
    email: str = f"testpatient.{uuid.uuid4().hex[:6]}@example.com", # Ensure unique email
    phone: str = f"555{random.randint(1000000, 9999999)}", # Ensure unique phone
    ssn: Optional[str] = None,
    date_of_birth: Optional[Union[str, date]] = None,
    patient_id: Optional[uuid.UUID] = None,
) -> PatientDomain:
    """
    Creates a Patient DOMAIN entity with default test data.
    Uses domain value objects directly.
    """
    if not patient_id:
        patient_id = uuid.uuid4()

    if date_of_birth is None:
        date_of_birth = date(1980, 1, 1)
    elif isinstance(date_of_birth, str):
        try:
            date_of_birth = date.fromisoformat(date_of_birth)
        except ValueError:
            logger.warning(f"Invalid date string '{date_of_birth}', using default.")
            date_of_birth = date(1980, 1, 1)

    # Generate SSN if not provided
    if ssn is None:
        ssn = f"{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}"

    patient_entity = PatientDomain(
        id=patient_id,
        name=Name(first_name=first_name, last_name=last_name),
        contact_info=ContactInfo(email=email, phone=phone),
        date_of_birth=date_of_birth,
        medical_record_number=f"MRN-TEST-{uuid.uuid4().hex[:8].upper()}",
        ssn=ssn,
        created_by=user_id or TEST_USER_ID, # Default to test user if not specified
        active=True,
        # Add other required fields with defaults if necessary
        gender="Prefer not to say",
        address=None, # Explicitly set complex types if needed
        emergency_contact=None,
        insurance_provider=None,
        medical_history=[],
        medications=[],
        allergies=[],
        treatment_notes=[],
        extra_data={},
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
        version=1,
        insurance_number=None,
        biometric_twin_id=None,
        external_id=None
    )
    return patient_entity

# Function to verify table existence (useful for debugging setup)
async def verify_table_exists(session: AsyncSession, table_name: str) -> bool:
    """Check if a table exists in the test database."""
    try:
        # Using a simple query that depends on the table existing
        await session.execute(text(f"SELECT 1 FROM {table_name} LIMIT 1;"))
        logger.info(f"Table '{table_name}' exists.")
        return True
    except Exception as e:
        # Catching broad exception as specific DB errors vary (e.g., NoSuchTableError, OperationalError)
        logger.warning(f"Table '{table_name}' does not seem to exist or query failed: {e}")
        return False
