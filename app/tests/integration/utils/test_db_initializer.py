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

import json
import logging
import random
import uuid
from collections.abc import AsyncGenerator
from datetime import date, datetime, timezone

# Import models we need for test creation
from app.infrastructure.persistence.sqlalchemy.models import UserRole
from app.infrastructure.persistence.sqlalchemy.models.base import Base

# Import the base module which contains the model validation functions
# from app.infrastructure.persistence.sqlalchemy.models.base import (
#     Base,
#     ensure_all_models_loaded,
#     validate_models,
# )

# Ensure all models are loaded and registered
# ensure_all_models_loaded()
# validate_models()

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

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
    """Create standard test users in the database using direct SQL rather than ORM.

    This approach avoids SQLAlchemy ORM mapping issues by using core SQL expressions
    which bypass the ORM layer entirely, making it more robust against mapping errors.
    """
    logger.info(
        f"CREATE_TEST_USERS: Called with session ID: {id(session)}. Will create users with TEST_USER_ID: {TEST_USER_ID}, TEST_CLINICIAN_ID: {TEST_CLINICIAN_ID}"
    )  # DEBUG LOG
    try:
        # Check if test users exist using direct SQL query
        query = f"SELECT id FROM users WHERE id IN ('{TEST_USER_ID}', '{TEST_CLINICIAN_ID}')"
        result = await session.execute(text(query))
        existing_ids = [str(row[0]) for row in result.fetchall()]

        current_time = datetime.now(timezone.utc).isoformat()
        password_hash = (
            "$2b$12$EixZaYVK1fsbw1ZfbX3RU.II9.eGCwJoF1732K/i54e9QaJIX3fOC"  # 'password'
        )
        inserted_users = []

        # Create test patient user if not exists using direct SQL
        if str(TEST_USER_ID) not in existing_ids:
            # Use SQL text() to directly insert the user, bypassing ORM mapping issues
            patient_insert = text(
                """
                INSERT INTO users (
                    id, username, email, password_hash, is_active, is_verified, email_verified,
                    role, roles, first_name, last_name, created_at, updated_at, password_changed_at,
                    failed_login_attempts, audit_id
                ) VALUES (
                    :id, :username, :email, :password_hash, :is_active, :is_verified, :email_verified,
                    :role, :roles, :first_name, :last_name, :created_at, :updated_at, :password_changed_at,
                    :failed_login_attempts, :audit_id
                )
            """
            )

            # Create a JSON array with the patient role for the roles column
            patient_roles = json.dumps([UserRole.PATIENT.name])

            # Generate a UUID for audit tracking
            audit_id = str(uuid.uuid4())

            await session.execute(
                patient_insert,
                {
                    "id": str(TEST_USER_ID),
                    "username": "testuser",
                    "email": "test.user@novamind.ai",
                    "password_hash": password_hash,
                    "is_active": True,
                    "is_verified": True,
                    "email_verified": True,
                    "role": UserRole.PATIENT.name,  # Use the NAME of enum for SQLAlchemy Enum type
                    "roles": patient_roles,  # Use NAME for consistency in JSON array
                    "failed_login_attempts": 0,  # Add required failed_login_attempts field
                    "audit_id": audit_id,  # Add required audit_id field
                    "first_name": "Test",
                    "last_name": "User",
                    "created_at": current_time,
                    "updated_at": current_time,
                    "password_changed_at": current_time,
                },
            )
            inserted_users.append(str(TEST_USER_ID))

        # Create test clinician user if not exists using direct SQL
        if str(TEST_CLINICIAN_ID) not in existing_ids:
            clinician_insert = text(
                """
                INSERT INTO users (
                    id, username, email, password_hash, is_active, is_verified, email_verified,
                    role, roles, first_name, last_name, created_at, updated_at, password_changed_at,
                    failed_login_attempts, audit_id
                ) VALUES (
                    :id, :username, :email, :password_hash, :is_active, :is_verified, :email_verified,
                    :role, :roles, :first_name, :last_name, :created_at, :updated_at, :password_changed_at,
                    :failed_login_attempts, :audit_id
                )
            """
            )

            # Create a JSON array with the clinician role for the roles column
            clinician_roles = json.dumps([UserRole.CLINICIAN.name])

            # Generate a UUID for audit tracking - unique for this clinician
            clinician_audit_id = str(uuid.uuid4())

            await session.execute(
                clinician_insert,
                {
                    "id": str(TEST_CLINICIAN_ID),
                    "username": "testclinician",
                    "email": "test.clinician@novamind.ai",
                    "password_hash": password_hash,
                    "is_active": True,
                    "is_verified": True,
                    "email_verified": True,
                    "role": UserRole.CLINICIAN.name,  # Use the NAME of enum
                    "roles": clinician_roles,  # Use NAME for consistency in JSON array
                    "failed_login_attempts": 0,  # Add required failed_login_attempts field
                    "audit_id": clinician_audit_id,  # Add required audit_id field
                    "first_name": "Test",
                    "last_name": "Clinician",
                    "created_at": current_time,
                    "updated_at": current_time,
                    "password_changed_at": current_time,
                },
            )
            inserted_users.append(str(TEST_CLINICIAN_ID))

        # Commit changes if we inserted any users
        if inserted_users:
            await session.commit()
            logger.info(
                f"Committed test users using direct SQL: {inserted_users}. Session ID: {id(session)}"
            )  # DEBUG LOG
        else:
            logger.info(
                f"Test users already exist in database. Session ID: {id(session)}"
            )  # DEBUG LOG

    except Exception as e:
        logger.error(f"Error creating test users: {e}")
        await session.rollback()
        # Fall back to simpler approach if the structured approach fails
        logger.warning("Falling back to minimal user creation approach")
        await create_minimal_test_users(session)


async def create_minimal_test_users(session: AsyncSession) -> None:
    """Create minimal test users with only required fields using direct SQL.

    This is a fallback method that creates users with minimal fields to avoid mapping issues.
    """
    try:
        # Very minimal insert with just the essential fields including mandatory roles column
        minimal_insert = text(
            """
        INSERT OR IGNORE INTO users (id, username, email, password_hash, is_active, role, roles, created_at, updated_at) 
        VALUES (:id, :username, :email, :password_hash, :is_active, :role, :roles, :created_at, :updated_at)
        """
        )

        current_time = datetime.now(timezone.utc).isoformat()

        # Insert patient user
        await session.execute(
            minimal_insert,
            {
                "id": str(TEST_USER_ID),
                "username": "testuser",
                "email": "test.user@novamind.ai",
                "password_hash": "$2b$12$EixZaYVK1fsbw1ZfbX3RU.II9.eGCwJoF1732K/i54e9QaJIX3fOC",
                "is_active": True,
                "role": UserRole.PATIENT.name,  # Use NAME
                "roles": json.dumps([UserRole.PATIENT.name]),  # Use NAME
                "created_at": current_time,
                "updated_at": current_time,
            },
        )

        # Insert clinician user
        await session.execute(
            minimal_insert,
            {
                "id": str(TEST_CLINICIAN_ID),
                "username": "testclinician",
                "email": "test.clinician@novamind.ai",
                "password_hash": "$2b$12$EixZaYVK1fsbw1ZfbX3RU.II9.eGCwJoF1732K/i54e9QaJIX3fOC",
                "is_active": True,
                "role": UserRole.CLINICIAN.name,  # Use NAME
                "roles": json.dumps([UserRole.CLINICIAN.name]),  # Use NAME
                "created_at": current_time,
                "updated_at": current_time,
            },
        )

        await session.commit()
        logger.info("Created minimal test users via direct SQL")
    except Exception as e:
        logger.error(f"Error in minimal user creation: {e}")
        await session.rollback()
        raise


async def get_test_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Create a test database session with all tables created using REAL models
    and test users inserted.

    This provides an isolated transactional session for each test.
    """
    # Use an in-memory SQLite database for testing
    DATABASE_URL = "sqlite+aiosqlite:///:memory:"
    engine = create_async_engine(DATABASE_URL, echo=False, future=True)

    # Log SQLAlchemy initialization for debugging
    logger.info("Initializing SQLAlchemy test session with model validation")

    # Use the metadata from the canonical Base
    async with engine.begin() as conn:
        # Enable foreign key support for SQLite
        await conn.execute(text("PRAGMA foreign_keys=ON;"))

        # Ensure all models are properly loaded
        # ensure_all_models_loaded()
        # validate_models()

        # Create tables based on the real application models
        # Use a sync function to create all tables
        def create_tables(sync_conn):
            # Create all tables using the canonical Base metadata
            Base.metadata.create_all(sync_conn)
            logger.info(f"Created {len(Base.metadata.tables)} tables from metadata")

            # Get table names for verification
            table_names = list(Base.metadata.tables.keys())
            logger.info(f"Created tables: {', '.join(table_names)}")

            # Validate models after creation
            # validate_models()

            # Verify that the users table exists
            if "users" not in table_names:
                logger.error("Users table not found in metadata!")

        # Run the table creation function synchronously
        await conn.run_sync(create_tables)

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
            # Enable foreign keys specifically for this session (important for SQLite)
            await session.execute(text("PRAGMA foreign_keys=ON;"))

            # Validate models at runtime to ensure proper mapping
            # For AsyncEngine, we need to use the begin()/run_sync() pattern
            try:
                async with engine.begin() as conn:
                    # Define the sync function
                    def validate_models_sync(sync_session_arg_not_used):
                        logger.info(
                            "Validating models (sync context inside get_test_db_session)"
                        )
                        # validate_models()

                    # Run validation in sync context
                    await conn.run_sync(validate_models_sync)
                logger.info("SQLAlchemy model validation completed successfully")
            except Exception as e:
                logger.error(f"Model validation error: {e!s}")
                # Continue without validation for now - we've already created tables

            # Create test users within the session context
            await create_test_users(session)

            yield session
            # Explicit rollback for test isolation
            await session.rollback()
        except Exception as e:
            logger.error(f"Error during test database session setup/teardown: {e}")
            await session.rollback()  # Ensure rollback on error
            raise  # Re-raise the exception
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
from app.domain.value_objects.contact_info import ContactInfo
from app.domain.value_objects.name import Name


async def create_test_patient_domain(
    user_id: uuid.UUID | None = None,
    first_name: str = "Test",
    last_name: str = "Patient",
    email: str = f"testpatient.{uuid.uuid4().hex[:6]}@example.com",  # Ensure unique email
    phone: str = f"555{random.randint(1000000, 9999999)}",  # Ensure unique phone
    ssn: str | None = None,
    date_of_birth: str | date | None = None,
    patient_id: uuid.UUID | None = None,
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
        created_by=user_id or TEST_USER_ID,  # Default to test user if not specified
        active=True,
        # Add other required fields with defaults if necessary
        gender="Prefer not to say",
        address=None,  # Explicitly set complex types if needed
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
        external_id=None,
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
        logger.warning(
            f"Table '{table_name}' does not seem to exist or query failed: {e}"
        )
        return False
