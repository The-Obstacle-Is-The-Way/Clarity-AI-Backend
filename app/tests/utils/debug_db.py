"""
DIRECT DATABASE DEBUGGING SCRIPT

This script provides a minimal, direct approach to creating the database tables
and diagnosing any issues with the SQLite setup.
"""

import asyncio
import logging
import os
import sys
import uuid
from datetime import UTC, datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

# Add the backend directory to sys.path if needed
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# Import SQLAlchemy components
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Direct SQL statements for table creation
DIRECT_SQL = {
    "enable_foreign_keys": """
    PRAGMA foreign_keys = ON;
    """,
    "users": """
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        email TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        is_active BOOLEAN NOT NULL DEFAULT 1,
        is_verified BOOLEAN NOT NULL DEFAULT 0,
        email_verified BOOLEAN NOT NULL DEFAULT 0,
        role TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    """,
    "patients": """
    CREATE TABLE IF NOT EXISTS patients (
        id TEXT PRIMARY KEY,
        user_id TEXT NULL REFERENCES users(id),
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN NOT NULL DEFAULT 1,
        first_name TEXT NULL,
        last_name TEXT NULL,
        date_of_birth TEXT NULL,
        email TEXT NULL,
        phone TEXT NULL
    );
    """,
}

# Constants for test users
TEST_USER_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
TEST_USER_EMAIL = "test.user@novamind.ai"
TEST_PASSWORD_HASH = "hashed_password_for_testing_only"


async def verify_table_exists(session: AsyncSession, table_name: str) -> bool:
    """Verify that a table exists in the database."""
    try:
        query = text(
            f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table_name}'"
        )
        result = await session.execute(query)
        exists = result.scalar() is not None

        if exists:
            # Also verify table has data structure by counting columns
            columns_query = text(f"PRAGMA table_info({table_name})")
            columns_result = await session.execute(columns_query)
            columns = columns_result.fetchall()
            column_names = [col[1] for col in columns]
            logger.info(
                f"Table {table_name} exists with {len(columns)} columns: {column_names}"
            )
            return len(columns) > 0
        logger.error(f"Table {table_name} does not exist")
        return False
    except Exception as e:
        logger.error(f"Error verifying table {table_name}: {e}")
        return False


async def create_test_user(session: AsyncSession) -> None:
    """Create a test user in the database."""
    try:
        logger.info(f"Creating test user with ID: {TEST_USER_ID}")
        query = text(
            """
        INSERT INTO users (id, username, email, password_hash, is_active, is_verified, email_verified, role, created_at, updated_at)
        VALUES (:id, :username, :email, :password_hash, :is_active, :is_verified, :email_verified, :role, :created_at, :updated_at)
        """
        )

        await session.execute(
            query,
            {
                "id": str(TEST_USER_ID),
                "username": "testuser",
                "email": TEST_USER_EMAIL,
                "password_hash": TEST_PASSWORD_HASH,
                "is_active": True,
                "is_verified": True,
                "email_verified": True,
                "role": "PATIENT",
                "created_at": datetime.now(UTC),
                "updated_at": datetime.now(UTC),
            },
        )
        await session.commit()
        logger.info("Test user created successfully")
    except Exception as e:
        logger.error(f"Error creating test user: {e}")
        await session.rollback()
        raise


async def create_test_patient(session: AsyncSession) -> None:
    """Create a test patient in the database."""
    try:
        patient_id = uuid.uuid4()
        logger.info(f"Creating test patient with ID: {patient_id}")
        query = text(
            """
        INSERT INTO patients (id, user_id, first_name, last_name, email, phone, created_at, updated_at, is_active)
        VALUES (:id, :user_id, :first_name, :last_name, :email, :phone, :created_at, :updated_at, :is_active)
        """
        )

        await session.execute(
            query,
            {
                "id": str(patient_id),
                "user_id": str(TEST_USER_ID),
                "first_name": "Test",
                "last_name": "Patient",
                "email": "test.patient@example.com",
                "phone": "555-123-4567",
                "created_at": datetime.now(UTC),
                "updated_at": datetime.now(UTC),
                "is_active": True,
            },
        )
        await session.commit()
        logger.info("Test patient created successfully")
    except Exception as e:
        logger.error(f"Error creating test patient: {e}")
        await session.rollback()
        raise


async def debug_database():
    """Create and test the database setup."""
    logger.info("Starting database debugging")

    # Create in-memory SQLite database
    db_url = "sqlite+aiosqlite:///:memory:"
    logger.info(f"Using database URL: {db_url}")

    # Create engine
    engine = create_async_engine(db_url, echo=True)

    # Create session factory
    async_session_factory = async_sessionmaker(
        bind=engine, expire_on_commit=False, autoflush=False, class_=AsyncSession
    )

    # Create session
    async with async_session_factory() as session:
        try:
            # Enable foreign keys
            logger.info("Enabling foreign keys")
            await session.execute(text(DIRECT_SQL["enable_foreign_keys"]))
            await session.commit()

            # Create users table
            logger.info("Creating users table")
            await session.execute(text(DIRECT_SQL["users"]))
            await session.commit()

            # Verify users table was created
            if not await verify_table_exists(session, "users"):
                raise RuntimeError("Failed to create users table")

            # Create patients table
            logger.info("Creating patients table")
            await session.execute(text(DIRECT_SQL["patients"]))
            await session.commit()

            # Verify patients table was created
            if not await verify_table_exists(session, "patients"):
                raise RuntimeError("Failed to create patients table")

            # Create test user
            await create_test_user(session)

            # Create test patient
            await create_test_patient(session)

            # Verify data
            logger.info("Verifying data")
            query = text("SELECT COUNT(*) FROM users")
            result = await session.execute(query)
            user_count = result.scalar()
            logger.info(f"User count: {user_count}")

            query = text("SELECT COUNT(*) FROM patients")
            result = await session.execute(query)
            patient_count = result.scalar()
            logger.info(f"Patient count: {patient_count}")

            logger.info("Database debugging completed successfully")
        except Exception as e:
            logger.error(f"Error during database debugging: {e}")
            await session.rollback()
            raise
        finally:
            await session.close()

    # Dispose of the engine
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(debug_database())
