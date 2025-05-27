"""
QUANTUM DATABASE INITIALIZER

This module provides a direct, guaranteed solution for database initialization
in tests. It ensures that all required tables are created in the correct order
with proper foreign key relationships.
"""

import asyncio
import logging
import sys
import uuid
from datetime import timezone, datetime
from pathlib import Path

# Import SQLAlchemy components
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Add the backend directory to sys.path if needed
current_file_path = Path(__file__)
backend_dir = current_file_path.parent.parent.parent.resolve()

if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

# Import application components
from app.core.config import settings
from app.core.security.passwords import get_password_hash
from app.infrastructure.database.base import Base

# Import model classes to register with metadata
try:
    PATIENT_IMPORTED = True
except Exception as e:
    logger.error(f"Error importing Patient model: {e}")
    PATIENT_IMPORTED = False

# Constants for test users
TEST_USER_ID = uuid.UUID("a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11")
TEST_CLINICIAN_ID = uuid.UUID("a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a12")
TEST_USER_EMAIL = "test.user@novamind.ai"
TEST_CLINICIAN_EMAIL = "test.clinician@novamind.ai"
TEST_PASSWORD_HASH = get_password_hash("testpassword")

# Direct SQL statements for table creation
DIRECT_SQL = {
    "enable_foreign_keys": """
    PRAGMA foreign_keys = ON;
    """,
    "users": """
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_active BOOLEAN NOT NULL DEFAULT 1,
        is_verified BOOLEAN NOT NULL DEFAULT 0,
        email_verified BOOLEAN NOT NULL DEFAULT 0,
        role TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP NULL,
        failed_login_attempts INTEGER DEFAULT 0,
        account_locked_until TIMESTAMP NULL,
        password_changed_at TIMESTAMP NULL,
        reset_token TEXT NULL,
        reset_token_expires_at TIMESTAMP NULL,
        verification_token TEXT NULL,
        first_name TEXT NULL,
        last_name TEXT NULL
    );
    """,
    "patients": """
    CREATE TABLE IF NOT EXISTS patients (
        id TEXT PRIMARY KEY,
        user_id TEXT NULL REFERENCES users(id),
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN NOT NULL DEFAULT 1,
        
        -- PHI fields
        first_name TEXT NULL,
        last_name TEXT NULL,
        date_of_birth TEXT NULL,
        email TEXT NULL,
        phone TEXT NULL,
        medical_record_number TEXT NULL,
        insurance_number TEXT NULL,
        gender TEXT NULL,
        allergies TEXT NULL,
        medications TEXT NULL,
        medical_history TEXT NULL,
        treatment_notes TEXT NULL,
        extra_data TEXT NULL,
        
        -- Address fields
        address_line1 TEXT NULL,
        address_line2 TEXT NULL,
        city TEXT NULL,
        state TEXT NULL,
        postal_code TEXT NULL,
        country TEXT NULL,
        
        -- Emergency contact
        emergency_contact TEXT NULL,
        
        -- Digital twin relationship
        biometric_twin_id TEXT NULL
    );
    """,
}


async def table_exists(session: AsyncSession, table_name: str) -> bool:
    """
    Check if a table exists in the SQLite database.
    Uses parameterized query to prevent SQL injection.
    """
    try:
        query = text("SELECT name FROM sqlite_master WHERE type='table' AND name=:table_name")
        result = await session.execute(query, {"table_name": table_name})
        exists = result.scalar() is not None
        logger.debug(f"Table '{table_name}' exists check result: {exists}")
        return exists
    except Exception as e:
        logger.error(f"Error checking if table {table_name} exists: {e}")
        return False


async def verify_table_exists(session: AsyncSession, table_name: str) -> bool:
    """
    Verify that a table exists in the database.

    Args:
        session: SQLAlchemy AsyncSession
        table_name: Name of the table to check

    Returns:
        bool: True if table exists, False otherwise
    """
    try:
        exists = await table_exists(session, table_name)

        if exists:
            # Also verify table has data structure by counting columns
            columns_query = text(f"PRAGMA table_info({table_name})")
            columns_result = await session.execute(columns_query)
            columns = columns_result.fetchall()
            logger.info(f"Table {table_name} exists with {len(columns)} columns")
            column_names = [col[1] for col in columns]
            logger.info(f"Columns: {column_names}")
            return len(columns) > 0
        return False
    except Exception as e:
        logger.error(f"Error verifying table {table_name}: {e}")
        return False


async def create_test_users(session: AsyncSession) -> None:
    """
    Create standard test users in the database if they don't already exist.
    """
    logger.info("Creating test users for foreign key relationships")

    # Check if test user exists
    query = text("SELECT id FROM users WHERE id = :user_id")
    result = await session.execute(query, {"user_id": TEST_USER_ID})
    test_user_exists = result.scalar() is not None

    # Check if test clinician exists
    query = text("SELECT id FROM users WHERE id = :user_id")
    result = await session.execute(query, {"user_id": TEST_CLINICIAN_ID})
    test_clinician_exists = result.scalar() is not None

    # Create test user if not exists
    if not test_user_exists:
        logger.info(f"Creating test user with ID: {TEST_USER_ID}")
        query = text(
            """
        INSERT INTO users (id, username, email, password_hash, is_active, 
                         is_verified, email_verified, role, created_at, updated_at)
        VALUES (:id, :username, :email, :password_hash, :is_active, 
                :is_verified, :email_verified, :role, :created_at, :updated_at)
        """
        )

        await session.execute(
            query,
            {
                "id": TEST_USER_ID,
                "username": "testuser",
                "email": TEST_USER_EMAIL,
                "password_hash": TEST_PASSWORD_HASH,
                "is_active": True,
                "is_verified": True,
                "email_verified": True,
                "role": "PATIENT",
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc),
            },
        )

    # Create test clinician if not exists
    if not test_clinician_exists:
        logger.info(f"Creating test clinician with ID: {TEST_CLINICIAN_ID}")
        query = text(
            """
        INSERT INTO users (id, username, email, password_hash, is_active, 
                         is_verified, email_verified, role, created_at, updated_at)
        VALUES (:id, :username, :email, :password_hash, :is_active, 
                :is_verified, :email_verified, :role, :created_at, :updated_at)
        """
        )

        await session.execute(
            query,
            {
                "id": TEST_CLINICIAN_ID,
                "username": "testclinician",
                "email": TEST_CLINICIAN_EMAIL,
                "password_hash": TEST_PASSWORD_HASH,
                "is_active": True,
                "is_verified": True,
                "email_verified": True,
                "role": "CLINICIAN",
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc),
            },
        )

    await session.commit()

    # Verify users were created
    query = text("SELECT id FROM users WHERE id = ANY(:user_ids)")
    result = await session.execute(query, {"user_ids": [TEST_USER_ID, TEST_CLINICIAN_ID]})
    users = result.fetchall()
    if len(users) != 2:
        logger.error(f"Failed to verify test users. Found {len(users)}.")
    logger.info(f"Verified {len(users)}/2 test users exist")


async def initialize_database() -> None:
    """
    Initialize the database with all required tables and test data.
    """
    logger.info("QUANTUM DATABASE INITIALIZER: Starting database initialization")

    engine = create_async_engine(settings.SQLALCHEMY_TEST_DATABASE_URI, echo=False)
    async_session_local = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async with engine.begin() as conn:
        logger.info("Dropping all tables if they exist...")
        await conn.run_sync(Base.metadata.drop_all)
        logger.info("Creating all tables...")
        await conn.run_sync(Base.metadata.create_all)

    async with async_session_local() as session:
        await create_test_users(session)

    logger.info("Database initialization complete.")


if __name__ == "__main__":
    asyncio.run(initialize_database())
