"""
QUANTUM DATABASE INITIALIZER

This module provides a direct, guaranteed solution for database initialization
in tests. It ensures that all required tables are created in the correct order
with proper foreign key relationships.
"""

import asyncio
import logging
import os
import sys
import uuid
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger(__name__)

# Add the backend directory to sys.path if needed
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# Import SQLAlchemy components
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Import application components

# Import model classes to register with metadata
try:
    PATIENT_IMPORTED = True
except Exception as e:
    logger.error(f"Error importing Patient model: {e}")
    PATIENT_IMPORTED = False

# Constants for test users
TEST_USER_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
TEST_CLINICIAN_ID = uuid.UUID("00000000-0000-0000-0000-000000000002")
TEST_USER_EMAIL = "test.user@novamind.ai"
TEST_CLINICIAN_EMAIL = "test.clinician@novamind.ai"
TEST_PASSWORD_HASH = "hashed_password_for_testing_only"

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
    """
}

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
        query = text(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table_name}'")
        result = await session.execute(query)
        exists = result.scalar() is not None
        
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
    query = text(f"SELECT id FROM users WHERE id = '{TEST_USER_ID}'")
    result = await session.execute(query)
    test_user_exists = result.scalar() is not None
    
    # Check if test clinician exists
    query = text(f"SELECT id FROM users WHERE id = '{TEST_CLINICIAN_ID}'")
    result = await session.execute(query)
    test_clinician_exists = result.scalar() is not None
    
    # Create test user if not exists
    if not test_user_exists:
        logger.info(f"Creating test user with ID: {TEST_USER_ID}")
        query = text("""
        INSERT INTO users (id, username, email, password_hash, is_active, is_verified, email_verified, role, created_at, updated_at)
        VALUES (:id, :username, :email, :password_hash, :is_active, :is_verified, :email_verified, :role, :created_at, :updated_at)
        """)
        
        await session.execute(query, {
            "id": str(TEST_USER_ID),
            "username": "testuser",
            "email": TEST_USER_EMAIL,
            "password_hash": TEST_PASSWORD_HASH,
            "is_active": True,
            "is_verified": True,
            "email_verified": True,
            "role": "PATIENT",
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        })
    
    # Create test clinician if not exists
    if not test_clinician_exists:
        logger.info(f"Creating test clinician with ID: {TEST_CLINICIAN_ID}")
        query = text("""
        INSERT INTO users (id, username, email, password_hash, is_active, is_verified, email_verified, role, created_at, updated_at)
        VALUES (:id, :username, :email, :password_hash, :is_active, :is_verified, :email_verified, :role, :created_at, :updated_at)
        """)
        
        await session.execute(query, {
            "id": str(TEST_CLINICIAN_ID),
            "username": "testclinician",
            "email": TEST_CLINICIAN_EMAIL,
            "password_hash": TEST_PASSWORD_HASH,
            "is_active": True,
            "is_verified": True,
            "email_verified": True,
            "role": "CLINICIAN",
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        })
    
    await session.commit()
    
    # Verify users were created
    query = text("SELECT id FROM users WHERE id = ANY(:user_ids)")
    result = await session.execute(query, {"user_ids": [TEST_USER_ID, TEST_CLINICIAN_ID]})
    users = result.fetchall()
    if len(users) != 2:
        logger.error(f"Failed to verify test users. Found {len(users)}.")
    logger.info(f"Verified {len(users)}/2 test users exist")

async def initialize_database():
    """
    Initialize the database with all required tables and test data.
    """
    logger.info("QUANTUM DATABASE INITIALIZER: Starting database initialization")
    
    # Create in-memory SQLite database
    db_url = "sqlite+aiosqlite:///:memory:"
    engine = create_async_engine(db_url, echo=True)
    
    # Create session factory
    async_session_factory = async_sessionmaker(
        bind=engine,
        expire_on_commit=False,
        autoflush=False,
        class_=AsyncSession
    )
    
    # Create session
    async with async_session_factory() as session:
        try:
            # Enable foreign keys - CRITICAL STEP
            logger.info("Enabling foreign keys in SQLite")
            await session.execute(text(DIRECT_SQL["enable_foreign_keys"]))
            
            # Create tables in correct order
            logger.info("Creating users table")
            await session.execute(text(DIRECT_SQL["users"]))
            await session.commit()
            
            # Verify users table was created
            if not await verify_table_exists(session, "users"):
                raise RuntimeError("Failed to create users table")
                
            logger.info("Creating patients table")
            await session.execute(text(DIRECT_SQL["patients"]))
            await session.commit()
            
            # Verify patients table was created
            if not await verify_table_exists(session, "patients"):
                raise RuntimeError("Failed to create patients table")
            
            # Create test users
            await create_test_users(session)
            
            # Final verification
            logger.info("Verifying all tables")
            query = text("SELECT name FROM sqlite_master WHERE type='table'")
            result = await session.execute(query)
            all_tables = [row[0] for row in result]
            logger.info(f"Tables in database: {all_tables}")
            
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
            
            logger.info("QUANTUM DATABASE INITIALIZER: Completed successfully")
        except Exception as e:
            logger.error(f"Error during database initialization: {e}")
            await session.rollback()
            raise
        finally:
            await session.close()
    
    # Dispose of the engine
    await engine.dispose()

if __name__ == "__main__":
    asyncio.run(initialize_database()) 