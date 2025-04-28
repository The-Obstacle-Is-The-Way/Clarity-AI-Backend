"""
Test Database Initializer

This module provides a standardized, production-quality approach to database initialization
for integration tests. It ensures consistent table creation and foreign key relationships,
regardless of the actual database schema state.

Features:
1. In-memory SQLite database with foreign keys enabled for fast test execution
2. Complete test schema based on domain models
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

from sqlalchemy import Column, String, Boolean, Integer, ForeignKey, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.future import select

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create a base class for our models
TestBase = declarative_base()

# Define standard test user IDs for consistent foreign keys
TEST_USER_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
TEST_CLINICIAN_ID = uuid.UUID("00000000-0000-0000-0000-000000000002")

# Test User Model
class TestUser(TestBase):
    """User model for testing database initialization."""
    
    __tablename__ = "users"
    __table_args__ = {'extend_existing': True}
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(100), nullable=False, unique=True)
    email = Column(String(255), nullable=False, unique=True)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    email_verified = Column(Boolean, default=False, nullable=False)
    role = Column(String(50), nullable=False)
    created_at = Column(String, default=lambda: datetime.now(timezone.utc).isoformat(), nullable=False)
    updated_at = Column(String, default=lambda: datetime.now(timezone.utc).isoformat(), nullable=False)
    last_login = Column(String, nullable=True)
    failed_login_attempts = Column(Integer, default=0)
    account_locked_until = Column(String, nullable=True)
    password_changed_at = Column(String, nullable=True)
    reset_token = Column(String(255), nullable=True)
    reset_token_expires_at = Column(String, nullable=True)
    verification_token = Column(String(255), nullable=True)
    first_name = Column(String(100), nullable=True)
    last_name = Column(String(100), nullable=True)
    
    # Relationships
    patients = relationship("TestPatient", back_populates="user", cascade="all, delete-orphan")

# Test Patient Model
class TestPatient(TestBase):
    """Patient model for testing database initialization.
    
    This comprehensive model includes all fields needed for integration tests,
    ensuring proper handling of foreign keys, value objects, and encryption.
    """
    
    __tablename__ = "patients"
    __table_args__ = {'extend_existing': True}
    
    # Core patient identity
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Status fields
    is_active = Column(Boolean, default=True, nullable=False)
    
    # User reference (created_by)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    user = relationship("TestUser", back_populates="patients")
    
    # Timestamps
    created_at = Column(String(50), default=lambda: datetime.now(timezone.utc).isoformat())
    updated_at = Column(String(50), default=lambda: datetime.now(timezone.utc).isoformat(), onupdate=lambda: datetime.now(timezone.utc).isoformat())
    version = Column(Integer, default=1)
    
    # Basic info fields (encrypted)
    first_name = Column(String(255))
    last_name = Column(String(255))
    date_of_birth = Column(String(50), nullable=True)  # Use string for dates in SQLite
    gender = Column(String(50), nullable=True)
    
    # Contact info (encrypted)
    email = Column(String(255), nullable=True)
    phone = Column(String(50), nullable=True)
    address = Column(String(1024), nullable=True)  # JSON address object
    
    # Address components (for backward compatibility)
    address_line1 = Column(String(255), nullable=True)
    address_line2 = Column(String(255), nullable=True)
    city = Column(String(100), nullable=True)
    state = Column(String(100), nullable=True)
    postal_code = Column(String(20), nullable=True)  # Also zip_code in some places
    zip_code = Column(String(20), nullable=True)     # Both needed for compatibility
    country = Column(String(100), nullable=True)
    
    # Medical identifiers (encrypted)
    medical_record_number = Column(String(100), nullable=True)
    insurance_number = Column(String(100), nullable=True)
    ssn = Column(String(15), nullable=True)
    
    # Medical info (encrypted)
    emergency_contact = Column(String(1024), nullable=True)  # JSON emergency contact
    medications_data = Column(String(2048), nullable=True)  # JSON medications data
    allergies = Column(String(1024), nullable=True)
    medications = Column(String(2048), nullable=True)
    medical_history = Column(String(4096), nullable=True)
    treatment_notes = Column(String(4096), nullable=True)
    
    # Extra data storage
    extra_data = Column(String(4096), nullable=True)  # For flexible JSON data
    biometric_twin_id = Column(String(100), nullable=True)
    external_id = Column(String(64), nullable=True)
    
    # Relationships
    user = relationship("TestUser", back_populates="patients")

async def create_test_users(session: AsyncSession) -> None:
    """Create standard test users in the database if they don't already exist."""
    
    # Check if test users exist
    result = await session.execute(select(TestUser).where(
        TestUser.id.in_([TEST_USER_ID, TEST_CLINICIAN_ID])
    ))
    existing_users = result.scalars().all()
    existing_ids = [user.id for user in existing_users]
    
    # Create test patient user if not exists
    if TEST_USER_ID not in existing_ids:
        test_user = TestUser(
            id=TEST_USER_ID,
            username="testuser",
            email="test.user@novamind.ai",
            password_hash="hashed_password_for_testing_only",
            is_active=True,
            is_verified=True,
            email_verified=True,
            role="PATIENT",
            first_name="Test",
            last_name="User"
        )
        session.add(test_user)
    
    # Create test clinician user if not exists
    if TEST_CLINICIAN_ID not in existing_ids:
        test_clinician = TestUser(
            id=TEST_CLINICIAN_ID,
            username="testclinician",
            email="test.clinician@novamind.ai",
            password_hash="hashed_password_for_testing_only",
            is_active=True,
            is_verified=True,
            email_verified=True,
            role="PROVIDER",
            first_name="Test",
            last_name="Clinician"
        )
        session.add(test_clinician)
    
    await session.commit()
    logger.info(f"Test users initialized with IDs: {TEST_USER_ID}, {TEST_CLINICIAN_ID}")

async def get_test_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Create a test database session with all tables created and test users inserted.
    
    This function:
    1. Creates an in-memory SQLite database with foreign keys enabled
    2. Creates all tables defined in the TestBase metadata
    3. Creates test users for foreign key relationships
    4. Yields a session for test use
    5. Rolls back and closes the session after test
    
    Yields:
        AsyncSession: SQLAlchemy async session with test users created
    """
    # Use in-memory SQLite for fastest tests with no file conflicts
    db_url = "sqlite+aiosqlite:///:memory:"
    
    logger.info(f"Setting up test database with URL: {db_url}")
    
    # Create engine with foreign keys enabled
    engine = create_async_engine(
        db_url,
        echo=False,
        connect_args={"check_same_thread": False}
    )
    
    # Create session factory
    async_session = async_sessionmaker(
        engine,
        expire_on_commit=False,
        class_=AsyncSession
    )
    
    # Create all tables
    async with engine.begin() as conn:
        # Enable foreign keys in SQLite
        await conn.execute(text("PRAGMA foreign_keys=ON"))
        
        # Create all tables
        await conn.run_sync(TestBase.metadata.create_all)
        logger.info("Created all tables in test database")
    
    # Create a session
    async with async_session() as session:
        # Create test users
        await create_test_users(session)
        
        # Yield the session for test use
        yield session
        
        # Rollback any changes made during the test
        await session.rollback()
        logger.info("Rolled back test database session")

async def create_test_patient(
    session: AsyncSession, 
    user_id: Optional[uuid.UUID] = None,
    first_name: str = "Test",
    last_name: str = "Patient",
    email: str = "testpatient@example.com",
    phone: str = "5551234567",  # Ensure 10 digits with no separators
    ssn: Optional[str] = None,
    date_of_birth: Optional[Union[str, date]] = None
) -> TestPatient:
    """
    Create a test patient in the database with all required fields.
    
    Args:
        session: SQLAlchemy async session
        user_id: UUID of the user to associate with the patient (default: None)
        first_name: First name of the patient (default: "Test")
        last_name: Last name of the patient (default: "Patient")
        email: Email of the patient (default: "testpatient@example.com")
        phone: Phone number of the patient (default: "5551234567")
        ssn: Social Security Number (default: None)
        date_of_birth: Date of birth (default: None)
        
    Returns:
        TestPatient: The created patient with all required fields
    """
    # Create patient object with all required fields
    patient = TestPatient(
        id=str(uuid.uuid4()),
        user_id=str(user_id) if user_id else None,
        first_name=first_name,
        last_name=last_name,
        email=email,
        phone=phone,
        ssn=ssn,
        is_active=True,
        version=1,
    )
    
    # Set date of birth if provided
    if date_of_birth:
        if isinstance(date_of_birth, date):
            patient.date_of_birth = date_of_birth.isoformat()
        else:
            patient.date_of_birth = str(date_of_birth)
    else:
        # Default to a sensible date of birth
        patient.date_of_birth = "1980-01-01"
    
    # Add gender and additional fields for completeness
    patient.gender = "male" if random.randint(0, 1) else "female"
    
    # Prepare address data in JSON format
    address_data = {
        "line1": "123 Test St",
        "line2": "Apt B",
        "city": "Test City",
        "state": "TS",
        "zip_code": "12345",
        "country": "USA"
    }
    
    # Set address fields as both JSON and individual fields for compatibility
    patient.address = json.dumps(address_data)
    patient.address_line1 = address_data["line1"]
    patient.address_line2 = address_data["line2"]
    patient.city = address_data["city"]
    patient.state = address_data["state"]
    patient.zip_code = address_data["zip_code"]
    patient.postal_code = address_data["zip_code"]
    patient.country = address_data["country"]
    
    # Add emergency contact info
    emergency_data = {
        "name": "Emergency Contact",
        "relationship": "Family",
        "phone": "5559876543"
    }
    patient.emergency_contact = json.dumps(emergency_data)
    
    # Add to the session
    session.add(patient)
    await session.flush()
    
    return patient

async def verify_table_exists(session: AsyncSession, table_name: str) -> bool:
    """
    Verify that a table exists in the database.
    
    Args:
        session: SQLAlchemy async session
        table_name: Name of the table to check
        
    Returns:
        bool: True if table exists with columns, False otherwise
    """
    try:
        result = await session.execute(text(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table_name}'"))
        exists = result.scalar() is not None
        
        if exists:
            # Also verify table has data structure by counting columns
            result = await session.execute(text(f"PRAGMA table_info({table_name})"))
            columns = result.fetchall()
            column_names = [col[1] for col in columns]
            logger.info(f"Table {table_name} exists with {len(columns)} columns: {column_names}")
            return len(columns) > 0
        
        logger.error(f"Table {table_name} does not exist")
        return False
    except Exception as e:
        logger.error(f"Error verifying table {table_name}: {e}")
        return False
