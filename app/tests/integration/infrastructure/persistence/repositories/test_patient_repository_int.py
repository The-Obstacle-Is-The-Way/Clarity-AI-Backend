"""
Standalone integration tests for Patient operations.

This module provides self-contained tests using in-memory SQLite database with proper
foreign key constraints and test data generation. This pure implementation follows
SOLID principles with single responsibility and dependency inversion.
"""

import asyncio
import uuid
import logging
from typing import AsyncGenerator, Dict, Any, Optional
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from sqlalchemy import Column, String, Boolean, Integer, ForeignKey, text, create_engine
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.future import select

# Import encryption service
from app.infrastructure.security.encryption.base_encryption_service import BaseEncryptionService

# Setup logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create a base class for our models
TestBase = declarative_base()

# Define standard test user IDs for consistent foreign keys
TEST_USER_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
TEST_CLINICIAN_ID = uuid.UUID("00000000-0000-0000-0000-000000000002")

# Test User Model
class TestUser(TestBase):
    """User model for testing."""
    
    __tablename__ = "users"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(100), nullable=False, unique=True)
    email = Column(String(255), nullable=False, unique=True)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    role = Column(String(50), nullable=False)
    first_name = Column(String(100), nullable=True)
    last_name = Column(String(100), nullable=True)
    
    # Relationships
    patients = relationship("TestPatient", back_populates="user", cascade="all, delete-orphan")


# Test Patient Model
class TestPatient(TestBase):
    """Patient model for testing."""
    
    __tablename__ = "patients"
    
    # Core patient identity
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Status fields
    is_active = Column(Boolean, default=True, nullable=False)
    
    # User reference (created_by)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    user = relationship("TestUser", back_populates="patients")
    
    # Basic info fields (encrypted)
    first_name = Column(String(255))
    last_name = Column(String(255))
    email = Column(String(255), nullable=True)
    phone = Column(String(20), nullable=True)
    date_of_birth = Column(String(50), nullable=True)
    gender = Column(String(50), nullable=True)
    
    # Additional data
    medications_data = Column(String(2000), nullable=True)  # JSON as string


async def create_test_user(session: AsyncSession) -> TestUser:
    """Create a test user in the database."""
    test_user = TestUser(
        id=str(TEST_USER_ID),
        username="testuser",
        email="test.user@example.com",
        password_hash="hashed_password_for_testing_only",
        is_active=True,
        role="PATIENT",
        first_name="Test",
        last_name="User"
    )
    
    session.add(test_user)
    await session.commit()
    return test_user


async def create_test_patient(
    session: AsyncSession, 
    user_id: Optional[uuid.UUID] = None,
    first_name: str = "Test",
    last_name: str = "Patient",
    email: str = "test@example.com",
    phone: str = "5551234567"
) -> TestPatient:
    """Create a test patient in the database."""
    # Format the phone properly - ensure 10 digits
    if phone:
        phone = ''.join(c for c in phone if c.isdigit())
        if len(phone) < 10:
            phone = phone.ljust(10, '5')  # Pad with 5s if needed
    
    # Create the patient with proper encryption prefix pattern
    patient = TestPatient(
        id=str(uuid.uuid4()),
        user_id=str(user_id) if user_id else None,
        first_name=f"ENCRYPTED_{first_name}",
        last_name=f"ENCRYPTED_{last_name}",
        email=f"ENCRYPTED_{email}",
        phone=f"ENCRYPTED_{phone}",
        is_active=True
    )
    
    session.add(patient)
    await session.commit()
    await session.refresh(patient)
    return patient


@pytest_asyncio.fixture
async def test_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Create a test database session with all necessary tables."""
    # Create an in-memory SQLite database with foreign keys enabled
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        echo=False
    )
    
    # Create all tables
    async with engine.begin() as conn:
        # Enable foreign keys
        await conn.execute(text("PRAGMA foreign_keys = ON;"))
        # Create tables
        await conn.run_sync(TestBase.metadata.drop_all)
        await conn.run_sync(TestBase.metadata.create_all)
    
    # Create a session factory
    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    
    # Create a session
    async with session_factory() as session:
        # Create test users for foreign key references
        await create_test_user(session)
        
        # Yield the session for test use
        yield session
        
        # Rollback any changes after the test
        await session.rollback()
        logger.info("Rolled back test database session")


# Mock encryption service that safely handles None values
@pytest.fixture
def mock_encryption_service():
    """Mock encryption service for testing."""
    service = MagicMock(spec=BaseEncryptionService)
    
    def encrypt_side_effect(value):
        if value is None:
            return None
        return f"ENCRYPTED_{str(value)}"
    
    def decrypt_side_effect(value):
        if value is None:
            return None
        if isinstance(value, str) and value.startswith("ENCRYPTED_"):
            return value[10:]
        return value
    
    service.encrypt.side_effect = encrypt_side_effect
    service.decrypt.side_effect = decrypt_side_effect
    
    return service


@pytest.mark.integration
class TestPatientBasics:
    """Basic sanity tests for patient database operations."""
    
    @pytest.mark.asyncio
    async def test_create_and_get_patient(self, test_db_session: AsyncSession):
        """Test creating and retrieving a patient directly."""
        # Create a test patient with the helper function that properly handles foreign keys
        test_patient = await create_test_patient(
            session=test_db_session,
            user_id=TEST_USER_ID,
            first_name="Test",
            last_name="Patient",
            email="test@example.com",
            phone="5551234567"
        )
        
        # Retrieve the patient
        stmt = select(TestPatient).where(TestPatient.id == test_patient.id)
        result = await test_db_session.execute(stmt)
        retrieved_patient = result.scalars().first()
        
        # Verify patient was retrieved successfully
        assert retrieved_patient is not None
        assert retrieved_patient.id == test_patient.id
        assert retrieved_patient.first_name == "ENCRYPTED_Test"
        assert retrieved_patient.last_name == "ENCRYPTED_Patient"
    
    @pytest.mark.asyncio
    async def test_update_patient(self, test_db_session: AsyncSession):
        """Test updating a patient using test models."""
        # Create a test patient using helper function
        test_patient = await create_test_patient(
            session=test_db_session,
            user_id=TEST_USER_ID,
            first_name="UpdateTest",
            last_name="UpdatePatient"
        )
        
        # Update the patient
        test_patient.first_name = "ENCRYPTED_Updated"
        await test_db_session.commit()
        
        # Retrieve the updated patient
        stmt = select(TestPatient).where(TestPatient.id == test_patient.id)
        result = await test_db_session.execute(stmt)
        updated_patient = result.scalars().first()
        
        # Verify patient was updated successfully
        assert updated_patient is not None
        assert updated_patient.first_name == "ENCRYPTED_Updated"
    
    @pytest.mark.asyncio
    async def test_delete_patient(self, test_db_session: AsyncSession):
        """Test deleting a patient using test models."""
        # Create a test patient
        test_patient = await create_test_patient(
            session=test_db_session,
            user_id=TEST_USER_ID,
            first_name="DeleteTest",
            last_name="DeletePatient"
        )
        
        # Delete the patient
        await test_db_session.delete(test_patient)
        await test_db_session.commit()
        
        # Try to retrieve the patient
        stmt = select(TestPatient).where(TestPatient.id == test_patient.id)
        result = await test_db_session.execute(stmt)
        deleted_patient = result.scalars().first()
        
        # Verify patient was deleted
        assert deleted_patient is None
    
    @pytest.mark.asyncio
    async def test_get_all_patients(self, test_db_session: AsyncSession):
        """Test retrieving multiple patients using test models."""
        # Create test patients
        patient_ids = []
        
        for i in range(3):
            test_patient = await create_test_patient(
                session=test_db_session,
                user_id=TEST_USER_ID,
                first_name=f"ListTest{i}",
                last_name=f"ListPatient{i}"
            )
            patient_ids.append(test_patient.id)
        
        # Retrieve all patients
        stmt = select(TestPatient)
        result = await test_db_session.execute(stmt)
        all_patients = result.scalars().all()
        
        # Verify our test patients are in the results
        test_patients = [p for p in all_patients if p.id in patient_ids]
        assert len(test_patients) == 3
