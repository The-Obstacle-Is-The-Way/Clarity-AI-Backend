# -*- coding: utf-8 -*-
"""
Integration tests for Patient PHI encryption in the database.

This module verifies that patient PHI is properly encrypted when stored in
the database and decrypted when retrieved, according to HIPAA requirements.
"""

import uuid
import json
import pytest
import pytest_asyncio
import asyncio
from datetime import date, datetime, timezone
from typing import AsyncGenerator
from sqlalchemy import text, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

# Import domain entities with clear namespace
from app.core.domain.entities.patient import Patient as DomainPatient
from app.domain.value_objects.address import Address
from app.domain.value_objects.emergency_contact import EmergencyContact

# Import SQLAlchemy models with clear namespace
from app.infrastructure.persistence.sqlalchemy.models import User as UserModel
from app.infrastructure.persistence.sqlalchemy.models import Patient as PatientModel
from app.infrastructure.persistence.sqlalchemy.models import UserRole, Base
from app.infrastructure.security.encryption.base_encryption_service import BaseEncryptionService

import logging
logger = logging.getLogger(__name__)

# Define standard test user IDs needed for foreign keys in the real models
TEST_USER_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")

@pytest_asyncio.fixture(scope="function")
async def integration_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Provides an isolated database session using the REAL model metadata.

    This fixture sets up an in-memory SQLite database with the schema defined
    by the actual application models (inheriting from the main Base).
    It also creates a necessary test user for foreign key constraints.
    """
    db_url = "sqlite+aiosqlite:///:memory:"
    logger.info(f"[Integration Fixture] Setting up test database with REAL metadata: {db_url}")

    engine = create_async_engine(
        db_url,
        echo=False, # Set to True for debugging SQL
        connect_args={"check_same_thread": False}
    )

    async_session_factory = async_sessionmaker(
        engine,
        expire_on_commit=False,
        class_=AsyncSession
    )

    # Create all tables using the real Base metadata
    async with engine.begin() as conn:
        await conn.execute(text("PRAGMA foreign_keys=ON"))
        await conn.run_sync(Base.metadata.create_all)
        logger.info("[Integration Fixture] Created all tables using real Base metadata.")

    # Create a session and add the necessary test user using direct SQL
    # This bypasses ORM mapping issues that might occur during testing
    async with async_session_factory() as session:
        try:
            # Use direct SQL to check if user exists and create if needed
            check_user_sql = text(f"SELECT id FROM users WHERE id = :user_id")
            result = await session.execute(check_user_sql, {"user_id": str(TEST_USER_ID)})
            user_exists = result.scalar_one_or_none()
            
            if not user_exists:
                # Use direct SQL insertion to avoid ORM mapping issues
                insert_user_sql = text("""
                INSERT INTO users 
                (id, username, email, password_hash, role, roles, is_active, is_verified, email_verified, 
                 created_at, updated_at, failed_login_attempts, password_changed_at, first_name, last_name,
                 audit_id, created_by, updated_by) 
                VALUES 
                (:id, :username, :email, :password_hash, :role, :roles, :is_active, :is_verified, :email_verified, 
                 :created_at, :updated_at, :failed_login_attempts, :password_changed_at, :first_name, :last_name,
                 :audit_id, :created_by, :updated_by)
                """)
                
                # Generate a UUID for audit_id
                audit_id = str(uuid.uuid4())
                
                # Create roles JSON array as string
                roles_json = json.dumps([UserRole.PATIENT.value])
                
                # Current timestamp for created_at and updated_at
                current_time = datetime.now(timezone.utc).isoformat()
                
                await session.execute(insert_user_sql, {
                    "id": str(TEST_USER_ID),
                    "username": "integration_testuser",
                    "email": "integration.test@novamind.ai",
                    "password_hash": "hashed_password",  # Placeholder
                    "role": UserRole.PATIENT.value,  # Use string value of enum
                    "roles": roles_json,  # JSON array as string
                    "is_active": True,
                    "is_verified": True,
                    "email_verified": True,
                    "created_at": current_time,
                    "updated_at": current_time,
                    "failed_login_attempts": 0,  # Default value for required field
                    "password_changed_at": current_time,  # Set to current time
                    "first_name": "Test",  # Add sample first name
                    "last_name": "User",  # Add sample last name
                    "audit_id": audit_id,  # Add audit ID for HIPAA compliance
                    "created_by": None,  # No user created this (system-generated)
                    "updated_by": None   # No user updated this (system-generated)
                })
                
                await session.commit()
                logger.info(f"[Integration Fixture] Created necessary test user using direct SQL: {TEST_USER_ID}")
            else:
                logger.info(f"[Integration Fixture] Test user {TEST_USER_ID} already exists.")

            # Yield the session for the test
            yield session

        finally:
            # Rollback any changes made during the test
            await session.rollback()
            logger.info("[Integration Fixture] Rolled back test database session.")
            await engine.dispose()
            logger.info("[Integration Fixture] Disposed engine.")

@pytest.mark.db_required()
class TestPatientEncryptionIntegration:
    """Integration test suite for Patient model encryption with database."""
    
    @pytest.fixture
    @staticmethod
    def encryption_service():
        """Fixture for encryption service used in tests."""
        return BaseEncryptionService()
    
    @pytest.fixture
    @staticmethod
    def sample_patient():
        """Fixture for a valid sample Patient domain entity."""
        return DomainPatient(
            id=uuid.uuid4(),
            first_name="Jane",
            last_name="Smith",
            date_of_birth=date(1985, 6, 15),
            email="jane.smith@example.com",
            phone="555-987-6543",
            address=Address(
                line1="456 Oak Avenue",
                line2="Suite 201",
                city="Metropolis",
                state="NY",
                postal_code="54321",
                country="USA"
            ),
            emergency_contact=EmergencyContact(
                name="John Smith",
                phone="555-123-4567",
                relationship="Spouse"
            ),
            insurance_info={
                "provider": "Premier Health",
                "policy_number": "POL-654321",
                "group_number": "GRP-987"
            },
            active=True,
            created_by=TEST_USER_ID
        )

    @pytest.mark.asyncio
    async def test_phi_encrypted_in_database(
            self, integration_db_session: AsyncSession, sample_patient, encryption_service):
        """Test that PHI is stored encrypted in the database."""
        # Use the provided integration_db_session fixture
        db_session = integration_db_session
        
        # Convert domain entity to model and save to database
        # The conversion happens through the from_domain method
        # This ensures all fields are properly encrypted and mapped to the correct database columns
        
        # Use the from_domain method to properly convert domain entity to SQLAlchemy model with encrypted fields
        patient_model = await PatientModel.from_domain(sample_patient, encryption_service)
        
        # Save to database
        db_session.add(patient_model)
        await db_session.commit()
        await db_session.refresh(patient_model)  # Refresh after commit to get generated values

        # Verify patient was saved
        assert patient_model.id is not None

        # Get raw database data to verify encryption
        # Access raw SQL data from the database (no underscore in column names)
        query = text(
            "SELECT first_name, last_name, date_of_birth, email, phone, address_line1 "
            "FROM patients WHERE id = :id"
        )
        result = await db_session.execute(query, {"id": patient_model.id})
        row = result.fetchone()

        # Verify PHI data is stored encrypted (check that it doesn't match plaintext)
        # Note: The column names in the result don't have underscores because they're from the database
        # but the data is still encrypted and needs to be decrypted
        decrypted_first_name = encryption_service.decrypt(row.first_name)
        decrypted_last_name = encryption_service.decrypt(row.last_name)
        decrypted_dob_str = encryption_service.decrypt(row.dob)
        decrypted_email = encryption_service.decrypt(row.email)
        decrypted_phone = encryption_service.decrypt(row.phone)
        decrypted_addr1 = encryption_service.decrypt(row.address_line1)

        assert decrypted_first_name == sample_patient.first_name
        assert decrypted_last_name == sample_patient.last_name
        assert decrypted_dob_str == sample_patient.date_of_birth.isoformat()
        assert decrypted_email == sample_patient.email
        assert decrypted_phone == sample_patient.phone
        assert decrypted_addr1 == sample_patient.address.line1

        # Check original encrypted values don't match plaintext
        assert row._first_name != sample_patient.first_name
        assert row._email != sample_patient.email

    @pytest.mark.asyncio
    async def test_phi_decrypted_in_repository(
        self, integration_db_session: AsyncSession, sample_patient):
        """Test that PHI is automatically decrypted when retrieved through repository."""
        db_session = integration_db_session
        
        # Create a patient model and save to database
        encryption_service = BaseEncryptionService()
        patient_model = await PatientModel.from_domain(sample_patient, encryption_service)
        db_session.add(patient_model)
        await db_session.commit()
        patient_id = patient_model.id
        await db_session.refresh(patient_model)
        
        # Clear session cache to ensure we're retrieving from DB
        retrieved_model = await db_session.get(PatientModel, patient_id)
        assert retrieved_model is not None

        # Convert back to domain using the model's method
        retrieved_patient = await retrieved_model.to_domain(encryption_service)

        # Verify PHI fields are correctly decrypted
        assert retrieved_patient.id == sample_patient.id
        assert retrieved_patient.first_name == sample_patient.first_name
        assert retrieved_patient.last_name == sample_patient.last_name
        assert retrieved_patient.date_of_birth == sample_patient.date_of_birth
        assert retrieved_patient.email == sample_patient.email
        assert retrieved_patient.phone == sample_patient.phone

        # Verify complex PHI objects are decrypted
        assert retrieved_patient.address.line1 == sample_patient.address.line1
        assert retrieved_patient.address.city == sample_patient.address.city

        assert retrieved_patient.emergency_contact.name == sample_patient.emergency_contact.name
        assert retrieved_patient.emergency_contact.phone == sample_patient.emergency_contact.phone

        # Verify insurance_info dictionary
        assert retrieved_patient.insurance_info["provider"] == sample_patient.insurance_info["provider"]
        assert retrieved_patient.insurance_info["policy_number"] == sample_patient.insurance_info["policy_number"]

    @pytest.mark.asyncio
    async def test_encryption_error_handling(
        self, integration_db_session: AsyncSession):
        """Test that encryption/decryption errors are handled gracefully."""
        db_session = integration_db_session
        
        # Create patient with an ID that can be referenced
        patient_id = uuid.uuid4()
        patient = Patient(
            id=patient_id,
            first_name="ErrorTest",
            last_name="Patient",
            date_of_birth=date(1990, 1, 1),
            email="errortest@example.com",
            phone="555-555-5555",
            address=None,  # Test with minimal data
            emergency_contact=None,
            insurance_info=None, # Use insurance_info consistently
            active=True,
            created_by=TEST_USER_ID
        )

        # Save to database
        encryption_service = BaseEncryptionService()
        patient_model = await PatientModel.from_domain(patient, encryption_service)
        db_session.add(patient_model)
        await db_session.commit()
        await db_session.refresh(patient_model)

        # Manually corrupt the encrypted data
        await db_session.execute(
            text("UPDATE patients SET _first_name = :corrupt WHERE id = :id"),
            {"corrupt": b"CORRUPTED_DATA", "id": patient_id}
        )
        await db_session.commit()

        # Retrieve patient model
        retrieved_model = await db_session.get(PatientModel, patient_id)
        assert retrieved_model is not None

        # Convert to domain - this should handle the decryption error gracefully
        retrieved_patient = await retrieved_model.to_domain(encryption_service)

        # The decryption failure for first_name should result in None
        assert retrieved_patient.id == patient_id
        assert retrieved_patient.first_name is None, "Decryption failure should yield None"
        # Other fields should decrypt correctly
        assert retrieved_patient.last_name == patient.last_name
        assert retrieved_patient.email == patient.email
