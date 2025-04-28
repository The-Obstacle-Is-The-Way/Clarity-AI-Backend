# -*- coding: utf-8 -*-
"""
Integration tests for Patient PHI encryption in the database.

This module verifies that patient PHI is properly encrypted when stored in
the database and decrypted when retrieved, according to HIPAA requirements.
"""

import uuid
import pytest
import pytest_asyncio
import asyncio
from datetime import date
from typing import AsyncGenerator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from app.domain.entities.patient import Patient
from app.domain.value_objects.address import Address
from app.domain.value_objects.emergency_contact import EmergencyContact
# Removed import of non-existent Insurance value object
from app.infrastructure.persistence.sqlalchemy.models.patient import Patient as PatientModel
from app.infrastructure.persistence.sqlalchemy.models.user import User as UserModel, UserRole
from app.infrastructure.persistence.sqlalchemy.models.base import Base
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

    # Create a session and add the necessary test user
    async with async_session_factory() as session:
        try:
            # Check if test user exists (necessary for patient.user_id foreign key)
            result = await session.execute(select(UserModel).where(UserModel.id == TEST_USER_ID))
            if not result.scalar_one_or_none():
                test_user = UserModel(
                    id=TEST_USER_ID,
                    username="integration_testuser",
                    email="integration.test@novamind.ai",
                    password_hash="hashed_password", # Placeholder
                    role=UserRole.PATIENT, # Example role
                    is_active=True,
                    is_verified=True,
                    email_verified=True
                )
                session.add(test_user)
                await session.commit()
                logger.info(f"[Integration Fixture] Created necessary test user: {TEST_USER_ID}")
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
    def sample_patient():
        """Fixture for a valid sample Patient domain entity."""
        return Patient(
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
            self, integration_db_session: AsyncSession, sample_patient):
        """Test that PHI is stored encrypted in the database."""
        # Use the provided integration_db_session fixture
        db_session = integration_db_session 
        
        # Convert domain entity to model and save to database
        patient_model = await PatientModel.from_domain(sample_patient, encryption_service)
        db_session.add(patient_model)
        await db_session.commit()
        await db_session.refresh(patient_model) # Refresh after commit

        # Verify patient was saved
        assert patient_model.id is not None

        # Get raw database data to verify encryption
        query = text(
            "SELECT _first_name, _last_name, _dob, _email, _phone, _address_line1 "
            "FROM patients WHERE id = :id"
        )
        result = await db_session.execute(query, {"id": patient_model.id})
        row = result.fetchone()

        # Verify PHI data is stored encrypted (check that it doesn't match plaintext)
        decrypted_first_name = encryption_service.decrypt(row._first_name)
        decrypted_last_name = encryption_service.decrypt(row._last_name)
        decrypted_dob_str = encryption_service.decrypt(row._dob)
        decrypted_email = encryption_service.decrypt(row._email)
        decrypted_phone = encryption_service.decrypt(row._phone)
        decrypted_addr1 = encryption_service.decrypt(row._address_line1)

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
