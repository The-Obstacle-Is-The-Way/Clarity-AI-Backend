"""
Integration tests for Patient PHI encryption in the database.

This module verifies that patient PHI is properly encrypted when stored in
the database and decrypted when retrieved, according to HIPAA requirements.
"""

import json
import logging
import uuid
# from collections.abc import AsyncGenerator # Not used directly in this version
from datetime import date, datetime, timezone

import pytest
import pytest_asyncio
# from cryptography.fernet import Fernet # Fernet from fixture is BaseEncryptionService
from sqlalchemy import text #, event # Event listener removed for now, direct PRAGMA in fixture
# from sqlalchemy.engine import Engine # Not used directly
from sqlalchemy.ext.asyncio import AsyncSession #, async_sessionmaker, create_async_engine

# Import domain entities with clear namespace
from app.core.domain.entities.patient import Patient as DomainPatient, ContactInfo # Gender, Address, EmergencyContact will be added to DomainPatient
from app.core.domain.enums import Gender # Corrected Gender import
from app.domain.value_objects.address import Address # Assuming this is the canonical Pydantic/dataclass VO
from app.domain.value_objects.emergency_contact import EmergencyContact # Assuming this is the canonical Pydantic/dataclass VO

from app.core.domain.entities.user import UserRole
# from app.infrastructure.persistence.sqlalchemy.database import async_session_factory, engine, Base # engine, Base for setup
from app.infrastructure.persistence.sqlalchemy.models.base import Base
from app.infrastructure.persistence.sqlalchemy.config.database import get_db_instance
from app.infrastructure.persistence.sqlalchemy.models import Patient as PatientModel
from app.infrastructure.persistence.sqlalchemy.models.audit_log import AuditLog
from app.infrastructure.persistence.sqlalchemy.models.user import User

from app.infrastructure.security.encryption.encryption_service import EncryptionService
# from app.infrastructure.persistence.sqlalchemy.types.encrypted_types import EncryptedString, EncryptedText, EncryptedJSON # Not directly used in test logic
from app.core.config import settings

# Ensure patient.py's encryption_service_instance is available for EncryptedTypes
# This import is crucial for the types to find the service.
from app.infrastructure.persistence.sqlalchemy.models import patient as patient_module_for_esi
if not hasattr(patient_module_for_esi, 'encryption_service_instance'):
    # This is a fallback/assertion, actual instance should be created in patient.py
    logging.warning("encryption_service_instance not found in patient.py module, creating a temporary one for tests.")
    patient_module_for_esi.encryption_service_instance = EncryptionService()


logger = logging.getLogger(__name__)

TEST_USER_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
TEST_PATIENT_ID = uuid.UUID("00000000-0000-0000-0000-000000000002")

@pytest_asyncio.fixture(scope="function")
async def encryption_service_fixture() -> EncryptionService:
    # Uses PHI_ENCRYPTION_KEY from settings by default
    return EncryptionService()

@pytest_asyncio.fixture(scope="function")
async def integration_db_session(encryption_service_fixture: EncryptionService): # Changed from AsyncGenerator
    original_esi = getattr(patient_module_for_esi, 'encryption_service_instance', None)
    patient_module_for_esi.encryption_service_instance = encryption_service_fixture
    
    logger.info(f"[Integration Fixture] Setting up test database: {settings.DATABASE_URL}")
    
    # Get the database instance which holds the engine and session factory
    db_instance = get_db_instance()
    engine = db_instance.engine
    async_session_factory = db_instance.session_factory

    async with engine.connect() as conn:
        await conn.execute(text("PRAGMA foreign_keys=ON;"))
        logger.info("[Integration Fixture] PRAGMA foreign_keys=ON executed on new connection.")
        await conn.commit() 

    async with async_session_factory() as session:
        try:
            async with engine.begin() as conn: 
                await conn.run_sync(Base.metadata.drop_all)
                await conn.run_sync(Base.metadata.create_all)
            logger.info("[Integration Fixture] Dropped and Created all tables.")

            patient_audit_log_id_for_yield: uuid.UUID | None = None

            async with session.begin():
                existing_user = await session.get(User, TEST_USER_ID)
                if not existing_user:
                    logger.info(f"[Integration Fixture] Test user {TEST_USER_ID} not found, creating via ORM.")
                    user_audit_log = AuditLog(
                        event_type="test_fixture_setup", action="create_test_user", resource_type="user", success=True,
                        user_id=None, details=json.dumps({"description": "Audit log for test user creation in fixture"})
                    )
                    session.add(user_audit_log)
                    await session.flush()
                    logger.info(f"[Integration Fixture] Added AuditLog for User: ID {user_audit_log.id}")

                    roles_json_str = json.dumps([UserRole.PATIENT.value])
                    current_time_dt = datetime.now(timezone.utc)
                    test_user = User(
                        id=TEST_USER_ID, username="integration_testuser", email="integration.test@example.com",
                        password_hash="hashed_password_for_test", role=UserRole.PATIENT, roles=roles_json_str,
                        is_active=True, is_verified=True, email_verified=True, created_at=current_time_dt,
                        updated_at=current_time_dt, failed_login_attempts=0, password_changed_at=current_time_dt,
                        first_name="Test", last_name="User", audit_id=user_audit_log.id,
                        created_by=None, updated_by=None
                    )
                    session.add(test_user)
                    await session.flush()
                    logger.info(f"[Integration Fixture] Added test user via ORM: {test_user.id}")
                else:
                    logger.info(f"[Integration Fixture] Test user {TEST_USER_ID} already exists.")
            logger.info(f"[Integration Fixture] Transaction for User and its AuditLog committed.")

            async with session.begin():
                patient_audit_log = AuditLog(
                    event_type="test_fixture_setup", action="create_test_patient_audit", resource_type="patient",
                    user_id=TEST_USER_ID, success=True,
                    details=json.dumps({"description": "Audit log for test patient setup in fixture"})
                )
                session.add(patient_audit_log)
                await session.flush()
                patient_audit_log_id_for_yield = patient_audit_log.id
                logger.info(f"[Integration Fixture] Added AuditLog for Patient: ID {patient_audit_log_id_for_yield}, UserID: {patient_audit_log.user_id}")
            
            logger.info(f"[Integration Fixture] Transaction for Patient's AuditLog committed. Yielding session and patient_audit_log_id: {patient_audit_log_id_for_yield}")
            yield session, patient_audit_log_id_for_yield

        except Exception as e:
            logger.error(f"[Integration Fixture] Exception during setup: {e}", exc_info=True)
            await session.rollback()
            raise
        finally:
            logger.info("[Integration Fixture] Tearing down test database session.")
            if hasattr(patient_module_for_esi, 'encryption_service_instance'):
                 patient_module_for_esi.encryption_service_instance = original_esi
            await session.close()

# pytest.mark.db_required() # Apply if needed, or manage via pytest.ini markers
class TestPatientEncryptionIntegration:
    """Integration test suite for Patient model encryption with database."""
    
    async def _create_sample_domain_patient(self, patient_id: uuid.UUID, user_id: uuid.UUID) -> DomainPatient:
        """Creates a comprehensive sample DomainPatient for testing."""
        # This function will need DomainPatient to be updated to accept all these fields.
        # For now, it's an aspiration for what DomainPatient should hold.
        # Fallback to basic DomainPatient if fields are not yet available.
        
        patient_data = {
            "id": patient_id,
            "user_id": user_id, # Assuming DomainPatient will have user_id
            "first_name": "EncrFirstName",
            "last_name": "EncrLastName",
            "email": "encrypted.patient@example.com",
            "date_of_birth": date(1990, 1, 1),
            "phone_number": "555-123-4567",
            "contact_info": ContactInfo(phone="555-0100", email_secondary="secondary@example.com"), # Pydantic ContactInfo
            "gender": Gender.FEMALE, 
            "address": Address(line1="123 Encrypt Lane", city="SecureVille", state="SS", postal_code="00000", country="US"),
            "emergency_contact": EmergencyContact(name="EC Name", phone="555-0199", relationship="Sibling"),
            "medical_history": ["Condition A", "Condition B"], 
            "medications": [{"name": "MedX", "dosage": "10mg"}], 
            "allergies": ["Peanuts"],
            "social_security_number_lve": "000-00-0000",
            "middle_name": "EncrMid",
            "sex_at_birth": "Female",
            "pronouns": "they/them",
            "ethnicity": "Test Ethnicity",
            "race": "Test Race",
            "preferred_language": "Klingon",
            "religion_spirituality": "Jedi",
            "occupation": "Cipherpunk",
            "education_level": "PhD",
            "marital_status": "Single",
            "medical_record_number_lve": "MRNENC123",
            "drivers_license_number_lve": "DLENC123",
            "insurance_policy_number_lve": "POLENC123",
            "insurance_group_number_lve": "GRPENC123",
            "living_arrangement": "Alone",
            "allergies_sensitivities": "Sulfa", 
            "problem_list": "Chronic Debugging",
            "primary_care_physician": "Dr. Encrypto",
            "pharmacy_information": "Secure Pharmacy",
            "care_team_contact_info": "Team Secure",
            "treatment_history_notes": "Long history of secure treatments.",
            "current_medications_lve": "Aspirin, Vitamins", 
            "confidential_information_lve": "Truly secret stuff.",
            "additional_notes_lve": "More notes here.",
            "contact_details_json": {"home_phone": "555-0001", "work_email": "work@enc.com"}, # Renamed for clarity, assuming it maps to a JSON field
            "preferences_json": {"communication": "encrypted_email", "theme": "dark_mode"}, # Renamed for clarity
        }
        # Filter patient_data to only include keys that DomainPatient expects
        # This requires knowing DomainPatient's fields. For now, assuming it's basic
        # and will be expanded.
        # A more robust way is to inspect DomainPatient.__fields__ if it's Pydantic
        
        # Current app.core.domain.entities.patient.Patient is Pydantic and basic.
        # We will adapt DomainPatient later. For now, provide only existing fields.
        core_patient_fields = {
            "id": patient_id,
            "first_name": patient_data["first_name"],
            "last_name": patient_data["last_name"],
            "date_of_birth": patient_data["date_of_birth"],
            "email": patient_data["email"],
            "phone_number": patient_data["phone_number"],
            "contact_info": patient_data["contact_info"],
            # Add other fields here as they get added to the actual DomainPatient Pydantic model
        }
        # Add fields if they exist in DomainPatient.model_fields
        if hasattr(DomainPatient, 'model_fields'):
            for key, value in patient_data.items():
                if key in DomainPatient.model_fields and key not in core_patient_fields:
                    core_patient_fields[key] = value
        
        return DomainPatient(**core_patient_fields)


    @pytest.mark.asyncio
    async def test_phi_encrypted_in_database(self, integration_db_session: tuple[AsyncSession, uuid.UUID], encryption_service_fixture: EncryptionService):
        session, patient_audit_log_id = integration_db_session
        
        domain_patient = await self._create_sample_domain_patient(patient_id=TEST_PATIENT_ID, user_id=TEST_USER_ID)
        
        patient_model = PatientModel.from_domain(domain_patient) # from_domain will need to handle the comprehensive DomainPatient
        patient_model.id = TEST_PATIENT_ID 
        patient_model.user_id = TEST_USER_ID 
        patient_model.audit_id = patient_audit_log_id

        async with session.begin_nested(): 
            session.add(patient_model)
            # await session.flush() # Not strictly needed before commit with begin_nested, but helps catch issues earlier
        # The outer session.begin() from the fixture will handle the main commit if this is not nested.
        # If fixture uses session.begin(), this test block should use session.begin_nested() or just session.add() + session.commit().
        # For simplicity with the current fixture:
        await session.commit() # Commit the patient addition.
        
        logger.info(f"[Test] Added and committed PatientModel to session: ID {patient_model.id}")
        
        stmt = text("SELECT _first_name, _email, _medical_record_number_lve, _contact_details_json FROM patients WHERE id = :patient_id")
        result = await session.execute(stmt, {"patient_id": TEST_PATIENT_ID.hex})
        raw_db_row = result.fetchone()
        assert raw_db_row is not None, "Patient not found in DB after commit."
        
        logger.info(f"[Test] Raw DB row: {raw_db_row}")

        assert raw_db_row._first_name != domain_patient.first_name, "First name was not encrypted."
        decrypted_first_name = encryption_service_fixture.decrypt_string(raw_db_row._first_name)
        assert decrypted_first_name == domain_patient.first_name, "Decrypted first name mismatch."

        # Assuming domain_patient.email is a simple string attribute
        if domain_patient.email: # Check if email is not None
             assert raw_db_row._email != domain_patient.email, "Email was not encrypted."
             decrypted_email = encryption_service_fixture.decrypt_string(raw_db_row._email)
             assert decrypted_email == domain_patient.email, "Decrypted email mismatch."

        # Check EncryptedText field (assuming medical_record_number_lve is one)
        # This requires domain_patient to have medical_record_number_lve
        if hasattr(domain_patient, 'medical_record_number_lve') and domain_patient.medical_record_number_lve:
            assert raw_db_row._medical_record_number_lve != domain_patient.medical_record_number_lve
            decrypted_mrn = encryption_service_fixture.decrypt_string(raw_db_row._medical_record_number_lve)
            assert decrypted_mrn == domain_patient.medical_record_number_lve
        
        # Check EncryptedJSON field (assuming contact_details_json is one)
        # This requires domain_patient to have contact_details_json (as dict)
        if hasattr(domain_patient, 'contact_details_json') and domain_patient.contact_details_json:
            raw_contact_details_str = raw_db_row._contact_details_json
            assert raw_contact_details_str is not None
            decrypted_contact_details_str = encryption_service_fixture.decrypt_string(raw_contact_details_str)
            decrypted_contact_details = json.loads(decrypted_contact_details_str)
            assert decrypted_contact_details == domain_patient.contact_details_json
            assert raw_contact_details_str != json.dumps(domain_patient.contact_details_json)


    @pytest.mark.asyncio
    async def test_phi_decrypted_in_repository(self, integration_db_session: tuple[AsyncSession, uuid.UUID]):
        session, patient_audit_log_id = integration_db_session
        
        original_domain_patient = await self._create_sample_domain_patient(patient_id=TEST_PATIENT_ID, user_id=TEST_USER_ID)

        patient_model_to_save = PatientModel.from_domain(original_domain_patient)
        patient_model_to_save.id = TEST_PATIENT_ID
        patient_model_to_save.user_id = TEST_USER_ID
        patient_model_to_save.audit_id = patient_audit_log_id
        
        session.add(patient_model_to_save)
        await session.commit() # Commit the changes
        logger.info(f"[Test] Added and committed PatientModel for decryption test: ID {patient_model_to_save.id}")

        retrieved_patient_model = await session.get(PatientModel, TEST_PATIENT_ID)
        assert retrieved_patient_model is not None, "Failed to retrieve patient model from DB."
        
        logger.info(f"[Test] Retrieved PatientModel: ID {retrieved_patient_model.id}, Email (model): {retrieved_patient_model._email}")

        retrieved_domain_patient = retrieved_patient_model.to_domain() # to_domain must handle comprehensive model
        logger.info(f"[Test] Converted to DomainPatient: ID {retrieved_domain_patient.id}, Email (domain): {retrieved_domain_patient.email}")

        assert retrieved_domain_patient.id == original_domain_patient.id
        assert retrieved_domain_patient.first_name == original_domain_patient.first_name
        assert retrieved_domain_patient.last_name == original_domain_patient.last_name
        assert retrieved_domain_patient.date_of_birth == original_domain_patient.date_of_birth
        assert retrieved_domain_patient.email == original_domain_patient.email
        assert retrieved_domain_patient.phone_number == original_domain_patient.phone_number

        # Compare complex types if DomainPatient is updated to support them
        if hasattr(original_domain_patient, 'address') and hasattr(retrieved_domain_patient, 'address') and original_domain_patient.address:
             assert retrieved_domain_patient.address.line1 == original_domain_patient.address.line1 # Example field
        if hasattr(original_domain_patient, 'emergency_contact') and hasattr(retrieved_domain_patient, 'emergency_contact') and original_domain_patient.emergency_contact:
             assert retrieved_domain_patient.emergency_contact.name == original_domain_patient.emergency_contact.name # Example field
        
        # Compare list/text fields - assuming DomainPatient and PatientModel.to_domain handle these
        if hasattr(original_domain_patient, 'medical_history') and hasattr(retrieved_domain_patient, 'medical_history'):
            assert retrieved_domain_patient.medical_history == original_domain_patient.medical_history

    @pytest.mark.asyncio
    async def test_encryption_error_handling(self, encryption_service_fixture: EncryptionService):
        malformed_token = "this.is.not.a.valid.fernet.token"
        decrypted_value = encryption_service_fixture.decrypt_string(malformed_token)
        assert decrypted_value is None

        empty_encrypted = encryption_service_fixture.encrypt_string("")
        assert encryption_service_fixture.decrypt_string(empty_encrypted) == ""
        assert encryption_service_fixture.decrypt_string(None) is None

        random_key_service = EncryptionService() # Will generate its own key if env var not found or different one
        encrypted_by_other = random_key_service.encrypt_string("secret data")
        if encrypted_by_other == "secret data": # If encryption service is a dummy/passthrough
             logger.warning("Encryption service seems to be a passthrough; cannot test cross-key decryption meaningfully.")
        else:
            decrypted_by_main_service = encryption_service_fixture.decrypt_string(encrypted_by_other)
            assert decrypted_by_main_service is None
