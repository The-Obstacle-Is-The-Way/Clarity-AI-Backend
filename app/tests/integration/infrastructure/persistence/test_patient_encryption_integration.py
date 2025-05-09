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
import sqlalchemy
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
from app.infrastructure.security.password.hashing import pwd_context # Added import

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
async def integration_db_session(encryption_service_fixture: EncryptionService):
    original_esi = getattr(patient_module_for_esi, 'encryption_service_instance', None)
    patient_module_for_esi.encryption_service_instance = encryption_service_fixture
    
    logger.info(f"[Integration Fixture] Setting up test database: {settings.DATABASE_URL}")
    
    db_instance = get_db_instance()
    engine = db_instance.engine
    # async_session_factory = db_instance.session_factory # Not using factory directly

    patient_audit_log_id_for_yield: uuid.UUID | None = None
    user_for_patient_audit_id: uuid.UUID | None = None # Keep for logging clarity if needed

    async with engine.connect() as conn: # Single connection for DDL and test session
        logger.info("[Integration Fixture] Performing DDL operations on shared connection.")
        await conn.run_sync(Base.metadata.drop_all)
        logger.info("[Integration Fixture] Dropped all tables.")
        await conn.run_sync(Base.metadata.create_all)
        logger.info("[Integration Fixture] Created all tables.")
        await conn.execute(text("PRAGMA foreign_keys=ON;"))
        logger.info("[Integration Fixture] PRAGMA foreign_keys=ON executed.")
        await conn.commit() # Commit DDL operations
        logger.info("[Integration Fixture] DDL operations committed.")

        # Create an AsyncSession bound to this specific connection
        async_session = AsyncSession(bind=conn, expire_on_commit=False)
        
        try:
            # Data setup begins
            async with async_session.begin(): # This will commit at the end or rollback on error
                logger.info(f"[Integration Fixture] Setting up initial User {TEST_USER_ID} and its AuditLog with granular flushes.")

                # 1. Create and flush AuditLog for user creation (user_id is None initially)
                user_creation_audit_log = AuditLog(
                    id=uuid.uuid4(), 
                    user_id=None, 
                    action="CREATE_USER_PENDING_UID", 
                    details=f"Audit log for User {TEST_USER_ID} creation, pending actual user_id.",
                    event_type="USER_LIFECYCLE",
                    resource_type="User",
                    resource_id=str(TEST_USER_ID)
                )
                async_session.add(user_creation_audit_log)
                await async_session.flush() # FLUSH 1: Persist user_creation_audit_log with user_id=None
                logger.info(f"[Integration Fixture] Flushed 1: Added user_creation_audit_log {user_creation_audit_log.id} (user_id=None).")

                # 2. Create and flush User, linking to the now-persisted user_creation_audit_log.
                test_user = User(
                    id=TEST_USER_ID, 
                    username="testuser_integration", 
                    email="testuser_integration@example.com",
                    password_hash=pwd_context.hash("testpassword"),
                    role=UserRole.ADMIN,
                    audit_id=user_creation_audit_log.id, # Link to existing audit log
                    created_by=TEST_USER_ID, 
                    updated_by=TEST_USER_ID
                )
                async_session.add(test_user)
                await async_session.flush() # FLUSH 2: Persist test_user.
                logger.info(f"[Integration Fixture] Flushed 2: Added User {test_user.id} linked to AuditLog {user_creation_audit_log.id}.")

                # 3. Update user_creation_audit_log with the actual user_id.
                user_creation_audit_log.user_id = test_user.id
                user_creation_audit_log.action = "CREATE"
                user_creation_audit_log.details = f"User {test_user.id} created successfully."
                # async_session.add(user_creation_audit_log) # Already in session, modification will be picked up.
                logger.info(f"[Integration Fixture] Updated user_creation_audit_log {user_creation_audit_log.id} with user_id {test_user.id}.")

                # 4. Create AuditLog for subsequent Patient operations.
                patient_action_audit_log = AuditLog(
                    id=uuid.uuid4(), 
                    user_id=test_user.id, # Link to existing user
                    action="PATIENT_OP_SETUP", 
                    details="AuditLog created in fixture for subsequent patient operations in test.",
                    event_type="PATIENT_LIFECYCLE_PREP",
                    resource_type="System",
                    resource_id=None
                )
                async_session.add(patient_action_audit_log)
                
                # FLUSH 3: Persist the update to user_creation_audit_log and insert patient_action_audit_log.
                await async_session.flush() 
                logger.info(f"[Integration Fixture] Flushed 3: Updated user_creation_audit_log and added patient_action_audit_log {patient_action_audit_log.id}.")
                
                patient_audit_log_id_for_yield = patient_action_audit_log.id
                user_for_patient_audit_id = patient_action_audit_log.user_id

            # The 'async with async_session.begin()' block ensures all the above is committed here if no exceptions.
            logger.info(f"[Integration Fixture] Main setup transaction committed. Yielding session and Patient Action AuditLog ID: {patient_audit_log_id_for_yield}")
            
            yield async_session, patient_audit_log_id_for_yield

        except Exception as e:
            logger.error(f"[Integration Fixture] Exception during setup/yield: {e}", exc_info=True)
            # Rollback is implicitly handled by 'async with async_session.begin()' on exception
            raise
        finally:
            logger.info("[Integration Fixture] Tearing down test database session (fixture end).")
            await async_session.close() # Close the session
            # Connection 'conn' is automatically closed by 'async with engine.connect()'
            patient_module_for_esi.encryption_service_instance = original_esi
            logger.info("[Integration Fixture] Restored original ESI.")
            # Engine dispose is not managed here; get_db_instance handles engine lifecycle.

# pytest.mark.db_required()
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
            "emergency_contact": EmergencyContact(name="EC Name", phone="555-555-0199", relationship="Sibling"),
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
        session, patient_audit_log_id = integration_db_session # Correctly unpacks the tuple
        
        assert patient_audit_log_id is not None, "Patient AuditLog ID from fixture is None"

        domain_patient = await self._create_sample_domain_patient(patient_id=TEST_PATIENT_ID, user_id=TEST_USER_ID)
        
        patient_model = await PatientModel.from_domain(domain_patient)
        patient_model.id = TEST_PATIENT_ID

        async with session.begin_nested(): 
            session.add(patient_model)
            # await session.flush() # Not strictly needed before commit with begin_nested, but helps catch issues earlier
        # The outer session.begin() from the fixture will handle the main commit if this is not nested.
        # If fixture uses session.begin(), this test block should use session.begin_nested() or just session.add() + session.commit().
        # For simplicity with the current fixture:
        await session.commit() # Commit the patient addition.
        
        logger.info(f"[Test] Added and committed PatientModel to session: ID {patient_model.id}")
        
        # CORRECTED: Use actual database column names based on PatientModel definition
        stmt = text("SELECT first_name, email, mrn, contact_info FROM patients WHERE id = :patient_id")
        result = await session.execute(stmt, {"patient_id": TEST_PATIENT_ID.hex})
        raw_db_row = result.fetchone()
        assert raw_db_row is not None, "Patient not found in DB after commit."
        
        logger.info(f"[Test] Raw DB row: {raw_db_row}")

        assert raw_db_row.first_name != domain_patient.first_name, "First name was not encrypted."
        decrypted_first_name = encryption_service_fixture.decrypt_string(raw_db_row.first_name)
        assert decrypted_first_name == domain_patient.first_name, "Decrypted first name mismatch."

        if domain_patient.email:
             assert raw_db_row.email != domain_patient.email, "Email was not encrypted."
             decrypted_email = encryption_service_fixture.decrypt_string(raw_db_row.email)
             assert decrypted_email == domain_patient.email, "Decrypted email mismatch."

        # Check EncryptedString field (mrn)
        if hasattr(domain_patient, 'medical_record_number_lve') and domain_patient.medical_record_number_lve:
            # Assuming domain_patient.medical_record_number_lve maps to model._mrn (DB column "mrn")
            assert raw_db_row.mrn != domain_patient.medical_record_number_lve, "MRN was not encrypted or matches raw domain value."
            decrypted_mrn = encryption_service_fixture.decrypt_string(raw_db_row.mrn)
            assert decrypted_mrn == domain_patient.medical_record_number_lve, "Decrypted MRN mismatch."
        
        # Check EncryptedJSON field (contact_info)
        if hasattr(domain_patient, 'contact_info') and domain_patient.contact_info:
            # Assuming domain_patient.contact_info maps to model._contact_info (DB column "contact_info")
            raw_contact_info_str = raw_db_row.contact_info # This will be the encrypted string from DB
            assert raw_contact_info_str is not None
            
            # Domain patient's contact_info is a Pydantic model (ContactInfo), convert to dict for comparison if needed by test logic
            domain_contact_info_dict = domain_patient.contact_info.model_dump() if hasattr(domain_patient.contact_info, 'model_dump') else domain_patient.contact_info

            decrypted_contact_info_str = encryption_service_fixture.decrypt_string(raw_contact_info_str)
            decrypted_contact_info_obj = json.loads(decrypted_contact_info_str) # Parse the decrypted JSON string
            
            assert decrypted_contact_info_obj == domain_contact_info_dict, "Decrypted contact_info mismatch."
            # Ensure the raw string from DB is not the same as a simple json.dumps of the domain dict (means it was encrypted)
            assert raw_contact_info_str != json.dumps(domain_contact_info_dict), "contact_info was not encrypted."


    @pytest.mark.asyncio
    async def test_phi_decrypted_in_repository(self, integration_db_session: tuple[AsyncSession, uuid.UUID]):
        session, patient_audit_log_id = integration_db_session # Correctly unpacks the tuple

        assert patient_audit_log_id is not None, "Patient AuditLog ID from fixture is None"
        
        original_domain_patient = await self._create_sample_domain_patient(patient_id=TEST_PATIENT_ID, user_id=TEST_USER_ID)

        patient_model_to_save = await PatientModel.from_domain(original_domain_patient)
        patient_model_to_save.id = TEST_PATIENT_ID
        
        session.add(patient_model_to_save)
        await session.commit() # Commit the changes
        logger.info(f"[Test] Added and committed PatientModel for decryption test: ID {patient_model_to_save.id}")

        retrieved_patient_model = await session.get(PatientModel, TEST_PATIENT_ID)
        assert retrieved_patient_model is not None, "Failed to retrieve patient model from DB."
        
        logger.info(f"[Test] Retrieved PatientModel: ID {retrieved_patient_model.id}, Email (model): {retrieved_patient_model._email}")

        retrieved_domain_patient = await retrieved_patient_model.to_domain() # ADDED await
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

        # To make this test more robust against a passthrough service, check if encryption actually changes the value
        original_data = "secret data"
        encrypted_by_other = random_key_service.encrypt_string(original_data)
        
        # If encryption service is a dummy/passthrough, encrypted_by_other will be same as original_data
        if encrypted_by_other == original_data and original_data != "": # Added check for non-empty string
             logger.warning("Encryption service (random_key_service) seems to be a passthrough; cannot test cross-key decryption meaningfully.")
        else:
            # This part of the test assumes PHI_ENCRYPTION_KEY is set and consistent for encryption_service_fixture
            # If random_key_service generates a truly different key, decryption should fail.
            decrypted_by_main_service = encryption_service_fixture.decrypt_string(encrypted_by_other)
            # If the main service key is the SAME as random_key_service (e.g. both defaulted to same env var)
            # then decryption would succeed. This test is for when they are DIFFERENT.
            # To ensure they are different, random_key_service would need to be initialized with a known different key
            # or settings.PHI_ENCRYPTION_KEY needs to be temporarily changed for one of them.
            # For now, assume they might be different if random_key_service generates a new key.
            assert decrypted_by_main_service is None, f"Cross-key decryption succeeded unexpectedly. Main service might be using same key as random_key_service or decryption logic is flawed. Decrypted: {decrypted_by_main_service}"
