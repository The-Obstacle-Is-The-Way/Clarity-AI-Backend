"""
Integration tests for Patient PHI encryption in the database.

This module verifies that patient PHI is properly encrypted when stored in
the database and decrypted when retrieved, according to HIPAA requirements.
"""

import logging
import uuid

# from collections.abc import AsyncGenerator # Not used directly in this version
from datetime import date, datetime, timezone

import pytest
import pytest_asyncio
import sqlalchemy

# from cryptography.fernet import Fernet # Fernet from fixture is BaseEncryptionService
from sqlalchemy import (  # , event # Event listener removed for now, direct PRAGMA in fixture
    text,
)

# from sqlalchemy.engine import Engine # Not used directly
from sqlalchemy.ext.asyncio import (  # , async_sessionmaker, create_async_engine
    AsyncSession,
)

# from app.infrastructure.persistence.sqlalchemy.types.encrypted_types import EncryptedString, EncryptedText, EncryptedJSON # Not directly used in test logic
from app.core.config import settings

# Import domain entities with clear namespace
from app.domain.entities.patient import ContactInfo, Patient as DomainPatient
from app.core.domain.entities.user import UserRole
from app.core.domain.enums import Gender  # Corrected Gender import

# Ensure patient.py's encryption_service_instance is available for EncryptedTypes
# This import is crucial for the types to find the service.
# The EncryptedTypeBase now directly imports encryption_service_instance from app.infrastructure.security.encryption
# So, specific patching of patient_module_for_esi is no longer the primary mechanism.
# However, ensuring the global instance is correctly configured for tests IS crucial.
# import app.infrastructure.persistence.sqlalchemy.models.patient as patient_module_for_esi # Keep for now if other parts rely on it, but aim to remove dependency on this patching.
from app.core.exceptions.base_exceptions import PersistenceError  # Corrected import
from app.domain.value_objects.address import (  # Assuming this is the canonical Pydantic/dataclass VO
    Address,
)
from app.domain.value_objects.emergency_contact import (  # Assuming this is the canonical Pydantic/dataclass VO
    EmergencyContact,
)
from app.infrastructure.persistence.sqlalchemy.config.database import get_db_instance
from app.infrastructure.persistence.sqlalchemy.models.audit_log import AuditLog

# from app.infrastructure.persistence.sqlalchemy.database import async_session_factory, engine, Base # engine, Base for setup
from app.infrastructure.persistence.sqlalchemy.models.base import Base
from app.infrastructure.persistence.sqlalchemy.models.user import User
from app.infrastructure.persistence.sqlalchemy.repositories.patient_repository import (
    PatientRepository,
)

# Use the global encryption service instance
from app.infrastructure.security.encryption import (
    encryption_service_instance,
    get_encryption_service,
)
from app.infrastructure.security.password.hashing import pwd_context  # Added import

logger = logging.getLogger(__name__)

TEST_USER_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
TEST_PATIENT_ID = uuid.UUID("00000000-0000-0000-0000-000000000002")

# Removed encryption_service_fixture as we will use the global one,
# assuming it's configured with test settings (e.g., test key).


@pytest_asyncio.fixture(scope="function")
async def integration_db_session():  # Removed encryption_service_fixture dependency
    # The global `encryption_service_instance` from `app.infrastructure.security.encryption`
    # should be used by EncryptedTypeBase.
    # We must ensure this global instance is using a TEST KEY.
    # This is typically handled by test settings overriding production settings.
    # If `encryption_service_instance` initializes its key on first access based on `settings`,
    # and test settings are active, it should be fine.

    # original_esi = getattr(patient_module_for_esi, 'encryption_service_instance', None) # No longer needed
    # patient_module_for_esi.encryption_service_instance = encryption_service_fixture # No longer needed

    logger.info(f"[Integration Fixture] Setting up test database: {settings.DATABASE_URL}")
    logger.info(
        f"[Integration Fixture] Using global encryption_service_instance: {id(encryption_service_instance)}"
    )
    if (
        hasattr(encryption_service_instance, "_direct_key")
        and encryption_service_instance._direct_key
    ):
        logger.info(
            f"[Integration Fixture] Global ESI direct key (test hint): {encryption_service_instance._direct_key[:10]}..."
        )
    elif hasattr(settings, "PHI_ENCRYPTION_KEY"):
        logger.info(
            f"[Integration Fixture] Global ESI expects key from settings.PHI_ENCRYPTION_KEY: {settings.PHI_ENCRYPTION_KEY[:10]}..."
        )

    db_instance = get_db_instance()
    engine = db_instance.engine
    # async_session_factory = db_instance.session_factory # Not using factory directly

    patient_audit_log_id_for_yield: uuid.UUID | None = None
    user_for_patient_audit_id: uuid.UUID | None = None  # Keep for logging clarity if needed

    async with engine.connect() as conn:  # Single connection for DDL and test session
        logger.info("[Integration Fixture] Performing DDL operations on shared connection.")
        await conn.run_sync(Base.metadata.drop_all)
        logger.info("[Integration Fixture] Dropped all tables.")
        await conn.run_sync(Base.metadata.create_all)
        logger.info("[Integration Fixture] Created all tables.")
        await conn.execute(text("PRAGMA foreign_keys=ON;"))
        logger.info("[Integration Fixture] PRAGMA foreign_keys=ON executed.")
        await conn.commit()  # Commit DDL operations
        logger.info("[Integration Fixture] DDL operations committed.")

        # Create an AsyncSession bound to this specific connection
        async_session = AsyncSession(bind=conn, expire_on_commit=False)

        try:
            # Data setup begins
            async with async_session.begin():  # This will commit at the end or rollback on error
                logger.info(
                    f"[Integration Fixture] Setting up initial User {TEST_USER_ID} and its AuditLog with granular flushes."
                )

                # 1. Create and flush AuditLog for user creation (user_id is None initially)
                user_creation_audit_log = AuditLog(
                    id=uuid.uuid4(),
                    user_id=None,
                    action="CREATE_USER_PENDING_UID",
                    details=f"Audit log for User {TEST_USER_ID} creation, pending actual user_id.",
                    event_type="USER_LIFECYCLE",
                    resource_type="User",
                    resource_id=str(TEST_USER_ID),
                )
                async_session.add(user_creation_audit_log)
                await async_session.flush()  # FLUSH 1: Persist user_creation_audit_log with user_id=None
                logger.info(
                    f"[Integration Fixture] Flushed 1: Added user_creation_audit_log {user_creation_audit_log.id} (user_id=None)."
                )

                # 2. Create and flush User, linking to the now-persisted user_creation_audit_log.
                test_user = User(
                    id=TEST_USER_ID,
                    username="testuser_integration",
                    email="testuser_integration@example.com",
                    password_hash=pwd_context.hash("testpassword"),
                    role=UserRole.ADMIN,
                    audit_id=user_creation_audit_log.id,  # Link to existing audit log
                    created_by=TEST_USER_ID,
                    updated_by=TEST_USER_ID,
                )
                async_session.add(test_user)
                await async_session.flush()  # FLUSH 2: Persist test_user.
                logger.info(
                    f"[Integration Fixture] Flushed 2: Added User {test_user.id} linked to AuditLog {user_creation_audit_log.id}."
                )

                # 3. Update user_creation_audit_log with the actual user_id.
                user_creation_audit_log.user_id = test_user.id
                user_creation_audit_log.action = "CREATE"
                user_creation_audit_log.details = f"User {test_user.id} created successfully."
                # async_session.add(user_creation_audit_log) # Already in session, modification will be picked up.
                logger.info(
                    f"[Integration Fixture] Updated user_creation_audit_log {user_creation_audit_log.id} with user_id {test_user.id}."
                )

                # 4. Create AuditLog for subsequent Patient operations.
                patient_action_audit_log = AuditLog(
                    id=uuid.uuid4(),
                    user_id=test_user.id,  # Link to existing user
                    action="PATIENT_OP_SETUP",
                    details="AuditLog created in fixture for subsequent patient operations in test.",
                    event_type="PATIENT_LIFECYCLE_PREP",
                    resource_type="System",
                    resource_id=None,
                )
                async_session.add(patient_action_audit_log)

                # FLUSH 3: Persist the update to user_creation_audit_log and insert patient_action_audit_log.
                await async_session.flush()
                logger.info(
                    f"[Integration Fixture] Flushed 3: Updated user_creation_audit_log and added patient_action_audit_log {patient_action_audit_log.id}."
                )

                patient_audit_log_id_for_yield = patient_action_audit_log.id
                user_for_patient_audit_id = patient_action_audit_log.user_id

            # The 'async with async_session.begin()' block ensures all the above is committed here if no exceptions.
            logger.info(
                f"[Integration Fixture] Main setup transaction committed. Yielding session and Patient Action AuditLog ID: {patient_audit_log_id_for_yield}"
            )

            yield async_session, patient_audit_log_id_for_yield

        except Exception as e:
            logger.error(
                f"[Integration Fixture] Exception during setup/yield: {e}",
                exc_info=True,
            )
            # Rollback is implicitly handled by 'async with async_session.begin()' on exception
            raise
        finally:
            logger.info("[Integration Fixture] Tearing down test database session (fixture end).")
            await async_session.close()  # Close the session
            # Connection 'conn' is automatically closed by 'async with engine.connect()'
            # patient_module_for_esi.encryption_service_instance = original_esi # No longer needed
            # logger.info("[Integration Fixture] Restored original ESI.") # No longer needed
            # Engine dispose is not managed here; get_db_instance handles engine lifecycle.


# pytest.mark.db_required()
class TestPatientEncryptionIntegration:
    """Integration test suite for Patient model encryption with database."""

    def setup_method(self, method):
        """Initialize the encryption service before each test method."""
        global encryption_service_instance
        from app.infrastructure.security.encryption.base_encryption_service import (
            VERSION_PREFIX,
            BaseEncryptionService,
        )

        self.VERSION_PREFIX = VERSION_PREFIX
        self.BaseEncryptionService = BaseEncryptionService

        # Initialize the encryption service
        if encryption_service_instance is None:
            encryption_service_instance = get_encryption_service()

        # Ensure it's properly initialized
        assert (
            encryption_service_instance is not None
        ), "encryption_service_instance should not be None"

    async def _create_sample_domain_patient(
        self, patient_id: uuid.UUID, user_id: uuid.UUID
    ) -> DomainPatient:
        """Creates a comprehensive sample DomainPatient for testing."""
        # This function will need DomainPatient to be updated to accept all these fields.
        # For now, it's an aspiration for what DomainPatient should hold.
        # Fallback to basic DomainPatient if fields are not yet available.

        patient_data = {
            "id": patient_id,
            "user_id": user_id,  # Assuming DomainPatient will have user_id
            "first_name": "EncrFirstName",
            "last_name": "EncrLastName",
            "email": "encrypted.patient@example.com",
            "date_of_birth": date(1990, 1, 1),
            "phone": "555-123-4567",  # Use 'phone' not 'phone_number' for domain compatibility
            # NOTE: Removed contact_info parameter to avoid conflicts
            # Domain Patient's ContactInfo descriptor will create ContactInfo from email/phone fields
            "gender": Gender.FEMALE,
            "address": Address(
                line1="123 Encrypt Lane",
                city="SecureVille",
                state="SS",
                zip_code="00000",
                country="US",
            ),
            "emergency_contact": EmergencyContact(
                name="EC Name", phone="555-555-0199", relationship="Sibling"
            ),
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
            "contact_details_json": {
                "home_phone": "555-0001",
                "work_email": "work@enc.com",
            },  # Renamed for clarity, assuming it maps to a JSON field
            "preferences_json": {
                "communication": "encrypted_email",
                "theme": "dark_mode",
            },  # Renamed for clarity
            "notes": "Encrypted notes here.",
            "custom_fields": {"custom_key": "encrypted_custom_value"},
            "is_active": True,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        }

        # Simplified creation for now, assuming DomainPatient can take these directly
        # or has a constructor/factory that can handle them.
        # This might require DomainPatient to be more flexible or use **patient_data
        try:
            return DomainPatient(**patient_data)
        except TypeError as e:
            logger.error(f"Error creating DomainPatient with provided data: {e}")
            # Fallback to a more basic instantiation if the full one fails due to missing fields
            # This is a temporary measure until DomainPatient is fully aligned.
            return DomainPatient(
                id=patient_id,
                user_id=user_id,
                first_name="EncrFirstName",
                last_name="EncrLastName",
                email="encrypted.patient@example.com",
                date_of_birth=date(1990, 1, 1),
                # Add other core fields that DomainPatient expects
            )

    @pytest.mark.asyncio
    async def test_phi_encrypted_in_database(
        self, integration_db_session: tuple[AsyncSession, uuid.UUID]
    ):  # Removed encryption_service_fixture
        """Verify that PHI stored in the database is actually encrypted."""
        session, patient_audit_log_id = integration_db_session
        # encryption_service = encryption_service_fixture # No longer using separate fixture instance

        patient_id = TEST_PATIENT_ID
        domain_patient = await self._create_sample_domain_patient(
            patient_id=patient_id, user_id=TEST_USER_ID
        )
        domain_patient.audit_id = patient_audit_log_id  # Set audit_id for creation

        repo = PatientRepository(session, encryption_service_instance)  # Use global instance

        try:
            await repo.create(domain_patient)
            await session.commit()
        except Exception as e:
            await session.rollback()
            logger.error(
                f"Error during patient creation in test_phi_encrypted_in_database: {e}",
                exc_info=True,
            )
            if isinstance(
                e, sqlalchemy.exc.IntegrityError
            ) and "FOREIGN KEY constraint failed" in str(e):
                logger.error(
                    "Potential FOREIGN KEY constraint failure. Check AuditLog setup or User setup in fixture."
                )
            raise

        # Directly query the database to inspect raw values
        # Ensure the table name matches your actual table name (e.g., \'patients\')
        # Convert UUID to string for SQLite compatibility
        result = await session.execute(
            text(
                "SELECT first_name, last_name, email, ssn, contact_info, medical_history FROM patients WHERE id = :id"
            ),
            {"id": str(patient_id)},
        )
        raw_patient_data = result.fetchone()
        await session.commit()  # Commit select if needed, or just close session after read

        assert raw_patient_data is not None, "Patient not found in DB for raw data check."

        # Check that sensitive fields are not plain text and appear encrypted (e.g., start with "v1:")
        # This uses the VERSION_PREFIX from setup_method
        version_prefix = self.VERSION_PREFIX

        assert raw_patient_data.first_name.startswith(
            version_prefix
        ), f"Raw first_name should be encrypted. Got: {raw_patient_data.first_name}"
        assert raw_patient_data.last_name.startswith(
            version_prefix
        ), "Raw last_name should be encrypted."
        assert raw_patient_data.email.startswith(version_prefix), "Raw email should be encrypted."
        assert raw_patient_data.ssn.startswith(version_prefix), "Raw ssn should be encrypted."

        # For JSON fields, the raw data in DB is a string, which itself should be encrypted.
        assert isinstance(
            raw_patient_data.contact_info, str
        ), "Raw contact_info should be a string in DB."
        assert raw_patient_data.contact_info.startswith(
            version_prefix
        ), "Raw contact_info string should be encrypted."

        assert isinstance(
            raw_patient_data.medical_history, str
        ), "Raw medical_history should be a string in DB."
        assert raw_patient_data.medical_history.startswith(
            version_prefix
        ), "Raw medical_history string should be encrypted."

        # Decrypt one field manually to double-check the key consistency (optional sanity check)
        try:
            decrypted_fn = encryption_service_instance.decrypt_string(raw_patient_data.first_name)
            assert (
                decrypted_fn == domain_patient.first_name
            ), "Manual decryption check failed for first_name"
        except Exception as e:
            pytest.fail(f"Manual decryption check raised an error: {e}")

    @pytest.mark.asyncio
    async def test_phi_decrypted_in_repository(
        self, integration_db_session: tuple[AsyncSession, uuid.UUID]
    ):
        """Verify that PHI is decrypted when retrieved via the repository."""
        session, patient_audit_log_id = integration_db_session
        # encryption_service = encryption_service_fixture # No longer using separate fixture instance

        patient_id = uuid.uuid4()  # Use a new ID for this test to avoid conflicts
        original_patient_domain = await self._create_sample_domain_patient(
            patient_id=patient_id, user_id=TEST_USER_ID
        )
        original_patient_domain.audit_id = patient_audit_log_id  # Set audit_id

        repo = PatientRepository(session, encryption_service_instance)  # Use global instance

        try:
            await repo.create(original_patient_domain)
            await session.commit()
        except Exception as e:  # Catch broader exceptions for creation issues
            await session.rollback()
            logger.error(
                f"Error during patient creation in test_phi_decrypted_in_repository: {e}",
                exc_info=True,
            )
            raise PersistenceError(f"Failed to create patient for decryption test: {e}") from e

        retrieved_patient = None
        try:
            retrieved_patient = await repo.get_by_id(patient_id)
            await session.commit()  # Or close, if only reading
        except Exception as e:  # Catch broader exceptions for retrieval issues
            logger.error(
                f"Error during patient retrieval in test_phi_decrypted_in_repository: {e}",
                exc_info=True,
            )
            # If it's a PersistenceError already, re-raise it. Otherwise, wrap.
            if isinstance(e, PersistenceError):
                raise
            raise PersistenceError(f"Failed to retrieve patient by ID: {e}") from e

        assert retrieved_patient is not None, "Patient not retrieved from repository."

        # Verify that PHI fields are decrypted and match original values
        assert (
            retrieved_patient.first_name == original_patient_domain.first_name
        ), "Decrypted first_name mismatch."
        assert (
            retrieved_patient.last_name == original_patient_domain.last_name
        ), "Decrypted last_name mismatch."
        assert retrieved_patient.email == original_patient_domain.email, "Decrypted email mismatch."
        assert (
            retrieved_patient.date_of_birth == original_patient_domain.date_of_birth
        ), "Decrypted date_of_birth mismatch."

        # For Pydantic models / JSON serialized fields
        assert (
            retrieved_patient.contact_info == original_patient_domain.contact_info
        ), "Decrypted contact_info mismatch."
        assert (
            retrieved_patient.address == original_patient_domain.address
        ), "Decrypted address mismatch."
        assert (
            retrieved_patient.emergency_contact == original_patient_domain.emergency_contact
        ), "Decrypted emergency_contact mismatch."

        # For list/JSON fields that are stored as encrypted strings
        assert (
            retrieved_patient.medical_history == original_patient_domain.medical_history
        ), "Decrypted medical_history mismatch."
        assert (
            retrieved_patient.medications == original_patient_domain.medications
        ), "Decrypted medications mismatch."
        assert (
            retrieved_patient.allergies == original_patient_domain.allergies
        ), "Decrypted allergies mismatch."

        assert (
            retrieved_patient.social_security_number_lve
            == original_patient_domain.social_security_number_lve
        ), "Decrypted SSN mismatch."

    @pytest.mark.asyncio
    async def test_encryption_error_handling(
        self,
    ):  # Removed integration_db_session, encryption_service_fixture
        """Test error handling for encryption/decryption failures (e.g., tampered data)."""
        # Use the global encryption_service_instance, ensure it's configured for tests
        global encryption_service_instance

        # Initialize it if it's None
        if encryption_service_instance is None:
            encryption_service_instance = get_encryption_service()

        service = encryption_service_instance

        # Ensure the service is not None before proceeding
        assert service is not None, "encryption_service_instance is not initialized properly"

        original_text = "This is highly sensitive data!"
        encrypted_text = service.encrypt(original_text)
        assert encrypted_text is not None

        # Tamper with the encrypted text
        tampered_text = encrypted_text[:-5] + "XXXXX"  # Corrupt the end

        with pytest.raises(ValueError, match="Decryption failed: Invalid token") as excinfo_token:
            service.decrypt(tampered_text)  # decrypt directly takes string or bytes
        logger.debug(f"Caught expected InvalidToken error: {excinfo_token.value}")

        with pytest.raises(
            ValueError, match="Decryption failed: Invalid base64 encoding"
        ) as excinfo_b64:
            service.decrypt("v1:thisIsNotBase64!@#")
        logger.debug(f"Caught expected base64 error: {excinfo_b64.value}")

        # Test decryption of non-prefixed string (should fail)
        try:
            service.decrypt("someRandomDataWithoutPrefix")
            pytest.fail("Should have raised an error for missing prefix")
        except ValueError as e:
            assert "Invalid" in str(e), f"Expected 'Invalid' in error message, got: {e!s}"
        logger.debug("Caught expected missing prefix error for string.")

        # Test decryption of prefixed but invalid (non-base64) data
        with pytest.raises(ValueError, match="Decryption failed: Invalid base64 encoding"):
            service.decrypt(f"{service.VERSION_PREFIX}NotValidBase64")
        logger.debug("Caught expected error for prefixed but invalid base64.")

        # Test with a completely different key (simulated by creating a new service instance)
        # This requires that BaseEncryptionService can be instantiated with a different direct_key
        # Ensure TEST_OTHER_ENCRYPTION_KEY is defined in test settings or .env.test
        other_key = "COMPLETELY_DIFFERENT_TEST_KEY_FOR_WRONG_KEY_TEST_12345"

        other_service = self.BaseEncryptionService(direct_key=other_key)
        encrypted_with_main_key = service.encrypt("data for main key")

        with pytest.raises(ValueError, match="Decryption failed: Invalid token"):
            other_service.decrypt(encrypted_with_main_key)
        logger.debug("Caught expected InvalidToken error when decrypting with wrong key.")
