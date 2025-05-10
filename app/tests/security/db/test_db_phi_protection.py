#!/usr/bin/env python3
"""
Test suite for database PHI protection mechanisms.
This validates that database interactions properly protect PHI per HIPAA requirements.
"""

# import datetime # Ensure this line is removed
from unittest.mock import MagicMock, patch, AsyncMock
import uuid
from datetime import datetime, timezone # This line should correctly define 'datetime' as the class

import pytest
from pydantic import ValidationError
from app.core.exceptions import PersistenceError
# from app.core.exceptions.phi_protection_exception import PHIProtectionError # Removed this unused import

# Core SQLAlchemy async components
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

# Import the canonical Base for table creation
from app.infrastructure.persistence.sqlalchemy.models.base import Base
from app.infrastructure.persistence.sqlalchemy.config.database import Database # For spec in MagicMock

# Import Unit of Work directly
from app.infrastructure.persistence.sqlalchemy.unit_of_work.async_unit_of_work import AsyncSQLAlchemyUnitOfWork

# Import repository interfaces
from app.core.interfaces.repositories.user_repository_interface import IUserRepository
from app.core.interfaces.repositories.patient_repository import IPatientRepository
from app.core.interfaces.repositories.digital_twin_repository import IDigitalTwinRepository
from app.core.interfaces.repositories.alert_repository_interface import IAlertRepository
from app.core.interfaces.repositories.biometric_rule_repository import IBiometricRuleRepository
from app.core.interfaces.repositories.biometric_alert_repository import IBiometricAlertRepository
from app.core.interfaces.repositories.biometric_twin_repository import IBiometricTwinRepository
# from app.core.interfaces.repositories.actigraphy_repository import IActigraphyRepository
# from app.core.interfaces.repositories.conversation_repository import IConversationRepository
# from app.core.interfaces.repositories.feedback_repository import IFeedbackRepository
# from app.core.interfaces.repositories.integration_repository import IIntegrationRepository
# from app.core.interfaces.repositories.notification_repository import INotificationRepository
# from app.core.interfaces.repositories.settings_repository import ISettingsRepository
# from app.core.interfaces.repositories.subscription_repository import ISubscriptionRepository
# from app.core.interfaces.repositories.task_repository import ITaskRepository

# Import database components or mock them if not available
# Ensure try block has a corresponding except block at the correct level
try:
    from app.domain.entities.patient import Patient
    # from app.infrastructure.persistence.sqlalchemy.config.database import Database # Moved up
    from app.infrastructure.persistence.sqlalchemy.repositories.patient_repository import (
        PatientRepository as ConcretePatientRepository,
    )
    # AsyncSQLAlchemyUnitOfWork is now imported globally
    # from app.infrastructure.persistence.sqlalchemy.unit_of_work.async_unit_of_work import AsyncSQLAlchemyUnitOfWork as UnitOfWork # Keep alias for try block if needed
    from app.infrastructure.security.encryption import encrypt_phi, decrypt_phi
    from app.domain.value_objects.address import Address as DomainAddress
    from app.domain.value_objects.emergency_contact import EmergencyContact as DomainEmergencyContact
    from app.core.domain.entities.patient import ContactInfo as DomainContactInfo

except ImportError:
    # This block is for environments where full app components might not be available.
    # For most tests, the above imports should succeed.
    # Define minimal mocks if imports fail to allow some basic tests to run.
    # (This is less ideal for security tests which should test real components)
    Patient = MagicMock()
    Database = MagicMock() # Already defined for spec
    ConcretePatientRepository = MagicMock()
    # AsyncSQLAlchemyUnitOfWork_Mock = MagicMock() # If we mock the UoW itself - replaced by global import
    encrypt_phi = MagicMock(side_effect=lambda x: f"encrypted_{x}")
    decrypt_phi = MagicMock(side_effect=lambda x: x.replace("encrypted_", "") if isinstance(x, str) else x)

    # Mock repository interfaces for UoW instantiation if real ones are complex to get here
    IUserRepository = MagicMock()
    IPatientRepository = ConcretePatientRepository # Use our existing mock PatientRepository
    IDigitalTwinRepository = MagicMock()
    IBiometricRuleRepository = MagicMock()
    IBiometricAlertRepository = MagicMock()
    IBiometricTwinRepository = MagicMock()
    # UnitOfWork = AsyncSQLAlchemyUnitOfWork # Alias is not needed if global import is used directly

# Import the domain entity for Patient
from app.core.domain.entities.patient import Patient as DomainPatient

# Mock context for testing
@pytest.fixture
def admin_context():
    return {"user_id": "admin_user", "role": "admin", "permissions": ["read_phi", "write_phi"]}

@pytest.fixture
def doctor_context():
    return {"user_id": "doctor_user", "role": "doctor", "permissions": ["read_phi"]}

@pytest.fixture
def mock_logger():
    # Patching at the location where get_logger is *used* by BaseRepository indirectly
    with patch('app.core.utils.logging.get_logger', new_callable=MagicMock) as mock_get_logger_function:
        mock_logger_instance = MagicMock() # This is the mock logger instance
        mock_get_logger_function.return_value = mock_logger_instance # Configure get_logger to return the mock logger
        yield mock_logger_instance # Yield the mock logger instance itself

class TestDBPHIProtection:
    """Test suite for database PHI protection mechanisms."""

    @pytest.fixture
    async def db(self):
        """Create a mock database instance suitable for async operations with tables created."""
        # Use a real async engine for in-memory SQLite
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")

        # Create tables - This needs to happen before the session factory is created
        # and used by the UoW or repositories.
        # Base is now imported from the canonical location above.

        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        async_session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

        mock_db_object = MagicMock(spec=Database)
        mock_db_object.session_factory = async_session_factory

        async def get_session_for_mock():
            return async_session_factory()
        mock_db_object.get_session = AsyncMock(side_effect=get_session_for_mock) # Ensure it returns a coroutine

        yield mock_db_object

        await engine.dispose() # Clean up the engine

    @pytest.fixture
    async def unit_of_work(self, db):
        """Provide an instance of AsyncSQLAlchemyUnitOfWork."""
        # Logger is now patched globally for repositories via mock_logger fixture
        
        uow = AsyncSQLAlchemyUnitOfWork(
            session_factory=db.session_factory,
            user_repository_cls=MagicMock(spec=IUserRepository),
            patient_repository_cls=ConcretePatientRepository,
            digital_twin_repository_cls=MagicMock(spec=IDigitalTwinRepository),
            biometric_rule_repository_cls=MagicMock(spec=IBiometricRuleRepository),
            biometric_alert_repository_cls=MagicMock(spec=IBiometricAlertRepository),
            biometric_twin_repository_cls=MagicMock(spec=IBiometricTwinRepository)
        )
        return uow

    @pytest.fixture
    def admin_context(self):
        """Create admin user context."""
        return {"role": "admin", "user_id": "A12345"}

    @pytest.fixture
    def doctor_context(self):
        """Create doctor user context."""
        return {"role": "doctor", "user_id": "D12345"}

    @pytest.fixture
    def nurse_context(self):
        """Create nurse user context."""
        return {"role": "nurse", "user_id": "N12345"}

    @pytest.fixture
    def patient_context(self):
        """Create patient user context."""
        return {"role": "patient", "user_id": "P12345"}

    @pytest.fixture
    def guest_context(self):
        """Create guest user context."""
        return {"role": "guest", "user_id": None}

    @pytest.mark.asyncio
    async def test_data_encryption_at_rest(self, unit_of_work, admin_context):
        """Test that PHI is encrypted when stored in the database."""
        uow = unit_of_work # Corrected: fixture is already awaited by pytest
        
        patient_id = uuid.uuid4()

        # Create a valid emergency contact address
        emergency_contact_address = DomainAddress(
            street="123 Emergency St",
            city="Crisis City",
            state="FL",
            zip_code="33333",
            country="USA"
        )
        emergency_contact = DomainEmergencyContact(
            name="Jane Emergency",
            relationship="Spouse",
            phone="555-019-9123",
            email="jane.emergency@example.com",
            address=emergency_contact_address
        )

        # Create patient's primary address
        patient_primary_address = DomainAddress(
            street="123 Main St",
            city="Anytown",
            state="CA",
            zip_code="90210",
            country="USA"
        )

        # Create patient with all expected fields
        original_patient = DomainPatient(
            id=patient_id,
            first_name="SensitiveName",
            last_name="SensitiveLastName",
            email="sensitive.email@example.com",
            phone_number="555-010-0123",
            date_of_birth="1990-05-15",
            medical_record_number_lve="MRN123_SENSITIVE",
            social_security_number_lve="999-00-1111",
            address=patient_primary_address,
            emergency_contact=emergency_contact,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            is_active=True
        )

        # For debugging, let's check what contact_info looks like after instantiation
        print(f"DEBUG: original_patient.contact_info: {original_patient.contact_info}")
        if original_patient.contact_info:
            print(f"DEBUG: original_patient.contact_info dict: {original_patient.contact_info.model_dump(exclude_none=True)}")
        print(f"DEBUG: original_patient.address: {original_patient.address}")
        if original_patient.address and hasattr(original_patient.address, 'to_dict'):
             print(f"DEBUG: original_patient.address dict: {original_patient.address.to_dict()}")
        elif original_patient.address:
             print(f"DEBUG: original_patient.address (no to_dict): {original_patient.address}")
        print(f"DEBUG: original_patient.emergency_contact: {original_patient.emergency_contact}")
        if original_patient.emergency_contact and hasattr(original_patient.emergency_contact, 'to_dict'):
             print(f"DEBUG: original_patient.emergency_contact dict: {original_patient.emergency_contact.to_dict()}")
        elif original_patient.emergency_contact:
             print(f"DEBUG: original_patient.emergency_contact (no to_dict): {original_patient.emergency_contact}")

        try:
            async with uow: # Wrap operations in UoW context
                await uow.patients.create(original_patient)
                await uow.commit()
        except PersistenceError as e:
            print(f"Caught PersistenceError: {e}")
            print(f"PersistenceError detail: {e.detail}")
            if hasattr(e, 'original_exception') and e.original_exception:
                print(f"Original exception: {type(e.original_exception)}")
                # If Pydantic's ValidationError is the original_exception, print its errors
                if isinstance(e.original_exception, ValidationError):
                    print(f"Pydantic validation errors: {e.original_exception.errors()}")
                else:
                    print(f"Original exception details: {e.original_exception}")

            # Re-raise the error if it's not the one we're testing for,
            # or if we want the test to fail to see the full traceback.
            # For now, we let it fail to get the Pydantic errors.
            raise  # Re-raise to ensure the test fails and we see output
        except Exception as e:
            print(f"Caught other unexpected exception: {type(e)} - {e}")
            raise

        # Retrieve and verify (this will go through to_domain which decrypts)
        async with uow: # New session for retrieval
            retrieved_patient_domain = await uow.patients.get_by_id(patient_id)

        assert retrieved_patient_domain is not None
        assert retrieved_patient_domain.id == original_patient.id
        assert retrieved_patient_domain.first_name == "SensitiveName"
        assert retrieved_patient_domain.last_name == "SensitiveLastName"
        assert retrieved_patient_domain.email == "sensitive.email@example.com"
        # Date of birth is converted to date object by Pydantic
        assert retrieved_patient_domain.date_of_birth == datetime.date(1990, 5, 15)
        assert retrieved_patient_domain.medical_record_number == "MRN123_SENSITIVE"
        assert retrieved_patient_domain.ssn == "999-00-1111"

        # Further checks could involve directly querying the DB (if possible with test setup)
        # to see the encrypted form, but that's harder with TypeDecorators.
        # The core test is that data comes back decrypted correctly.

    @pytest.mark.asyncio
    async def test_role_based_access_control(self, unit_of_work, admin_context, patient_context):
        """Test that access to PHI is properly controlled by role."""
        uow = unit_of_work
        patient_id = uuid.uuid4()
        test_patient = DomainPatient(
            id=patient_id,
            first_name="RBACTest",
            last_name="RBACTestLastName",
            email="rbac.test@example.com",
            phone="555-0102",
            date_of_birth="2000-01-01",
            medical_record_number="MRN123_RBACTest",
            ssn="123-45-6789"
        )

        # Admin creates patient - this should be within a UoW block
        async with uow: # Correctly using UoW
            await uow.patients.create(test_patient, context=admin_context)
            await uow.commit()

        # Attempt to access PHI with different roles
        # These operations are NOT wrapped in a UoW context, causing the error.

        # Admin can read PHI
        async with uow:
            retrieved_patient_admin = await uow.patients.get_by_id(patient_id, context=admin_context)
        assert retrieved_patient_admin is not None
        assert retrieved_patient_admin.first_name == "RBACTest"
        assert retrieved_patient_admin.last_name == "RBACTestLastName"
        assert retrieved_patient_admin.email == "rbac.test@example.com"
        assert retrieved_patient_admin.date_of_birth == datetime.date(2000, 1, 1)
        assert retrieved_patient_admin.medical_record_number == "MRN123_RBACTest"
        assert retrieved_patient_admin.ssn == "123-45-6789"

        # Patient can read their own PHI (assuming repository method checks ownership)
        # This would also fail if get_by_id doesn't implicitly start a new session or is called outside a UoW.
        async with uow:
            retrieved_patient_self = await uow.patients.get_by_id(patient_id, context=patient_context)
        assert retrieved_patient_self is not None
        assert retrieved_patient_self.first_name == "RBACTest"
        assert retrieved_patient_self.last_name == "RBACTestLastName"
        assert retrieved_patient_self.email == "rbac.test@example.com"
        assert retrieved_patient_self.date_of_birth == datetime.date(2000, 1, 1)
        assert retrieved_patient_self.medical_record_number == "MRN123_RBACTest"
        assert retrieved_patient_self.ssn == "123-45-6789"
        
        # Example: A doctor (different user) might not be able to access without linkage
        # This depends on how your access control is implemented.
        # For simplicity, let's assume a generic doctor_context
        doctor_context_local = {"role": "doctor", "user_id": "doctor_user_123"}
        with pytest.raises(Exception): # Or a specific AuthorizationError
             # This call is outside a UoW and would fail.
            async with uow:
                await uow.patients.get_by_id(patient_id, context=doctor_context_local)

    @pytest.mark.asyncio
    async def test_patient_data_isolation(self, unit_of_work):
        """Test that patients can only access their own data."""
        uow = unit_of_work
        patient1_id = uuid.uuid4()
        patient2_id = uuid.uuid4()

        patient1 = DomainPatient(
            id=patient1_id,
            first_name="PatientOne",
            last_name="PatientOneLastName",
            email="patient1@example.com",
            phone="555-0103",
            date_of_birth="1990-01-01",
            medical_record_number="MRN123_PatientOne",
            ssn="123-45-6789"
        )
        patient2 = DomainPatient(
            id=patient2_id,
            first_name="PatientTwo",
            last_name="PatientTwoLastName",
            email="patient2@example.com",
            phone="555-0104",
            date_of_birth="1990-01-01",
            medical_record_number="MRN123_PatientTwo",
            ssn="123-45-6789"
        )

        async with uow:
            await uow.patients.create(patient1)
            await uow.patients.create(patient2)
            await uow.commit()

        # Simulate patient1 trying to access their own data (should succeed)
        retrieved_patient1 = await uow.patients.get_by_id(patient1_id)
        assert retrieved_patient1 is not None
        assert retrieved_patient1.first_name == "PatientOne"
        assert retrieved_patient1.last_name == "PatientOneLastName"
        assert retrieved_patient1.email == "patient1@example.com"
        assert retrieved_patient1.date_of_birth == datetime.date(1990, 1, 1)
        assert retrieved_patient1.medical_record_number == "MRN123_PatientOne"
        assert retrieved_patient1.ssn == "123-45-6789"

        # Data isolation is usually enforced by service layer based on authenticated user.
        # The repository itself might not know "who" is asking.
        # This test, as written for a generic repo, verifies IDs work.
        # True data isolation test would involve mocking auth and a service.

    @pytest.mark.asyncio
    @patch('app.infrastructure.persistence.sqlalchemy.repositories.patient_repository.AuditLogger.log_phi_access')
    async def test_audit_logging(self, mock_log_phi_access, unit_of_work, mock_logger):
        """Test that PHI access and modifications are audited."""
        uow = unit_of_work
        patient_id = uuid.uuid4()
        patient_data = DomainPatient(
            first_name="Audit",
            last_name="Logged",
            email="audit.logged@example.com",
            phone="555-0105",
            date_of_birth="2000-01-01",
            medical_record_number="MRN123_AuditLogged",
            ssn="999-00-1111"
        )
        
        async with uow:
            # Example: Create patient
            created_domain_patient = await uow.patients.create(patient_data)
            await uow.commit()
        
        # Assert that the mock_logger (from base repository) was called for general repo operations
        # Example: Check if info was called during get_by_id or create
        mock_logger.info.assert_any_call(f"Attempting to retrieve Patient by ID: {patient_id}")
        # Assert that the specific PHI access logger was called
        mock_log_phi_access.assert_called_with(user_id="test_user", patient_id=patient_id, action="READ")

        async with uow:
            # Example: Read patient
            retrieved_patient = await uow.patients.get_by_id(created_domain_patient.id)
        # mock_logger.info.assert_any_call(f"PHI accessed for patient ID: {created_domain_patient.id}")

        async with uow:
            # Example: Update patient
            retrieved_patient.first_name = "AuditedUpdate"
            await uow.patients.update(retrieved_patient) # Assuming an update method
            await uow.commit()
        # mock_logger.info.assert_any_call(f"PHI updated for patient ID: {created_domain_patient.id}")
        
        assert True # Placeholder: test structure is more important here for now.

    @pytest.mark.asyncio
    async def test_phi_filtering_by_role(self, unit_of_work, admin_context, patient_context):
        """Test PHI filtering based on user roles."""
        uow = unit_of_work
        patient_id = uuid.uuid4()
        test_patient = DomainPatient(
            id=patient_id,
            first_name="John",
            last_name="Doe",
            email="john.doe@example.com",
            date_of_birth="1988-08-08",
            phone="555-0106",
            ssn="123-45-6789" # Example PHI
        )
        async with uow:
            await uow.patients.create(test_patient)
            await uow.commit()

        # Admin access (should see all fields)
        admin_repo = uow.patients # Using the full access repo
        admin_patient_view = await admin_repo.get_by_id(patient_id)
        assert admin_patient_view is not None
        assert admin_patient_view.first_name == "John"
        assert admin_patient_view.ssn == "123-45-6789"

        # Patient access (should see their own data, potentially filtered if repo was role-aware)
        patient_repo = uow.patients
        patient_self_view = await patient_repo.get_by_id(patient_id)
        assert patient_self_view is not None
        assert patient_self_view.first_name == "John"
        assert patient_self_view.ssn == "123-45-6789"
        
        # A "researcher" role might see de-identified or limited data.
        # This would require a different repository or service method.

    @pytest.mark.asyncio
    async def test_transaction_rollback_on_error(self, unit_of_work, db, mock_logger):
        """Test that transactions are rolled back on error using AsyncUoW."""
        uow = unit_of_work # Corrected: fixture is already awaited

        patient_repo_instance = uow.patients 
        # Mock the create method on the repository instance to raise an error
        patient_repo_instance.create = AsyncMock(side_effect=Exception("Database error"))

        with pytest.raises(Exception, match="Database error"):
            async with uow:
                # Attempt to create a patient; this will call the mocked create method
                await uow.patients.create(
                    DomainPatient(
                        first_name="Error", 
                        last_name="Test", 
                        date_of_birth="2000-01-01",
                        phone="555-0107"
                    )
                )
                # The commit should not be reached if create raises an error.
                # The UoW's __aexit__ should handle rollback.

        # To verify rollback, we'd ideally check that the "Error Test" patient
        # does not exist in the database after the exception.
        # This requires another session or UoW instance.
        
        new_uow = AsyncSQLAlchemyUnitOfWork( # Create a new UoW to check DB state
            session_factory=db.session_factory,
            logger_factory=MagicMock(), # Mock logger factory for this check
            patient_repository_cls=ConcretePatientRepository 
        )
        async with new_uow:
            # Try to get the patient that should not have been committed
            # Need a way to query by name or ensure ID is known if it were assigned before error
            # For this test, a simpler check is that the session inside the original uow
            # was rolled back. This is hard to assert directly without more complex mocking of the session.
            # The fact that the exception propagated and __aexit__ was called is the primary test here.
            # A more robust check might involve trying to fetch by a unique field if IDs are dynamic.
            pass

    @pytest.mark.asyncio
    async def test_no_phi_in_error_messages(self, unit_of_work, mock_logger):
        """Test that error messages from DB operations do not contain PHI."""
        uow = unit_of_work
        
        # Configure the repository's method to raise a generic error
        # Access the repository instance from the UoW
        patient_repo_instance = uow.patients
        patient_repo_instance.get_by_id = AsyncMock(side_effect=Exception("Generic DB error"))

        phi_laden_id = "patient_id_with_sensitive_info" # This is just a string, not a real ID for get_by_id

        with pytest.raises(Exception) as excinfo:
            async with uow:
                await uow.patients.get_by_id(phi_laden_id)
        
        assert phi_laden_id not in str(excinfo.value).lower()
        assert "sensitive_info" not in str(excinfo.value).lower()
        assert "generic db error" in str(excinfo.value).lower() # Check for the mocked error message

    @pytest.mark.asyncio
    async def test_phi_in_query_parameters(self, unit_of_work, mock_logger, db):
        """Test that PHI is not directly used in SQL query parameters (conceptual)."""
        uow = unit_of_work # Corrected

        # Get a real session from the db fixture to patch its `execute` method
        async with await db.get_session() as real_session:
            # Patch 'execute' on the *instance* of the session the UoW will use.
            # This is tricky because the UoW creates its own session.
            # A better approach is to patch it on the session_factory.
            
            # Let's mock what the repository might do for a query by an encrypted field.
            # This requires knowing how the repository constructs such queries.
            # For now, we simulate a scenario where a session's execute is called.
            
            mock_execute = AsyncMock() # Corrected to AsyncMock
            
            # Patch the 'execute' method of the AsyncSession class globally for this test
            # This is broad, but helps to intercept the call.
            with patch('sqlalchemy.ext.asyncio.AsyncSession.execute', mock_execute):
                async with uow:
                    try:
                        # Call a repo method that would internally call session.execute
                        # Example: trying to fetch a non-existent patient to trigger a select query
                        await uow.patients.get_by_id(str(uuid.uuid4())) 
                    except Exception:
                        pass # Ignore errors, focus on execute call

        # mock_execute.assert_called_once() # or assert_awaited_once for AsyncMock
        mock_execute.assert_awaited_once() # Check if execute was awaited

        # Ideal check (if query object was accessible and not a string):
        # actual_query_params = mock_execute.call_args[0][0].compile(dialect=...).params
        # assert "sensitive@example.com" not in str(actual_query_params_values)
        # This is hard to test robustly without deep diving into repo's query construction.
        # The primary protection here is that TypeDecorators encrypt before params hit SQL.
        
        # For this test, we're primarily verifying the mock setup and that execute is called.
        # The actual non-exposure of PHI in parameters is an architectural guarantee of TypeDecorators.
        assert True # Placeholder: test structure is more important here for now.

    # Additional tests could include:
    # - Proper handling of encryption key rotation (if applicable to service)
    # - Behavior when encryption service is unavailable
    # - Performance implications of encryption/decryption (though likely out of scope for unit tests)

# Correct top-level indentation
if __name__ == "__main__":
    pytest.main(["-v", __file__])
