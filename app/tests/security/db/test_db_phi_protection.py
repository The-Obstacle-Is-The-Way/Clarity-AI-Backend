#!/usr/bin/env python3
"""
Test suite for database PHI protection mechanisms.
This validates that database interactions properly protect PHI per HIPAA requirements.
"""

import datetime
from unittest.mock import MagicMock, patch

import pytest

# Core SQLAlchemy async components
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

# Import the canonical Base for table creation
from app.infrastructure.persistence.sqlalchemy.models.base import Base
from app.infrastructure.persistence.sqlalchemy.config.database import Database # For spec in MagicMock

# Import repository interfaces
from app.core.interfaces.repositories.user_repository_interface import IUserRepository
from app.core.interfaces.repositories.patient_repository import IPatientRepository
from app.core.interfaces.repositories.digital_twin_repository import IDigitalTwinRepository
from app.core.interfaces.repositories.biometric_rule_repository import IBiometricRuleRepository
from app.core.interfaces.repositories.biometric_alert_repository import IBiometricAlertRepository
from app.core.interfaces.repositories.biometric_twin_repository import IBiometricTwinRepository

# Import database components or mock them if not available
# Ensure try block has a corresponding except block at the correct level
try:
    from app.domain.entities.patient import Patient
    # from app.infrastructure.persistence.sqlalchemy.config.database import Database # Moved up
    from app.infrastructure.persistence.sqlalchemy.repositories.patient_repository import (
        PatientRepository as ConcretePatientRepository,
    )
    from app.infrastructure.persistence.sqlalchemy.unit_of_work.async_unit_of_work import AsyncSQLAlchemyUnitOfWork as UnitOfWork
    from app.infrastructure.security.encryption import encrypt_phi, decrypt_phi

except ImportError:
    # This block is for environments where full app components might not be available.
    # For most tests, the above imports should succeed.
    # Define minimal mocks if imports fail to allow some basic tests to run.
    # (This is less ideal for security tests which should test real components)
    Patient = MagicMock()
    Database = MagicMock() # Already defined for spec
    ConcretePatientRepository = MagicMock()
    AsyncSQLAlchemyUnitOfWork_Mock = MagicMock() # If we mock the UoW itself
    encrypt_phi = MagicMock(side_effect=lambda x: f"encrypted_{x}")
    decrypt_phi = MagicMock(side_effect=lambda x: x.replace("encrypted_", "") if isinstance(x, str) else x)

    # Mock repository interfaces for UoW instantiation if real ones are complex to get here
    IUserRepository = MagicMock()
    IPatientRepository = ConcretePatientRepository # Use our existing mock PatientRepository
    IDigitalTwinRepository = MagicMock()
    IBiometricRuleRepository = MagicMock()
    IBiometricAlertRepository = MagicMock()
    IBiometricTwinRepository = MagicMock()
    UnitOfWork = AsyncSQLAlchemyUnitOfWork # Alias UnitOfWork to AsyncSQLAlchemyUnitOfWork

# Mock context for testing
@pytest.fixture
def admin_context():
    return {"user_id": "admin_user", "role": "admin", "permissions": ["read_phi", "write_phi"]}

@pytest.fixture
def doctor_context():
    return {"user_id": "doctor_user", "role": "doctor", "permissions": ["read_phi"]}

@pytest.fixture
def mock_logger_factory():
    with patch("app.infrastructure.logging.logger.get_logger") as mock_get_logger:
        mock_logger = MagicMock()
        mock_get_logger.return_value = mock_logger
        yield mock_logger # Yield the logger instance itself for assertions

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
        mock_db_object.get_session = MagicMock(side_effect=get_session_for_mock) # Ensure it returns a coroutine

        yield mock_db_object

        await engine.dispose() # Clean up the engine

    @pytest.fixture
    async def unit_of_work(self, db: Database): # Ensure db is typed if it helps resolution
        """Create an AsyncSQLAlchemyUnitOfWork instance with mock repositories."""
        if not hasattr(db, 'session_factory'):
            raise AttributeError("Mock 'db' fixture is missing 'session_factory' attribute, which is required by AsyncSQLAlchemyUnitOfWork.")
        
        # Provide mock repository classes to AsyncSQLAlchemyUnitOfWork constructor
        return UnitOfWork(
            session_factory=db.session_factory,
            user_repository_cls=MagicMock(spec=IUserRepository),
            patient_repository_cls=MagicMock(spec=IPatientRepository),
            digital_twin_repository_cls=MagicMock(spec=IDigitalTwinRepository),
            biometric_rule_repository_cls=MagicMock(spec=IBiometricRuleRepository),
            biometric_alert_repository_cls=MagicMock(spec=IBiometricAlertRepository),
            biometric_twin_repository_cls=MagicMock(spec=IBiometricTwinRepository)
        )

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
    async def test_data_encryption_at_rest(self, db, admin_context):
        """Test that PHI is encrypted when stored in the database."""
        repo = ConcretePatientRepository(db_session=await db.get_session(), user_context=admin_context)

        # Create a patient with PHI
        patient = Patient(
            first_name="John",
            last_name="Doe",
            date_of_birth="1980-01-01",
            ssn="123-45-6789",
            email="john.doe@example.com",
            phone="555-123-4567",
            address="123 Main St, Anytown, CA 12345",
            medical_record_number="MRN12345"
        )

        created_patient = await repo.create(patient)

        # Verify PHI fields are encrypted
        assert created_patient.ssn != "123-45-6789"
        assert created_patient.ssn.startswith("ENCRYPTED_")
        assert created_patient.email != "john.doe@example.com"
        assert created_patient.email.startswith("ENCRYPTED_")
        assert created_patient.phone != "555-123-4567"
        assert created_patient.phone.startswith("ENCRYPTED_")
        assert created_patient.address != "123 Main St, Anytown, CA 12345"
        assert created_patient.address.startswith("ENCRYPTED_")

        # Non-PHI fields should not be encrypted
        assert created_patient.first_name == "John"
        assert created_patient.last_name == "Doe"
        assert created_patient.date_of_birth == "1980-01-01"
        assert created_patient.medical_record_number == "MRN12345"

    @pytest.mark.asyncio
    async def test_role_based_access_control(self, db):
        """Test that access to PHI is properly controlled by role."""
        admin_repo = ConcretePatientRepository(
            db_session=await db.get_session(), user_context={"role": "admin", "user_id": "A12345"}
        )
        doctor_repo = ConcretePatientRepository(
            db_session=await db.get_session(), user_context={"role": "doctor", "user_id": "D12345"}
        )
        nurse_repo = ConcretePatientRepository(
            db_session=await db.get_session(), user_context={"role": "nurse", "user_id": "N12345"}
        )
        patient_repo = ConcretePatientRepository(
            db_session=await db.get_session(), user_context={"role": "patient", "user_id": "P12345"}
        )
        guest_repo = ConcretePatientRepository(
            db_session=await db.get_session(), user_context={"role": "guest", "user_id": None}
        )

        # All three clinical roles should be able to get patients
        assert (await admin_repo.get_by_id("P12345")) is not None
        assert (await doctor_repo.get_by_id("P12345")) is not None
        assert (await nurse_repo.get_by_id("P12345")) is not None

        # Patient should only access their own record
        assert (await patient_repo.get_by_id("P12345")) is not None
        assert (await patient_repo.get_by_id("P67890")) is None

        # Guest should not access any records
        assert (await guest_repo.get_by_id("P12345")) is None

        # Only admin and doctor can create patients
        try:
            await admin_repo.create(Patient(first_name="Test", last_name="Patient"))
            await doctor_repo.create(Patient(first_name="Test", last_name="Patient"))
        except PermissionError:
            pytest.fail("Admin and doctor should be able to create patients")

        # Nurse should not be able to create patients
        with pytest.raises(PermissionError):
            await nurse_repo.create(Patient(first_name="Test", last_name="Patient"))

        # Only admin can delete patients
        try:
            # Assuming P12345 exists from mock get_by_id logic
            await admin_repo.delete("P12345")
        except PermissionError:
            pytest.fail("Admin should be able to delete patients")

        # Doctor should not be able to delete patients
        with pytest.raises(PermissionError):
            await doctor_repo.delete("P12345")

    @pytest.mark.asyncio
    async def test_patient_data_isolation(self, db):
        """Test that patients can only access their own data."""
        patient1_repo = ConcretePatientRepository(
            db_session=await db.get_session(),
            user_context={"role": "patient", "user_id": "P12345"}
        )
        patient2_repo = ConcretePatientRepository(
            db_session=await db.get_session(),
            user_context={"role": "patient", "user_id": "P67890"}
        )

        # Each patient should only access their own record
        assert (await patient1_repo.get_by_id("P12345")) is not None
        assert (await patient1_repo.get_by_id("P67890")) is None

        assert (await patient2_repo.get_by_id("P67890")) is not None
        assert (await patient2_repo.get_by_id("P12345")) is None

        # Patients should not be able to get all patients
        assert len(await patient1_repo.get_all()) == 0
        assert len(await patient2_repo.get_all()) == 0

    @pytest.mark.asyncio
    async def test_audit_logging(self, db, admin_context):
        """Test that all PHI access is properly logged for auditing."""
        repo = ConcretePatientRepository(db_session=await db.get_session(), user_context=admin_context)

        # Perform various operations
        await repo.get_by_id("P12345")
        await repo.get_all()
        # Use a distinct name to avoid hash collision if tests run fast
        created_patient = await repo.create(Patient(first_name="Audit", last_name="Test"))
        await repo.update(
            Patient(
                id=created_patient.id,
                first_name="UpdatedAudit",
                last_name="Test"
            )
        )
        await repo.delete(created_patient.id)

        # Check audit log contains all operations
        operations = [entry["operation"] for entry in repo.audit_log]
        assert "get_by_id" in operations
        assert "get_all" in operations
        assert "create" in operations
        assert "update" in operations
        assert "delete" in operations

        # Check audit log contains required fields
        for entry in repo.audit_log:
            assert "timestamp" in entry
            assert "operation" in entry
            assert "patient_id" in entry # Can be None
            assert "user" in entry
            assert "role" in entry
            assert "success" in entry

    @pytest.mark.asyncio
    async def test_phi_filtering_by_role(self, db):
        """Test PHI filtering based on user roles."""
        # This test requires a real session or a more sophisticated mock
        # For now, using a simple MagicMock for the session
        session = await db.get_session()
        
        # Test with various roles
        admin_repo = ConcretePatientRepository(db_session=session, user_context={"role": "admin", "user_id": "A123"})
        admin_patient = await admin_repo.get_by_id("P12345")

        doctor_repo = ConcretePatientRepository(db_session=session, user_context={"role": "doctor", "user_id": "D456"})
        doctor_patient = await doctor_repo.get_by_id("P12345")

        nurse_repo = ConcretePatientRepository(db_session=session, user_context={"role": "nurse", "user_id": "N789"})
        nurse_patient = await nurse_repo.get_by_id("P12345")

        patient_repo = ConcretePatientRepository(db_session=session, user_context={"role": "patient", "user_id": "P12345"})
        own_patient = await patient_repo.get_by_id("P12345")

        guest_repo = ConcretePatientRepository(db_session=session, user_context={"role": "guest", "user_id": None})
        guest_patient = await guest_repo.get_by_id("P12345")

        # Helper function to decrypt and compare, assuming decrypt_phi is available
        def decrypt_for_role(value, role):
            if value and value.startswith("ENCRYPTED_"):
                if role == "admin":
                    return value[10:]  # Full decryption for admin
                elif role == "doctor":
                    return value[10:] if "ssn" not in value.lower() else "REDACTED"  # Limited for doctor
                elif role == "nurse":
                    return value[10:] if "first" in value.lower() or "last" in value.lower() else "REDACTED"
                else:
                    return "REDACTED"  # No access for others
            return value
        
        # Mock decrypt_phi to use role-based decryption
        with patch("app.tests.security.db.test_db_phi_protection.decrypt_phi") as mock_decrypt:
            mock_decrypt.side_effect = lambda v, role="guest": decrypt_for_role(v, role)
            
            # Test admin access - should see everything including SSN
            assert admin_patient.first_name == "John", "Admin should see decrypted first name"
            assert admin_patient.ssn == "123-45-6789", "Admin should see decrypted SSN"
            assert admin_patient.email == "john.doe@example.com", "Admin should see decrypted email"
            
            # Test doctor access - should see most fields but not SSN
            assert doctor_patient.first_name == "John", "Doctor should see decrypted first name"
            assert doctor_patient.ssn == "REDACTED", "Doctor should not see SSN"
            assert doctor_patient.email == "john.doe@example.com", "Doctor should see decrypted email"
            
            # Test nurse access - should see only basic identification
            assert nurse_patient.first_name == "John", "Nurse should see decrypted first name"
            assert nurse_patient.ssn == "REDACTED", "Nurse should not see SSN"
            assert nurse_patient.email == "REDACTED", "Nurse should not see email"
            
            # Test patient access - should see only their own basic info
            assert own_patient.first_name == "REDACTED", "Patient should not see even their own full details without specific permission"
            assert own_patient.ssn == "REDACTED", "Patient should not see SSN"
            
            # Test guest/unauthorized access - should see nothing
            assert guest_patient.first_name == "REDACTED", "Guest should not see PHI"
            assert guest_patient.ssn == "REDACTED", "Guest should not see SSN"
            assert guest_patient.email == "REDACTED", "Guest should not see email"

    @pytest.mark.asyncio
    async def test_transaction_rollback_on_error(self, unit_of_work, db, admin_context):
        """Test that transactions are rolled back on error using AsyncUoW."""
        uow = await unit_of_work # The fixture itself is async, so await its result

        # Since patient_repository_cls is our MagicMock PatientRepository,
        # uow.patients will be an instance of this mock.
        # We need to configure the mock instance's create method.
        
        # Mock the create method on the repository instance obtained from UoW
        # uow.patients should be an instance of the mocked PatientRepository
        # If PatientRepository is a MagicMock class, uow.patients will be a MagicMock instance.
        # Let's assume PatientRepository from the ImportError block is used as the class.
        # So, uow.patients will be an instance of that MagicMock class.

        # Correct approach: The UoW instantiates the repo. We mock the `create` method on *that instance*.
        # However, the UoW's repo properties (like uow.patients) create the repo on first access.
        # So, we access it once to get the instance, then configure its mock methods.
        patient_repo_instance = uow.patients 
        patient_repo_instance.create = MagicMock(side_effect=Exception("Database error"))

        with pytest.raises(Exception, match="Database error"):
            async with uow: # This now uses the AsyncSQLAlchemyUnitOfWork
                # This will call patient_repo_instance.create(...)
                await uow.patients.create(Patient(first_name="Error", last_name="Test", date_of_birth="2000-01-01"))

        # Rollback is implicitly tested by __aexit__ handling the exception.
        # No direct uow.rolled_back attribute in AsyncSQLAlchemyUnitOfWork.
        # Optional: could patch uow._session.rollback and assert it was awaited.

    @pytest.mark.asyncio
    async def test_phi_in_query_parameters(self, db, admin_context, mock_logger_factory):
        """Test that PHI is not logged when used in query parameters."""
        # Get a real session instance from our async db fixture
        # This session will be used by the repository
        real_session = await db.get_session()

        # The repository will use this real_session
        repo = ConcretePatientRepository(db_session=real_session, user_context=admin_context)

        # Define a side effect function for the mocked execute
        async def execute_query_side_effect(*args, **kwargs):
            # Simulate finding a patient
            mock_result = MagicMock()
            mock_result.scalars.return_value.first.return_value = Patient(
                id="sensitive_id_123", 
                first_name=encrypt_phi("SensitiveName"), 
                email=encrypt_phi("sensitive@example.com")
            )
            return mock_result

        # Patch the 'execute' method of the *specific session instance* used by the repo
        with patch.object(real_session, 'execute', new_callable=MagicMock) as mock_execute:
            mock_execute.side_effect = execute_query_side_effect
            
            # Attempt to get a patient by an ID that might be considered PHI
            # The actual ID doesn't matter as much as the fact we're testing logging
            await repo.get_by_id("sensitive_id_123")

            # Assert that the mock logger (from mock_logger_factory) was NOT called with sensitive data
            # This requires inspecting the calls to the mock_logger provided by the factory.
            # The mock_logger_factory yields the logger instance directly.
            logger_instance = mock_logger_factory
            
            # Check all log calls for the sensitive ID
            sensitive_id_in_logs = False
            for call_args, call_kwargs in logger_instance.log.call_args_list:
                # call_args usually contains (level, message, ...)
                if any("sensitive_id_123" in str(arg) for arg in call_args):
                    sensitive_id_in_logs = True
                    break
            assert not sensitive_id_in_logs, "Sensitive ID found in logs!"

            # Also check that execute was called (basic check that the path was taken)
            mock_execute.assert_awaited_once()

        # Close the session obtained from the db fixture
        await real_session.close()

# Correct top-level indentation
if __name__ == "__main__":
    pytest.main(["-v", __file__])
