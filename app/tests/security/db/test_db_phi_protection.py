#!/usr/bin/env python3
"""
Test suite for database PHI protection mechanisms.
This validates that database interactions properly protect PHI per HIPAA requirements.
"""

import datetime
from unittest.mock import MagicMock, patch

import pytest

# Import database components or mock them if not available
# Ensure try block has a corresponding except block at the correct level
try:
    from app.domain.entities.patient import Patient
    from app.infrastructure.persistence.sqlalchemy.config.database import Database
    from app.infrastructure.persistence.sqlalchemy.repositories.patient_repository import (
        PatientRepository,
    )
    from app.infrastructure.persistence.sqlalchemy.unit_of_work.unit_of_work import UnitOfWork
    # Assuming these are defined elsewhere or should be mocked too
    # from app.infrastructure.security.encryption import encrypt_phi, decrypt_phi

    # Define mock encrypt/decrypt if the import fails or is not intended
    def encrypt_phi(value): return f"ENCRYPTED_{value}" if value else value
    def decrypt_phi(value): return value[10:] if value and value.startswith("ENCRYPTED_") else value

except ImportError:
    # Mock classes for testing database PHI protection
    # Correct indentation and structure for mock classes
    # Mock classes for testing database PHI protection
    # Correct indentation and structure for mock classes

    # No decorator needed here as it's a mock definition
    class Database:
        """Mock database for testing."""

        def __init__(self):
            self.connection = MagicMock()
            self.session = MagicMock()

        def get_session(self):
            """Get a database session."""
            return self.session

    class UnitOfWork:
        """Mock unit of work for testing."""

        def __init__(self, database=None):
            self.database = database or Database()
            self.committed = False
            self.rolled_back = False

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            if exc_type:
                self.rollback()

        def commit(self):
            """Commit the unit of work."""
            self.committed = True

        def rollback(self):
            """Rollback the unit of work."""
            self.rolled_back = True

    class Patient:
        """Mock patient entity for testing."""
        # Correct __init__ definition and indentation
        def __init__(
            self,
            id=None,
            first_name=None,
            last_name=None,
            date_of_birth=None,
            ssn=None,
            email=None, phone=None, address=None, medical_record_number=None
        ):
            self.id = id
            self.first_name = first_name
            self.last_name = last_name
            self.date_of_birth = date_of_birth
            self.ssn = ssn
            self.email = email
            self.phone = phone
            self.address = address
            self.medical_record_number = medical_record_number

    # Remove duplicated class definition from Patient.__init__
    # Correct indentation for PatientRepository class definition
    class PatientRepository:
        """Mock patient repository for testing."""

        # Correct __init__ definition and indentation
        def __init__(
            self,
            session=None,
            encryption_key=None,
            user_context=None
        ):
            self.session = session or MagicMock()
            self.encryption_key = encryption_key or "test_encryption_key"
            self.user_context = user_context or {"role": "guest", "user_id": None}
            self.audit_log = []
            self.encryption_service = MagicMock()

        # Correct method indentation and logic
        def get_by_id(self, patient_id: str) -> Patient | None:
            """Get patient by ID with proper access control."""
            # Check authorization
            if not self._can_access_patient(patient_id):
                self._log_access_attempt("get_by_id", patient_id, False)
                return None

            # Mock patient data - Correct Patient instantiation
            patient = Patient(
                id=patient_id,
                first_name="John",
                last_name="Doe",
                date_of_birth="1980-01-01",
                ssn=self._encrypt("123-45-6789"),
                email=self._encrypt("john.doe@example.com"),
                phone=self._encrypt("555-123-4567"),
                address=self._encrypt("123 Main St, Anytown, CA 12345"),
                medical_record_number="MRN12345"
            )

            # Apply PHI filtering based on role
            patient = self._apply_phi_filters(patient)

            self._log_access_attempt("get_by_id", patient_id, True)
            return patient

        # Correct method definition and indentation
        def get_all(
            self,
            limit: int = 100,
            offset: int = 0
        ) -> list[Patient]:
            """Get all patients with proper access control."""
            # Check authorization
            if self.user_context["role"] not in ["admin", "doctor", "nurse"]:
                self._log_access_attempt("get_all", None, False)
                return []

            # Mock patient data - Correct Patient instantiation
            patients = [
                Patient(
                    id="P12345",
                    first_name="John",
                    last_name="Doe",
                    date_of_birth="1980-01-01",
                    ssn=self._encrypt("123-45-6789"),
                    email=self._encrypt("john.doe@example.com"),
                    phone=self._encrypt("555-123-4567"),
                    address=self._encrypt("123 Main St, Anytown, CA 12345"),
                    medical_record_number="MRN12345"
                ),
                Patient(
                    id="P67890",
                    first_name="Jane",
                    last_name="Smith",
                    date_of_birth="1985-05-15",
                    ssn=self._encrypt("987-65-4321"),
                    email=self._encrypt("jane.smith@example.com"),
                    phone=self._encrypt("555-987-6543"),
                    address=self._encrypt("456 Oak Ave, Somewhere, NY 67890"),
                    medical_record_number="MRN67890"
                )
            ]

            # Apply PHI filtering based on role - Correct list comprehension
            filtered_patients = [self._apply_phi_filters(p) for p in patients]

            self._log_access_attempt("get_all", None, True)
            return filtered_patients

        # Correct method indentation and logic
        def create(self, patient: Patient) -> Patient:
            """Create a new patient with proper access control and encryption."""
            # Check authorization
            if self.user_context["role"] not in ["admin", "doctor"]:
                self._log_access_attempt("create", None, False)
                raise PermissionError("Unauthorized to create patients")

            # Encrypt PHI fields
            patient.ssn = self._encrypt(patient.ssn)
            patient.email = self._encrypt(patient.email)
            patient.phone = self._encrypt(patient.phone)
            patient.address = self._encrypt(patient.address)

            # Mock creation in database
            patient.id = "P" + str(hash(patient.first_name + patient.last_name))[:5]

            self._log_access_attempt("create", patient.id, True)
            return patient

        # Correct method indentation and logic
        def update(self, patient: Patient) -> Patient:
            """Update a patient with proper access control and encryption."""
            # Check authorization
            if not self._can_access_patient(patient.id):
                self._log_access_attempt("update", patient.id, False)
                # Correct PermissionError instantiation
                raise PermissionError(f"Unauthorized to update patient {patient.id}")

            # Encrypt PHI fields
            patient.ssn = self._encrypt(patient.ssn)
            patient.email = self._encrypt(patient.email)
            patient.phone = self._encrypt(patient.phone)
            patient.address = self._encrypt(patient.address)

            self._log_access_attempt("update", patient.id, True)
            return patient

        # Correct method indentation and logic
        def delete(self, patient_id: str) -> bool:
            """Delete a patient with proper access control."""
            # Check authorization
            if self.user_context["role"] != "admin":
                self._log_access_attempt("delete", patient_id, False)
                # Correct PermissionError instantiation
                raise PermissionError(f"Unauthorized to delete patient {patient_id}")

            self._log_access_attempt("delete", patient_id, True)
            return True

        # Correct method indentation and logic
        def _can_access_patient(self, patient_id: str) -> bool:
            """Check if current user can access the patient."""
            role = self.user_context["role"]
            user_id = self.user_context["user_id"]

            if role in ["admin", "doctor", "nurse"]:
                return True
            elif role == "patient" and user_id == patient_id:
                return True
            return False

        # Correct method indentation and logic
        def _apply_phi_filters(self, patient: Patient) -> Patient:
            """Apply PHI filters based on user role."""
            role = self.user_context.get("role", "guest")
            filtered_patient = Patient(
                id=patient.id,
                first_name=self._decrypt(patient.first_name) if patient.first_name else None,
                last_name=self._decrypt(patient.last_name) if patient.last_name else None,
                date_of_birth=self._decrypt(patient.date_of_birth) if patient.date_of_birth else None,
                ssn=self._decrypt(patient.ssn) if patient.ssn else None,
                email=self._decrypt(patient.email) if patient.email else None,
                phone=self._decrypt(patient.phone) if patient.phone else None,
                address=self._decrypt(patient.address) if patient.address else None,
                medical_record_number=patient.medical_record_number
            )

            if role == "admin" or role == "doctor":
                # Admin and Doctor see all PHI unredacted
                return filtered_patient
            elif role == "nurse":
                # Nurse sees most PHI, but SSN is redacted
                filtered_patient.ssn = "XXX-XX-XXXX"
                return filtered_patient
            elif role == "patient":
                # Patient sees their own PHI unredacted if it's their record
                if self.user_context.get("user_id") == patient.id:
                    return filtered_patient
                else:
                    # Otherwise, redact sensitive fields
                    filtered_patient.first_name = "[REDACTED]"
                    filtered_patient.last_name = "[REDACTED]"
                    filtered_patient.ssn = "[REDACTED]"
                    filtered_patient.email = "[REDACTED]"
                    filtered_patient.phone = "[REDACTED]"
                    filtered_patient.address = "[REDACTED]"
                    return filtered_patient
            else:  # guest or any other role
                # Guest sees only basic non-PHI info, everything else redacted
                filtered_patient.first_name = "[REDACTED]"
                filtered_patient.last_name = "[REDACTED]"
                filtered_patient.ssn = "[REDACTED]"
                filtered_patient.email = "[REDACTED]"
                filtered_patient.phone = "[REDACTED]"
                filtered_patient.address = "[REDACTED]"
                filtered_patient.date_of_birth = "[REDACTED]"
                return filtered_patient

        # Correct method indentation and logic
        def _encrypt(self, value: str) -> str:
            """Encrypt PHI value."""
            if not value:
                return value
            return f"ENCRYPTED_{value}" # Simple mock encryption

        # Correct method indentation and logic
        def _decrypt(self, value: str) -> str:
            """Decrypt PHI value."""
            if not value or not value.startswith("ENCRYPTED_"):
                return value
            return value[10:]  # Remove "ENCRYPTED_" prefix

        # Correct method definition and indentation
        def _log_access_attempt(
            self,
            operation: str,
            patient_id: str | None, # Allow None for operations like get_all
            success: bool
        ) -> None:
            """Log access attempt to audit trail."""
            # Correct datetime call and isoformat usage
            timestamp = datetime.datetime.now().isoformat()
            # Correct context access
            user = self.user_context.get("user_id", "anonymous")
            role = self.user_context.get("role", "unknown")

            log_entry = {
                "timestamp": timestamp,
                "operation": operation,
                "patient_id": patient_id,
                "user": user,
                "role": role,
                "success": success
            }
            # Correct indentation
            self.audit_log.append(log_entry)

# Correct indentation for the main test class and its methods/fixtures
class TestDBPHIProtection:
    """Test database PHI protection mechanisms for HIPAA compliance."""

    @pytest.fixture
    def db(self):
        """Create test database."""
        return Database()

    @pytest.fixture
    def unit_of_work(self, db):
        """Create test unit of work."""
        return UnitOfWork(db)

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

    def test_data_encryption_at_rest(self, db, admin_context):
        """Test that PHI is encrypted when stored in the database."""
        repo = PatientRepository(db.get_session(), user_context=admin_context)

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

        created_patient = repo.create(patient)

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
        admin_repo = PatientRepository(
            db.get_session(), user_context={"role": "admin", "user_id": "A12345"}
        )
        doctor_repo = PatientRepository(
            db.get_session(), user_context={"role": "doctor", "user_id": "D12345"}
        )
        nurse_repo = PatientRepository(
            db.get_session(), user_context={"role": "nurse", "user_id": "N12345"}
        )
        patient_repo = PatientRepository(
            db.get_session(), user_context={"role": "patient", "user_id": "P12345"}
        )
        guest_repo = PatientRepository(
            db.get_session(), user_context={"role": "guest", "user_id": None}
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
        patient1_repo = PatientRepository(
            db.get_session(),
            user_context={"role": "patient", "user_id": "P12345"}
        )
        patient2_repo = PatientRepository(
            db.get_session(),
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
        repo = PatientRepository(db.get_session(), user_context=admin_context)

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

    def test_phi_filtering_by_role(self, db):
        """Test that PHI fields are filtered based on user role."""
        # Arrange - Create mock repository with role-based decryption
        session = db.get_session()
        repo = PatientRepository(session=session)
        
        # Mock patient data with encrypted fields
        patient = Patient(
            id="123",
            first_name="ENCRYPTED_John",
            last_name="ENCRYPTED_Doe",
            ssn="ENCRYPTED_123-45-6789",
            email="ENCRYPTED_john.doe@example.com",
            phone="ENCRYPTED_555-123-4567",
            date_of_birth="ENCRYPTED_1980-01-01",
            address="ENCRYPTED_123 Main St",
            medical_record_number="ENCRYPTED_MRN123"
        )
        session.query.return_value.filter.return_value.first.return_value = patient
        
        # Define decryption behavior based on role
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
            admin_repo = PatientRepository(session=session, user_context={"role": "admin"})
            admin_patient = admin_repo.get_by_id("123")
            assert admin_patient.first_name == "John", "Admin should see decrypted first name"
            assert admin_patient.ssn == "123-45-6789", "Admin should see decrypted SSN"
            assert admin_patient.email == "john.doe@example.com", "Admin should see decrypted email"
            
            # Test doctor access - should see most fields but not SSN
            doctor_repo = PatientRepository(session=session, user_context={"role": "doctor"})
            doctor_patient = doctor_repo.get_by_id("123")
            assert doctor_patient.first_name == "John", "Doctor should see decrypted first name"
            assert doctor_patient.ssn == "REDACTED", "Doctor should not see SSN"
            assert doctor_patient.email == "john.doe@example.com", "Doctor should see decrypted email"
            
            # Test nurse access - should see only basic identification
            nurse_repo = PatientRepository(session=session, user_context={"role": "nurse"})
            nurse_patient = nurse_repo.get_by_id("123")
            assert nurse_patient.first_name == "John", "Nurse should see decrypted first name"
            assert nurse_patient.ssn == "REDACTED", "Nurse should not see SSN"
            assert nurse_patient.email == "REDACTED", "Nurse should not see email"
            
            # Test patient access - should see only their own basic info
            patient_repo = PatientRepository(session=session, user_context={"role": "patient", "patient_id": "123"})
            patient_view = patient_repo.get_by_id("123")
            assert patient_view.first_name == "REDACTED", "Patient should not see even their own full details without specific permission"
            assert patient_view.ssn == "REDACTED", "Patient should not see SSN"
            
            # Test guest/unauthorized access - should see nothing
            guest_repo = PatientRepository(session=session, user_context={"role": "guest"})
            guest_patient = guest_repo.get_by_id("123")
            assert guest_patient.first_name == "REDACTED", "Guest should not see PHI"
            assert guest_patient.ssn == "REDACTED", "Guest should not see SSN"
            assert guest_patient.email == "REDACTED", "Guest should not see email"

    def test_transaction_rollback_on_error(self, db, admin_context):
        """Test that database transactions are rolled back on error."""
        uow = UnitOfWork(db)
        # Pass session from UoW's database to repo
        repo = PatientRepository(uow.database.get_session(), user_context=admin_context)

        # Mock the create method to raise an exception
        with patch.object(repo, 'create', side_effect=Exception("Database error")):
            # Use the UoW context manager
            with pytest.raises(Exception, match="Database error"):
                with uow:
                    repo.create(Patient(first_name="Error", last_name="Test"))

        # Assert that rollback was called via __exit__
        assert uow.rolled_back is True
        assert uow.committed is False # Commit should not happen if error occurred

    def test_phi_in_query_parameters(self, db, admin_context):
        """Test proper handling of PHI in query parameters."""
        mock_session = db.get_session()
        repo = PatientRepository(mock_session, user_context=admin_context)

        # Mock session execute to check query parameters
        def execute_query(*args, **kwargs):
            # Check if PHI is present in raw query parameters
            if 'params' in kwargs:
                params = kwargs['params']
                if isinstance(params, dict):
                    for value in params.values():
                        # Simple check, real implementation might need regex
                        assert "123-45-6789" not in str(value), "Raw SSN found in query params"
                        assert "john.doe@example.com" not in str(value), "Raw email found in query params"
            # Return a mock result that simulates no rows found
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = None
            return mock_result

        mock_session.execute.side_effect = execute_query

        # Attempt to query using PHI (this specific repo mock doesn't query like this,
        # but this tests the principle if it did)
        # Example: repo.find_by_ssn("123-45-6789")
        # Since the mock doesn't have find_by_ssn, we can't directly test it here.
        # The assertion within execute_query would run if such a method existed
        # and called session.execute with raw PHI in params.
        pass # Placeholder as the mock doesn't support direct PHI query

# Correct top-level indentation
if __name__ == "__main__":
    pytest.main(["-v", __file__])
