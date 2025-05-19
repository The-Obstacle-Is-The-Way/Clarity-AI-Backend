"""
Tests for the Appointment Service.
"""

# Defer service import if necessary, though typically fine in tests
# from app.domain.services.appointment_service import AppointmentService
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

# Defer entity import
# from app.domain.entities.appointment import Appointment
# Import only Enums
from app.domain.entities.appointment import (
    AppointmentStatus,
    AppointmentType,
    # AppointmentPriority # Still assuming this doesn't exist
)
from app.domain.exceptions.appointment_exceptions import AppointmentConflictError

# Removed duplicate import of InvalidAppointmentTimeError
# Removed AppointmentNotFoundException, PatientNotFoundException, ProviderNotFoundException


@pytest.fixture
def future_datetime():
    """Fixture for a future datetime."""
    return datetime.now(UTC) + timedelta(days=1)


@pytest.fixture
def appointment_repository():
    """Fixture for appointment repository."""
    repository = MagicMock()
    repository.get_by_id.return_value = None
    repository.save.side_effect = lambda x: x
    # Add mock for get_by_provider_id used in conflict checks
    repository.get_by_provider_id.return_value = []
    return repository


@pytest.fixture
def patient_repository():
    """Fixture for patient repository."""
    repository = MagicMock()
    repository.get_by_id.return_value = {"id": "patient123", "name": "John Doe"}
    return repository


@pytest.fixture
def provider_repository():
    """Fixture for provider repository."""
    repository = MagicMock()
    repository.get_by_id.return_value = {"id": "provider456", "name": "Dr. Smith"}
    return repository


@pytest.fixture
def appointment_service(appointment_repository, patient_repository, provider_repository):
    """Fixture for appointment service."""
    # Import service here
    from app.domain.services.appointment_service import AppointmentService

    return AppointmentService(
        appointment_repository=appointment_repository,
        patient_repository=patient_repository,
        provider_repository=provider_repository,
        default_appointment_duration=60,
        min_reschedule_notice=24,
        max_appointments_per_day=8,
        buffer_between_appointments=15,
    )


@pytest.fixture
def valid_appointment_data(future_datetime):
    """Fixture for valid appointment data (used only by valid_appointment fixture)"""
    return {
        "id": str(uuid.uuid4()),  # Keep id for direct use in valid_appointment
        "patient_id": "patient123",
        "provider_id": "provider456",
        "start_time": future_datetime,
        "end_time": future_datetime + timedelta(hours=1),
        "appointment_type": AppointmentType.INITIAL_CONSULTATION,
        "status": AppointmentStatus.SCHEDULED,
        # "priority": AppointmentPriority.NORMAL, # Removed
        "location": "Office 101",
        "notes": "Initial consultation for anxiety",
        "reason": "Anxiety and depression"
        # Removed created_at/updated_at as they are usually set by the entity/repo
    }


@pytest.fixture
def valid_appointment(valid_appointment_data):
    """Fixture for a valid appointment entity instance."""
    # Import Appointment here where it is instantiated
    from app.domain.entities.appointment import Appointment

    # Create using only necessary fields for instantiation, others are defaulted/set later
    # Using data from valid_appointment_data fixture ensures consistency
    data = valid_appointment_data.copy()
    appointment_id = data.pop("id")  # Pop id to use with BaseEntity's factory
    # If BaseEntity auto-generates ID, we might not need to pass it.
    # Assuming BaseEntity handles ID generation if not provided.
    app = Appointment(**data)
    # If ID needs to be set post-init for test consistency:
    app.id = uuid.UUID(appointment_id)
    return app


@pytest.mark.venv_only()
class TestAppointmentService:
    """Tests for the AppointmentService class."""

    # No direct Appointment instantiation needed in tests if using fixtures/service methods
    # Ensure tests use the service methods and rely on the valid_appointment fixture

    def test_get_appointment(self, appointment_service, appointment_repository, valid_appointment):
        """Test getting an appointment."""
        appointment_repository.get_by_id.return_value = valid_appointment
        appointment = appointment_service.get_appointment(valid_appointment.id)
        assert appointment == valid_appointment
        appointment_repository.get_by_id.assert_called_once_with(valid_appointment.id)

    # ... (other tests using service methods and valid_appointment fixture)

    # Example modification for conflict test (imports Appointment locally)
    def test_create_appointment_conflict(
        self, appointment_service, appointment_repository, future_datetime
    ):
        """Test creating an appointment with a conflict."""
        # Import Appointment here where it is instantiated for the mock return value
        from app.domain.entities.appointment import Appointment

        # Set up the repository to return a conflicting appointment
        appointment_repository.get_by_provider_id.return_value = [
            Appointment(
                patient_id="patient789",  # Need required fields
                provider_id="provider456",
                start_time=future_datetime - timedelta(minutes=30),
                end_time=future_datetime + timedelta(minutes=30),
                appointment_type=AppointmentType.FOLLOW_UP,
                status=AppointmentStatus.SCHEDULED
                # Assuming priority is gone
            )
        ]

        with pytest.raises(AppointmentConflictError):
            appointment_service.create_appointment(
                patient_id="patient123",
                provider_id="provider456",
                start_time=future_datetime,
                end_time=future_datetime + timedelta(hours=1)
                # Assuming priority is gone
            )

    def test_create_appointment_daily_limit(
        self, appointment_service, appointment_repository, future_datetime
    ):
        """Test creating an appointment when the daily limit is reached."""
        # Import Appointment here where it is instantiated for the mock return value
        from app.domain.entities.appointment import Appointment

        # Set up the repository to return a list of appointments at the limit
        appointments = [
            Appointment(
                patient_id=f"patient{i}",
                provider_id="provider456",
                start_time=future_datetime + timedelta(hours=i),
                end_time=future_datetime + timedelta(hours=i + 1),
                appointment_type=AppointmentType.FOLLOW_UP,
                status=AppointmentStatus.SCHEDULED,
            )
            for i in range(8)  # Assuming max_appointments_per_day=8 in service fixture
        ]
        appointment_repository.get_by_provider_id.return_value = appointments

        with pytest.raises(AppointmentConflictError):  # Change to AppointmentConflictError
            appointment_service.create_appointment(
                patient_id="patient_new",
                provider_id="provider456",
                start_time=future_datetime + timedelta(hours=9),
                end_time=future_datetime + timedelta(hours=10),
            )

    # ... (ensure other tests don't directly instantiate Appointment)
