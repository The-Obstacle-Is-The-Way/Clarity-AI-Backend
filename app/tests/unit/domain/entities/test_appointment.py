"""
Tests for the Appointment entity.
"""

import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest

# Import Appointment entity and related enums
from app.domain.entities.appointment import (
    Appointment,
    AppointmentStatus,
    AppointmentType,
)

# Import exceptions if needed for specific tests
from app.domain.exceptions import (
    InvalidAppointmentTimeError,  # InvalidAppointmentStateError, # May not be used anymore; May not be used anymore
)


@pytest.fixture
def future_datetime():
    """Fixture for a future datetime."""
    # Ensure timezone-aware datetime if needed, otherwise naive
    # Using timezone.utc for consistency if BaseEntity uses it

    return datetime.now(timezone.utc) + timedelta(days=1)  # Make timezone-aware
    # return datetime.now() + timedelta(days=1)


@pytest.fixture
def valid_appointment_data(future_datetime):
    """Fixture for valid appointment data matching the dataclass."""
    # Use actual UUID objects
    patient_uuid = uuid.uuid4()
    provider_uuid = uuid.uuid4()
    return {
        "id": uuid.uuid4(),  # id is likely inherited, provide if needed for direct init
        "patient_id": patient_uuid,
        "provider_id": provider_uuid,
        "start_time": future_datetime,
        "end_time": future_datetime + timedelta(hours=1),
        "appointment_type": AppointmentType.INITIAL_CONSULTATION,
        "status": AppointmentStatus.SCHEDULED,  # Default, but explicit here
        "location": "Office 101",
        "notes": "Initial consultation notes",
        # created_at and last_updated have defaults
    }


@pytest.mark.venv_only()
class TestAppointment:
    """Tests for the Appointment class."""

    def test_create_appointment(self, valid_appointment_data) -> None:
        """Test creating an appointment."""
        appointment = Appointment(**valid_appointment_data)

        assert appointment.id == valid_appointment_data["id"]
        assert appointment.patient_id == valid_appointment_data["patient_id"]
        assert appointment.provider_id == valid_appointment_data["provider_id"]
        assert appointment.start_time == valid_appointment_data["start_time"]
        assert appointment.end_time == valid_appointment_data["end_time"]
        assert appointment.appointment_type == valid_appointment_data["appointment_type"]
        assert appointment.status == valid_appointment_data["status"]
        assert appointment.location == valid_appointment_data["location"]
        assert appointment.notes == valid_appointment_data["notes"]
        assert isinstance(appointment.created_at, datetime)
        assert isinstance(appointment.last_updated, datetime)

    def test_create_appointment_with_string_type(self, valid_appointment_data) -> None:
        """Test creating an appointment with string type (enum conversion)."""
        data = valid_appointment_data.copy()
        data["appointment_type"] = "follow_up"  # Use string value

        appointment = Appointment(**data)

        assert appointment.appointment_type == AppointmentType.FOLLOW_UP
        assert appointment.status == AppointmentStatus.SCHEDULED  # Check default

    def test_validate_required_fields(self, future_datetime) -> None:
        """Test validation of required fields (via TypeError)."""
        patient_id = uuid.uuid4()
        provider_id = uuid.uuid4()
        start_time = future_datetime
        end_time = future_datetime + timedelta(hours=1)
        appt_type = AppointmentType.THERAPY_SESSION

        # Missing patient_id
        with pytest.raises(TypeError):
            Appointment(
                provider_id=provider_id,
                start_time=start_time,
                end_time=end_time,
                appointment_type=appt_type,
            )
        # Missing provider_id
        with pytest.raises(TypeError):
            Appointment(
                patient_id=patient_id,
                start_time=start_time,
                end_time=end_time,
                appointment_type=appt_type,
            )
        # Missing start_time
        with pytest.raises(TypeError):
            Appointment(
                patient_id=patient_id,
                provider_id=provider_id,
                end_time=end_time,
                appointment_type=appt_type,
            )
        # Missing end_time
        with pytest.raises(TypeError):
            Appointment(
                patient_id=patient_id,
                provider_id=provider_id,
                start_time=start_time,
                appointment_type=appt_type,
            )
        # Missing appointment_type
        with pytest.raises(TypeError):
            Appointment(
                patient_id=patient_id,
                provider_id=provider_id,
                start_time=start_time,
                end_time=end_time,
            )

    def test_validate_appointment_times(self, valid_appointment_data) -> None:
        """Test validation of appointment times in __post_init__."""
        data = valid_appointment_data.copy()
        # End time before start time
        data["end_time"] = data["start_time"] - timedelta(minutes=1)
        with pytest.raises(
            InvalidAppointmentTimeError,
            match="Appointment end time must be after start time.",
        ):
            Appointment(**data)

        # End time equal to start time
        data["end_time"] = data["start_time"]
        with pytest.raises(
            InvalidAppointmentTimeError,
            match="Appointment end time must be after start time.",
        ):
            Appointment(**data)

    def test_update_status(self, valid_appointment_data) -> None:
        """Test updating the appointment status."""
        appointment = Appointment(**valid_appointment_data)
        original_updated_at = appointment.last_updated
        time.sleep(0.01)  # Ensure time difference

        appointment.update_status(AppointmentStatus.CONFIRMED)
        assert appointment.status == AppointmentStatus.CONFIRMED
        assert appointment.last_updated > original_updated_at

        time.sleep(0.01)
        original_updated_at = appointment.last_updated
        appointment.update_status(AppointmentStatus.COMPLETED)
        assert appointment.status == AppointmentStatus.COMPLETED
        assert appointment.last_updated > original_updated_at

    def test_reschedule_appointment(self, valid_appointment_data, future_datetime) -> None:
        """Test rescheduling an appointment."""
        appointment = Appointment(**valid_appointment_data)
        original_updated_at = appointment.last_updated
        time.sleep(0.01)

        new_start_time = future_datetime + timedelta(days=2)
        new_end_time = new_start_time + timedelta(hours=1)

        appointment.reschedule(new_start_time, new_end_time)

        assert appointment.start_time == new_start_time
        assert appointment.end_time == new_end_time
        # Check if status resets (depends on implementation logic in reschedule)
        assert (
            appointment.status == AppointmentStatus.RESCHEDULED
        )  # Assuming it resets to RESCHEDULED
        assert appointment.last_updated > original_updated_at

    def test_reschedule_appointment_calculates_end_time(
        self, valid_appointment_data, future_datetime
    ) -> None:
        """Test rescheduling calculates end time if not provided."""
        appointment = Appointment(**valid_appointment_data)
        original_duration = appointment.end_time - appointment.start_time
        original_updated_at = appointment.last_updated
        time.sleep(0.01)

        new_start_time = future_datetime + timedelta(days=3)
        appointment.reschedule(new_start_time)  # Provide only start time

        assert appointment.start_time == new_start_time
        assert appointment.end_time == new_start_time + original_duration
        assert appointment.status == AppointmentStatus.RESCHEDULED  # Changed from SCHEDULED
        assert appointment.last_updated > original_updated_at

    def test_reschedule_invalid_times(self, valid_appointment_data, future_datetime) -> None:
        """Test rescheduling with invalid times."""
        appointment = Appointment(**valid_appointment_data)
        new_start_time = future_datetime + timedelta(days=2)

        # End time before start time
        with pytest.raises(
            InvalidAppointmentTimeError,
            match="Rescheduled end time must be after start time.",
        ):
            appointment.reschedule(new_start_time, new_start_time - timedelta(minutes=1))

        # End time equal to start time
        with pytest.raises(
            InvalidAppointmentTimeError,
            match="Rescheduled end time must be after start time.",
        ):
            appointment.reschedule(new_start_time, new_start_time)

    def test_touch_updates_timestamp(self, valid_appointment_data) -> None:
        """Test the touch method updates last_updated."""
        appointment = Appointment(**valid_appointment_data)
        original_updated_at = appointment.last_updated
        time.sleep(0.01)  # Ensure time difference
        appointment.touch()
        assert appointment.last_updated > original_updated_at

    def test_equality(self, valid_appointment_data) -> None:
        """Test appointment equality."""
        # Use the same ID for comparison
        fixed_id = uuid.uuid4()
        data1 = {**valid_appointment_data, "id": fixed_id}
        data2 = {**valid_appointment_data, "id": fixed_id}
        # Ensure timestamps are identical for equality check
        ts = datetime.now()
        data1["created_at"] = ts
        data1["last_updated"] = ts
        data2["created_at"] = ts
        data2["last_updated"] = ts

        appointment1 = Appointment(**data1)
        appointment2 = Appointment(**data2)

        assert appointment1 == appointment2

    def test_inequality(self, valid_appointment_data) -> None:
        """Test appointment inequality."""
        appointment1 = Appointment(**valid_appointment_data)
        data2 = valid_appointment_data.copy()
        data2["id"] = uuid.uuid4()  # Different ID
        appointment2 = Appointment(**data2)

        assert appointment1 != appointment2
        assert appointment1 != "not an appointment"

    def test_string_representation(self, valid_appointment_data) -> None:
        """Test string representation of an appointment."""
        appointment = Appointment(**valid_appointment_data)
        string_repr = repr(appointment)  # Use repr for dataclass default

        assert str(appointment.id) in string_repr
        assert str(appointment.patient_id) in string_repr
        assert str(appointment.provider_id) in string_repr
        assert appointment.status.value in string_repr
        assert appointment.appointment_type.value in string_repr
