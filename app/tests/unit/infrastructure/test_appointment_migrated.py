"""
Migrated from standalone test to proper unit test.
Original file: app/tests/standalone/infrastructure/test_appointment.py

This test uses the actual implementations from the main codebase.
Migration date: Tue May 13 10:04:16 EDT 2025
"""

# Import the actual implementations being tested
from app.domain.entities.appointment import Appointment, AppointmentStatus
from app.domain.exceptions import InvalidAppointmentStateError, InvalidAppointmentTimeError

import pytest
from datetime import datetime, timedelta
from uuid import uuid4, UUID
from app.domain.utils.datetime_utils import UTC

@pytest.fixture
def sample_appointment():
    """Create a sample appointment for testing."""
    now = datetime.now(UTC)
    start_time = now + timedelta(days=1)
    end_time = start_time + timedelta(hours=1)
    
    return Appointment(
        id=str(uuid4()),
        patient_id=str(uuid4()),
        provider_id=str(uuid4()),
        start_time=start_time,
        end_time=end_time,
        appointment_type="INITIAL_CONSULTATION",
        status="scheduled"
    )

class TestAppointment:
    """Tests for the Appointment entity."""
    
    def test_init(self, sample_appointment):
        """Test that an appointment can be initialized with valid parameters."""
        assert sample_appointment.status == AppointmentStatus.SCHEDULED
        assert sample_appointment.appointment_type == "INITIAL_CONSULTATION"
        
    def test_reschedule(self, sample_appointment):
        """Test that an appointment can be rescheduled."""
        new_start = sample_appointment.start_time + timedelta(days=1)
        new_end = new_start + timedelta(hours=1)
        
        sample_appointment.reschedule(new_start, new_end)
        
        assert sample_appointment.start_time == new_start
        assert sample_appointment.end_time == new_end
        
    def test_cancel(self, sample_appointment):
        """Test that an appointment can be canceled."""
        reason = "Patient request"
        cancelled_by = UUID(str(uuid4()))  # Create a user ID for who cancelled
        
        sample_appointment.cancel(cancelled_by=cancelled_by, reason=reason)
        
        assert sample_appointment.status == AppointmentStatus.CANCELLED
        assert sample_appointment.cancellation_reason == reason
        assert sample_appointment.cancelled_by_user_id == cancelled_by
        assert sample_appointment.cancelled_at is not None

# Run with pytest -vx app/tests/unit/infrastructure/test_appointment_migrated.py

