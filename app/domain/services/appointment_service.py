"""
Appointment Service

This module provides services for managing appointments, including scheduling,
rescheduling, and cancellation, as well as checking for conflicts.
"""

from datetime import datetime, timedelta
from uuid import UUID

from app.domain.entities.appointment import (
    Appointment,
    AppointmentPriority,
    AppointmentStatus,
    AppointmentType,
)
from app.domain.exceptions import (
    AppointmentConflictError,
    EntityNotFoundError,  # Use generic not found error
    InvalidAppointmentStateError,
    InvalidAppointmentTimeError,
)

# Removed specific not found exceptions
from app.domain.repositories.appointment_repository import AppointmentRepository
from app.domain.repositories.patient_repository import PatientRepository
from app.domain.repositories.provider_repository import ProviderRepository


class AppointmentService:
    """
    Service for managing appointments.

    This service encapsulates business logic for appointment management,
    including scheduling, rescheduling, and cancellation, as well as
    checking for conflicts.
    """

    def __init__(
        self,
        appointment_repository: AppointmentRepository,
        patient_repository: PatientRepository,
        provider_repository: ProviderRepository,
        default_appointment_duration: int = 60,  # minutes
        min_reschedule_notice: int = 24,  # hours
        max_appointments_per_day: int = 8,
        buffer_between_appointments: int = 15,  # minutes
    ):
        """
        Initialize the appointment service.

        Args:
            appointment_repository: Repository for appointment data
            patient_repository: Repository for patient data
            provider_repository: Repository for provider data
            default_appointment_duration: Default appointment duration in minutes
            min_reschedule_notice: Minimum notice for rescheduling in hours
            max_appointments_per_day: Maximum appointments per day for a provider
            buffer_between_appointments: Buffer time between appointments in minutes
        """
        self.appointment_repository = appointment_repository
        self.patient_repository = patient_repository
        self.provider_repository = provider_repository
        self.default_appointment_duration = default_appointment_duration
        self.min_reschedule_notice = min_reschedule_notice
        self.max_appointments_per_day = max_appointments_per_day
        self.buffer_between_appointments = buffer_between_appointments

    def get_appointment(self, appointment_id: UUID | str) -> Appointment:
        """
        Get an appointment by ID.

        Args:
            appointment_id: ID of the appointment

        Returns:
            Appointment entity

        Raises:
            EntityNotFoundError: If the appointment is not found
        """
        appointment = self.appointment_repository.get_by_id(appointment_id)

        if not appointment:
            raise EntityNotFoundError(f"Appointment with ID {appointment_id} not found")

        return appointment

    def get_appointments_for_patient(
        self,
        patient_id: UUID | str,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        status: AppointmentStatus | str | None = None,
    ) -> list[Appointment]:
        """
        Get appointments for a patient.

        Args:
            patient_id: ID of the patient
            start_date: Optional start date for filtering
            end_date: Optional end date for filtering
            status: Optional status for filtering

        Returns:
            List of appointments

        Raises:
            EntityNotFoundError: If the patient is not found
        """
        # Check if patient exists
        patient = self.patient_repository.get_by_id(patient_id)

        if not patient:
            raise EntityNotFoundError(f"Patient with ID {patient_id} not found")

        # Convert string status to enum if necessary
        if isinstance(status, str):
            status = AppointmentStatus(status)

        # Get appointments
        return self.appointment_repository.get_by_patient_id(
            patient_id, start_date, end_date, status
        )

    def get_appointments_for_provider(
        self,
        provider_id: UUID | str,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        status: AppointmentStatus | str | None = None,
    ) -> list[Appointment]:
        """
        Get appointments for a provider.

        Args:
            provider_id: ID of the provider
            start_date: Optional start date for filtering
            end_date: Optional end date for filtering
            status: Optional status for filtering

        Returns:
            List of appointments

        Raises:
            EntityNotFoundError: If the provider is not found
        """
        # Check if provider exists
        provider = self.provider_repository.get_by_id(provider_id)

        if not provider:
            raise EntityNotFoundError(f"Provider with ID {provider_id} not found")

        # Convert string status to enum if necessary
        if isinstance(status, str):
            status = AppointmentStatus(status)

        # Get appointments
        return self.appointment_repository.get_by_provider_id(
            provider_id, start_date, end_date, status
        )

    def create_appointment(
        self,
        patient_id: UUID | str,
        provider_id: UUID | str,
        start_time: datetime,
        end_time: datetime | None = None,
        appointment_type: AppointmentType | str = AppointmentType.FOLLOW_UP,
        priority: AppointmentPriority | str = AppointmentPriority.NORMAL,
        location: str | None = None,
        notes: str | None = None,
        reason: str | None = None,
    ) -> Appointment:
        """
        Create a new appointment.

        Args:
            patient_id: ID of the patient
            provider_id: ID of the provider
            start_time: Start time of the appointment
            end_time: Optional end time of the appointment
            appointment_type: Type of appointment
            priority: Priority of the appointment
            location: Optional location of the appointment
            notes: Optional notes about the appointment
            reason: Optional reason for the appointment

        Returns:
            Created appointment

        Raises:
            EntityNotFoundError: If the patient or provider is not found
            AppointmentConflictError: If there is a conflict with another appointment
            InvalidAppointmentTimeError: If the appointment time is invalid
        """
        # Check if patient exists
        patient = self.patient_repository.get_by_id(patient_id)

        if not patient:
            raise EntityNotFoundError(f"Patient with ID {patient_id} not found")

        # Check if provider exists
        provider = self.provider_repository.get_by_id(provider_id)

        if not provider:
            raise EntityNotFoundError(f"Provider with ID {provider_id} not found")

        # Set end time if not provided
        if not end_time:
            end_time = start_time + timedelta(minutes=self.default_appointment_duration)

        # Check for conflicts
        self._check_for_conflicts(provider_id, start_time, end_time)

        # Check provider's daily appointment limit
        self._check_daily_appointment_limit(provider_id, start_time)

        # Create the appointment
        appointment = Appointment(
            patient_id=patient_id,
            provider_id=provider_id,
            start_time=start_time,
            end_time=end_time,
            appointment_type=appointment_type,
            status=AppointmentStatus.SCHEDULED,
            priority=priority,
            location=location,
            notes=notes,
            reason=reason,
        )

        # Save the appointment
        return self.appointment_repository.save(appointment)

    def reschedule_appointment(
        self,
        appointment_id: UUID | str,
        new_start_time: datetime,
        new_end_time: datetime | None = None,
        reason: str | None = None,
        user_id: UUID | str | None = None,
    ) -> Appointment:
        """
        Reschedule an appointment.

        Args:
            appointment_id: ID of the appointment
            new_start_time: New start time
            new_end_time: Optional new end time
            reason: Optional reason for rescheduling
            user_id: ID of the user performing the rescheduling

        Returns:
            Updated appointment

        Raises:
            EntityNotFoundError: If the appointment is not found
            InvalidAppointmentStateError: If the appointment cannot be rescheduled
            InvalidAppointmentTimeError: If the new time is invalid
            AppointmentConflictError: If there is a conflict with another appointment
        """
        # Get the appointment
        appointment = self.get_appointment(appointment_id)

        # Set new end time if not provided
        if not new_end_time:
            duration = (appointment.end_time - appointment.start_time).total_seconds() / 60
            new_end_time = new_start_time + timedelta(minutes=duration)

        # Check for minimum notice period
        self._check_reschedule_notice_period(appointment)

        # Check for conflicts
        self._check_for_conflicts(
            appointment.provider_id, new_start_time, new_end_time, appointment_id
        )

        # Reschedule the appointment
        appointment.reschedule(new_start_time, new_end_time, reason)

        # Save the appointment
        return self.appointment_repository.save(appointment)

    def cancel_appointment(
        self,
        appointment_id: UUID | str,
        cancelled_by: UUID | str,
        reason: str | None = None,
    ) -> Appointment:
        """
        Cancel an appointment.

        Args:
            appointment_id: ID of the appointment
            cancelled_by: ID of the user cancelling the appointment
            reason: Optional reason for cancellation

        Returns:
            Updated appointment

        Raises:
            EntityNotFoundError: If the appointment is not found
            InvalidAppointmentStateError: If the appointment cannot be cancelled
        """
        # Get the appointment
        appointment = self.get_appointment(appointment_id)

        # Cancel the appointment
        appointment.cancel(cancelled_by, reason)

        # Save the appointment
        return self.appointment_repository.save(appointment)

    def confirm_appointment(self, appointment_id: UUID | str) -> Appointment:
        """
        Confirm an appointment.

        Args:
            appointment_id: ID of the appointment

        Returns:
            Updated appointment

        Raises:
            EntityNotFoundError: If the appointment is not found
            InvalidAppointmentStateError: If the appointment cannot be confirmed
        """
        # Get the appointment
        appointment = self.get_appointment(appointment_id)

        # Confirm the appointment
        appointment.confirm()

        # Save the appointment
        return self.appointment_repository.save(appointment)

    def check_in_appointment(self, appointment_id: UUID | str) -> Appointment:
        """
        Check in an appointment.

        Args:
            appointment_id: ID of the appointment

        Returns:
            Updated appointment

        Raises:
            EntityNotFoundError: If the appointment is not found
            InvalidAppointmentStateError: If the appointment cannot be checked in
        """
        # Get the appointment
        appointment = self.get_appointment(appointment_id)

        # Check in the appointment
        appointment.check_in()

        # Save the appointment
        return self.appointment_repository.save(appointment)

    def start_appointment(self, appointment_id: UUID | str) -> Appointment:
        """
        Start an appointment.

        Args:
            appointment_id: ID of the appointment

        Returns:
            Updated appointment

        Raises:
            EntityNotFoundError: If the appointment is not found
            InvalidAppointmentStateError: If the appointment cannot be started
        """
        # Get the appointment
        appointment = self.get_appointment(appointment_id)

        # Start the appointment
        appointment.start()

        # Save the appointment
        return self.appointment_repository.save(appointment)

    def complete_appointment(self, appointment_id: UUID | str) -> Appointment:
        """
        Complete an appointment.

        Args:
            appointment_id: ID of the appointment

        Returns:
            Updated appointment

        Raises:
            EntityNotFoundError: If the appointment is not found
            InvalidAppointmentStateError: If the appointment cannot be completed
        """
        # Get the appointment
        appointment = self.get_appointment(appointment_id)

        # Complete the appointment
        appointment.complete()

        # Save the appointment
        return self.appointment_repository.save(appointment)

    def mark_no_show(self, appointment_id: UUID | str) -> Appointment:
        """
        Mark an appointment as a no-show.

        Args:
            appointment_id: ID of the appointment

        Returns:
            Updated appointment

        Raises:
            EntityNotFoundError: If the appointment is not found
            InvalidAppointmentStateError: If the appointment cannot be marked as no-show
        """
        # Get the appointment
        appointment = self.get_appointment(appointment_id)

        # Mark as no-show
        appointment.mark_no_show()

        # Save the appointment
        return self.appointment_repository.save(appointment)

    def schedule_follow_up(
        self,
        appointment_id: UUID | str,
        follow_up_start_time: datetime,
        follow_up_end_time: datetime | None = None,
        appointment_type: AppointmentType | str = AppointmentType.FOLLOW_UP,
        priority: AppointmentPriority | str = AppointmentPriority.NORMAL,
        location: str | None = None,
        notes: str | None = None,
        reason: str | None = None,
    ) -> Appointment:
        """
        Schedule a follow-up appointment.

        Args:
            appointment_id: ID of the original appointment
            follow_up_start_time: Start time of the follow-up
            follow_up_end_time: Optional end time of the follow-up
            appointment_type: Type of appointment
            priority: Priority of the appointment
            location: Optional location of the appointment
            notes: Optional notes about the appointment
            reason: Optional reason for the appointment

        Returns:
            Created follow-up appointment

        Raises:
            EntityNotFoundError: If the original appointment is not found
            InvalidAppointmentStateError: If a follow-up cannot be scheduled
            AppointmentConflictError: If there is a conflict with another appointment
        """
        # Get the original appointment
        original_appointment = self.get_appointment(appointment_id)

        # Check if the original appointment is completed
        if original_appointment.status != AppointmentStatus.COMPLETED:
            raise InvalidAppointmentStateError(
                f"Cannot schedule follow-up for appointment with status {original_appointment.status.value}"
            )

        # Set end time if not provided
        if not follow_up_end_time:
            follow_up_end_time = follow_up_start_time + timedelta(
                minutes=self.default_appointment_duration
            )

        # Check for conflicts
        self._check_for_conflicts(
            original_appointment.provider_id, follow_up_start_time, follow_up_end_time
        )

        # Create the follow-up appointment
        follow_up_appointment = Appointment(
            patient_id=original_appointment.patient_id,
            provider_id=original_appointment.provider_id,
            start_time=follow_up_start_time,
            end_time=follow_up_end_time,
            appointment_type=appointment_type,
            status=AppointmentStatus.SCHEDULED,
            priority=priority,
            location=location or original_appointment.location,
            notes=notes,
            reason=reason or original_appointment.reason,
            previous_appointment_id=original_appointment.id,
        )

        # Save the follow-up appointment
        follow_up_appointment = self.appointment_repository.save(follow_up_appointment)

        # Update the original appointment
        original_appointment.schedule_follow_up(follow_up_appointment.id)
        self.appointment_repository.save(original_appointment)

        return follow_up_appointment

    def send_reminder(self, appointment_id: UUID | str) -> Appointment:
        """
        Send a reminder for an appointment.

        Args:
            appointment_id: ID of the appointment

        Returns:
            Updated appointment

        Raises:
            AppointmentNotFoundException: If the appointment is not found
        """
        # Get the appointment
        appointment = self.get_appointment(appointment_id)

        # Send reminder
        appointment.send_reminder()

        # Save the appointment
        return self.appointment_repository.save(appointment)

    def update_notes(self, appointment_id: UUID | str, notes: str) -> Appointment:
        """
        Update the notes for an appointment.

        Args:
            appointment_id: ID of the appointment
            notes: New notes

        Returns:
            Updated appointment

        Raises:
            AppointmentNotFoundException: If the appointment is not found
        """
        # Get the appointment
        appointment = self.get_appointment(appointment_id)

        # Update notes
        appointment.update_notes(notes)

        # Save the appointment
        return self.appointment_repository.save(appointment)

    def _check_for_conflicts(
        self,
        provider_id: UUID | str,
        start_time: datetime,
        end_time: datetime,
        exclude_appointment_id: UUID | str | None = None,
    ) -> None:
        """
        Check for conflicts with other appointments.

        Args:
            provider_id: ID of the provider
            start_time: Start time to check
            end_time: End time to check
            exclude_appointment_id: Optional ID of an appointment to exclude

        Raises:
            AppointmentConflictError: If there is a conflict
        """
        # Get provider's appointments for the day
        day_start = datetime(start_time.year, start_time.month, start_time.day)
        day_end = day_start + timedelta(days=1)

        appointments = self.appointment_repository.get_by_provider_id(
            provider_id, day_start, day_end
        )

        # Add buffer to start and end times
        buffered_start = start_time - timedelta(minutes=self.buffer_between_appointments)
        buffered_end = end_time + timedelta(minutes=self.buffer_between_appointments)

        # Check for conflicts
        for appointment in appointments:
            # Skip the appointment being rescheduled
            if exclude_appointment_id and str(appointment.id) == str(exclude_appointment_id):
                continue

            # Skip cancelled appointments
            if appointment.status in [
                AppointmentStatus.CANCELLED,
                AppointmentStatus.NO_SHOW,
            ]:
                continue

            # Check for overlap
            if (
                (buffered_start <= appointment.start_time < buffered_end)
                or (buffered_start < appointment.end_time <= buffered_end)
                or (
                    appointment.start_time <= buffered_start
                    and appointment.end_time >= buffered_end
                )
            ):
                raise AppointmentConflictError(
                    f"Appointment conflicts with existing appointment at {appointment.start_time}"
                )

    def _check_daily_appointment_limit(self, provider_id: UUID | str, date: datetime) -> None:
        """
        Check if a provider has reached their daily appointment limit.

        Args:
            provider_id: ID of the provider
            date: Date to check

        Raises:
            AppointmentConflictError: If the limit has been reached
        """
        # Get provider's appointments for the day
        day_start = datetime(date.year, date.month, date.day)
        day_end = day_start + timedelta(days=1)

        appointments = self.appointment_repository.get_by_provider_id(
            provider_id, day_start, day_end
        )

        # Count active appointments
        active_count = sum(
            1
            for a in appointments
            if a.status not in [AppointmentStatus.CANCELLED, AppointmentStatus.NO_SHOW]
        )

        if active_count >= self.max_appointments_per_day:
            raise AppointmentConflictError(
                f"Provider has reached the maximum of {self.max_appointments_per_day} appointments for the day"
            )

    def _check_reschedule_notice_period(self, appointment: Appointment) -> None:
        """
        Check if an appointment can be rescheduled based on notice period.

        Args:
            appointment: Appointment to check

        Raises:
            InvalidAppointmentTimeError: If the notice period is insufficient
        """
        # Check if the appointment is within the minimum notice period
        if (
            appointment.start_time - datetime.now()
        ).total_seconds() / 3600 < self.min_reschedule_notice:
            raise InvalidAppointmentTimeError(
                f"Appointments must be rescheduled at least {self.min_reschedule_notice} hours in advance"
            )
