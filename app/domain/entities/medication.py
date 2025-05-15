"""
Medication entity module for the NOVAMIND backend.

This module contains the Medication entity, which is a core domain entity
representing medications prescribed to patients in the concierge psychiatry practice.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from uuid import UUID, uuid4

from app.domain.utils.datetime_utils import UTC, now


class MedicationStatus(Enum):
    """Enum representing the possible statuses of a medication prescription"""

    ACTIVE = auto()
    DISCONTINUED = auto()
    COMPLETED = auto()
    ON_HOLD = auto()
    PENDING = auto()


class RefillStatus(Enum):
    """Enum representing the possible statuses of a medication refill"""

    AVAILABLE = auto()
    PENDING = auto()
    DENIED = auto()
    EXPIRED = auto()


@dataclass
class DosageSchedule:
    """Value object for medication dosage schedule"""

    amount: str  # e.g., "10mg"
    frequency: str  # e.g., "twice daily"
    timing: str | None = None  # e.g., "with meals"
    max_daily: str | None = None  # e.g., "20mg"

    def __str__(self) -> str:
        """String representation of dosage schedule"""
        result = f"{self.amount} {self.frequency}"
        if self.timing:
            result += f" {self.timing}"
        if self.max_daily:
            result += f" (max: {self.max_daily} daily)"
        return result


@dataclass
class SideEffectReport:
    """Value object for reported medication side effects"""

    effect: str
    severity: int  # 1-10 scale
    reported_at: datetime
    notes: str | None = None
    reported_by: UUID | None = None  # patient or provider ID


@dataclass
class Medication:
    """
    Medication entity representing a medication prescribed to a patient.

    This is a rich domain entity containing business logic related to medication management.
    It follows DDD principles, is framework-independent, and adheres to HIPAA compliance requirements.
    """

    patient_id: UUID
    provider_id: UUID
    name: str
    dosage_schedule: DosageSchedule
    start_date: datetime
    id: UUID = field(default_factory=uuid4)
    end_date: datetime | None = None
    status: MedicationStatus = MedicationStatus.ACTIVE
    instructions: str | None = None
    reason_prescribed: str | None = None
    pharmacy_info: dict[str, str] | None = None
    refill_status: RefillStatus = RefillStatus.AVAILABLE
    refills_remaining: int = 0
    refill_history: list[datetime] = field(default_factory=list)
    side_effects: list[SideEffectReport] = field(default_factory=list)
    created_at: datetime = field(default_factory=now)
    updated_at: datetime = field(default_factory=now)
    tags: set[str] = field(default_factory=set)

    @property
    def is_active(self) -> bool:
        """Check if the medication is currently active"""
        return self.status == MedicationStatus.ACTIVE

    @property
    def duration(self) -> timedelta | None:
        """Get the duration of the medication prescription"""
        if not self.end_date:
            return None
        return self.end_date - self.start_date

    @property
    def days_remaining(self) -> int | None:
        """Get the number of days remaining for this medication"""
        if not self.end_date:
            return None

        remaining = (self.end_date - datetime.now(UTC)).days
        return max(0, remaining)

    @property
    def needs_refill(self) -> bool:
        """Check if the medication needs a refill"""
        return (
            self.is_active
            and self.refill_status != RefillStatus.PENDING
            and self.refills_remaining <= 0
        )

    def discontinue(self, reason: str | None = None) -> None:
        """
        Discontinue the medication

        Args:
            reason: The reason for discontinuation
        """
        self.status = MedicationStatus.DISCONTINUED
        self.end_date = datetime.now(UTC)
        if reason:
            self.instructions = f"DISCONTINUED: {reason}"
        self.updated_at = datetime.now(UTC)

    def put_on_hold(self, reason: str | None = None) -> None:
        """
        Put the medication on hold

        Args:
            reason: The reason for putting on hold
        """
        self.status = MedicationStatus.ON_HOLD
        if reason:
            self.instructions = f"ON HOLD: {reason}"
        self.updated_at = datetime.now(UTC)

    def resume(self) -> None:
        """Resume a medication that was on hold"""
        if self.status != MedicationStatus.ON_HOLD:
            raise ValueError("Can only resume medications that are on hold")

        self.status = MedicationStatus.ACTIVE
        # Remove the ON HOLD prefix from instructions if it exists
        if self.instructions and self.instructions.startswith("ON HOLD:"):
            self.instructions = self.instructions[8:].strip()
        self.updated_at = datetime.now(UTC)

    def complete(self) -> None:
        """Mark the medication as completed (course finished)"""
        self.status = MedicationStatus.COMPLETED
        self.end_date = datetime.now(UTC)
        self.updated_at = datetime.now(UTC)

    def request_refill(self) -> None:
        """Request a refill for the medication"""
        if not self.is_active:
            raise ValueError("Cannot request refill for inactive medication")

        self.refill_status = RefillStatus.PENDING
        self.updated_at = datetime.now(UTC)

    def approve_refill(self, refills_granted: int = 1) -> None:
        """
        Approve a refill request

        Args:
            refills_granted: Number of refills to grant

        Raises:
            ValueError: If no refill was requested
        """
        if self.refill_status != RefillStatus.PENDING:
            raise ValueError("No refill request pending")

        self.refills_remaining += refills_granted
        self.refill_status = RefillStatus.AVAILABLE
        self.refill_history.append(datetime.now(UTC))
        self.updated_at = datetime.now(UTC)

    def deny_refill(self, reason: str | None = None) -> None:
        """
        Deny a refill request

        Args:
            reason: Reason for denying the refill

        Raises:
            ValueError: If no refill was requested
        """
        if self.refill_status != RefillStatus.PENDING:
            raise ValueError("No refill request pending")

        self.refill_status = RefillStatus.DENIED
        if reason:
            self.instructions = (
                f"{self.instructions or ''}\nREFILL DENIED: {reason}".strip()
            )
        self.updated_at = datetime.now(UTC)

    def use_refill(self) -> None:
        """
        Use one refill

        Raises:
            ValueError: If no refills are available
        """
        if self.refills_remaining <= 0:
            raise ValueError("No refills remaining")

        self.refills_remaining -= 1
        if self.refills_remaining <= 0:
            self.refill_status = RefillStatus.EXPIRED
        self.updated_at = datetime.now(UTC)

    def report_side_effect(
        self,
        effect: str,
        severity: int,
        notes: str | None = None,
        reported_by: UUID | None = None,
    ) -> None:
        """
        Report a side effect for this medication

        Args:
            effect: Description of the side effect
            severity: Severity on a scale of 1-10
            notes: Additional notes about the side effect
            reported_by: ID of the person reporting the side effect

        Raises:
            ValueError: If severity is not between 1 and 10
        """
        if not 1 <= severity <= 10:
            raise ValueError("Severity must be between 1 and 10")

        report = SideEffectReport(
            effect=effect,
            severity=severity,
            reported_at=datetime.now(UTC),
            notes=notes,
            reported_by=reported_by,
        )

        self.side_effects.append(report)
        self.updated_at = datetime.now(UTC)

    def update_dosage(self, new_dosage: DosageSchedule) -> None:
        """
        Update the dosage schedule for this medication

        Args:
            new_dosage: The new dosage schedule

        Raises:
            ValueError: If the medication is not active
        """
        if not self.is_active:
            raise ValueError("Cannot update dosage for inactive medication")

        self.dosage_schedule = new_dosage
        self.updated_at = datetime.now(UTC)

    def extend_prescription(self, new_end_date: datetime) -> None:
        """
        Extend the prescription end date

        Args:
            new_end_date: The new end date for the prescription

        Raises:
            ValueError: If the medication is not active or if the new end date is not in the future
        """
        if not self.is_active:
            raise ValueError("Cannot extend inactive medication")

        if new_end_date <= datetime.now(UTC):
            raise ValueError("New end date must be in the future")

        if self.end_date and new_end_date <= self.end_date:
            raise ValueError("New end date must be later than current end date")

        self.end_date = new_end_date
        self.updated_at = datetime.now(UTC)

    def add_tag(self, tag: str) -> None:
        """Add a tag to the medication"""
        self.tags.add(tag)
        self.updated_at = datetime.now(UTC)

    def remove_tag(self, tag: str) -> None:
        """Remove a tag from the medication"""
        if tag in self.tags:
            self.tags.remove(tag)
            self.updated_at = datetime.now(UTC)
