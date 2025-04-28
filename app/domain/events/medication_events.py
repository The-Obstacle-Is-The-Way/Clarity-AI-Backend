"""
Medication events module for the NOVAMIND backend.

This module contains domain events related to medication management in the
concierge psychiatry practice, following the Domain-Driven Design pattern.
"""

from dataclasses import dataclass
from datetime import datetime
from app.domain.utils.datetime_utils import UTC
from uuid import UUID


@dataclass
class MedicationEvent:
    """Base class for all medication-related domain events"""

    medication_id: UUID
    patient_id: UUID
    provider_id: UUID
    timestamp: datetime = datetime.now(UTC)


@dataclass
class MedicationPrescribed(MedicationEvent):
    """Event raised when a medication is prescribed"""

    medication_name: str
    dosage: str
    frequency: str
    duration_days: int | None = None
    is_controlled_substance: bool = False
    prescription_id: UUID | None = None


@dataclass
class MedicationRefilled(MedicationEvent):
    """Event raised when a medication is refilled"""

    refill_quantity: int
    previous_prescription_id: UUID
    refill_number: int  # Which refill this is (1st, 2nd, etc.)
    authorized_refills_remaining: int
    new_prescription_id: UUID | None = None


@dataclass
class MedicationDiscontinued(MedicationEvent):
    """Event raised when a medication is discontinued"""

    discontinuation_reason: str
    taper_schedule: str | None = None
    alternative_medication_id: UUID | None = None


@dataclass
class MedicationDosageChanged(MedicationEvent):
    """Event raised when a medication dosage is changed"""

    previous_dosage: str
    new_dosage: str
    change_reason: str
    is_increase: bool  # Whether this is an increase or decrease


@dataclass
class MedicationInteractionDetected(MedicationEvent):
    """Event raised when a potential medication interaction is detected"""

    interacting_medication_id: UUID
    interaction_severity: str  # e.g., "Mild", "Moderate", "Severe"
    interaction_description: str
    override_reason: str | None = None
    was_overridden: bool = False


@dataclass
class MedicationAdherenceRecorded(MedicationEvent):
    """Event raised when medication adherence is recorded"""

    adherence_level: str  # e.g., "Full", "Partial", "None"
    adherence_issues: list[str] | None = None
    patient_reported: bool = True
    intervention_required: bool = False


@dataclass
class MedicationSideEffectReported(MedicationEvent):
    """Event raised when a medication side effect is reported"""

    side_effect_description: str
    severity: str  # e.g., "Mild", "Moderate", "Severe"
    onset_date: datetime | None = None
    action_taken: str | None = (
        None  # e.g., "Discontinued", "Reduced Dosage", "Monitoring"
    )
    is_serious_adverse_event: bool = False
