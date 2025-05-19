"""
Medication service module for the NOVAMIND backend.

This module contains the MedicationService, which encapsulates complex business logic
related to medication management in the concierge psychiatry practice.
"""

from datetime import datetime
from uuid import UUID

from app.domain.entities.medication import (
    DosageSchedule,
    Medication,
    MedicationStatus,
    RefillStatus,
)
from app.domain.repositories.medication_repository import MedicationRepository
from app.domain.repositories.patient_repository import PatientRepository
from app.domain.utils.datetime_utils import UTC


class MedicationInteractionError(Exception):
    """Exception raised when there is a potential medication interaction"""

    pass


class MedicationService:
    """
    Service for managing medications in the concierge psychiatry practice.

    This service encapsulates complex business logic related to medication
    prescribing, refill management, and interaction checking.
    """

    def __init__(
        self,
        medication_repository: MedicationRepository,
        patient_repository: PatientRepository,
    ):
        """
        Initialize the medication service

        Args:
            medication_repository: Repository for medication data access
            patient_repository: Repository for patient data access
        """
        self._medication_repo = medication_repository
        self._patient_repo = patient_repository

        # Define known medication interactions (simplified for example)
        # In a real system, this would likely come from an external drug interaction API
        self._known_interactions: dict[str, set[str]] = {
            "fluoxetine": {"tramadol", "linezolid", "monoamine oxidase inhibitors"},
            "lithium": {"nsaids", "diuretics", "ace inhibitors"},
            "clozapine": {"carbamazepine", "fluvoxamine", "ciprofloxacin"},
            "valproate": {"aspirin", "lamotrigine", "carbapenems"},
            "lamotrigine": {"valproate", "carbamazepine", "phenytoin"},
            "bupropion": {"carbamazepine", "clopidogrel", "efavirenz"},
        }

    async def prescribe_medication(
        self,
        patient_id: UUID,
        provider_id: UUID,
        name: str,
        dosage: str,
        frequency: str,
        start_date: datetime,
        end_date: datetime | None = None,
        timing: str | None = None,
        max_daily: str | None = None,
        instructions: str | None = None,
        reason_prescribed: str | None = None,
        refills: int = 0,
        check_interactions: bool = True,
    ) -> Medication:
        """
        Prescribe a new medication to a patient

        Args:
            patient_id: UUID of the patient
            provider_id: UUID of the prescribing provider
            name: Name of the medication
            dosage: Dosage amount (e.g., "10mg")
            frequency: Frequency of administration (e.g., "twice daily")
            start_date: When to start taking the medication
            end_date: Optional end date for the medication
            timing: Optional timing instructions (e.g., "with meals")
            max_daily: Optional maximum daily dosage
            instructions: Optional additional instructions
            reason_prescribed: Optional reason for prescribing
            refills: Number of refills allowed
            check_interactions: Whether to check for interactions with other medications

        Returns:
            The created medication entity

        Raises:
            ValueError: If the medication data is invalid
            MedicationInteractionError: If there is a potential interaction with existing medications
        """
        # Verify patient exists
        patient = await self._patient_repo.get_by_id(patient_id)
        if not patient:
            raise ValueError(f"Patient with ID {patient_id} does not exist")

        # Create dosage schedule
        dosage_schedule = DosageSchedule(
            amount=dosage, frequency=frequency, timing=timing, max_daily=max_daily
        )

        # Check for interactions if requested
        if check_interactions:
            await self._check_interactions(patient_id, name.lower())

        # Create medication
        medication = Medication(
            patient_id=patient_id,
            provider_id=provider_id,
            name=name,
            dosage_schedule=dosage_schedule,
            start_date=start_date,
            end_date=end_date,
            instructions=instructions,
            reason_prescribed=reason_prescribed,
            refills_remaining=refills,
            status=MedicationStatus.ACTIVE,
            refill_status=(RefillStatus.AVAILABLE if refills > 0 else RefillStatus.EXPIRED),
        )

        # Save to repository
        return await self._medication_repo.create(medication)

    async def update_prescription(
        self,
        medication_id: UUID,
        dosage: str | None = None,
        frequency: str | None = None,
        timing: str | None = None,
        max_daily: str | None = None,
        end_date: datetime | None = None,
        instructions: str | None = None,
        refills: int | None = None,
        check_interactions: bool = True,
    ) -> Medication:
        """
        Update an existing medication prescription

        Args:
            medication_id: UUID of the medication to update
            dosage: Optional new dosage amount
            frequency: Optional new frequency
            timing: Optional new timing instructions
            max_daily: Optional new maximum daily dosage
            end_date: Optional new end date
            instructions: Optional new instructions
            refills: Optional new number of refills
            check_interactions: Whether to check for interactions with other medications

        Returns:
            The updated medication entity

        Raises:
            ValueError: If the medication data is invalid
            MedicationInteractionError: If there is a potential interaction with existing medications
        """
        # Retrieve the medication
        medication = await self._medication_repo.get_by_id(medication_id)
        if not medication:
            raise ValueError(f"Medication with ID {medication_id} does not exist")

        # Check if medication can be updated
        if not medication.is_active:
            raise ValueError(f"Cannot update inactive medication with status {medication.status}")

        # Update dosage schedule if any dosage parameters changed
        if any([dosage, frequency, timing, max_daily]):
            new_dosage = DosageSchedule(
                amount=dosage or medication.dosage_schedule.amount,
                frequency=frequency or medication.dosage_schedule.frequency,
                timing=(timing if timing is not None else medication.dosage_schedule.timing),
                max_daily=(
                    max_daily if max_daily is not None else medication.dosage_schedule.max_daily
                ),
            )
            medication.update_dosage(new_dosage)

        # Update end date if provided
        if end_date:
            medication.extend_prescription(end_date)

        # Update instructions if provided
        if instructions:
            medication.instructions = instructions
            medication.updated_at = datetime.now(UTC)

        # Update refills if provided
        if refills is not None:
            medication.refills_remaining = refills
            medication.refill_status = (
                RefillStatus.AVAILABLE if refills > 0 else RefillStatus.EXPIRED
            )
            medication.updated_at = datetime.now(UTC)

        # Save to repository
        return await self._medication_repo.update(medication)

    async def discontinue_medication(
        self, medication_id: UUID, reason: str | None = None
    ) -> Medication:
        """
        Discontinue a medication

        Args:
            medication_id: UUID of the medication to discontinue
            reason: Optional reason for discontinuation

        Returns:
            The updated medication entity

        Raises:
            ValueError: If the medication cannot be discontinued
        """
        # Retrieve the medication
        medication = await self._medication_repo.get_by_id(medication_id)
        if not medication:
            raise ValueError(f"Medication with ID {medication_id} does not exist")

        # Discontinue the medication
        medication.discontinue(reason)

        # Save to repository
        return await self._medication_repo.update(medication)

    async def approve_refill(self, medication_id: UUID, refills_granted: int = 1) -> Medication:
        """
        Approve a medication refill request

        Args:
            medication_id: UUID of the medication
            refills_granted: Number of refills to grant

        Returns:
            The updated medication entity

        Raises:
            ValueError: If the refill cannot be approved
        """
        # Retrieve the medication
        medication = await self._medication_repo.get_by_id(medication_id)
        if not medication:
            raise ValueError(f"Medication with ID {medication_id} does not exist")

        # Approve the refill
        medication.approve_refill(refills_granted)

        # Save to repository
        return await self._medication_repo.update(medication)

    async def deny_refill(self, medication_id: UUID, reason: str | None = None) -> Medication:
        """
        Deny a medication refill request

        Args:
            medication_id: UUID of the medication
            reason: Optional reason for denial

        Returns:
            The updated medication entity

        Raises:
            ValueError: If the refill cannot be denied
        """
        # Retrieve the medication
        medication = await self._medication_repo.get_by_id(medication_id)
        if not medication:
            raise ValueError(f"Medication with ID {medication_id} does not exist")

        # Deny the refill
        medication.deny_refill(reason)

        # Save to repository
        return await self._medication_repo.update(medication)

    async def report_side_effect(
        self,
        medication_id: UUID,
        effect: str,
        severity: int,
        notes: str | None = None,
        reported_by: UUID | None = None,
    ) -> Medication:
        """
        Report a side effect for a medication

        Args:
            medication_id: UUID of the medication
            effect: Description of the side effect
            severity: Severity on a scale of 1-10
            notes: Optional additional notes
            reported_by: Optional UUID of the person reporting

        Returns:
            The updated medication entity

        Raises:
            ValueError: If the side effect data is invalid
        """
        # Retrieve the medication
        medication = await self._medication_repo.get_by_id(medication_id)
        if not medication:
            raise ValueError(f"Medication with ID {medication_id} does not exist")

        # Report the side effect
        medication.report_side_effect(effect, severity, notes, reported_by)

        # Save to repository
        return await self._medication_repo.update(medication)

    async def get_active_medications(self, patient_id: UUID) -> list[Medication]:
        """
        Get all active medications for a patient

        Args:
            patient_id: UUID of the patient

        Returns:
            List of active medication entities
        """
        # Verify patient exists
        patient = await self._patient_repo.get_by_id(patient_id)
        if not patient:
            raise ValueError(f"Patient with ID {patient_id} does not exist")

        # Get active medications
        return await self._medication_repo.list_active_by_patient(patient_id)

    async def get_medications_needing_attention(self) -> list[tuple[Medication, str]]:
        """
        Get all medications that need attention (refills, expiring soon, etc.)

        Returns:
            List of tuples containing medication entities and reason for attention
        """
        result: list[tuple[Medication, str]] = []

        # Get medications needing refill
        refill_medications = await self._medication_repo.get_medications_needing_refill()
        for med in refill_medications:
            result.append((med, "Needs refill"))

        # Get medications expiring soon
        expiring_medications = await self._medication_repo.get_medications_expiring_soon(days=7)
        for med in expiring_medications:
            result.append((med, f"Expires in {med.days_remaining} days"))

        return result

    async def _check_interactions(self, patient_id: UUID, new_medication_name: str) -> None:
        """
        Check for potential interactions between a new medication and existing medications

        Args:
            patient_id: UUID of the patient
            new_medication_name: Name of the new medication (lowercase)

        Raises:
            MedicationInteractionError: If there is a potential interaction
        """
        # Get active medications for the patient
        active_medications = await self._medication_repo.list_active_by_patient(patient_id)

        # Check for interactions
        potential_interactions = []

        # Check if the new medication has known interactions
        if new_medication_name in self._known_interactions:
            # Get medications that might interact with the new one
            interacting_meds = self._known_interactions[new_medication_name]

            # Check if any active medications match the interacting medications
            for med in active_medications:
                med_name_lower = med.name.lower()
                if med_name_lower in interacting_meds:
                    potential_interactions.append(med.name)

        # Also check if any active medications have the new one listed as an interaction
        for med in active_medications:
            med_name_lower = med.name.lower()
            if (
                med_name_lower in self._known_interactions
                and new_medication_name in self._known_interactions[med_name_lower]
            ):
                potential_interactions.append(med.name)

        # Raise error if interactions found
        if potential_interactions:
            interaction_list = ", ".join(potential_interactions)
            raise MedicationInteractionError(
                f"Potential interaction between {new_medication_name} and: {interaction_list}"
            )
