"""
Therapeutic plan value object for the NOVAMIND backend.

This module contains the TherapeuticPlan value object, which represents
a structured treatment plan with immutable properties and validation.
"""

from dataclasses import dataclass, field
from datetime import date, timedelta
from enum import Enum
from uuid import UUID


class TreatmentGoalStatus(Enum):
    """Enumeration of treatment goal statuses"""

    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    ACHIEVED = "achieved"
    PARTIALLY_ACHIEVED = "partially_achieved"
    DISCONTINUED = "discontinued"


class TreatmentGoalPriority(Enum):
    """Enumeration of treatment goal priorities"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    URGENT = "urgent"


@dataclass(frozen=True)
class TreatmentGoal:
    """Value object representing a treatment goal within a therapeutic plan"""

    description: str
    target_date: date | None = None
    status: TreatmentGoalStatus = TreatmentGoalStatus.NOT_STARTED
    priority: TreatmentGoalPriority = TreatmentGoalPriority.MEDIUM
    measures: list[str] = field(default_factory=list)

    def __post_init__(self):
        """Validate the treatment goal"""
        if not self.description:
            raise ValueError("Treatment goal description cannot be empty")

        if self.target_date and self.target_date < date.today():
            raise ValueError("Target date cannot be in the past")


@dataclass(frozen=True)
class TherapeuticIntervention:
    """Value object representing a therapeutic intervention within a plan"""

    name: str
    description: str
    frequency: str  # e.g., "Weekly", "Daily", "Twice weekly"
    duration_weeks: int | None = None
    modality: str | None = None  # e.g., "CBT", "DBT", "Psychodynamic"

    def __post_init__(self):
        """Validate the therapeutic intervention"""
        if not self.name:
            raise ValueError("Intervention name cannot be empty")

        if not self.description:
            raise ValueError("Intervention description cannot be empty")

        if not self.frequency:
            raise ValueError("Intervention frequency cannot be empty")

        if self.duration_weeks is not None and self.duration_weeks <= 0:
            raise ValueError("Duration must be positive")


@dataclass(frozen=True)
class TherapeuticPlan:
    """
    Value object representing a comprehensive therapeutic plan.

    This is an immutable value object with validation logic for
    psychiatric treatment plans.
    """

    patient_id: UUID
    provider_id: UUID
    start_date: date
    goals: list[TreatmentGoal]
    interventions: list[TherapeuticIntervention]
    diagnosis_codes: list[str]
    end_date: date | None = None
    review_frequency_weeks: int = 4

    def __post_init__(self):
        """Validate the therapeutic plan"""
        if not self.goals:
            raise ValueError("Therapeutic plan must have at least one goal")

        if not self.interventions:
            raise ValueError("Therapeutic plan must have at least one intervention")

        if not self.diagnosis_codes:
            raise ValueError("Therapeutic plan must have at least one diagnosis code")

        if self.start_date > date.today():
            raise ValueError("Start date cannot be in the future")

        if self.end_date and self.end_date <= self.start_date:
            raise ValueError("End date must be after start date")

        if self.review_frequency_weeks <= 0:
            raise ValueError("Review frequency must be positive")

    @property
    def is_active(self) -> bool:
        """Check if the therapeutic plan is currently active"""
        today = date.today()
        if self.end_date:
            return self.start_date <= today <= self.end_date
        return self.start_date <= today

    @property
    def next_review_date(self) -> date:
        """Calculate the next review date based on the start date and review frequency"""
        today = date.today()
        weeks_since_start = (today - self.start_date).days // 7
        reviews_completed = weeks_since_start // self.review_frequency_weeks
        next_review = self.start_date + timedelta(
            weeks=(reviews_completed + 1) * self.review_frequency_weeks
        )
        return next_review

    @property
    def progress_percentage(self) -> float:
        """Calculate the overall progress percentage based on goal statuses"""
        if not self.goals:
            return 0.0

        goal_weights = {
            TreatmentGoalStatus.NOT_STARTED: 0.0,
            TreatmentGoalStatus.IN_PROGRESS: 0.5,
            TreatmentGoalStatus.PARTIALLY_ACHIEVED: 0.75,
            TreatmentGoalStatus.ACHIEVED: 1.0,
            TreatmentGoalStatus.DISCONTINUED: 0.0,
        }

        total_progress = sum(goal_weights[goal.status] for goal in self.goals)
        return (total_progress / len(self.goals)) * 100
