"""
Patient events module for the NOVAMIND backend.

This module contains domain events related to patients in the
concierge psychiatry practice, following the Domain-Driven Design pattern.
"""

from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID

from app.domain.events.base_event import DomainEvent


@dataclass
class PatientCreated(DomainEvent):
    patient_id: UUID
    created_at: datetime = field(default_factory=datetime.now)

    def get_event_name(self) -> str:
        return "PatientCreated"


@dataclass
class PatientUpdated(DomainEvent):
    patient_id: UUID
    updated_fields: list[str]
    updated_at: datetime = field(default_factory=datetime.now)

    def get_event_name(self) -> str:
        return "PatientUpdated"


@dataclass
class PatientDeleted(DomainEvent):
    patient_id: UUID
    deleted_at: datetime = field(default_factory=datetime.now)

    def get_event_name(self) -> str:
        return "PatientDeleted"
