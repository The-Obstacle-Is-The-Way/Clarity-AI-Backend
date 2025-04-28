# Domain Model

This document describes the core domain model of the Novamind Digital Twin Platform, capturing the essential entities, value objects, aggregates, services, events, and repository interfaces that form the foundation of the system's business logic.

---

## 1. Domain Overview

The Novamind domain model represents the key concepts in psychiatric and mental health care, with a focus on enabling digital twin modeling and predictive analytics. The domain is designed to support:

- Patient representation and clinical relationships
- Psychiatric assessment and diagnosis
- Treatment planning and tracking
- Digital twin state modeling
- Temporal analysis and prediction

The domain layer contains the core business logic and is independent of application and infrastructure concerns. It consists of Entities, Value Objects, Aggregates, Domain Services, Domain Events, and Repository Interfaces.

## 2. Core Domain Entities

Entities are objects with a distinct identity that persists over time. They encapsulate attributes and behavior related to a core domain concept.

*Note: The Python `@dataclass` examples below illustrate the data structure. Full entity implementations often include methods that enforce business rules (invariants) and manage state transitions.* 

### 2.1. Patient

Represents an individual receiving psychiatric care.

- Unique identifier (UUID) - The entity's identity.
- Contains demographic information, clinical history links, status.
- *Behavior*: Might include methods to update status, link assessments, etc., ensuring business rules are followed.

```python
# Illustrative Structure
@dataclass
class Patient:
    id: UUID
    medical_record_number: str # Often a key business identifier
    first_name: str
    last_name: str
    date_of_birth: date
    gender: Optional[str]
    contact_info: ContactInfo # Value Object
    status: PatientStatus # Enum Value Object
    created_at: datetime
    updated_at: datetime

    # Example of a method enforcing a rule
    def update_status(self, new_status: PatientStatus):
        if self.status == PatientStatus.DECEASED and new_status != PatientStatus.DECEASED:
             raise ValueError("Cannot change status of a deceased patient.")
        self.status = new_status
        self.updated_at = datetime.now()

    @staticmethod
    def create(
        medical_record_number: str,
        first_name: str,
        last_name: str,
        date_of_birth: date,
        contact_info: ContactInfo,
        # ... other required fields
    ) -> "Patient":
        """Factory method ensuring valid initial state"""
        # Add validation logic here if needed
        return Patient(
            id=uuid4(),
            medical_record_number=medical_record_number,
            first_name=first_name,
            last_name=last_name,
            date_of_birth=date_of_birth,
            contact_info=contact_info,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            status=PatientStatus.ACTIVE,
            # ...
        )
```

### 2.2. Clinician

Represents a healthcare provider in the system.

- Unique identifier (UUID).
- Contains professional credentials, contact info.
- *Behavior*: Methods might relate to managing assigned patients or specialties.

```python
# Illustrative Structure
@dataclass
class Clinician:
    id: UUID
    npi_number: str
    first_name: str
    last_name: str
    specialty: str
    # ... other relevant attributes
```

### 2.3. DigitalTwin

The core entity representing a patient's evolving neuropsychiatric state. *Note: This reflects the entity currently used by `DigitalTwinService` (`app/domain/entities/digital_twin.py`), which is simpler than some earlier/aspirational designs.*

- Unique identifier (UUID).
- Links to a specific `Patient`.
- Contains configuration settings for the twin's behavior.
- Holds a high-level summary of the twin's current state.
- Manages versioning.
- *Behavior*: Methods to update configuration, update high-level state, manage versions.

```python
# Illustrative Structure based on digital_twin.py
@dataclass
class DigitalTwinConfiguration: # Likely defined separately or nested
    simulation_granularity_hours: int = 24
    prediction_models_enabled: List[str] = field(default_factory=list)
    data_sources_enabled: List[str] = field(default_factory=list)
    alert_thresholds: Dict[str, float] = field(default_factory=dict)
    # ... other config fields

@dataclass
class DigitalTwinState: # Likely defined separately or nested
    last_sync_time: Optional[datetime] = None
    overall_risk_level: Optional[str] = None
    dominant_symptoms: List[str] = field(default_factory=list)
    current_treatment_effectiveness: Optional[str] = None
    predicted_phq9_trajectory: Optional[List[Dict[str, Any]]] = None # Example placeholder
    # ... other high-level state summary fields

@dataclass
class DigitalTwin:
    id: UUID
    patient_id: UUID
    configuration: DigitalTwinConfiguration # Composition
    state: DigitalTwinState # Composition
    created_at: datetime
    updated_at: datetime # Renamed from last_updated for consistency
    version: int

    def update_configuration(self, new_config: DigitalTwinConfiguration):
        # Logic to validate and update configuration
        self.configuration = new_config
        self.touch() # Update timestamp

    def update_summary_state(self, new_state_summary: DigitalTwinState):
        # Logic to update high-level state summary fields
        # Note: Complex state calculation likely happens elsewhere (Application/Domain Service)
        self.state = new_state_summary
        self.touch()

    def touch(self):
        """Updates the timestamp and potentially increments version."""
        self.updated_at = datetime.now()
        self.version += 1
        # Consider raising Domain Event: DigitalTwinUpdated

    @classmethod
    def create(cls, patient_id: UUID) -> "DigitalTwin":
        """Factory method to create a new Digital Twin"""
        now = datetime.now()
        return cls(
            id=uuid4(),
            patient_id=patient_id,
            configuration=DigitalTwinConfiguration(), # Default config
            state=DigitalTwinState(), # Default state
            created_at=now,
            updated_at=now,
            version=1
        )
```

*Self-Correction Note: Analysis reveals significant overlap and potential redundancy in Digital Twin related entities across different files (`digital_twin.py`, `digital_twin_entity.py`, `biometric_twin.py`, `biometric_twin_enhanced.py`). The description above is based on `digital_twin.py`, which documentation suggests is currently canonical, but the others represent different or potentially legacy/aspirational aspects.* 

### 2.4. Assessment

Represents a clinical evaluation performed on a patient at a specific time.

- Unique identifier (UUID).
- Links to `Patient` and potentially `Clinician`.
- Contains assessment type, date, results/scores.
- *Behavior*: May include methods for scoring or interpretation based on raw results.

### 2.10. Knowledge Graph Components

Represents elements related to the knowledge graph construction and querying.

*(Details TBD - Link to `knowledge_graph.py` and potentially related Neurotransmitter/Temporal files found in `digital_twin_entity.py`)*

### 2.11. Pharmacogenomics (PGX)

Represents pharmacogenomic data or markers relevant to the patient.

*(Details TBD - Link to `pgx.py`)*

### 2.12. Biometric Data & Rules

Represents biometric time-series data and rules for analysis. *Note: Implemented across `biometric_twin.py` (Pydantic) and `biometric_twin_enhanced.py` (classes with ranges), plus related `temporal_...` files. These need reconciliation.*

*(Details TBD - Link to relevant files)*

### 2.13. Analytics & Temporal Data

Represents aggregated analytics or temporal event sequences.

*(Details TBD - Link to `analytics.py`, `temporal_sequence.py`, `temporal_events.py`, and potentially `TemporalPattern` in `digital_twin_entity.py`)*

### 2.5. Treatment

Represents a therapeutic intervention applied to a patient.

- Unique identifier (UUID).
- Links to `Patient` and prescribing `Clinician`.
- Base concept, often specialized (e.g., `Medication`, `TherapySession`).
- Contains start/end dates, status.

```python
# Illustrative Structure for a specialized Treatment
@dataclass
class Medication(Treatment): # Assuming Treatment is a base class/protocol
    # Common Treatment fields inherited/defined...
    id: UUID
    patient_id: UUID
    prescriber_id: UUID
    start_date: datetime
    end_date: Optional[datetime]
    status: TreatmentStatus
    # Medication specific fields
    name: str
    dosage: str # Consider dedicated Value Object for dosage/units
    frequency: str # Consider dedicated Value Object
    route: str

    @property
    def is_active(self) -> bool:
        """Check if medication is currently active"""
        now = datetime.now()
        if self.status != TreatmentStatus.ACTIVE:
            return False
        if not self.end_date:
            return self.start_date <= now
        return self.start_date <= now < self.end_date
```

### 2.6. User

Represents an authenticated user of the system (could be a Patient, Clinician, or Admin).

*(Details TBD - Link to `user.py`)*

### 2.7. Appointment

Represents a scheduled meeting between a Patient and a Clinician.

*(Details TBD - Link to `appointment.py`)*

### 2.8. Clinical Session

Represents a specific instance of a clinical interaction (e.g., a therapy session).

*(Details TBD - Link to `clinical_session.py`)*

### 2.9. Clinical Note

Represents notes recorded during a clinical session or interaction.

*(Details TBD - Link to `clinical_note.py`)*

### 2.14. Provider

*Alias/Refinement of Clinician.* Represents a healthcare provider or entity.

*(Details TBD - Link to `provider.py`, clarify relationship with Clinician if distinct)*

## 3. Value Objects

Value Objects are objects defined by their attributes rather than a unique identity. They are typically immutable (`frozen=True`) and used to describe aspects of entities.

*Note: Ensure Value Objects are properly validated upon creation (e.g., in `__post_init__` or factory methods).* 

### 3.1. ContactInfo

Encapsulates contact information.

```python
@dataclass(frozen=True)
class ContactInfo:
    email: Optional[EmailStr] = None # Use Pydantic types for validation if helpful
    phone: Optional[str] = None
    address: Optional[Address] = None
```

### 3.2. Address

Represents a physical address.

```python
@dataclass(frozen=True)
class Address:
    street_line1: str
    street_line2: Optional[str] = None
    city: str
    state: str
    postal_code: str
    country: str = "USA"

    # Example validation
    def __post_init__(self):
        if not self.postal_code.isdigit() or len(self.postal_code) != 5:
            raise ValueError("Invalid postal code format")
```

### 3.3. NeurotransmitterState

Represents the state of neurotransmitter systems at a point in time.

```python
@dataclass(frozen=True)
class NeurotransmitterState:
    serotonin: float
    dopamine: float
    norepinephrine: float
    gaba: float
    glutamate: float
    acetylcholine: float
    timestamp: datetime

    def as_dict(self) -> Dict[str, float]:
        # ... implementation ...
```

### 3.4. PsychologicalState

Represents the psychological state variables at a point in time.

```python
@dataclass(frozen=True)
class PsychologicalState:
    mood_level: float
    anxiety_level: float
    cognition_score: float
    energy_level: float
    sleep_quality: float
    social_engagement: float
    timestamp: datetime

    def as_dict(self) -> Dict[str, float]:
        # ... implementation ...
```

### 3.5. Other Potential Value Objects

- `PatientStatus` (Enum: ACTIVE, INACTIVE, DECEASED)
- `TreatmentStatus` (Enum: PLANNED, ACTIVE, COMPLETED, CANCELLED)
- `Dosage` (value, unit)
- `ConfidenceScore` (value, metric_name)

## 4. Aggregates

Aggregates group entities and value objects that should be treated as a single unit for data changes. Each aggregate has a root entity, which is the only member accessible from outside the aggregate. Transactions should ideally span only one aggregate.

### 4.1. PatientAggregate

- **Root**: `Patient`
- **Contains**: `ContactInfo`, `Address` (via ContactInfo)
- **Invariants**: Patient status transitions are valid; required fields are present.

### 4.2. DigitalTwinAggregate

- **Root**: `DigitalTwin`
- **Contains**: `NeurotransmitterState`, `PsychologicalState`, `ConfidenceScore`s, potentially a collection of historical states or events internal to the twin.
- **Invariants**: Version increases monotonically; confidence scores relate to current state; state updates are timestamped correctly.

### 4.3. TreatmentAggregate

- **Root**: `Treatment` (or specialized types like `Medication`)
- **Contains**: Dosage, Frequency (if Value Objects)
- **Invariants**: Start/end dates are logical; status transitions are valid.

## 5. Repository Interfaces

Repository interfaces define the contract for data persistence operations for Aggregates. They belong to the domain layer, abstracting away the specific database technology. Implementations reside in the Infrastructure layer.

*Note: Methods typically operate on Aggregate Roots.* 

```python
from typing import Protocol, Optional, List
from uuid import UUID

class IPatientRepository(Protocol):
    async def get_by_id(self, patient_id: UUID) -> Optional[Patient]: ...
    async def get_by_mrn(self, mrn: str) -> Optional[Patient]: ...
    async def save(self, patient: Patient) -> None: ... # Create or Update
    async def list_active(self) -> List[Patient]: ...

class IDigitalTwinRepository(Protocol):
    async def get_by_id(self, twin_id: UUID) -> Optional[DigitalTwin]: ...
    async def get_by_patient_id(self, patient_id: UUID) -> Optional[DigitalTwin]: ...
    async def save(self, digital_twin: DigitalTwin) -> None: ...

class ITreatmentRepository(Protocol):
    async def get_by_id(self, treatment_id: UUID) -> Optional[Treatment]: ...
    async def find_active_by_patient_id(self, patient_id: UUID) -> List[Treatment]: ...
    async def save(self, treatment: Treatment) -> None: ...

# ... other repository interfaces (Clinician, Assessment) ...
```

Refer to `40_Database_Management.md` for implementation patterns of these interfaces.

## 6. Domain Services

Domain Services encapsulate domain logic that doesn't naturally fit within a single Entity or Value Object. They often orchestrate operations involving multiple domain objects.

- **Characteristics**: Stateless; inputs/outputs are typically domain objects.
- **Example**: A service to calculate the initial state of a `DigitalTwin` based on a `Patient`'s recent `Assessment` history, or a service to check for drug interactions between active `Medication` treatments.

```python
# Conceptual Example
class TreatmentConflictService:
    def __init__(self, treatment_repo: ITreatmentRepository):
        self._treatment_repo = treatment_repo

    async def check_for_conflicts(self, patient_id: UUID, new_treatment: Treatment) -> List[ConflictInfo]:
        active_treatments = await self._treatment_repo.find_active_by_patient_id(patient_id)
        conflicts = []
        for existing in active_treatments:
            if self._detect_interaction(existing, new_treatment):
                conflicts.append(ConflictInfo(existing, new_treatment))
        return conflicts

    def _detect_interaction(self, t1: Treatment, t2: Treatment) -> bool:
        # Complex interaction logic here...
        return False
```

## 7. Domain Events

Domain Events represent significant occurrences within the domain. They can be used to decouple parts of the domain and trigger side effects (e.g., updating other aggregates, sending notifications) handled by application services or dedicated event handlers.

- **Characteristics**: Immutable objects representing something that *happened*.
- **Examples**:
    - `PatientRegistered`
    - `DigitalTwinStateUpdated`
    - `TreatmentStarted`
    - `AssessmentCompleted`
- **Usage**: Entities or Domain Services can raise events. A mechanism (e.g., in the application layer or via a message bus) dispatches these events to handlers.

```python
@dataclass(frozen=True)
class DigitalTwinStateUpdated:
    twin_id: UUID
    patient_id: UUID
    new_version: int
    update_timestamp: datetime
```

*(Note: The implementation of event dispatching and handling resides outside the core domain model itself, typically in the application or infrastructure layers).* 

## 6. Domain Directory Structure Overview

Beyond entities and value objects, the `backend/app/domain/` directory contains several subdirectories:

- **`domain/entities/`**: Contains the core domain entity definitions (as listed above).
- **`domain/value_objects/`**: Contains value object definitions.
- **`domain/repositories/`**: Defines the interfaces (contracts) for data persistence repositories (e.g., `PatientRepository`, `DigitalTwinRepository`). Implementations reside in the `infrastructure` layer.
- **`domain/services/`**: Holds domain services - logic that involves multiple entities or complex business rules that don't belong to a single entity.
- **`domain/events/`**: Defines domain events (e.g., `PatientRegistered`, `MedicationPrescribed`) that signal significant occurrences within the domain, using dataclasses stored in files like `patient_events.py`, `medication_events.py`, etc. These are crucial for decoupling parts of the system.
- **`domain/exceptions/`**: Contains custom exception classes specific to domain rule violations (e.g., `InvalidPatientStateError`).
- **`domain/enums/`**: Holds enumeration types used within the domain model.
- **`domain/interfaces/`**: Defines abstract interfaces (using `typing.Protocol`) for infrastructure services or patterns that the domain layer depends on, such as `IUnitOfWork`, `IAuditService`, `IMentalLlamaService`, etc. This enforces the Dependency Inversion Principle.
- **`domain/models/`**: Contains Pydantic models used within the domain (e.g., a `User` model in `user.py`). These might represent data structures for internal use or transfer, potentially distinct from full domain entities or ORM models. *(Relationship to `domain/entities/` requires clarification)*
- **`domain/ml/`**: Contains domain-level concepts related to ML, specifically an `MLModel` dataclass defining model metadata and a `ModelType` enum, as well as ML-specific domain exceptions (`exceptions.py`).
- **`domain/utils/`**: Contains utility functions specific to the domain layer, such as datetime and text manipulation helpers, and potentially test utilities (`standalone_test_utils.py`).

---

This domain model provides the language and structure for the core business logic. Adherence to these concepts ensures a clean, maintainable, and extensible system.

Last Updated: 2025-04-20