# Domain Models & Entities

## Overview

The Clarity AI Backend implements a sophisticated domain model architecture that forms the cognitive foundation of the psychiatric digital twin platform. This document details the core domain entities, their relationships, and the design principles that guide their implementation, following clean architecture and domain-driven design principles.

The domain layer is intentionally isolated from infrastructure concerns, ensuring that the core business logic remains pure and uncontaminated by technical implementation details. This separation enables the platform to evolve its interfaces while maintaining the integrity of the underlying psychiatric modeling algorithms.

## Core Domain Entities

### Patient

The `Patient` entity represents the central domain concept of the platform - the individual whose psychiatric state is being modeled and analyzed.

```python
@dataclass
class Patient:
    """Core domain model for a patient."""
    id: UUID
    name: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    date_of_birth: date | None = None
    gender: str | None = None
    email: str | None = None
    phone: str | None = None
    # Additional fields...
```

**Key Characteristics:**

- Implements sophisticated name handling to support both unified and split name patterns
- Utilizes the descriptor pattern with `PatientContactInfoDescriptor` to provide elegant access to contact information
- Contains HIPAA-compliant data encapsulation mechanisms
- Manages PHI (Protected Health Information) fields with explicit annotations
- Maintains referential integrity with related entities like emergency contacts

The `Patient` entity serves as an aggregate root in the domain, with multiple child entities and value objects that complete the representation of patient data.

### Digital Twin

The `DigitalTwin` entity forms the central computational model of the platform, providing a comprehensive psychiatric representation of a patient.

```python
@dataclass
class DigitalTwin:
    """Core Digital Twin entity."""
    patient_id: UUID 
    baseline_serotonin: float = 1.0
    baseline_dopamine: float = 1.0
    baseline_gaba: float = 1.0
    baseline_norepinephrine: float = 1.0
    cortisol_sensitivity: float = 0.5
    medication_sensitivity: float = 1.0
    therapy_sensitivity: float = 0.8
    id: UUID = field(default_factory=uuid4)
    configuration: DigitalTwinConfiguration = field(default_factory=DigitalTwinConfiguration)
    state: DigitalTwinState = field(default_factory=DigitalTwinState)
    # Additional fields...
```

**Key Characteristics:**

- Models core neurotransmitter baselines with scientifically-calibrated defaults
- Implements sensitivity parameters for individualized treatment response modeling
- Contains a versioning system to track updates and modifications
- Maintains configuration and state as separate, well-defined nested structures
- Provides methods for state updates with automatic timestamp management

The Digital Twin serves as the computational core of the system, integrating data from various sources to create a holistic model of the patient's psychiatric state.

### DigitalTwinConfiguration

The `DigitalTwinConfiguration` value object encapsulates the configurable aspects of a digital twin model:

```python
@dataclass
class DigitalTwinConfiguration:
    """Configuration settings specific to a digital twin."""
    simulation_granularity_hours: int = 1 
    prediction_models_enabled: list[str] = field(default_factory=lambda: ["risk_relapse", "treatment_response"])
    data_sources_enabled: list[str] = field(default_factory=lambda: ["actigraphy", "symptoms", "sessions"])
    alert_thresholds: dict[str, float] = field(default_factory=dict)
```

This configuration controls the precision, data sources, and algorithmic components used in the digital twin simulation.

### DigitalTwinState

The `DigitalTwinState` value object captures the current calculated state of a digital twin:

```python
@dataclass
class DigitalTwinState:
    """Represents the current snapshot or aggregated state of the twin."""
    last_sync_time: datetime | None = None
    overall_risk_level: str | None = None # e.g., 'low', 'moderate', 'high'
    dominant_symptoms: list[str] = field(default_factory=list)
    current_treatment_effectiveness: str | None = None
    predicted_phq9_trajectory: list[dict[str, Any]] | None = None
```

This state representation aggregates the outputs of various predictive models and data analyses into a coherent representation of the patient's current psychiatric status.

### User

The `User` entity represents any individual interacting with the platform:

```python
class User(BaseModel):
    """Core user entity representing a platform user."""
    id: UUID4 | str | None = None
    email: str
    hashed_password: str | None = None
    roles: list[UserRole] = []
    is_active: bool = True
    first_name: str | None = None
    last_name: str | None = None
```

**Key Characteristics:**
- Implements a comprehensive role-based authorization model
- Uses Pydantic for robust validation and serialization
- Follows the principle of least privilege in information exposure

### UserRole

The `UserRole` enum defines the authorization scopes within the platform:

```python
class UserRole(str, Enum):
    """Enumeration of user roles within the Novamind platform."""
    ADMIN = "admin"
    PROVIDER = "provider"
    PATIENT = "patient"
    RESEARCHER = "researcher"
    SUPPORT = "support"
```

This granular role definition enables precise access control throughout the application.

### BiometricAlertRule

```python
@dataclass
class BiometricAlertRule:
    """Rule definition for generating biometric alerts."""
    id: UUID
    patient_id: UUID
    metric_name: str  # e.g., "heart_rate", "sleep_duration"
    condition: str    # e.g., "above", "below", "change_exceeds"
    threshold: float
    time_window_hours: int
    enabled: bool = True
    created_at: datetime = field(default_factory=now_utc)
    updated_at: datetime = field(default_factory=now_utc)
    description: str | None = None
    severity: str = "medium"  # "low", "medium", "high", "critical"
```

Biometric Alert Rules define the conditions under which the system generates alerts based on patient biometric data, supporting proactive intervention.

### ClinicalNote

```python
@dataclass
class ClinicalNote:
    """Represents a clinical note documenting a patient interaction."""
    id: UUID
    patient_id: UUID
    provider_id: UUID
    content: str
    created_at: datetime
    updated_at: datetime
    note_type: str  # e.g., "progress_note", "intake", "assessment"
    session_id: UUID | None = None
    tags: list[str] = field(default_factory=list)
```

Clinical Notes provide a secure mechanism for providers to document patient interactions while maintaining HIPAA compliance.

## Digital Twin Specialized Entities

The Digital Twin model incorporates several specialized entities that model specific aspects of neural and psychiatric function:

### BrainRegion

```python
@dataclass
class BrainRegion:
    """Represents a specific brain region in the digital twin model."""
    id: UUID = field(default_factory=uuid4)
    name: str  # e.g., "prefrontal_cortex", "amygdala"
    baseline_activity: float = 1.0
    current_activity: float = 1.0
    sensitivity_factors: dict[str, float] = field(default_factory=dict)
```

### NeurotransmitterModel

```python
@dataclass
class NeurotransmitterModel:
    """Models neurotransmitter dynamics for a patient."""
    id: UUID = field(default_factory=uuid4)
    patient_id: UUID
    serotonin_baseline: float = 1.0
    dopamine_baseline: float = 1.0
    gaba_baseline: float = 1.0
    norepinephrine_baseline: float = 1.0
    current_serotonin: float = 1.0
    current_dopamine: float = 1.0
    current_gaba: float = 1.0
    current_norepinephrine: float = 1.0
```

### ClinicalInsight

```python
@dataclass
class ClinicalInsight:
    """Represents an AI-generated clinical insight from the digital twin."""
    id: UUID = field(default_factory=uuid4)
    patient_id: UUID
    digital_twin_id: UUID
    insight_type: str  # e.g., "treatment_adjustment", "risk_factor"
    content: str
    confidence_score: float
    supporting_data: dict[str, Any] = field(default_factory=dict)
    generated_at: datetime = field(default_factory=now_utc)
    reviewed: bool = False
    reviewer_id: UUID | None = None
    review_notes: str | None = None
```

These entities together form a comprehensive model of neural function that drives the sophisticated psychiatric modeling capabilities of the platform.

## Value Objects

In addition to entities, the domain model employs immutable value objects to represent concepts that lack identity but have domain significance:

### EmergencyContact

```python
@dataclass(frozen=True)
class EmergencyContact:
    """Contact information for patient emergencies."""
    name: str
    relationship: str
    phone: str
    email: str | None = None
```

### MedicationDosage

```python
@dataclass(frozen=True)
class MedicationDosage:
    """Medication dosage information."""
    value: float
    unit: str  # e.g., "mg", "mL"
    frequency: str  # e.g., "daily", "twice_daily", "weekly" 
    timing: str | None = None  # e.g., "morning", "with_food"
```

Value objects are implemented as frozen dataclasses to ensure immutability and semantic integrity.

## Aggregates and Entity Relationships

The domain model organizes entities into logical aggregates to maintain data consistency and enforce invariants:

1. **Patient Aggregate**
   - Root: Patient
   - Members: EmergencyContact, BiometricAlertRule, ClinicalNote

2. **Digital Twin Aggregate**
   - Root: DigitalTwin
   - Members: BrainRegion, NeurotransmitterModel, ClinicalInsight

3. **Clinical Session Aggregate**
   - Root: ClinicalSession
   - Members: ClinicalNote, Assessment

Aggregate boundaries explicitly define transaction consistency boundaries and access paths through the domain model.

## Domain Events

The system employs domain events to communicate significant state changes and maintain decoupled components:

```python
@dataclass
class PatientCreatedEvent:
    """Event fired when a new patient is created."""
    patient_id: UUID
    created_at: datetime
    created_by: UUID | None = None
```

```python
@dataclass
class DigitalTwinUpdatedEvent:
    """Event fired when a digital twin is updated."""
    digital_twin_id: UUID
    patient_id: UUID
    updated_at: datetime
    previous_version: int
    new_version: int
    changes: dict[str, Any] = field(default_factory=dict)
```

Domain events facilitate reactive programming patterns and ensure that interdependent components remain loosely coupled.

## Domain Enums

The model includes several enumerations to represent constrained value sets with domain significance:

### DigitalTwinState (Enum)

```python
class DigitalTwinState(Enum):
    """Enumeration of possible states for a Digital Twin model."""
    INITIALIZED = auto()
    TRAINING = auto()
    TRAINED = auto()
    VALIDATING = auto()
    VALIDATED = auto()
    ACTIVE = auto()
    DISABLED = auto()
    ARCHIVED = auto()
    FAILED = auto()
    RETRAINING = auto()
    DEPRECATED = auto()
```

This enumeration represents the lifecycle stages of a digital twin from creation through training, validation, and deployment.

## Design Principles

The domain model adheres to several key design principles:

1. **Rich Domain Models**: Entities encapsulate both data and behavior, ensuring that domain logic remains centralized and coherent.

2. **Immutability**: Value objects are implemented as immutable structures to prevent unexpected state changes.

3. **Explicit State Transitions**: State changes are modeled as explicit operations with clear validation and consistency rules.

4. **HIPAA Compliance by Design**: PHI handling is built into the domain model through explicit annotations and access controls.

5. **Clean Architecture Compatibility**: Domain entities are free from infrastructure or framework dependencies.

6. **Type Safety**: Extensive use of type hints and validation constraints ensures domain model integrity.

7. **Encapsulation**: Internal state is protected through controlled access methods and careful property exposure.

## Implementation Details

The domain entities are implemented using Python dataclasses for entities and Pydantic models for DTOs, providing a clean separation between internal domain models and external data transfer objects.

Key implementation patterns include:

1. **Post-initialization validation** using `__post_init__` to enforce complex invariants.
2. **Factory methods** to encapsulate complex entity creation logic.
3. **Descriptors** for sophisticated property access patterns (e.g., `PatientContactInfoDescriptor`).
4. **Dedicated timestamps** for creation and modification tracking.
5. **Version tracking** for optimistic concurrency control.

## Conclusion

The domain model forms the conceptual core of the Clarity AI Backend, providing a rich, expressive, and technically sound representation of the psychiatric concepts needed to implement the digital twin platform. By adhering to clean architecture principles and domain-driven design practices, the model maintains a clear separation of concerns while delivering the complex functionality required for advanced psychiatric modeling.
