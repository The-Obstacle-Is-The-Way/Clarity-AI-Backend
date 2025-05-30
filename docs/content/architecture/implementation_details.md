# Domain Model

## Core Entities

The domain layer contains the business entities, value objects, and domain services that form the core of the Clarity AI system. This documentation reflects the actual implementation in the codebase.

### Patient Entity

Represents a psychiatric patient in the system:

```python
class Patient:
    def __init__(
        self,
        id: UUID,
        name: str,
        date_of_birth: date,
        status: PatientStatus,
        provider_id: UUID,
        digital_twin_id: Optional[UUID] = None
    ):
        self.id = id
        self.name = name
        self.date_of_birth = date_of_birth
        self.status = status
        self.provider_id = provider_id
        self.digital_twin_id = digital_twin_id
```

### BiometricAlert Entity

Represents an alert generated from biometric data analysis:

```python
class BiometricAlert:
    def __init__(
        self,
        id: UUID,
        patient_id: UUID,
        rule_id: UUID,
        status: AlertStatus,
        severity: AlertSeverity,
        metric_type: MetricType,
        metric_value: float,
        created_at: datetime,
        updated_at: Optional[datetime] = None
    ):
        self.id = id
        self.patient_id = patient_id
        self.rule_id = rule_id
        self.status = status
        self.severity = severity
        self.metric_type = metric_type
        self.metric_value = metric_value
        self.created_at = created_at
        self.updated_at = updated_at
```

### DigitalTwin Entity

Represents a psychiatric digital twin model:

```python
class DigitalTwin:
    def __init__(
        self,
        id: UUID,
        patient_id: UUID,
        status: TwinStatus,
        model_version: str,
        last_updated: datetime,
        confidence: float
    ):
        self.id = id
        self.patient_id = patient_id
        self.status = status
        self.model_version = model_version
        self.last_updated = last_updated
        self.confidence = confidence
```

## Value Objects

Immutable objects that represent concepts in the domain:

### MetricThreshold

```python
@dataclass(frozen=True)
class MetricThreshold:
    metric_type: MetricType
    operator: ComparisonOperator
    value: float
    
    def evaluate(self, actual_value: float) -> bool:
        if self.operator == ComparisonOperator.GREATER_THAN:
            return actual_value > self.value
        elif self.operator == ComparisonOperator.LESS_THAN:
            return actual_value < self.value
        elif self.operator == ComparisonOperator.EQUAL_TO:
            return actual_value == self.value
        elif self.operator == ComparisonOperator.NOT_EQUAL_TO:
            return actual_value != self.value
        else:
            raise ValueError(f"Unsupported operator: {self.operator}")
```

### BiometricData

```python
@dataclass(frozen=True)
class BiometricData:
    patient_id: UUID
    metric_type: MetricType
    value: float
    timestamp: datetime
    device_id: str
    source: DataSource
```

## Domain Services

Services that encapsulate business logic:

### DigitalTwinService

```python
class DigitalTwinService:
    def __init__(
        self,
        repository: IDigitalTwinRepository,
        model_service: IModelService
    ):
        self.repository = repository
        self.model_service = model_service
    
    async def update_digital_twin(
        self,
        patient_id: UUID,
        biometric_data: List[BiometricData],
        clinical_data: Optional[ClinicalData] = None
    ) -> DigitalTwin:
        """
        Update a patient's digital twin with new data.
        """
        # Get current digital twin
        twin = await self.repository.get_by_patient_id(patient_id)
        
        # If no twin exists, create a new one
        if not twin:
            twin = DigitalTwin(
                id=uuid4(),
                patient_id=patient_id,
                status=TwinStatus.INITIALIZING,
                model_version=self.model_service.get_current_version(),
                last_updated=datetime.now(UTC),
                confidence=0.0
            )
        
        # Update the model with new data
        model_result = await self.model_service.update_model(
            twin_id=twin.id,
            biometric_data=biometric_data,
            clinical_data=clinical_data
        )
        
        # Update twin properties
        twin.status = TwinStatus.ACTIVE
        twin.last_updated = datetime.now(UTC)
        twin.confidence = model_result.confidence
        
        # Persist changes
        return await self.repository.update(twin)
```

## Enumerations

Domain-specific enumerations:

```python
class AlertStatus(str, Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"

class AlertSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class MetricType(str, Enum):
    HEART_RATE = "heart_rate"
    BLOOD_OXYGEN = "blood_oxygen"
    BLOOD_PRESSURE = "blood_pressure"
    TEMPERATURE = "temperature"
    SLEEP_DURATION = "sleep_duration"
    ACTIVITY_LEVEL = "activity_level"

class TwinStatus(str, Enum):
    INITIALIZING = "initializing"
    ACTIVE = "active"
    DEGRADED = "degraded"
    INVALID = "invalid"
```

## Repository Interfaces

Interfaces that define data access patterns:

```python
class IPatientRepository(Protocol):
    async def get_by_id(self, id: UUID) -> Optional[Patient]:
        ...
    
    async def create(self, patient: Patient) -> Patient:
        ...
    
    async def update(self, patient: Patient) -> Patient:
        ...
    
    async def get_by_provider_id(self, provider_id: UUID) -> List[Patient]:
        ...

class IDigitalTwinRepository(Protocol):
    async def get_by_id(self, id: UUID) -> Optional[DigitalTwin]:
        ...
    
    async def get_by_patient_id(self, patient_id: UUID) -> Optional[DigitalTwin]:
        ...
    
    async def create(self, digital_twin: DigitalTwin) -> DigitalTwin:
        ...
    
    async def update(self, digital_twin: DigitalTwin) -> DigitalTwin:
        ...
```