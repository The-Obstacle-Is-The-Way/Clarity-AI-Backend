# Domain Model

## Core Entities

The domain layer contains the business entities, value objects, and domain services that form the core of the Clarity AI system.

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
    lower_bound: Optional[float]
    upper_bound: Optional[float]
    
    def is_exceeded(self, value: float) -> bool:
        if self.lower_bound is not None and value < self.lower_bound:
            return True
        if self.upper_bound is not None and value > self.upper_bound:
            return True
        return False
```

### TimeWindow

```python
@dataclass(frozen=True)
class TimeWindow:
    start_time: time
    end_time: time
    
    def contains(self, timestamp: datetime) -> bool:
        check_time = timestamp.time()
        if self.start_time <= self.end_time:
            return self.start_time <= check_time <= self.end_time
        else:  # Handles overnight windows (e.g., 22:00 to 06:00)
            return check_time >= self.start_time or check_time <= self.end_time
```

## Domain Services

Services that implement domain logic:

### BiometricEventProcessor

```python
class BiometricEventProcessor:
    def __init__(
        self,
        alert_repository: IBiometricAlertRepository,
        rule_repository: IAlertRuleRepository
    ):
        self.alert_repository = alert_repository
        self.rule_repository = rule_repository
    
    async def process_biometric_event(
        self,
        patient_id: UUID,
        metric_type: MetricType,
        metric_value: float,
        timestamp: datetime
    ) -> Optional[BiometricAlert]:
        """
        Process a biometric event and create an alert if rules are triggered.
        """
        # Get applicable rules for this patient and metric
        rules = await self.rule_repository.get_rules_for_patient(
            patient_id=patient_id,
            metric_type=metric_type
        )
        
        # Check if any rules are triggered
        for rule in rules:
            if rule.is_triggered(metric_value, timestamp):
                # Create and persist alert
                alert = BiometricAlert(
                    id=uuid4(),
                    patient_id=patient_id,
                    rule_id=rule.id,
                    status=AlertStatus.NEW,
                    severity=rule.severity,
                    metric_type=metric_type,
                    metric_value=metric_value,
                    created_at=datetime.now(UTC)
                )
                
                return await self.alert_repository.create(alert)
                
        return None
```

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