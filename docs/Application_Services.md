# Application Services

## Overview

Application Services act as the orchestration layer in the Clarity AI Backend, coordinating domain entities, use cases, and infrastructure components to fulfill business requirements. They represent the boundary between the domain layer and the presentation layer, providing a clean API that exposes domain capabilities while abstracting implementation details.

## Architectural Principles

1. **Layer Isolation**: Application services act as an abstraction layer between domain model and external systems
2. **Dependency Inversion**: Services depend on interfaces, not concrete implementations
3. **Single Responsibility**: Each service has a focused set of related operations
4. **Command-Query Separation**: Methods either perform actions or return data, not both
5. **Pure Orchestration**: Services coordinate but don't contain business logic (which belongs in entities)

## Service Interface Design

Application service interfaces are defined in the core layer:

```python
from abc import ABC, abstractmethod
from typing import List, Optional
from app.core.domain.entities import Patient
from app.core.domain.value_objects import PatientId

class IPatientService(ABC):
    """Interface for patient management operations."""
    
    @abstractmethod
    async def get_patient(self, patient_id: PatientId) -> Optional[Patient]:
        """
        Retrieve patient by ID.
        
        Args:
            patient_id: Unique identifier for the patient
            
        Returns:
            Patient entity if found, None otherwise
        """
        pass
    
    @abstractmethod
    async def create_patient(self, patient: Patient) -> Patient:
        """
        Create a new patient record.
        
        Args:
            patient: Patient entity to persist
            
        Returns:
            The created patient with populated ID
        """
        pass
```

## Service Implementation

Service implementations are placed in the application layer:

```python
from app.core.interfaces.services import IPatientService
from app.core.interfaces.repositories import IPatientRepository
from app.core.interfaces.security import IAuditLogger
from app.core.domain.entities import Patient
from app.core.domain.value_objects import PatientId
from typing import List, Optional

class PatientService(IPatientService):
    """Implementation of patient management operations."""
    
    def __init__(
        self,
        patient_repository: IPatientRepository,
        audit_logger: IAuditLogger
    ):
        self._patient_repository = patient_repository
        self._audit_logger = audit_logger
    
    async def get_patient(self, patient_id: PatientId) -> Optional[Patient]:
        """
        Retrieve patient by ID.
        
        Args:
            patient_id: Unique identifier for the patient
            
        Returns:
            Patient entity if found, None otherwise
        """
        patient = await self._patient_repository.get_by_id(patient_id)
        
        if patient:
            # Log PHI access for HIPAA compliance
            await self._audit_logger.log_phi_access(
                action="read",
                resource_type="Patient",
                resource_id=str(patient_id)
            )
        
        return patient
    
    async def create_patient(self, patient: Patient) -> Patient:
        """
        Create a new patient record.
        
        Args:
            patient: Patient entity to persist
            
        Returns:
            The created patient with populated ID
            
        Raises:
            DuplicateResourceError: If a patient with the same MRN already exists
        """
        # Check for duplicate MRN
        existing = await self._patient_repository.get_by_mrn(
            patient.medical_record_number
        )
        
        if existing:
            raise DuplicateResourceError(
                f"Patient with MRN {patient.medical_record_number} already exists"
            )
        
        # Persist the patient
        created_patient = await self._patient_repository.create(patient)
        
        # Log PHI creation for HIPAA compliance
        await self._audit_logger.log_phi_access(
            action="create",
            resource_type="Patient",
            resource_id=str(created_patient.id)
        )
        
        return created_patient
```

## Dependency Injection

Services are registered for dependency injection:

```python
from fastapi import Depends
from app.core.interfaces.repositories import IPatientRepository
from app.core.interfaces.security import IAuditLogger
from app.infrastructure.persistence.repositories import get_patient_repository
from app.infrastructure.security.audit import get_audit_logger
from app.application.services.patient import PatientService

def get_patient_service(
    repository: IPatientRepository = Depends(get_patient_repository),
    audit_logger: IAuditLogger = Depends(get_audit_logger)
) -> PatientService:
    """Dependency provider for PatientService."""
    return PatientService(repository, audit_logger)
```

## Transaction Management

Application services handle transaction boundaries:

```python
from app.core.interfaces.unit_of_work import IUnitOfWork

class BiometricService(IBiometricService):
    """Service for managing biometric data."""
    
    def __init__(
        self,
        patient_repository: IPatientRepository,
        biometric_repository: IBiometricRepository,
        alert_service: IAlertService,
        unit_of_work: IUnitOfWork
    ):
        self._patient_repository = patient_repository
        self._biometric_repository = biometric_repository
        self._alert_service = alert_service
        self._unit_of_work = unit_of_work
    
    async def process_readings(
        self,
        patient_id: PatientId,
        readings: List[BiometricReading]
    ) -> List[BiometricAlert]:
        """
        Process new biometric readings and generate alerts if needed.
        
        Args:
            patient_id: Patient ID
            readings: List of biometric readings to process
            
        Returns:
            List of generated alerts
        """
        async with self._unit_of_work:
            # Get patient
            patient = await self._patient_repository.get_by_id(patient_id)
            if not patient:
                raise PatientNotFoundError(f"Patient {patient_id} not found")
            
            # Store readings
            for reading in readings:
                await self._biometric_repository.add_reading(
                    patient_id, reading
                )
            
            # Check alert rules
            alerts = await self._alert_service.check_rules(
                patient_id, readings
            )
            
            # Commit the transaction
            await self._unit_of_work.commit()
            
            return alerts
```

## Error Handling

Application services translate domain errors to application errors:

```python
from app.core.domain.errors import DomainError
from app.application.errors import ApplicationError, ResourceNotFoundError

class MLModelService(IMLModelService):
    """Service for ML model operations."""
    
    async def analyze_patient_data(
        self,
        patient_id: PatientId,
        analysis_type: str
    ) -> AnalysisResult:
        """
        Perform ML analysis on patient data.
        
        Args:
            patient_id: Patient ID
            analysis_type: Type of analysis to perform
            
        Returns:
            Analysis results
            
        Raises:
            ResourceNotFoundError: If patient doesn't exist
            UnsupportedAnalysisError: If analysis type is not supported
        """
        try:
            # Domain operations...
            
        except DomainError as e:
            # Translate domain errors to application errors
            if isinstance(e, PatientNotFoundError):
                raise ResourceNotFoundError(
                    f"Patient {patient_id} not found"
                ) from e
            elif isinstance(e, UnsupportedAnalysisTypeError):
                raise UnsupportedAnalysisError(
                    f"Analysis type {analysis_type} not supported"
                ) from e
            else:
                # Re-raise other domain errors as application errors
                raise ApplicationError(str(e)) from e
```

## HIPAA Compliance

Application services implement HIPAA safeguards:

1. **Access Logging**: All PHI access is logged for audit trail
2. **Authorization**: Verification of permissions before allowing access
3. **Data Sanitization**: Sensitive data is filtered based on user role
4. **De-identification**: Services provide methods for de-identified analytics

```python
class PatientAnalyticsService(IPatientAnalyticsService):
    """Service for population health analytics."""
    
    async def get_deidentified_population_data(
        self,
        filters: Dict[str, Any]
    ) -> List[DeidentifiedPatientData]:
        """
        Get de-identified patient data for population analytics.
        
        Removes all PHI and ensures k-anonymity of the dataset.
        """
        patients = await self._patient_repository.search(filters)
        
        # Apply de-identification rules
        deidentified_data = [
            self._deidentify_patient(patient)
            for patient in patients
        ]
        
        # Apply k-anonymity (ensure groups have at least k members)
        return self._apply_k_anonymity(deidentified_data, k=5)
```

## Service Composition

Complex operations may require composing multiple services:

```python
class DigitalTwinService(IDigitalTwinService):
    """Service for digital twin operations."""
    
    def __init__(
        self,
        patient_service: IPatientService,
        biometric_service: IBiometricService,
        ml_service: IMLModelService
    ):
        self._patient_service = patient_service
        self._biometric_service = biometric_service
        self._ml_service = ml_service
    
    async def generate_patient_insights(
        self,
        patient_id: PatientId
    ) -> PatientInsights:
        """
        Generate comprehensive patient insights by integrating
        multiple data sources and models.
        """
        # Get patient information
        patient = await self._patient_service.get_patient(patient_id)
        
        # Get recent biometric data
        biometrics = await self._biometric_service.get_recent_readings(
            patient_id,
            days=30
        )
        
        # Run ML analysis
        analysis = await self._ml_service.analyze_patient_data(
            patient_id,
            analysis_type="comprehensive"
        )
        
        # Integrate all data into insights
        return PatientInsights(
            patient_id=patient_id,
            demographic_risk_factors=analysis.demographic_risks,
            biometric_trends=self._calculate_trends(biometrics),
            medical_observations=patient.observations,
            predicted_outcomes=analysis.predictions
        )
```

## Testing Application Services

Services should be thoroughly tested with mocked dependencies:

```python
import pytest
from unittest.mock import AsyncMock, MagicMock
from app.application.services.patient import PatientService
from app.core.domain.entities import Patient
from app.core.domain.value_objects import PatientId

class TestPatientService:
    @pytest.fixture
    def patient_repository_mock(self):
        repository = AsyncMock()
        repository.get_by_id.return_value = Patient(
            id=PatientId("patient-123"),
            name="Jane Doe",
            medical_record_number="MRN12345",
            date_of_birth="1985-05-15"
        )
        return repository
    
    @pytest.fixture
    def audit_logger_mock(self):
        return AsyncMock()
    
    @pytest.fixture
    def service(self, patient_repository_mock, audit_logger_mock):
        return PatientService(
            patient_repository=patient_repository_mock,
            audit_logger=audit_logger_mock
        )
    
    async def test_get_patient_exists(
        self,
        service,
        patient_repository_mock,
        audit_logger_mock
    ):
        # Arrange
        patient_id = PatientId("patient-123")
        
        # Act
        result = await service.get_patient(patient_id)
        
        # Assert
        patient_repository_mock.get_by_id.assert_called_once_with(patient_id)
        audit_logger_mock.log_phi_access.assert_called_once()
        assert result is not None
        assert result.id == patient_id
```

## Current Implementation Status

### Strengths

- Clean separation of concerns with use cases and services
- Dependency injection for all services
- HIPAA-compliant audit logging implemented

### Architectural Gaps

- Some services bypass use cases and access repositories directly
- Occasional domain logic leakage into services
- Transaction boundaries not consistently defined
- Error handling inconsistency across services

### Improvement Plan

- Standardize error handling patterns
- Ensure consistent transaction management
- Complete migration to interface-based dependencies
- Implement comprehensive integration tests

By following these patterns and addressing the gaps, the Clarity AI Backend maintains a clean, maintainable service layer that properly orchestrates domain operations while enforcing security, compliance, and architectural boundaries.
