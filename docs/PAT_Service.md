# Pretrained Actigraphy Transformer (PAT) Service

## Overview

The Pretrained Actigraphy Transformer (PAT) Service is a specialized machine learning component within the Clarity AI Backend that analyzes patient actigraphy data to derive psychiatric insights. This service represents a breakthrough approach in psychiatric assessment, using movement patterns to identify markers of mental health conditions, monitor treatment efficacy, and provide objective behavioral data for the digital twin.

## Current Implementation Status

The PAT Service is currently implemented with two parallel interfaces:

1. **Core Layer Interface (PATInterface)**: Defined in `app/core/interfaces/services/ml/pat_interface.py`
2. **Route-Level Interface (IPATService)**: Defined inline in `app/presentation/api/v1/routes/actigraphy.py`

This dual interface approach represents an architectural refinement opportunity in the clean architecture implementation.

## Interface Definitions

### Core Layer Interface

```python
class PATInterface(ABC):
    """
    Interface for psychiatric assessment tool services that analyze actigraphy data.
    
    PAT services analyze movement patterns and provide clinical insights,
    predictions, and digital twin modeling capabilities.
    """
    
    @abstractmethod
    async def initialize(self) -> bool:
        """
        Initialize the PAT service with required models and configurations.
        
        Returns:
            True if initialization successful, False otherwise
        """
        pass
    
    @abstractmethod
    async def analyze_actigraphy(
        self, 
        patient_id: str, 
        readings: List[Dict[str, Any]], 
        device_info: Optional[Dict[str, Any]] = None,
        analysis_types: Optional[List[str]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Analyze actigraphy data to extract clinical insights.
        
        Args:
            patient_id: Patient identifier
            readings: Actigraphy data readings
            device_info: Information about the recording device
            analysis_types: Types of analysis to perform
            
        Returns:
            Analysis results with clinical insights
        """
        pass
    
    @abstractmethod
    async def get_embeddings(
        self, 
        patient_id: str, 
        readings: Optional[List[Dict[str, Any]]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Generate embeddings from actigraphy data for use in machine learning models.
        
        Args:
            patient_id: Patient identifier
            readings: Actigraphy data readings
            
        Returns:
            Vector embeddings and metadata
        """
        pass
    
    @abstractmethod
    async def get_model_info(self) -> Dict[str, Any]:
        """
        Get information about the underlying models used by the PAT service.
        
        Returns:
            Model information including version, training data, and capabilities
        """
        pass
```

### Route-Level Interface

```python
class IPATService:
    """Interface for PAT analysis service."""
    
    async def analyze_actigraphy(self, data: dict[str, Any]) -> dict[str, Any]:
        """Analyze actigraphy data and return results."""
        pass
    
    async def get_embeddings(self, data: dict[str, Any]) -> dict[str, Any]:
        """Generate embeddings from actigraphy data."""
        pass
```

## Implementation Variations

The current implementation of the PAT Service demonstrates several architectural patterns:

### Mock Implementation

A `MockPATService` implementation is provided directly in the routes file for development and testing:

```python
class MockPATService(IPATService):
    """Mock service for PAT analysis during development."""
    
    async def analyze_actigraphy(self, data: dict[str, Any]) -> dict[str, Any]:
        """Return mock analysis results for actigraphy data."""
        return {
            "analysis_id": str(uuid.uuid4()),
            "patient_id": data.get("patient_id", ""),
            "timestamp": datetime.now().isoformat(),
            "analysis_types": data.get("analysis_types", []),
            "results": {
                "sleep_quality": "good",
                "activity_level": "moderate",
                "circadian_rhythm": "normal",
                "risk_factors": [],
                "confidence": 0.85
            }
        }
    
    async def get_embeddings(self, data: dict[str, Any]) -> dict[str, Any]:
        """Return mock embeddings for actigraphy data."""
        return {
            "patient_id": data.get("patient_id", ""),
            "timestamp": datetime.now().isoformat(),
            "embeddings": [random.random() for _ in range(128)],
            "metadata": {
                "model_version": "mock-1.0",
                "dimensions": 128
            }
        }
```

### API Endpoints

The PAT Service is exposed through FastAPI endpoints in the actigraphy routes:

```python
@router.post(
    "/analyze", 
    response_model=AnalyzeActigraphyResponse,
    summary="Analyze actigraphy data"
)
async def analyze_actigraphy(
    data: ActigraphyAnalysisRequest,
    pat_service: IPATService = Depends(get_pat_service)
) -> AnalyzeActigraphyResponse:
    """
    Analyze actigraphy data to extract relevant features and patterns.
    
    This endpoint processes raw movement data to identify:
    - Sleep quality metrics
    - Activity level patterns
    - Circadian rhythm analysis
    - Psychiatric symptom indicators
    
    The analysis results can be used to inform clinical decision-making
    and contribute to the patient's digital twin model.
    """
    result = await pat_service.analyze_actigraphy(data.dict())
    return AnalyzeActigraphyResponse(**result)
```

## HIPAA Compliance 

The PAT Service implements HIPAA compliance measures to protect Protected Health Information (PHI):

1. **PHI Minimization**: Service interfaces are designed to operate with anonymized patient identifiers
2. **Secure Data Handling**: All PHI is properly encrypted in transit and at rest
3. **Audit Logging**: PAT service operations involving PHI are logged for compliance
4. **Access Control**: Service access is controlled through dependency injection and authentication
5. **Error Sanitization**: Error handling prevents leakage of PHI in error messages

```python
# Example of HIPAA-compliant PAT service call with audit logging
async def analyze_with_audit(
    patient_id: str,
    data: dict[str, Any],
    user_id: str,
    pat_service: PATInterface,
    audit_logger: IAuditLogger
) -> dict[str, Any]:
    """Analyze actigraphy data with proper HIPAA audit logging."""
    
    # Log PHI access before analysis
    await audit_logger.log_phi_access(
        user_id=user_id,
        resource_type="actigraphy_data",
        resource_id=patient_id,
        action="analyze",
        reason="Clinical assessment"
    )
    
    # Perform analysis
    result = await pat_service.analyze_actigraphy(
        patient_id=patient_id,
        readings=data.get("readings", []),
        analysis_types=data.get("analysis_types", [])
    )
    
    return result
```

## Clinical Applications

The PAT Service supports various clinical applications through specialized analysis types:

1. **Mood Disorder Assessment**: Identifies patterns associated with depression and bipolar disorder
2. **Sleep Analysis**: Quantifies sleep quality, duration, and disturbances
3. **Treatment Response**: Tracks changes in activity patterns in response to interventions
4. **Relapse Prediction**: Identifies early warning signs of symptom recurrence
5. **Digital Phenotyping**: Characterizes behavioral signatures of psychiatric conditions

## Integration with Digital Twin

The PAT Service integrates with the Digital Twin system to:

1. **Update Twin State**: Provide behavioral state information to the digital twin
2. **Generate Predictions**: Inform predictive models about expected behavioral trajectories
3. **Treatment Planning**: Support intervention planning based on behavioral patterns
4. **Risk Assessment**: Contribute to composite risk models that include behavioral data

## Architectural Refinement Opportunities

The current PAT Service implementation presents several opportunities for architectural improvement:

1. **Interface Consolidation**: Unify the dual interfaces (PATInterface and IPATService) into a single core interface
2. **Implementation Separation**: Move the mock implementation to a dedicated test module
3. **Factory Implementation**: Create a proper factory for PAT service implementations
4. **Dependency Injection**: Enhance dependency injection for the PAT service
5. **Domain Model Integration**: Create domain-specific models for actigraphy data

## Implementation Roadmap

To address the architectural refinement opportunities, the following implementation roadmap is proposed:

1. **Phase 1: Interface Consolidation**
   - Migrate to a unified interface in the core layer
   - Update dependency injection to use the consolidated interface
   - Ensure consistent method signatures across all implementations

2. **Phase 2: Clean Architecture Alignment**
   - Move mock implementations to dedicated test modules
   - Implement a factory pattern for service creation
   - Create proper domain models for actigraphy data

3. **Phase 3: Enhanced Capabilities**
   - Implement advanced machine learning models for psychiatric insight
   - Add specialized analysis types for different conditions
   - Create comprehensive domain events for integration with other components

By following this implementation roadmap, the PAT Service will achieve alignment with clean architecture principles while enhancing its psychiatric assessment capabilities for the digital twin platform.
