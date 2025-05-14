# Pretrained Actigraphy Transformer (PAT) Service

## Overview

The Pretrained Actigraphy Transformer (PAT) Service is a specialized machine learning component within the Clarity AI Backend that analyzes physical activity data (actigraphy) to derive psychiatric insights. This service represents a breakthrough approach in psychiatric assessment, using motion patterns captured by wearable devices to identify markers of mental health conditions, monitor treatment efficacy, and provide objective data for the digital twin.

## Clean Architecture Implementation

The PAT Service exemplifies clean architecture principles through:

1. **Interface Segregation**: The interface defines clear, cohesive methods without unnecessary dependencies
2. **Dependency Inversion**: Higher-level modules depend on the abstract interface, not concrete implementations
3. **Single Responsibility**: Each method has a specific, well-defined purpose
4. **Domain-Driven Design**: The interface represents a bounded context within psychiatric assessment

## Interface Definition

The PAT Service interface is defined in `app/core/services/ml/pat/pat_interface.py`:

```python
class PATInterface(abc.ABC):
    """Interface for the PAT service.

    This interface defines the contract that all PAT service implementations
    must follow, providing methods for analyzing actigraphy data, generating
    embeddings, and integrating with digital twin profiles.
    """

    @abc.abstractmethod
    def initialize(self, config: dict[str, Any]) -> None:
        """Initialize the PAT service with configuration."""
        pass

    @abc.abstractmethod
    def analyze_actigraphy(
        self,
        patient_id: str,
        readings: list[dict[str, Any]],
        start_time: str,
        end_time: str,
        sampling_rate_hz: float,
        device_info: dict[str, Any],
        analysis_types: list[str],
        **kwargs
    ) -> dict[str, Any]:
        """Analyze actigraphy data and return insights."""
        pass

    @abc.abstractmethod
    def get_actigraphy_embeddings(
        self,
        patient_id: str,
        readings: list[dict[str, Any]],
        start_time: str,
        end_time: str,
        sampling_rate_hz: float,
        **kwargs
    ) -> dict[str, Any]:
        """Generate embeddings from actigraphy data."""
        pass

    @abc.abstractmethod
    def get_model_info(self) -> dict[str, Any]:
        """Get information about the PAT model."""
        pass

    @abc.abstractmethod
    def detect_activity_patterns(
        self,
        patient_id: str,
        readings: list[dict[str, Any]],
        pattern_types: list[str],
        **kwargs
    ) -> dict[str, Any]:
        """Detect specific activity patterns in actigraphy data."""
        pass

    @abc.abstractmethod
    def compare_activity_periods(
        self,
        patient_id: str,
        period_a: dict[str, Any],
        period_b: dict[str, Any],
        metrics: list[str],
        **kwargs
    ) -> dict[str, Any]:
        """Compare two activity periods and identify changes."""
        pass

    @abc.abstractmethod
    def predict_indicators(
        self,
        patient_id: str,
        readings: list[dict[str, Any]],
        indicators: list[str],
        **kwargs
    ) -> dict[str, Any]:
        """Predict mental health indicators from actigraphy data."""
        pass
```

## Key Capabilities

### Actigraphy Analysis

The PAT Service processes raw accelerometer data from wearable devices to extract clinically relevant features:

```python
def analyze_actigraphy(
    self,
    patient_id: str,
    readings: list[dict[str, Any]],
    start_time: str,
    end_time: str,
    sampling_rate_hz: float,
    device_info: dict[str, Any],
    analysis_types: list[str],
    **kwargs
) -> dict[str, Any]:
```

This method transforms raw motion data into psychiatric insights such as:

- Sleep quality metrics
- Activity level patterns
- Diurnal variations
- Behavioral rhythms
- Movement characteristics
- Energy expenditure

### Embedding Generation

The service can generate vector embeddings from actigraphy data for use in downstream machine learning tasks:

```python
def get_actigraphy_embeddings(
    self,
    patient_id: str,
    readings: list[dict[str, Any]],
    start_time: str,
    end_time: str,
    sampling_rate_hz: float,
    **kwargs
) -> dict[str, Any]:
```

These embeddings represent a dimensional reduction of complex activity patterns, enabling:

- Similarity comparisons between patients
- Anomaly detection
- Longitudinal tracking
- Integration with other modalities in the digital twin

### Pattern Detection

The service can identify specific activity patterns that correlate with psychiatric states:

```python
def detect_activity_patterns(
    self,
    patient_id: str,
    readings: list[dict[str, Any]],
    pattern_types: list[str],
    **kwargs
) -> dict[str, Any]:
```

Pattern types may include:

- Psychomotor agitation
- Psychomotor retardation
- Circadian dysregulation
- Social withdrawal patterns
- Manic activation
- Depressive inactivity

### Indicator Prediction

The service can predict specific mental health indicators from actigraphy data:

```python
def predict_indicators(
    self,
    patient_id: str,
    readings: list[dict[str, Any]],
    indicators: list[str],
    **kwargs
) -> dict[str, Any]:
```

Examples of indicators include:

- Depression severity
- Anxiety levels
- Sleep disturbance
- Treatment response
- Relapse risk
- Overall functional status

## Service Implementations

### AWS Bedrock Implementation

The primary implementation uses AWS Bedrock for scalable, cloud-based processing:

```python
class BedrockPAT(PATInterface):
    """AWS Bedrock-based implementation of the PAT service."""
    
    def __init__(self):
        self._initialized = False
        self._bedrock_client = None
        self._analysis_model_id = None
        self._embedding_model_id = None
        self._config = None
```

Key features of this implementation:

- Serverless architecture for elastic scaling
- Managed infrastructure reducing operational overhead
- Pay-per-use pricing model
- Integration with AWS security features for HIPAA compliance

### Mock Implementation

A mock implementation is provided for testing and development:

```python
class MockPAT(PATInterface):
    """Mock implementation of the PAT service for testing."""
    
    def __init__(self):
        self._initialized = False
        self._config = None
        
    def initialize(self, config: dict[str, Any]) -> None:
        """Initialize the mock PAT service."""
        self._initialized = True
        self._config = config
```

This implementation returns deterministic, simulated results for unit testing and development without external dependencies.

## Integration with Digital Twin

The PAT Service is tightly integrated with the Digital Twin system, providing objective behavioral data that complements subjective psychiatric assessments:

```python
def integrate_with_digital_twin(
    self,
    patient_id: str,
    twin_id: str,
    actigraphy_results: dict[str, Any],
    integration_options: dict[str, Any],
    **kwargs
) -> dict[str, Any]:
```

This integration enables:

1. **Multimodal Analysis**: Combining activity data with other clinical measures
2. **Longitudinal Tracking**: Monitoring changes in activity patterns over time
3. **Treatment Response**: Objective measurement of intervention effects
4. **Relapse Prediction**: Early warning through activity pattern changes

## HIPAA Compliance

The PAT Service implements several measures to ensure HIPAA compliance:

1. **Data Anonymization**: Patient identifiers are separated from raw data
2. **Audit Logging**: All data access is logged for compliance tracking
3. **Encryption**: Data is encrypted both in transit and at rest
4. **Access Control**: Service access is restricted to authorized components

## Input Validation

To ensure data quality and reliability, the service implements comprehensive validation:

```python
def _validate_readings(self, readings: list[dict[str, Any]], sampling_rate_hz: float) -> bool:
    """
    Validate actigraphy readings format and quality.
    
    Args:
        readings: List of accelerometer readings
        sampling_rate_hz: Expected sampling rate
        
    Returns:
        True if valid, raises ValidationError otherwise
    """
```

Validation checks include:

- Data format correctness
- Temporal consistency
- Sampling rate verification
- Signal quality assessment
- Adherence to expected ranges

## Service Factory

The PAT Service is instantiated using a factory pattern:

```python
class PATFactory:
    """
    Factory for creating PAT service instances.
    
    This factory creates the appropriate PAT service implementation
    based on configuration, supporting dependency injection and
    proper separation of concerns.
    """
    
    @staticmethod
    def create_service(config: dict[str, Any]) -> PATInterface:
        """
        Create a PAT service instance.
        
        Args:
            config: Service configuration dictionary
            
        Returns:
            Initialized PAT service instance
            
        Raises:
            ValueError: If provider type is unknown
        """
        provider_type = config.get("provider_type", "mock")
        
        if provider_type == "bedrock":
            service = BedrockPAT()
        elif provider_type == "mock":
            service = MockPAT()
        else:
            raise ValueError(f"Unknown PAT provider type: {provider_type}")
        
        service.initialize(config)
        return service
```

## Error Handling

The service implements robust error handling to maintain system reliability:

```python
class AnalysisError(Exception):
    """Error during actigraphy analysis."""
    pass

class ValidationError(Exception):
    """Error validating actigraphy data."""
    pass

class InitializationError(Exception):
    """Error initializing PAT service."""
    pass

class EmbeddingError(Exception):
    """Error generating embeddings."""
    pass
```

These specialized exceptions enable precise error reporting and appropriate handling at higher levels.

## Dependency Injection

The PAT Service is integrated into the application through FastAPI's dependency injection system:

```python
def get_pat_service(
    settings: Settings = Depends(get_settings),
) -> PATInterface:
    """
    Dependency provider for PAT service.
    
    Returns:
        Initialized PAT service instance
    """
    config = {
        "provider_type": settings.PAT_PROVIDER_TYPE,
        "aws_region": settings.AWS_REGION,
        "analysis_model_id": settings.PAT_ANALYSIS_MODEL_ID,
        "embedding_model_id": settings.PAT_EMBEDDING_MODEL_ID,
        # Other configuration parameters
    }
    
    return PATFactory.create_service(config)
```

## Scientific Background

The PAT Service is based on established research showing that physical activity patterns correlate with psychiatric states:

1. **Psychomotor Changes**: Depression and bipolar disorder manifest in altered movement patterns
2. **Circadian Rhythms**: Disruptions in daily activity cycles correlate with mood disorders
3. **Sleep Architecture**: Activity during sleep periods indicates sleep quality issues
4. **Social Rhythms**: Changes in regular activity patterns often precede psychiatric decompensation

## Related Components

- **Actigraphy Data Collection**: Subsystem for gathering raw activity data
- **Digital Twin Integration**: Services that incorporate PAT outputs into the digital twin
- **Longitudinal Analysis**: Components for tracking changes over time
- **Alert Generation**: Systems that create clinician alerts based on significant pattern changes
