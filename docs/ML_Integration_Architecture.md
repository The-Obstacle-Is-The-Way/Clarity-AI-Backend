# ML Integration Architecture

## Overview

The ML Integration Architecture is the foundation of the Clarity AI Backend's machine learning capabilities, providing a unified framework for integrating diverse ML models into the psychiatric digital twin platform. The architecture enables seamless integration of multiple model types, from depression detection to PHI identification, while maintaining clean architecture principles and ensuring HIPAA compliance.

## Architectural Principles

The ML Integration Architecture strictly adheres to clean architecture principles:

1. **Interface-First Design**: All ML services are defined through abstract interfaces, enabling multiple implementations
2. **Provider Pattern**: ML models are accessed through provider implementations that abstract infrastructure details
3. **Factory Pattern**: Model instantiation is handled by factories to decouple configuration from usage
4. **Dependency Inversion**: Business logic depends on abstractions, not concrete implementations
5. **Clear Separation**: Domain logic remains isolated from the specifics of ML infrastructure

## Core Interfaces

### Base ML Interface

The `BaseMLInterface` defines the foundational contract for all ML services:

```python
class BaseMLInterface(ABC):
    """Base interface for all ML services."""
    
    @abstractmethod
    def initialize(self, config: dict[str, Any]) -> None:
        """
        Initialize the service with configuration.
        
        Args:
            config: Configuration dictionary
            
        Raises:
            InvalidConfigurationError: If configuration is invalid
        """
        pass
    
    @abstractmethod
    def is_healthy(self) -> bool:
        """
        Check if the service is healthy.
        
        Returns:
            True if healthy, False otherwise
        """
        pass
    
    @abstractmethod
    def shutdown(self) -> None:
        """Shutdown the service and release resources."""
        pass
```

### Specialized ML Interfaces

The architecture provides specialized interfaces for different ML capabilities:

#### MentaLLaMA Interface

```python
class MentaLLaMAInterface(BaseMLInterface):
    """Interface for MentaLLaMA ML services."""
    
    @abstractmethod
    def process(
        self, 
        text: str,
        model_type: str | None = None,
        options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Process text using the MentaLLaMA model."""
        pass
    
    @abstractmethod
    def detect_depression(
        self, 
        text: str,
        options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Detect depression signals in text."""
        pass
```

#### PHI Detection Interface

```python
class PHIDetectionInterface(BaseMLInterface):
    """Interface for PHI detection services."""

    @abstractmethod
    def detect_phi(self, text: str) -> list[dict[str, Any]]:
        """Detect potential PHI entities in the given text."""
        pass
    
    @abstractmethod
    def sanitize_text(self, text: str, replacement_strategy: str = "redact") -> str:
        """Sanitize text by removing or replacing detected PHI."""
        pass
```

#### Digital Twin Interface

```python
class DigitalTwinInterface(BaseMLInterface):
    """Interface for Digital Twin services."""
    
    @abstractmethod
    def create_digital_twin(self, patient_id: str, initial_data: dict[str, Any]) -> dict[str, Any]:
        """Create a new digital twin for a patient."""
        pass
    
    @abstractmethod
    def get_twin_status(self, twin_id: str) -> dict[str, Any]:
        """Get the current status of a digital twin."""
        pass
    
    @abstractmethod
    def update_twin_data(self, twin_id: str, data: dict[str, Any]) -> dict[str, Any]:
        """Update the data associated with a digital twin."""
        pass
    
    @abstractmethod
    def get_insights(self, twin_id: str, insight_types: list[str]) -> dict[str, Any]:
        """Generate insights from the digital twin's data."""
        pass
    
    @abstractmethod
    def interact(self, twin_id: str, query: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        """Interact with the digital twin, potentially asking questions or running simulations."""
        pass
```

#### PAT Interface

The Psychiatric Analysis Tool (PAT) interface handles specialized psychiatric assessments:

```python
class PATInterface(BaseMLInterface):
    """Interface for Psychiatric Analysis Tool services."""
    
    @abstractmethod
    def analyze_text(self, text: str, analysis_type: str) -> dict[str, Any]:
        """Analyze psychiatric text for specific indicators."""
        pass
    
    @abstractmethod
    def get_model_info(self) -> dict[str, Any]:
        """Get information about the available models."""
        pass
    
    @abstractmethod
    def validate_analysis(self, analysis_result: dict[str, Any]) -> bool:
        """Validate analysis results for quality and reliability."""
        pass
```

## ML Providers

The ML architecture implements multiple providers (concrete implementations of the interfaces):

### AWS Bedrock Provider

```python
class AWSBedrockProvider(BaseMLInterface):
    """Provider implementation for AWS Bedrock ML services."""
    
    def initialize(self, config: dict[str, Any]) -> None:
        """Initialize connection to AWS Bedrock."""
        pass
    
    def is_healthy(self) -> bool:
        """Check connection to AWS Bedrock."""
        pass
    
    def shutdown(self) -> None:
        """Release AWS Bedrock resources."""
        pass
```

### OpenAI Provider

```python
class OpenAIProvider(BaseMLInterface):
    """Provider implementation for OpenAI services."""
    
    def initialize(self, config: dict[str, Any]) -> None:
        """Initialize connection to OpenAI API."""
        pass
    
    def is_healthy(self) -> bool:
        """Check connection to OpenAI API."""
        pass
    
    def shutdown(self) -> None:
        """Release OpenAI resources."""
        pass
```

### Mock Providers

For testing and development, mock providers implement the interfaces with simulated responses:

```python
class MockMentaLLaMAProvider(MentaLLaMAInterface):
    """Mock implementation of MentaLLaMA interface for testing."""
    
    def process(self, text: str, model_type: str | None = None, options: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return simulated processing results."""
        pass
```

## Factory Pattern

ML services are instantiated through factories to centralize configuration and enable dependency injection:

```python
class MLServiceFactory:
    """Factory for creating ML service instances."""
    
    @staticmethod
    def create_mentallama_service(config: dict[str, Any]) -> MentaLLaMAInterface:
        """Create MentaLLaMA service instance."""
        pass
    
    @staticmethod
    def create_phi_detection_service(config: dict[str, Any]) -> PHIDetectionInterface:
        """Create PHI detection service instance."""
        pass
    
    @staticmethod
    def create_digital_twin_service(config: dict[str, Any]) -> DigitalTwinInterface:
        """Create digital twin service instance."""
        pass
```

## Integration with Core Application

The ML services are integrated with the application through dependency providers that configure and instantiate service instances:

```python
# Example dependency provider in the presentation layer
def get_mentallama_service(settings: Settings = Depends(get_settings)) -> MentaLLaMAInterface:
    """Dependency provider for MentaLLaMA service."""
    config = {
        "provider": settings.ML_PROVIDER,
        "api_key": settings.ML_API_KEY,
        "model_id": settings.MENTALLAMA_MODEL_ID,
        # Other configuration parameters
    }
    return MLServiceFactory.create_mentallama_service(config)
```

## XGBoost Integration

The architecture includes specialized support for XGBoost models, particularly for predictive analytics in psychiatric assessment:

```python
class XGBoostInterface(BaseMLInterface):
    """Interface for XGBoost ML services."""
    
    @abstractmethod
    def predict(self, features: dict[str, Any]) -> dict[str, Any]:
        """Make predictions using XGBoost model."""
        pass
    
    @abstractmethod
    def batch_predict(self, features_batch: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Make batch predictions using XGBoost model."""
        pass
    
    @abstractmethod
    def get_feature_importance(self) -> dict[str, float]:
        """Get feature importance for the model."""
        pass
```

## HIPAA Compliance and Security

The ML Integration Architecture implements several security measures to ensure HIPAA compliance:

### PHI Protection

1. **Automatic Detection**: PHI detection services identify and flag sensitive information
2. **Sanitization**: Text sanitization removes PHI before it's sent to external ML services
3. **Local Processing**: When possible, PHI-containing data is processed locally rather than using external APIs

### Authentication and Authorization

1. **API Key Security**: ML provider API keys are securely stored and never exposed
2. **Service Authentication**: ML services authenticate with providers using secure mechanisms
3. **Access Control**: ML service access is restricted to authorized application components

### Audit Logging

1. **Usage Tracking**: All ML service usage is logged for compliance auditing
2. **PHI Access Logging**: Any potential PHI exposure is documented
3. **Error Logging**: ML service errors are logged without exposing sensitive information

## Asynchronous Processing

Many ML operations are computationally intensive and benefit from asynchronous processing:

```python
async def process_clinical_text(text: str, patient_id: str) -> dict[str, Any]:
    """Process clinical text asynchronously using multiple ML services."""
    # First, detect and sanitize PHI
    phi_service = get_phi_detection_service()
    sanitized_text = await phi_service.sanitize_text(text)
    
    # Then, process with MentaLLaMA
    mentallama_service = get_mentallama_service()
    analysis_result = await mentallama_service.process(sanitized_text)
    
    # Update digital twin with results
    twin_service = get_digital_twin_service()
    await twin_service.update_twin_data(patient_id, {"analysis": analysis_result})
    
    return analysis_result
```

## Fallback Mechanisms

The architecture implements fallback mechanisms to handle service disruptions:

1. **Provider Fallbacks**: If a primary ML provider is unavailable, the system can switch to alternatives
2. **Degraded Mode**: Critical application functions continue with reduced ML capabilities
3. **Cached Results**: Previous ML results may be used when new processing is unavailable

## Model Versioning

To ensure reproducibility and traceability, the architecture supports model versioning:

1. **Version Tracking**: All models are versioned and tracked
2. **Compatibility Checks**: Services verify model version compatibility
3. **Version-Specific Configurations**: Different model versions may have different configurations

## Future Extensibility

The ML Integration Architecture is designed for extensibility:

1. **New Providers**: Additional ML providers can be added with minimal code changes
2. **New Capabilities**: New ML interfaces can be defined for emerging capabilities
3. **Model Upgrades**: Models can be upgraded without disrupting application functionality

## Related Components

- **ML API Routes**: REST endpoints for accessing ML functionality
- **ML-Related Database Models**: Data structures for storing ML results
- **Configuration Services**: Services for managing ML configuration
- **ML Logging Services**: Specialized logging for ML operations
