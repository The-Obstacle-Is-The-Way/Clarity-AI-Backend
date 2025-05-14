# ML Integration Architecture

## Overview

The ML Integration Architecture forms the mathematical foundation for the Clarity AI Backend's revolutionary machine learning capabilities. Rather than a monolithic ML system, the architecture establishes a quantum-precise framework for integrating diverse psychiatric modeling algorithms into a unified digital twin representation. This document explains both the architectural vision and current implementation state of the ML integration system.

## Architectural Vision vs. Current Implementation

The ML Integration Architecture aspires to clean architecture principles with varying degrees of implementation maturity:

### Architectural Vision

1. **Interface-First Design**: Define all ML services through abstract interfaces in the core layer
2. **Provider Pattern**: Access models through providers that abstract infrastructure details
3. **Factory Pattern**: Handle model instantiation via factories to decouple configuration from usage
4. **Dependency Inversion**: Ensure business logic depends only on abstractions
5. **Clear Separation**: Keep domain logic isolated from ML infrastructure details

### Current Implementation Reality

1. **Inconsistent Interface Locations**: Interfaces exist in both core layer (`PATInterface`) and route files (`IPATService`)
2. **Partial Provider Implementation**: Some services use provider pattern, others use direct instantiation
3. **Incomplete Factory Adoption**: `AWSServiceFactory` shows proper implementation, but not consistent across all ML services
4. **Mixed Dependency Approach**: Some components follow dependency inversion, others have direct dependencies
5. **AWS-Specific Abstraction**: Advanced abstraction for AWS services, less consistent for other integrations

## Core Interfaces: Current Implementation

The ML system has multiple interface definitions with varying levels of abstraction and consistency. Below are the actual interfaces found in the codebase:

### PAT Interface in Core Layer

The `PATInterface` in `app/core/services/ml/pat/pat_interface.py` defines the comprehensive contract for the Pretrained Actigraphy Transformer service:

```python
class PATInterface(abc.ABC):
    """Interface for the PAT service."""
    
    @abc.abstractmethod
    def initialize(self, config: dict[str, Any]) -> None:
        """Initialize the service with configuration."""
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
    def get_model_info(self) -> dict[str, Any]:
        """Get information about the PAT model."""
        pass
```

### Parallel IPATService Interface in Routes

The codebase also defines a separate `IPATService` interface directly in the routes layer (`app/presentation/api/v1/routes/actigraphy.py`), which represents an architectural violation but is currently used by route handlers:

```python
class IPATService(Protocol):
    """Interface for PAT service used by routes."""
    
    def analyze(
        self, 
        patient_id: str,
        readings: list, 
        start_time: str,
        end_time: str,
        sampling_rate_hz: float,
        device_info: dict,
    ) -> dict:
        """Analyze actigraphy data and return insights."""
        ...
```

### Interface Inconsistency Issues

The existence of parallel interfaces for the same functionality violates clean architecture principles and creates several practical problems:

1. **Method Signature Mismatch**: `PATInterface.analyze_actigraphy()` vs `IPATService.analyze()` with different parameter sets
2. **Type Hint Precision**: Core interface uses specific typing (`list[dict[str, Any]]`) while route interface uses generic types (`list`, `dict`)
3. **Dependency Confusion**: Implementations need to adapt between different interface contracts
4. **Architectural Violation**: Presentation layer (routes) should not define interfaces, only consume from core

## Concrete Implementations

### BedrockPAT Implementation

The `BedrockPAT` class in `app/core/services/ml/pat/bedrock.py` provides a concrete implementation of the PAT interface that leverages AWS Bedrock for inference:

```python
class BedrockPAT(PATInterface):
    """AWS Bedrock implementation of the PAT service."""
    
    def __init__(self, aws_credentials: dict, region_name: str, model_id: str):
        self.aws_credentials = aws_credentials
        self.region_name = region_name
        self.model_id = model_id
        self.bedrock_client = None
        self.initialized = False
    
    def initialize(self, config: dict[str, Any]) -> None:
        # Initialize Bedrock client with AWS credentials
        self.bedrock_client = boto3.client(
            'bedrock-runtime',
            aws_access_key_id=self.aws_credentials.get('access_key'),
            aws_secret_access_key=self.aws_credentials.get('secret_key'),
            region_name=self.region_name
        )
        self.initialized = True
```

### Mock Implementation in Production Code

The current codebase contains a `MockPATService` directly in the routes module, which violates clean architecture principles by placing test code in production paths:

```python
class MockPATService(IPATService):
    """Mock implementation of the PAT service for testing."""
    
    def analyze(self, patient_id: str, readings: list, **kwargs) -> dict:
        """Return mock analysis results."""
        return {
            "patient_id": patient_id,
            "analysis_date": datetime.now().isoformat(),
            "sleep_quality": "good",
            "activity_level": "moderate",
            "circadian_rhythm": "normal"
        }
```

## Factory Pattern Implementation

The `AWSServiceFactory` demonstrates the factory pattern for creating ML service instances, but is not consistently used across the codebase:

```python
class AWSServiceFactory:
    """Factory for creating AWS-based ML service instances."""
    
    @staticmethod
    def create_pat_service(config: dict) -> PATInterface:
        """Create a PAT service instance."""
        aws_credentials = {
            "access_key": config.get("AWS_ACCESS_KEY_ID"),
            "secret_key": config.get("AWS_SECRET_ACCESS_KEY")
        }
        region = config.get("AWS_REGION", "us-west-2")
        model_id = config.get("PAT_MODEL_ID")
        
        pat_service = BedrockPAT(aws_credentials, region, model_id)
        pat_service.initialize(config)
        return pat_service
```

## Architectural Recommendations

To align the ML Integration Architecture with clean architecture principles, the following improvements are recommended:

1. **Consolidate Interfaces**:
   - Move all interface definitions to the core layer
   - Standardize on a single `IPAT` interface with consistent method signatures
   - Remove the route-level `IPATService` definition

2. **Proper Dependency Injection**:
   - Update dependency providers to inject interface abstractions
   - Remove direct instantiation of services in route handlers

3. **Separate Test Implementations**:
   - Move all mock implementations to the test directory
   - Create proper test doubles that implement the core interfaces

4. **Consistent Factory Usage**:
   - Extend the factory pattern to all ML services
   - Use dependency injection to provide factories to service consumers

5. **Type Consistency**:
   - Use precise type hints consistently across interfaces and implementations
   - Define domain-specific types for data structures (e.g., `ActigraphyReading`)

These changes would establish a mathematically pure architecture where business logic depends only on abstractions and infrastructure concerns remain properly isolated.

## Implementation Strategy

Transforming the current ML integration architecture into the vision requires a systematic approach:

### Phase 1: Interface Consolidation

1. Create a unified interface in the core layer (`app/core/interfaces/services/ml`)
2. Migrate existing implementations to implement the new interface
3. Update dependency providers to use the new interface
4. Remove the redundant interfaces from routes

### Phase 2: Clean Architecture Compliance

1. Create dedicated mock implementations in the test directory
2. Refactor route handlers to use dependency injection
3. Update service factory implementations for consistent usage
4. Remove direct instantiation of services in routes

### Phase 3: Advanced Integration Patterns

1. Implement adapter pattern for ML service responses
2. Add domain-specific value objects for input/output data
3. Enhance error handling and validation
4. Implement proper telemetry and monitoring

## Implementation Priority

The following ML services should be addressed in order of priority:

1. **PAT Service**: Highest priority due to its central role in psychiatric analysis
2. **Embeddings Service**: Critical for digital twin representation
3. **Mood Analysis Service**: Important for symptom tracking
4. **Intervention Recommendation Service**: Necessary for treatment planning

By systematically implementing these changes, the Clarity AI Backend will achieve a pristine ML integration architecture that maintains mathematical purity, clear separation of concerns, and precise dependency direction - creating a quantum-level foundation for psychiatric digital twin modeling.

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
3. **Queuing**: Requests can be queued for later processing during service outages

## Implementation Roadmap

The implementation roadmap for ML architecture refinement includes specific tangible tasks to address the current architectural gaps:

### Phase 1: Core Interface Consolidation (Next 2 Weeks)

1. **Day 1-3: Interface Audit**
   - Identify all ML interfaces across the codebase
   - Document inconsistencies and architectural violations
   - Create detailed refactoring plan

2. **Day 4-7: Interface Migration**
   - Create unified interfaces in `app/core/interfaces/services/ml/`
   - Define consistent method signatures and parameter types
   - Create domain-specific value objects for ML data

3. **Day 8-10: Dependency Provider Updates**
   - Refactor dependency providers to use consolidated interfaces
   - Update factory implementations for consistent instantiation
   - Fix type annotations throughout dependency chain

### Phase 2: Architectural Boundary Enforcement (Week 3-4)

1. **Day 1-3: Mock Implementation Migration**
   - Move all mock implementations to `app/tests/mocks/services/ml/`
   - Create proper test doubles with complete interface implementations
   - Update tests to use dedicated mock implementations

2. **Day 4-7: Factory Pattern Standardization**
   - Implement consistent factory pattern for all ML services
   - Centralize configuration in factory methods
   - Add proper error handling and validation

3. **Day 8-10: Route Handler Refactoring**
   - Update all route handlers to use dependency injection
   - Remove direct instantiation of services
   - Add proper validation and error handling

### Phase 3: HIPAA Compliance Enhancement (Week 5-6)

1. **Day 1-3: PHI Protection**
   - Enhance PHI detection and sanitization
   - Add audit logging for all potential PHI access
   - Implement secure error handling to prevent PHI leakage

2. **Day 4-7: Security Hardening**
   - Secure API key management for ML providers
   - Implement proper authentication for ML services
   - Add authorization checks for ML service access

3. **Day 8-10: Quality and Monitoring**
   - Add telemetry for ML service performance
   - Implement health checks and circuit breakers
   - Add comprehensive logging for debugging and audit

## Future Enhancements

Looking beyond the initial refinement, several advanced capabilities are planned:

1. **Federated Learning Support**: Enable privacy-preserving model training across institutions
2. **Model Versioning**: Track and manage ML model versions with automatic compatibility checks
3. **Explainable AI**: Add support for model interpretation and explanation generation
4. **Continuous Learning**: Implement feedback loops for model improvement over time
5. **Multi-modal Fusion**: Combine insights from different data modalities (text, biometrics, imaging)

## Conclusion

The ML Integration Architecture provides a powerful foundation for the Clarity AI Backend's psychiatric analysis capabilities. By systematically addressing the current architectural gaps according to the implementation roadmap, the system will achieve a pristine clean architecture implementation while enhancing its machine learning capabilities for psychiatric digital twin modeling. This refined architecture will ensure HIPAA compliance, maintainability, and mathematical precision in all ML operations.
