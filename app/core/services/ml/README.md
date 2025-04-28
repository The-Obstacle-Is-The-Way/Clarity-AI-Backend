# MentaLLaMA: HIPAA-Compliant Mental Health AI

MentaLLaMA is a comprehensive, HIPAA-compliant mental health AI framework designed for luxury concierge psychiatry practices. This service provides clinical-grade AI capabilities while maintaining the highest standards of data security, privacy, and compliance.

## Overview

MentaLLaMA combines state-of-the-art foundation models with clinical expertise to offer sophisticated mental health analyses while maintaining strict HIPAA compliance. The implementation is provider-agnostic, supporting multiple backend AI services including AWS Bedrock, OpenAI, and Anthropic.

Key features:
- Depression detection and severity assessment
- Clinical risk assessment
- Sentiment and emotional analysis
- Wellness dimension evaluation
- PHI (Protected Health Information) detection and redaction
- Digital Patient Twin simulation

## Architecture

MentaLLaMA follows Clean Architecture principles with clear separation of concerns:

1. **Interface Layer**: Defines abstract interfaces for all ML services
2. **Base Implementation**: Provides common functionality shared across providers
3. **Provider-Specific Implementations**: Concrete implementations for each supported AI provider
4. **Factory**: Creates appropriate service instances based on configuration

### Design Patterns

- **Strategy Pattern**: Allows interchangeable AI providers without altering client code
- **Factory Method Pattern**: Centralized creation of service instances
- **Template Method Pattern**: Common workflow with provider-specific steps
- **Adapter Pattern**: Uniform interface over diverse AI provider APIs

## Components

### Core Interfaces

- `MentaLLaMAInterface`: Core interface for mental health assessments
- `PHIDetectionService`: Interface for PHI detection and redaction
- `DigitalTwinService`: Interface for digital patient twin operations

### Base Implementations

- `BaseMentaLLaMA`: Shared functionality for all MentaLLaMA implementations
  - Prompt engineering for specific clinical tasks
  - Caching and performance optimization
  - Error handling and recovery
  - PHI detection integration
  - Structured response parsing

### Provider-Specific Implementations

- `BedrockMentaLLaMA`: AWS Bedrock implementation
- `OpenAIMentaLLaMA`: OpenAI API implementation
- `AnthropicMentaLLaMA`: Anthropic Claude implementation
- `InternalMentaLLaMA`: Self-hosted model implementation

### Factory

- `MLServiceFactory`: Creates service instances based on configuration

## Configuration

Configuration is handled through the `ml_settings.py` module, which uses Pydantic for validation and environment variable loading. Settings include:

- Service enablement flags
- Provider selection
- Model parameters
- Security and compliance settings
- Performance and caching options

Example `.env` configuration:
```
ML_ENABLE_MENTALLAMA=true
ML_MENTALLAMA__PROVIDER=aws-bedrock
ML_MENTALLAMA__DEFAULT_MODEL=mentallama-33b-lora
ML_MENTALLAMA__HIPAA_COMPLIANT=true
ML_AWS_BEDROCK__REGION=us-east-1
ML_AWS_BEDROCK__PROFILE=hipaa-compliant
```

## Usage

### Basic Usage

```python
from app.core.services.ml.factory import MLServiceFactory
from app.core.services.ml.interface import MentaLLaMAInterface

# Create service instance
config = {
    "provider": "aws-bedrock",
    "default_model": "mentallama-33b-lora",
    "hipaa_compliant": True,
    # Other configuration options
}
mentallama = MLServiceFactory.create_typed_service(
    service_type="mentalllama",
    service_interface=MentaLLaMAInterface,
    config=config
)

# Perform depression detection
result = mentallama.depression_detection(
    text="Patient reports feelings of sadness and hopelessness...",
    include_rationale=True,
    severity_assessment=True
)

# Access structured results
depression_indicated = result["structured_data"]["depression_indicated"]
severity = result["structured_data"]["severity"]
key_indicators = result["structured_data"]["key_indicators"]
```

### FastAPI Integration

Services are integrated with FastAPI through dependency injection:

```python
from fastapi import Depends

# In your router file
@router.post("/depression-detection")
async def detect_depression(
    request: DepressionDetectionRequest,
    mentallama_service: MentaLLaMAInterface = Depends(get_mentalllama_service),
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> DepressionDetectionResponse:
    # Implementation...
```

## HIPAA Compliance

MentaLLaMA has been designed with HIPAA compliance as a core requirement:

1. **PHI Detection**: Automatic detection of Protected Health Information
2. **Data Minimization**: Only necessary clinical information is processed
3. **Secure Providers**: Integration with HIPAA-eligible cloud providers (BAA in place)
4. **Access Controls**: All endpoints enforce authentication and authorization
5. **Audit Logging**: All operations are logged for compliance auditing
6. **No Data Retention**: Raw PHI is never stored by the service

## Digital Twin Capabilities

The Digital Twin service allows for creating virtual patient models that can be used for:

1. **Predictive Analysis**: Anticipate treatment outcomes
2. **Scenario Testing**: Evaluate potential interventions
3. **Personalization**: Tailor treatment plans to individual patients
4. **Risk Assessment**: Identify potential risks over time

## PHI Detection and Redaction

The PHI Detection service automatically identifies and redacts Protected Health Information:

```python
from app.core.services.ml.factory import MLServiceFactory
from app.core.services.ml.interface import PHIDetectionService

# Create service
phi_service = MLServiceFactory.create_typed_service(
    service_type="phi_detection",
    service_interface=PHIDetectionService,
    config=phi_config
)

# Detect PHI
detection_result = phi_service.detect_phi(
    text="Patient John Smith (DOB: 01/01/1980) reports...",
    categories=["NAME", "DATE", "PHONE", "ADDRESS"],
    sensitivity=0.8
)

# Redact PHI
redaction_result = phi_service.redact_phi(
    text="Patient John Smith (DOB: 01/01/1980) reports...",
    mode="category",  # Options: "token", "category", "custom"
    categories=["NAME", "DATE", "PHONE", "ADDRESS"],
    sensitivity=0.8
)
# Result: "Patient [NAME] (DOB: [DATE]) reports..."
```

## Testing

Comprehensive tests are provided:
- Unit tests for core functionality
- Integration tests for API endpoints
- Mock implementations for testing without external dependencies

## Next Steps

- Performance optimization for high-volume practices
- Multi-modal support (text + audio/video)
- Additional clinical assessment models
- Enhanced Digital Twin capabilities
- Support for additional provider-specific features