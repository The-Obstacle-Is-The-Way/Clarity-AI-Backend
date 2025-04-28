# XGBoost Service Module

This module provides a comprehensive solution for machine learning capabilities in the Concierge Psychiatry Platform using XGBoost models. It is designed to support psychiatric risk assessment, treatment response prediction, and clinical outcome forecasting.

## Refactoring Information

This directory has been refactored to resolve issues with multiple parallel implementations of the same service that were causing test failures and maintenance problems. The refactoring follows Robert C. Martin's clean architecture principles, SOLID design patterns, and ensures HIPAA compliance throughout.

### Implementation Structure

The refactored codebase follows this structure:

* `aws_service.py` - Definitive implementation of the XGBoost service with AWS integration
* `factory.py` - Primary factory for creating service instances
* `aws_compatibility.py` - Compatibility layer for legacy code transitions
* `interface.py` - Core interface defining the contract for all implementations
* `exceptions.py` - Centralized exception definitions
* `enums.py` - Enumeration values used by the service
* `mock.py` - Mock implementation for testing
* `__init__.py` - Module exports and configuration helpers

## Architecture

The XGBoost service follows Clean Architecture principles and incorporates several design patterns:

- **Strategy Pattern**: Multiple implementations of the same interface (AWS, Mock)
- **Observer Pattern**: Notification system for events like predictions and errors
- **Factory Pattern**: Creation of service instances based on configuration
- **Bridge Pattern**: Compatibility layer for transitions from legacy implementations

## Features

- **Risk Prediction**: Predict relapse, suicide, or hospitalization risk
- **Treatment Response**: Predict response to medications or therapy
- **Outcome Prediction**: Forecast symptom, functional, or quality of life outcomes
- **Feature Importance**: Explain which factors influenced predictions
- **Digital Twin Integration**: Integrate predictions with neurological digital twin models
- **Model Information**: Retrieve model metadata, performance metrics, and features

## HIPAA Compliance

The module implements comprehensive HIPAA safeguards:

- PHI detection to prevent sensitive data in requests
- Anonymized logging without PHI
- Configurable privacy levels
- Token-based authentication requirements
- Role-based access control
- Data encrypted at rest (DynamoDB TTL for data retention)
- Comprehensive audit logging
- PHI detection and sanitization
- Proper error handling that prevents PHI leakage

## Usage Examples 

### Factory Pattern Usage

1. New code should use the primary factory:
   ```python
   from app.core.services.ml.xgboost.factory import create_xgboost_service
   
   # Create service instance
   xgboost_service = create_xgboost_service()
   ```

2. For FastAPI dependency injection:
   ```python
   from app.core.services.ml.xgboost.factory import get_xgboost_service
   from fastapi import Depends
   
   @app.get("/predictions")
   async def get_predictions(
       xgboost_service: XGBoostInterface = Depends(get_xgboost_service)
   ):
       # Use the service
       pass
   ```

### Creating and Initializing the Service

```python
from app.core.services.ml.xgboost import create_xgboost_service, get_xgboost_service

# Create from environment variables (recommended for production)
service = get_xgboost_service()

# Or create with explicit configuration
service = create_xgboost_service("aws")
service.initialize({
    "region_name": "us-east-1",
    "endpoint_prefix": "xgboost-prod",
    "bucket_name": "novamind-ml-models",
    "privacy_level": PrivacyLevel.ENHANCED
})
```

### Predicting Risk

```python
result = service.predict_risk(
    patient_id="P12345",
    risk_type="relapse",
    clinical_data={
        "symptom_severity": 7,
        "medication_adherence": 0.8,
        "previous_episodes": 2,
        "social_support": 5,
        "stress_level": 6
    },
    time_frame_days=30
)

print(f"Risk level: {result['risk_level']}")
print(f"Prediction score: {result['prediction_score']}")
print(f"Confidence: {result['confidence']}")
```

### Predicting Treatment Response

```python
result = service.predict_treatment_response(
    patient_id="P12345",
    treatment_type="medication_ssri",
    treatment_details={
        "medication": "Fluoxetine",
        "dosage": "20mg",
        "frequency": "daily",
        "duration_weeks": 8
    },
    clinical_data={
        "symptom_severity": 7,
        "medication_adherence": 0.8,
        "previous_episodes": 2
    }
)

print(f"Response probability: {result['response_probability']}")
print(f"Expected time to response: {result['time_to_response_weeks']} weeks")
```

### Using the Observer Pattern

```python
class PredictionLogger(Observer):
    def update(self, event_type: EventType, data: Dict[str, Any]) -> None:
        if event_type == EventType.PREDICTION:
            print(f"New prediction: {data['prediction_type']} for {data['patient_id']}")

# Register the observer
observer = PredictionLogger()
service.register_observer(EventType.PREDICTION, observer)

# Make predictions as usual - observer will be notified
```

## Configuration Options

### Environment Variables

The service can be configured using environment variables:

- `XGBOOST_IMPLEMENTATION`: Service implementation to use (aws, mock)
- `XGBOOST_LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR)
- `XGBOOST_PRIVACY_LEVEL`: PHI detection level (STANDARD, ENHANCED, MAXIMUM)

AWS-specific settings:
- `XGBOOST_AWS_REGION`: AWS region
- `XGBOOST_AWS_ENDPOINT_PREFIX`: Prefix for SageMaker endpoints
- `XGBOOST_AWS_BUCKET`: S3 bucket name
- `XGBOOST_AWS_MODEL_*`: Model type to SageMaker model name mappings

Mock-specific settings:
- `XGBOOST_MOCK_DELAY_MS`: Delay in milliseconds to simulate network latency

### Programmatic Configuration

When initializing the service directly:

```python
config = {
    "log_level": "INFO",
    "privacy_level": PrivacyLevel.STANDARD,
    
    # AWS-specific configuration
    "region_name": "us-east-1",
    "endpoint_prefix": "xgboost-prod",
    "bucket_name": "novamind-ml-models",
    "model_mappings": {
        "risk-relapse": "relapse-risk-model-v2",
        "risk-suicide": "suicide-risk-model-v1",
        # ... other model mappings
    }
}

service.initialize(config)
```

## Error Handling

The service uses a comprehensive hierarchy of domain-specific exceptions:

- `XGBoostServiceError`: Base exception class
  - `ValidationError`: Invalid parameters
  - `DataPrivacyError`: PHI detected in data
  - `ResourceNotFoundError`: Resource not found
    - `ModelNotFoundError`: Model not found
  - `PredictionError`: Error during prediction
  - `ServiceConnectionError`: Error connecting to service
  - `ConfigurationError`: Invalid configuration

Example error handling:

```python
try:
    result = service.predict_risk(...)
except ValidationError as e:
    print(f"Invalid parameters: {e}")
except DataPrivacyError as e:
    print(f"PHI detected: {e.pattern_types}")
except ModelNotFoundError as e:
    print(f"Model not found: {e.model_type}")
except ServiceConnectionError as e:
    print(f"Service connection error: {e.service} - {e.error_type}")
except XGBoostServiceError as e:
    print(f"General error: {e}")
```

## Testing

The service includes comprehensive testing utilities:

- `MockXGBoostService`: Full mock implementation for testing
- Unit tests for all components
- Integration tests using AWS SDK mocks

## Integration with FastAPI

The service is designed to be easily integrated with FastAPI endpoints using dependency injection:

```python
from fastapi import Depends
from app.core.services.ml.xgboost import XGBoostInterface, get_xgboost_service

@router.post("/risk/{risk_type}")
async def predict_risk(
    risk_type: str,
    request: RiskPredictionRequest,
    xgboost_service: XGBoostInterface = Depends(get_xgboost_service)
):
    result = xgboost_service.predict_risk(
        patient_id=request.patient_id,
        risk_type=risk_type,
        clinical_data=request.clinical_data
    )
    return RiskPredictionResponse(**result)