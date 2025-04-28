# Physical Activity Tracking (PAT) Service

The PAT service is a HIPAA-compliant machine learning service that processes actigraphy data to provide physical activity insights, movement analysis, and digital twin integration for the Concierge Psychiatry Platform.

## Architecture

This service follows Clean Architecture principles with strict layering:

1. **Domain Layer**: Interfaces and domain models
2. **Infrastructure Layer**: Implementations of the interfaces
3. **Presentation Layer**: API routes and schemas

## Components

### Core Service

- `interface.py` - Defines the `PATInterface` and domain types
- `exceptions.py` - Custom exceptions for the PAT service
- `factory.py` - Factory for creating PAT service instances
- `mock.py` - Mock implementation for development/testing

### API

- `app/api/schemas/actigraphy.py` - Pydantic schemas for request/response
- `app/api/routes/actigraphy.py` - FastAPI routes for actigraphy endpoints

## Features

The PAT service provides the following capabilities:

1. **Activity Level Analysis**: Measures sedentary, light, moderate, and vigorous activity
2. **Sleep Analysis**: Analyzes sleep patterns, stages, and quality
3. **Gait Analysis**: Evaluates walking patterns and stability
4. **Tremor Analysis**: Detects and characterizes tremors
5. **Embedding Generation**: Creates vector embeddings from actigraphy data
6. **Digital Twin Integration**: Updates digital twin models with physical activity insights

## Security & HIPAA Compliance

- All PHI is properly secured in transit and at rest
- No PHI is included in logs or metrics
- All endpoints require authentication and authorization
- Robust error handling to prevent data leakage

## Usage

The service is accessed through the API routes defined in `app/api/routes/actigraphy.py`:

- `POST /actigraphy/analyze` - Analyze raw actigraphy data
- `POST /actigraphy/embeddings` - Generate embeddings from actigraphy data
- `GET /actigraphy/analyses/{analysis_id}` - Retrieve a specific analysis
- `GET /actigraphy/patient/{patient_id}/analyses` - List analyses for a patient
- `GET /actigraphy/model-info` - Get information about the PAT model
- `POST /actigraphy/integrate-with-digital-twin` - Integrate analysis with digital twin

## Configuration

The PAT service can be configured through environment variables or a settings file:

```python
# Example configuration
PAT_SERVICE_TYPE="mock"  # or "aws" for production
PAT_MODEL_VERSION="1.0.0"
PAT_AWS_REGION="us-east-1"
PAT_ENDPOINT_URL="https://example.com/api/pat"
```

## Testing

Tests are organized as follows:

- `tests/unit/services/ml/pat/test_mock_pat.py` - Unit tests for mock implementation
- `tests/unit/api/routes/test_actigraphy_routes.py` - Unit tests for API routes
- `tests/integration/api/test_actigraphy_api_integration.py` - Integration tests

Run the tests with pytest:

```bash
pytest tests/unit/services/ml/pat
pytest tests/unit/api/routes/test_actigraphy_routes.py
pytest tests/integration/api/test_actigraphy_api_integration.py
```

## Future Enhancements

1. Implement AWS-based production service (SageMaker, Lambda)
2. Add real-time analysis capabilities
3. Implement caching for frequently accessed analyses
4. Create batch processing capabilities for large datasets
5. Enhance digital twin integration with more sophisticated models