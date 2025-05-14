# Digital Twin API Routes

## Overview

The Digital Twin API Routes constitute a core component of the Clarity AI Backend, providing the interface for accessing and interacting with psychiatric digital twin models. These routes enable clinicians and authorized users to access patient-specific digital representations, retrieve status information, generate personalized insights, and analyze clinical text through advanced ML models.

## Implementation Status

> ⚠️ **IMPORTANT**: There are several implementation gaps between the documented API and the actual codebase:

| Component | Documentation Status | Implementation Status | Notes |
|-----------|---------------------|----------------------|-------|
| DigitalTwinServiceInterface | ✅ Documented | ✅ Defined | Complete interface in app/core/interfaces/services/digital_twin_service_interface.py |
| API Routes | ✅ Documented | ✅ Implemented | All documented endpoints exist in app/presentation/api/v1/routes/digital_twin.py |
| Service Implementation | ✅ Documented | ⚠️ Partially Implemented | Uses DigitalTwinIntegrationService but not fully implementing the interface |
| MentaLLaMA Integration | ✅ Documented | ⚠️ Mock Implementation | Using MockMentaLLaMAService instead of actual implementation |
| Schema Validation | ✅ Documented | ⚠️ Partially Implemented | Using Dict[str, Any] types instead of proper Pydantic models in some responses |

### Current Implementation Gaps

1. **Missing Interface Implementation**: No class properly implements the complete DigitalTwinServiceInterface
2. **Mock ML Services**: Using mock implementations instead of actual ML models
3. **Loose Schema Validation**: API routes use Dict[str, Any] for response models instead of strict Pydantic schemas
4. **Missing Tests**: Insufficient test coverage for the Digital Twin API functionality

## Clean Architecture Context

The Digital Twin API adheres to clean architecture principles by:

1. **Separation of Concerns**: Routes handle HTTP interactions only, delegating business logic to services
2. **Dependency Injection**: Service dependencies are injected via FastAPI's dependency system
3. **Domain Boundaries**: Routes transform between HTTP layer and domain model
4. **Error Handling**: Structured exception handling pattern normalizes errors across the API

## Route Definition

The Digital Twin API routes are defined in `app/presentation/api/v1/routes/digital_twin.py`:

```python
"""
Digital Twin Endpoints Module.

Provides API endpoints for interacting with the user's digital twin.
"""

import logging
from typing import Optional, Dict, Any
from uuid import UUID
from datetime import datetime, timezone, timedelta
import copy

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.domain.entities.user import User
from app.core.exceptions.base_exceptions import ResourceNotFoundError, ModelExecutionError
from app.presentation.api.dependencies.auth import get_current_active_user

# Assuming schemas exist here, adjust if necessary
from app.presentation.api.schemas.digital_twin import (
    DigitalTwinResponse,
    DigitalTwinStatusResponse,
    ComponentStatus,
    PersonalizedInsightResponse,
    ClinicalTextAnalysisRequest,
    ClinicalTextAnalysisResponse
)
from app.presentation.api.v1.dependencies.digital_twin import DigitalTwinServiceDep

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/digital-twin", tags=["digital-twin"], dependencies=[Depends(get_current_active_user)]
)
```

## Available Endpoints

### 1. Retrieve Digital Twin

```python
@router.get(
    "/",
    response_model=DigitalTwinResponse,
    summary="Get the user's digital twin data",
)
async def get_digital_twin(
    dt_service: DigitalTwinServiceDep,
    current_user: User = Depends(get_current_active_user),
) -> DigitalTwinResponse:
    """
    Retrieve the digital twin representation for the currently authenticated user.
    """
```

**Implementation Notes:**
- ✅ Returns a properly validated DigitalTwinResponse
- ⚠️ The underlying service implementation is not complete
- ❌ May return mock data instead of actual patient digital twin

This endpoint retrieves the complete digital twin model for the authenticated user, containing the aggregated psychological, biometric, and behavioral data that constitutes their psychiatric digital twin.

**Authentication**: Requires authenticated user  
**Authorization**: Limited to the user's own digital twin  
**Response**: Complete `DigitalTwinResponse` data structure  
**Errors**:

- 404: Digital twin not found for user
- 500: Server error during retrieval

### 2. Digital Twin Status

```python
@router.get(
    "/{patient_id}/status",
    response_model=Dict[str, Any],  # Use Dict instead of DigitalTwinStatusResponse to avoid validation
    summary="Get the digital twin status for a patient",
)
async def get_twin_status(
    patient_id: UUID,
    dt_service: DigitalTwinServiceDep,
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """
    Retrieve the status of a patient's digital twin, showing which components are available.
    """
```

**Implementation Notes:**
- ⚠️ Returns Dict[str, Any] instead of validating against DigitalTwinStatusResponse
- ⚠️ Bypasses schema validation, potentially allowing inconsistent responses
- ❌ May return mock data instead of actual digital twin status

This endpoint checks the status and availability of different components within a patient's digital twin, allowing clinicians to understand which models and data are ready for analysis.

**Authentication**: Requires authenticated user  
**Authorization**: Requires appropriate clinical access to patient data  
**Parameters**: `patient_id` (UUID) - The patient's unique identifier  
**Response**: Status of each digital twin component (e.g., psychological model, biometric data)  
**Errors**:

- 404: Patient or digital twin not found
- 500: Server error during status check

### 3. Comprehensive Insights

```python
@router.get(
    "/{patient_id}/insights",
    response_model=Dict[str, Any],  # Use Dict instead of PersonalizedInsightResponse
    summary="Get comprehensive insights for a patient",
)
async def get_comprehensive_insights(
    patient_id: UUID,
    dt_service: DigitalTwinServiceDep,
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """
    Generate comprehensive personalized insights for a patient based on their digital twin.
    """
```

**Implementation Notes:**
- ⚠️ Returns Dict[str, Any] instead of validating against PersonalizedInsightResponse
- ⚠️ Bypasses schema validation, potentially allowing inconsistent responses
- ❌ Likely returns mock insights instead of ML-generated insights

This endpoint generates personalized insights for a patient by analyzing their digital twin data through advanced ML models, providing clinicians with actionable information for treatment planning.

**Authentication**: Requires authenticated user  
**Authorization**: Requires appropriate clinical access to patient data  
**Parameters**: `patient_id` (UUID) - The patient's unique identifier  
**Response**: Comprehensive insights derived from digital twin analysis  
**Errors**:

- 404: Patient or digital twin not found
- 500: Error during model execution or insight generation

### 4. Clinical Text Analysis

```python
@router.post(
    "/{patient_id}/analyze-text",
    response_model=Dict[str, Any],  # Use Dict instead of ClinicalTextAnalysisResponse
    summary="Analyze clinical text using the digital twin",
)
async def analyze_clinical_text(
    patient_id: UUID,
    request: ClinicalTextAnalysisRequest,
    dt_service: DigitalTwinServiceDep,
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    """
    Analyze clinical text using MentaLLaMA integration with the patient's digital twin.
    """
```

**Implementation Notes:**
- ✅ Properly validates input using ClinicalTextAnalysisRequest schema
- ⚠️ Returns Dict[str, Any] instead of validating against ClinicalTextAnalysisResponse
- ❓ Uses MockMentaLLaMAService instead of actual MentaLLaMA implementation

This endpoint processes and analyzes clinical text against a patient's digital twin using the MentaLLaMA model, providing context-aware insights based on the patient's specific psychological profile.

**Authentication**: Requires authenticated user  
**Authorization**: Requires appropriate clinical access to patient data  
**Parameters**:

- `patient_id` (UUID) - The patient's unique identifier
- `request` (ClinicalTextAnalysisRequest) - Contains text to analyze and analysis type  

**Response**: Analysis results contextualized with the patient's digital twin  
**Errors**:

- 404: Patient or digital twin not found
- 500: Model execution error or general server error

## Error Handling

The Digital Twin API implements structured error handling that:

1. Maps domain-specific exceptions to appropriate HTTP status codes
2. Sanitizes error messages for PHI/PII before returning them to clients
3. Logs detailed error information for troubleshooting
4. Preserves the original error type information for clients

```python
try:
    # Service call
except ResourceNotFoundError as e:
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Digital twin status not found: {str(e)}"
    )
except ModelExecutionError as e:
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=f"Model inference failed: {str(e)}"
    )
except Exception as e:
    logger.error(f"Error retrieving digital twin status: {str(e)}")
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=f"Failed to retrieve digital twin status: {str(e)}"
    )
```

## Security Considerations

The Digital Twin API implements several security measures to protect sensitive patient data:

1. **Authentication**: All endpoints require a valid authentication token
2. **Authorization**: Access is restricted to a patient's care team and the patient themselves
3. **PHI Protection**: Error messages are sanitized to prevent PHI leakage
4. **Audit Logging**: All access to digital twin data is logged for compliance

## Implementation Roadmap

To address the current implementation gaps:

1. **Complete Service Implementation**
   - Create a proper implementation of DigitalTwinServiceInterface
   - Ensure all methods required by the interface are implemented

2. **Schema Validation**
   - Update all routes to use proper Pydantic response models
   - Add comprehensive validation to ensure HIPAA compliance

3. **ML Integration**
   - Implement actual MentaLLaMA service instead of mock
   - Develop proper ML model integration for digital twin insights

4. **Testing**
   - Add comprehensive test suite for all Digital Twin API routes
   - Include tests for error handling and edge cases

## Response Schema Examples

While the API currently uses flexible dictionary responses, it defines structured schemas for future standardization:

- **DigitalTwinResponse**: Complete digital twin model with psychological, biometric, and behavioral components
- **DigitalTwinStatusResponse**: Status of each digital twin component and its data availability
- **PersonalizedInsightResponse**: Insights generated from the digital twin analysis
- **ClinicalTextAnalysisResponse**: Results from analyzing clinical text against the digital twin

## Related Components

- **DigitalTwinIntegrationService**: Main service that integrates multiple ML services
- **MockMentaLLaMAService**: Currently used instead of actual MentaLLaMA integration
- **Authentication Dependencies**: Ensure only authorized access to patient digital twins
