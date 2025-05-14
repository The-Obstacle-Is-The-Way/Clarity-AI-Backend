# Biometric Alert Rules API

## Overview

The Biometric Alert Rules API is a critical component of the Clarity AI Backend that enables the creation, management, and execution of automated alert rules based on patient biometric data. These rules form the foundation of the platform's proactive monitoring capabilities, allowing clinicians to define personalized thresholds for patient metrics and receive notifications when those thresholds are exceeded.

## Clean Architecture Context

The Biometric Alert Rules API exemplifies clean architecture principles through:

1. **Separation of Concerns**: API routes strictly handle HTTP interactions, domain logic resides in services
2. **Schema Validation**: Input/output validation via Pydantic models ensures data integrity
3. **Domain-Driven Design**: Rules are modeled as domain entities with strong encapsulation
4. **Repository Pattern**: Data access is abstracted through repositories, enabling multiple storage options

## Route Definition

The Biometric Alert Rules API routes are defined in `app/presentation/api/v1/routes/biometric_alert_rules.py`:

```python
"""
Biometric Alert Rules Endpoints Module.

Provides API endpoints for managing biometric alert rules.
"""

import logging
import uuid
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from pydantic import UUID4
from sqlalchemy.ext.asyncio import AsyncSession

from app.application.services.biometric_alert_rule_service import BiometricAlertRuleService
from app.core.domain.entities.user import User
from app.presentation.api.dependencies.database import get_db
from app.infrastructure.security.rate_limiting.limiter import RateLimiter
from app.presentation.api.dependencies.auth import (
    get_current_active_user_wrapper,
)
from app.presentation.api.schemas.alert import (
    AlertRuleCreateFromTemplateRequest,
    AlertRuleCreateRequest,
    AlertRuleResponse,
    AlertRuleUpdateRequest,
)
from app.presentation.api.v1.dependencies.biometric_alert import (
    get_biometric_alert_rule_service,
)

logger = logging.getLogger(__name__)

# Router without global dependencies that might interfere with static analysis
router = APIRouter(
    tags=["biometric-alert-rules"],
)
```

## Available Endpoints

### 1. Create Alert Rule

```python
@router.post(
    "",
    response_model=AlertRuleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new biometric alert rule",
    description="Adds a new biometric alert rule to the system.",
)
async def create_alert_rule(
    rule_data: AlertRuleCreateRequest,
    alert_rule_service: BiometricAlertRuleService = Depends(get_biometric_alert_rule_service),
    current_user: User = Depends(get_current_active_user_wrapper),
    db: AsyncSession = Depends(get_db),
) -> AlertRuleResponse:
```

This endpoint creates a new biometric alert rule with custom conditions, enabling clinicians to define personalized monitoring thresholds for a patient.

**Authentication**: Requires authenticated user  
**Authorization**: Requires appropriate clinical privileges  
**Request Body**: `AlertRuleCreateRequest` containing rule parameters  
**Response**: Created rule with assigned ID and metadata  
**Errors**:

- 400: Bad request (validation error, invalid rule parameters)
- 401: Unauthorized (authentication required)
- 403: Forbidden (insufficient permissions)
- 500: Server error during rule creation

### 2. Create Alert Rule From Template

```python
@router.post(
    "/from-template",
    response_model=AlertRuleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new alert rule from a template",
    description="Creates a new alert rule based on a predefined template with custom overrides.",
)
async def create_alert_rule_from_template(
    template_request: AlertRuleCreateFromTemplateRequest,
    alert_rule_service: BiometricAlertRuleService = Depends(get_biometric_alert_rule_service),
    current_user: User = Depends(get_current_active_user_wrapper),
) -> AlertRuleResponse:
```

This endpoint allows clinicians to create new alert rules based on standardized templates, with optional custom overrides for patient-specific adjustments.

**Authentication**: Requires authenticated user  
**Authorization**: Requires appropriate clinical privileges  
**Request Body**: `AlertRuleCreateFromTemplateRequest` containing template ID, patient ID, and customizations  
**Response**: Created rule with assigned ID and metadata  
**Errors**:

- 400: Bad request (invalid template ID, invalid UUID format)
- 401: Unauthorized (authentication required)
- 403: Forbidden (insufficient permissions)
- 404: Not found (template not found)
- 500: Server error during rule creation

### 3. Get Alert Rules

```python
@router.get(
    "",
    response_model=list[AlertRuleResponse],
    summary="Get biometric alert rules",
    description=(
        "Retrieves a list of biometric alert rules with optional filtering."
    ),
)
async def get_alert_rules(
    patient_id: UUID | None = Query(None, description="Filter by patient ID"),
    is_active: bool | None = Query(None, description="Filter by active status"),
    alert_rule_service: BiometricAlertRuleService = Depends(get_biometric_alert_rule_service),
    current_user: User = Depends(get_current_active_user_wrapper),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> list[AlertRuleResponse]:
```

This endpoint retrieves a list of biometric alert rules with optional filtering by patient ID and active status, supporting pagination through limit and offset parameters.

**Authentication**: Requires authenticated user  
**Authorization**: Requires appropriate clinical privileges  
**Query Parameters**:

- `patient_id` (optional): Filter rules by patient
- `is_active` (optional): Filter by active/inactive status
- `limit`: Maximum number of rules to return (1-1000)
- `offset`: Pagination offset

**Response**: List of alert rules matching filter criteria  
**Errors**:

- 401: Unauthorized (authentication required)
- 403: Forbidden (insufficient permissions)
- 500: Server error during retrieval

### 4. Get Specific Alert Rule

```python
@router.get(
    "/{rule_id}",
    response_model=AlertRuleResponse,
    summary="Get biometric alert rule details",
    description="Get details for a specific biometric alert rule.",
)
async def get_alert_rule(
    rule_id: UUID4 = Path(..., description="ID of the alert rule to retrieve"),
    alert_rule_service: BiometricAlertRuleService = Depends(get_biometric_alert_rule_service),
    current_user: User = Depends(get_current_active_user_wrapper),
):
```

This endpoint retrieves detailed information about a specific biometric alert rule by its unique identifier.

**Authentication**: Requires authenticated user  
**Authorization**: Requires appropriate clinical privileges  
**Path Parameters**: `rule_id` - UUID of the alert rule to retrieve  
**Response**: Detailed alert rule information  
**Errors**:

- 401: Unauthorized (authentication required)
- 403: Forbidden (insufficient permissions)
- 404: Not found (rule not found)
- 500: Server error during retrieval

### 5. Update Alert Rule

```python
@router.put(
    "/{rule_id}",
    response_model=AlertRuleResponse,
    summary="Update biometric alert rule",
    description="Update an existing biometric alert rule.",
)
async def update_alert_rule(
    rule_data: AlertRuleUpdateRequest,
    rule_id: UUID4 = Path(..., description="ID of the alert rule to update"),
    alert_rule_service: BiometricAlertRuleService = Depends(get_biometric_alert_rule_service),
    current_user: User = Depends(get_current_active_user_wrapper),
):
```

This endpoint updates an existing biometric alert rule with new parameters while maintaining its association with the patient.

**Authentication**: Requires authenticated user  
**Authorization**: Requires appropriate clinical privileges  
**Path Parameters**: `rule_id` - UUID of the alert rule to update  
**Request Body**: `AlertRuleUpdateRequest` containing updated rule parameters  
**Response**: Updated alert rule information  
**Errors**:

- 400: Bad request (validation error, invalid rule parameters)
- 401: Unauthorized (authentication required)
- 403: Forbidden (insufficient permissions)
- 404: Not found (rule not found)
- 500: Server error during update

### 6. Delete Alert Rule

```python
@router.delete(
    "/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete biometric alert rule",
    description="Delete a specific biometric alert rule.",
)
async def delete_alert_rule(
    rule_id: UUID4 = Path(..., description="ID of the alert rule to delete"),
    alert_rule_service: BiometricAlertRuleService = Depends(get_biometric_alert_rule_service),
    current_user: User = Depends(get_current_active_user_wrapper),
):
```

This endpoint permanently deletes a biometric alert rule from the system.

**Authentication**: Requires authenticated user  
**Authorization**: Requires appropriate clinical privileges  
**Path Parameters**: `rule_id` - UUID of the alert rule to delete  
**Response**: 204 No Content on successful deletion  
**Errors**:

- 401: Unauthorized (authentication required)
- 403: Forbidden (insufficient permissions)
- 404: Not found (rule not found)
- 500: Server error during deletion

## Data Models

### Alert Rule Creation

The `AlertRuleCreateRequest` model defines the structure for creating new alert rules:

```python
class AlertRuleCreateRequest(BaseModel):
    name: str
    description: str
    patient_id: str
    biometric_type: str  # e.g., "heart_rate", "sleep_quality"
    threshold_level: float
    comparison_operator: str  # e.g., ">", "<", "=="
    priority: str = "medium"  # "low", "medium", "high", "critical"
    is_active: bool = True
```

### Alert Rule Update

The `AlertRuleUpdateRequest` model defines the structure for updating existing alert rules:

```python
class AlertRuleUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    threshold_level: Optional[float] = None
    comparison_operator: Optional[str] = None
    priority: Optional[str] = None
    is_active: Optional[bool] = None
```

### Alert Rule Response

The `AlertRuleResponse` model defines the structure for alert rule responses:

```python
class AlertRuleResponse(BaseModel):
    id: UUID
    name: str
    description: str
    biometric_type: str
    threshold_level: float
    comparison_operator: str
    is_active: bool
    created_by: str
    updated_by: str
    created_at: datetime
    last_updated: datetime
```

## Security Considerations

The Biometric Alert Rules API implements several security measures:

1. **Authentication**: All endpoints require valid authentication
2. **Authorization**: Users can only access rules for patients under their care
3. **Input Validation**: Strict validation of inputs prevents injection attacks
4. **Audit Logging**: All rule creations and modifications are logged for compliance
5. **Rate Limiting**: Protection against abuse through rate limiting

## HIPAA Compliance

The API maintains HIPAA compliance through:

1. **PHI Protection**: Patient identifiers are handled securely throughout
2. **Access Controls**: Only authorized users can access patient alert rules
3. **Audit Trails**: Comprehensive logging of all rule operations
4. **Data Minimization**: Responses include only necessary information

## Related Components

- **BiometricAlertRuleService**: Application service implementing rule management logic
- **Alert Rule Repository**: Data access layer for persisting and retrieving rules
- **Alert Evaluation Service**: Service that evaluates rules against incoming biometric data
- **Notification Service**: Handles delivering alerts when rules are triggered
