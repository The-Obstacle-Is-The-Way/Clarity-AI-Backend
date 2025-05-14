# API Versioning Strategy

## Overview

This document outlines the versioning strategy for the Clarity AI Backend APIs. As a healthcare-focused digital twin platform with HIPAA requirements, API stability and backward compatibility are critical concerns. This versioning strategy ensures that APIs can evolve while maintaining support for existing integrations.

## Core Principles

1. **Semantic Versioning**: Follow semantic versioning principles (MAJOR.MINOR.PATCH)
2. **Non-Breaking Evolution**: Prioritize backward compatible API changes
3. **Explicit Versioning**: All API endpoints include explicit version information
4. **Deprecation Process**: Clear process for deprecating and retiring API versions
5. **Documentation**: Complete documentation of API changes between versions

## Versioning Implementation

### URL Path Versioning

The Clarity AI Backend uses path-based versioning as the primary versioning mechanism:

```text
/api/v{major_version}/{resource}
```

Example:

```text
/api/v1/patients
/api/v2/patients
```

This approach offers several advantages:

- Highly visible to API consumers
- Easy to implement and test
- Compatible with API management tools and documentation
- Allows major version changes to coexist

### Router Structure

```python
# app/presentation/api/api.py
from fastapi import APIRouter
from app.presentation.api.v1 import api_router as api_router_v1
from app.presentation.api.v2 import api_router as api_router_v2

api_router = APIRouter()

# Mount version-specific routers
api_router.include_router(api_router_v1, prefix="/v1")
api_router.include_router(api_router_v2, prefix="/v2")
```

```python
# app/presentation/api/v1/api_router.py
from fastapi import APIRouter
from app.presentation.api.v1.endpoints import (
    patients,
    digital_twins,
    biometrics,
    auth
)

api_router = APIRouter()

# Include domain-specific routers
api_router.include_router(patients.router, prefix="/patients", tags=["patients"])
api_router.include_router(digital_twins.router, prefix="/digital-twins", tags=["digital_twins"])
api_router.include_router(biometrics.router, prefix="/biometrics", tags=["biometrics"])
api_router.include_router(auth.router, prefix="/auth", tags=["authentication"])
```

### Version Header Support

In addition to path-based versioning, the API supports header-based versioning for finer-grained control:

```python
# app/presentation/api/dependencies/versioning.py
from fastapi import Request, Depends, HTTPException, status
from enum import Enum
from typing import Optional, Callable

class APIVersion(str, Enum):
    """API versions supported via headers."""
    V1 = "1.0"
    V1_1 = "1.1"
    V2 = "2.0"

def api_version_header(request: Request) -> Optional[str]:
    """Extract API version from headers."""
    return request.headers.get("X-API-Version")

def version_dependency(min_version: APIVersion, max_version: Optional[APIVersion] = None):
    """
    Create a dependency that enforces API version constraints.
    
    Args:
        min_version: Minimum required API version
        max_version: Maximum supported API version
        
    Returns:
        Dependency function checking version
    """
    def check_version(version: Optional[str] = Depends(api_version_header)):
        # If no version header, assume compatible with base path version
        if not version:
            return
            
        # Check if version is in the supported format
        try:
            client_version = APIVersion(version)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported API version: {version}"
            )
        
        # Check minimum version
        if client_version.value < min_version.value:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"API version {version} is not supported. Minimum version: {min_version.value}"
            )
        
        # Check maximum version if specified
        if max_version and client_version.value > max_version.value:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"API version {version} is not supported. Maximum version: {max_version.value}"
            )
            
    return check_version
```

### Feature Flags

For fine-grained control of features within a version:

```python
# app/core/config/feature_flags.py
from pydantic import BaseSettings
from typing import Dict, Any
import json

class FeatureFlags(BaseSettings):
    """
    Feature flag configuration for the API.
    
    Allows enabling/disabling features without API version changes.
    """
    
    # Feature flags with default values
    ENABLE_ML_PREDICTIONS: bool = True
    ENABLE_ADVANCED_ANALYTICS: bool = False
    ENABLE_BIOMETRIC_ALERTS_V2: bool = False
    ENABLE_DIGITAL_TWIN_SIMULATIONS: bool = False
    USE_NEW_PATIENT_SCHEMA: bool = False
    
    # Additional feature flags loaded from environment variable
    _ADDITIONAL_FLAGS: Dict[str, Any] = {}
    
    class Config:
        """Pydantic configuration."""
        env_prefix = "FEATURE_"
        extra = "ignore"
    
    def __init__(self, **kwargs):
        """
        Initialize feature flags.
        
        Load additional flags from FEATURE_FLAGS environment variable.
        """
        super().__init__(**kwargs)
        
        # Try to load additional flags from environment
        additional_flags_str = kwargs.get("ADDITIONAL_FLAGS", "{}")
        try:
            self._ADDITIONAL_FLAGS = json.loads(additional_flags_str)
        except json.JSONDecodeError:
            self._ADDITIONAL_FLAGS = {}
    
    def is_enabled(self, feature_name: str) -> bool:
        """
        Check if a feature is enabled.
        
        Args:
            feature_name: Name of the feature to check
            
        Returns:
            True if the feature is enabled
        """
        # Check built-in flags first
        if hasattr(self, feature_name):
            return getattr(self, feature_name)
            
        # Then check additional flags
        return self._ADDITIONAL_FLAGS.get(feature_name, False)
```

## Versioning Decision Process

### When to Create a New Major Version (v1 → v2)

A new major version is created when introducing **breaking changes**:

1. **Incompatible API Changes:**
   - Removing or renaming endpoints
   - Changing parameter types or required status
   - Removing fields from response objects
   - Changing authentication mechanisms
   - Modifying error response formats

2. **Significant Architectural Changes:**
   - Complete data model restructuring
   - Fundamental security model changes
   - Major performance optimizations requiring interface changes

### When to Create a Minor Version (v1.0 → v1.1)

Minor versions represent **non-breaking enhancements**:

1. **API Additions:**
   - New endpoints within existing resource groups
   - Optional parameters to existing endpoints
   - Additional fields in response objects (that clients can ignore)
   - New resource types that don't affect existing ones

2. **Enhanced Functionality:**
   - Improved algorithms with the same interface
   - Additional filtering or sorting options
   - Extended validation rules that don't reject previously valid inputs

### Implementation with Code Examples

#### API Endpoint with Version-Specific Logic

```python
from fastapi import APIRouter, Depends, Query
from app.presentation.api.dependencies.versioning import version_dependency, APIVersion
from app.presentation.schemas.patient import (
    PatientResponseV1,
    PatientResponseV2
)

router = APIRouter()

@router.get(
    "/{patient_id}",
    response_model=None,  # Dynamic based on version
    summary="Get patient by ID",
    description="Retrieve a patient by ID with version-specific response format"
)
async def get_patient(
    patient_id: str,
    version: str = Depends(api_version_header)
):
    """
    Get patient with version-specific response format.
    
    Demonstrates handling different API versions within a single endpoint.
    """
    # Get patient from service (common logic)
    patient = await patient_service.get_by_id(patient_id)
    
    # Return version-specific response
    if version == APIVersion.V2:
        # V2 adds additional fields and uses different naming
        return PatientResponseV2.from_domain_entity(patient)
    else:
        # Default to V1 response format
        return PatientResponseV1.from_domain_entity(patient)
```

#### Feature Flag Usage

```python
from fastapi import APIRouter, Depends, HTTPException, status
from app.core.config import settings

router = APIRouter()

@router.post(
    "/predict",
    summary="Generate prediction",
    description="Generate a prediction using ML models"
)
async def generate_prediction(
    data: PredictionRequest,
    model_service: IModelService = Depends(get_model_service)
):
    """Generate prediction with feature flag control."""
    if not settings.feature_flags.is_enabled("ENABLE_ML_PREDICTIONS"):
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="ML prediction feature is currently disabled"
        )
    
    # Feature is enabled, proceed with prediction
    result = await model_service.predict(data.input_features)
    return {"prediction": result.prediction, "confidence": result.confidence}
```

## Version Lifecycle Management

### API Lifecycle Stages

1. **Active Development**: Upcoming version in development
2. **Current**: Latest stable version, fully supported
3. **Supported**: Previous versions still maintained
4. **Deprecated**: Scheduled for removal, still functional
5. **Retired**: No longer available

### Deprecation Process

1. **Announcement**: Notify users of deprecation with timeline
2. **Warning Headers**: Include deprecation warning in responses
3. **Documentation**: Mark deprecated features in documentation
4. **Monitoring**: Track usage of deprecated endpoints
5. **Retirement**: Remove deprecated version after grace period

```python
from fastapi import APIRouter, Response
from datetime import datetime

router = APIRouter()

@router.get(
    "/legacy-endpoint",
    summary="Legacy endpoint",
    description="This endpoint is deprecated and will be removed soon"
)
async def legacy_endpoint(response: Response):
    """
    Example of a deprecated endpoint with warning headers.
    """
    # Add deprecation headers
    response.headers["Deprecation"] = "true"
    response.headers["Sunset"] = "Sat, 31 Dec 2023 23:59:59 GMT"
    response.headers["Link"] = "</api/v2/new-endpoint>; rel=\"successor-version\""
    
    # Return response with warning
    return {
        "message": "This endpoint is deprecated. Please use /api/v2/new-endpoint instead.",
        "data": {"legacy": "data"}
    }
```

## API Version Documentation

### Version Changelog

Each API version includes comprehensive documentation of changes:

```markdown
# API v2.0 Changelog

## Breaking Changes

- **Patient Resource**
  - Renamed `medical_number` to `medical_record_number`
  - Changed `dob` format from MM/DD/YYYY to ISO 8601 (YYYY-MM-DD)
  - Removed `middle_name` field

- **Authentication**
  - Removed Basic Auth support
  - JWT tokens now require `Bearer` prefix

## New Features

- **Digital Twin Resource**
  - Added `/digital-twins/{id}/simulate` endpoint
  - Added support for multiple simulation models

- **Biometric Data**
  - Added support for batch uploads
  - Added new biometric types (HRV, SpO2)

## Improvements

- Standardized error responses
- Improved validation error messages
- Added pagination to all collection endpoints
```

### OpenAPI Documentation

```python
# app/main.py
from fastapi import FastAPI
from app.core.config import settings

app = FastAPI(
    title="Clarity AI Backend API",
    description="Healthcare Digital Twin Platform API",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# Add version-specific documentation
app.openapi_tags = [
    {
        "name": "v1",
        "description": "Version 1.0 endpoints (deprecated, sunset date: 2023-12-31)"
    },
    {
        "name": "v2",
        "description": "Version 2.0 endpoints (current)"
    }
]
```

## Implementation Status

### Current Status

- ✅ Path-based major versioning implemented (`/api/v1`, `/api/v2`)
- ✅ Header-based minor versioning support
- ✅ OpenAPI documentation with version information
- ✅ Deprecation warning headers

### Architectural Gaps

- 🔄 Automated compatibility testing between versions
- 🔄 Version-specific documentation generation
- 🔄 Comprehensive feature flag system

## Migration Guides

For each major version change, a migration guide is provided to help clients transition:

```markdown
# Migrating from v1 to v2

## Authentication Changes

- Update all authentication requests to use Bearer tokens
- Tokens now require the `Bearer` prefix:
  - v1: `Authorization: eyJhbGciOi...`
  - v2: `Authorization: Bearer eyJhbGciOi...`

## Patient Data Changes

- Update all `dob` fields to ISO 8601 format (YYYY-MM-DD)
- Rename `medical_number` to `medical_record_number`
- Remove any `middle_name` field usage

## Error Handling

- Error responses now follow RFC 7807 (Problem Details)
- All errors include a `type`, `title`, `status`, and `detail`
- Handle HTTP 422 responses for validation errors
```

By following this versioning strategy, the Clarity AI Backend maintains a proper balance between API evolution and stability, ensuring a reliable and predictable experience for API consumers while enabling the platform to grow and improve over time.
