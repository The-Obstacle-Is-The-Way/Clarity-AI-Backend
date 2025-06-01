# API Standardization Plan

## Objective

Create a standardized, clean architecture-compliant API structure for the Clarity AI Backend that addresses all identified issues, ensures HIPAA compliance, and provides a maintainable foundation for future development.

## Implementation Phases

This plan divides the standardization process into four distinct phases to minimize disruption and ensure quality at each step. Based on SPARC analysis findings, special attention will be given to PHI exposure risks and critical Clean Architecture violations.

### Phase 1: Core Architecture Standardization

**Goal**: Establish foundational patterns and missing interfaces without changing existing functionality.

#### 1.1 Define Missing Interfaces

Create the following interfaces in the core layer:

- `app/core/interfaces/repositories/token_blacklist_repository_interface.py`
- `app/core/interfaces/services/audit_logger_interface.py`
- `app/core/interfaces/security/password_handler_interface.py`
- `app/core/interfaces/services/redis_service_interface.py`

Example implementation:

```python
# app/core/interfaces/repositories/token_blacklist_repository_interface.py
from abc import ABC, abstractmethod
from typing import List
from datetime import datetime


class ITokenBlacklistRepository(ABC):
    """Interface for token blacklist repository operations."""

    @abstractmethod
    async def add_token(self, token: str, expires_at: datetime) -> None:
        """Add a token to the blacklist."""
        pass

    @abstractmethod
    async def is_blacklisted(self, token: str) -> bool:
        """Check if a token is blacklisted."""
        pass

    @abstractmethod
    async def remove_expired_tokens(self) -> int:
        """Remove expired tokens from the blacklist.
        
        Returns:
            int: Number of tokens removed
        """
        pass
```

#### 1.2 Standardize Dependency Structure

1. Create a consistent dependency directory structure:

```
app/presentation/api/dependencies/
├── common/
│   ├── database.py
│   ├── security.py
│   └── logging.py
├── services/
│   ├── patient_service.py
│   └── alert_service.py
└── repositories/
    ├── user_repository.py
    └── alert_repository.py
```

2. Move existing dependencies to the standardized structure
3. Maintain backwards compatibility with imports

#### 1.3 Create Dependency Documentation

Create a comprehensive markdown document detailing all available dependencies:

```markdown
# API Dependencies

## Service Dependencies

| Dependency | Interface | Implementation | Usage |
|------------|-----------|----------------|-------|
| `get_patient_service` | `IPatientService` | `PatientService` | Patient CRUD operations |
| `get_alert_service` | `IAlertService` | `AlertService` | Alert management |
```

#### 1.4 Define Centralized Error Handling

Based on SPARC's discovery of PHI exposure risks, implement a centralized error handling system:

```python
# app/core/utils/error_handling.py
from fastapi import Request, status
from fastapi.responses import JSONResponse
from app.core.interfaces.logging import IAuditLogger

async def handle_exception(request: Request, exc: Exception, audit_logger: IAuditLogger) -> JSONResponse:
    """Handle exceptions without exposing PHI.
    
    Sanitizes error messages and logs the full error details securely.
    """
    # Log the full error with PHI for audit purposes
    await audit_logger.log_error(request.url.path, str(exc), request.client.host)
    
    # Return sanitized error without PHI
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal server error occurred"}
    )
```

### Phase 2: Endpoint Consolidation and HIPAA Compliance

**Goal**: Standardize all API endpoints into a single pattern while maintaining backward compatibility and ensuring HIPAA compliance.

#### 2.1 Choose Standard Pattern

Based on clean architecture principles and the existing codebase, adopt the following standard:

- All endpoints will be consolidated in the `app/presentation/api/v1/endpoints/` directory
- Files will be named after the primary resource they manage
- All endpoints will use interface-based dependency injection
- Each file will maintain a single `router` export

#### 2.2 Implement Missing Endpoints

Implement the following missing endpoints:

1. **Patient Endpoints**: `app/presentation/api/v1/endpoints/patient.py`
   - Implement CRUD operations for patients
   - Follow HIPAA data handling requirements
   - Integrate with existing patient services

2. **Actigraphy Endpoints**: `app/presentation/api/v1/endpoints/actigraphy.py`
   - Consolidate existing implementations
   - Ensure proper test coverage

3. **Digital Twin Endpoints**: `app/presentation/api/v1/endpoints/digital_twin.py`
   - Port from routes to endpoints directory
   - Ensure interface-based dependency injection

4. **Biometric Alert Rules**: Update `app/presentation/api/v1/endpoints/biometric_alert_rules.py`
   - Implement missing handlers for `PATCH /alerts/{id}/status` and `POST /patients/{id}/trigger`
   - Replace code like this identified by SPARC:
   ```python
   try:
       # Implementation
   except Exception as e:
       # Unsafe: Exposes PHI
       return JSONResponse(status_code=500, content={"detail": str(e)})
   ```
   - With centralized error handling:
   ```python
   try:
       # Implementation
   except Exception as e:
       return await handle_exception(request, e, audit_logger)
   ```

#### 2.3 Update API Router

Update `app/presentation/api/v1/api_router.py` to import all routers from the standardized locations:

```python
# Example of updated imports
from app.presentation.api.v1.endpoints.analytics import router as analytics_router
from app.presentation.api.v1.endpoints.auth import router as auth_router
from app.presentation.api.v1.endpoints.biometric import router as biometric_router
# ... and so on
```

### Phase 3: Testing & Validation

**Goal**: Ensure all changes maintain functionality and improve test coverage.

#### 3.1 Create Test Plan

Develop a comprehensive test plan covering:

1. Unit tests for all endpoint handlers
2. Integration tests for API flows
3. HIPAA compliance validation tests
4. Performance benchmarks

#### 3.2 Implement Missing Tests

Focus on adding tests for previously untested endpoints:

```python
# Example test for a patient endpoint
async def test_create_patient_with_valid_data(client, auth_headers):
    """Test that a patient can be created with valid data."""
    # Test implementation
```

#### 3.3 Validate HIPAA Compliance

Create specific tests to verify HIPAA compliance, addressing the PHI exposure issues identified by SPARC:

1. PHI sanitization in error responses:
   ```python
   async def test_error_response_sanitizes_phi(client, auth_headers):
       """Test that error responses do not leak PHI."""
       # Trigger an error that would contain PHI
       response = await client.get("/api/v1/patients/invalid-id", headers=auth_headers)
       
       # Verify sanitized response
       assert response.status_code == 500
       assert response.json() == {"detail": "An internal server error occurred"}
       assert "invalid-id" not in response.text  # Ensure PHI not leaked
   ```

2. Proper audit logging of access events
3. Authorization checks for patient data access
4. Exception handling middleware compliance

### Phase 4: Documentation & Finalization

**Goal**: Ensure the API is well-documented and the transition is complete.

#### 4.1 Generate OpenAPI Documentation

Ensure comprehensive API documentation:

1. Update all route docstrings for OpenAPI generation
2. Generate a static API documentation site
3. Create examples for common API operations

#### 4.2 Create API Style Guide

Document the standardized patterns for future development:

```markdown
# API Development Style Guide

## Endpoint Structure

All endpoints should:
1. Use interface-based dependency injection
2. Follow RESTful resource naming
3. Include comprehensive docstrings
4. Implement proper error handling with PHI sanitization
```

#### 4.3 Remove Deprecated Routes

Once all tests pass with the new structure:

1. Remove deprecated route files
2. Update any remaining imports
3. Verify all functionality remains intact

## Implementation Timeline

Based on SPARC analysis findings, we've adjusted priorities to address critical HIPAA risks first:

| Phase | Task | Estimated Time | Dependencies | Priority |
|-------|------|----------------|--------------|----------|
| 1.1 | Define Missing Interfaces | 1 day | None | High |
| 1.2 | Standardize Dependency Structure | 2 days | 1.1 | High |
| 1.3 | Create Dependency Documentation | 1 day | 1.2 | Medium |
| 1.4 | Define Centralized Error Handling | 1 day | 1.1 | Critical |
| 2.1 | Choose Standard Pattern | 0.5 days | 1.1-1.4 | Medium |
| 2.2 | Implement Missing Endpoints | 3 days | 2.1 | High |
| 2.3 | Update API Router | 0.5 days | 2.2 | Medium |
| 3.1 | Create Test Plan | 1 day | 2.1-2.3 | Medium |
| 3.2 | Implement Missing Tests | 3 days | 3.1 | High |
| 3.3 | Validate HIPAA Compliance | 1 day | 3.2 | Critical |
| 4.1 | Generate OpenAPI Documentation | 1 day | 3.1-3.3 | Low |
| 4.2 | Create API Style Guide | 1 day | 4.1 | Low |
| 4.3 | Remove Deprecated Routes | 1 day | 4.2 | Medium |
| **Total** | | **~16 days** | | |

## Risk Management

| Risk | Mitigation |
|------|------------|
| Breaking changes | Maintain backward compatibility until full transition |
| Test failures | Implement changes incrementally with continuous testing |
| Performance impacts | Benchmark before and after changes |
| HIPAA compliance gaps | Include specific compliance tests in validation |
| Knowledge transfer | Document all changes thoroughly with examples |

## Conclusion

This standardization plan addresses the identified API issues while ensuring clean architecture compliance, maintainability, and proper security. By following this structured approach, the Clarity AI Backend will achieve a consistent, robust API layer that supports future development needs while maintaining HIPAA compliance and security requirements.
