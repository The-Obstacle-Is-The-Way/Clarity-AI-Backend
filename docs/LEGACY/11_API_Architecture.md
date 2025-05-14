# API Architecture

**Status:** This document describes the target API architecture. Significant discrepancies exist with the current implementation, particularly regarding endpoint availability, path structures, and security features. Refer also to `37_Digital_Twin_API.md` for specific (though also partially outdated) Digital Twin endpoint details.

## Overview

The Novamind API *is intended to serve* as the primary interface for external systems to interact with the Digital Twin platform. This document outlines the architectural principles, design patterns, and *target* implementation details of the API layer.

## Core Principles

The API architecture *is intended to be* built on:

1.  **RESTful Design** *(Partially implemented: Basic structure, but inconsistencies exist)*
2.  **Security First** *(Aspirational: Core security features largely missing)*
3.  **Consistency** *(Partially implemented: Response structure defined, but error handling and paths inconsistent)*
4.  **Versioning** *(Implemented: `/api/v1/` path prefix used)*
5.  **Documentation** *(Inconsistent: OpenAPI intended, but docs don't match code)*
6.  **Performance** *(Aspirational)*
7.  **Observability** *(Aspirational: Logging/monitoring TBD)*

## API Structure

### Versioning Strategy

All API endpoints are versioned using URL path prefixing:

```
/api/v1/resources
```
*Current Status: Implemented.* Code uses `/api/v1/` in `presentation/api/v1/`.

### Resource Hierarchy (Inconsistent)

*Documentation (`11_...`) suggests hierarchies like:* `/api/v1/patients/{patient_id}/twins/{twin_id}`
*Documentation (`37_...`) suggests:* `/api/v1/digital-twins/{twin_id}`
*Code (`digital_twins.py`) uses:* `/api/v1/digital-twins/{patient_id}/...` for many twin-related actions.
*Code (`patients.py`) uses:* `/api/v1/patients/{patient_id}`

*Current Status: Path structure is inconsistent between documentation sources and the actual code. The use of `{patient_id}` in the `/digital-twins/` prefix in code needs clarification/correction.*

### Standard HTTP Methods

The API *should use* standard HTTP methods consistently:

| Method | Purpose                        | Response Codes         | Status |
|--------|--------------------------------|------------------------|--------|
| GET    | Retrieve resources             | 200, 404               | Used |
| POST   | Create new resources           | 201, 400, 409          | Used |
| PUT    | Replace existing resources     | 200/204, 400, 404      | Documented, but PATCH used in `patients.py` |
| PATCH  | Partially update resources     | 200/204, 400, 404      | Used in `patients.py` |
| DELETE | Remove resources               | 204, 404               | Used |

### Response Format

*Target* API responses follow a consistent JSON structure:

```json
{
  "data": { ... },         // Payload
  "meta": { ... },         // Metadata (timestamp, request_id, pagination)
  "errors": [ ... ]        // Optional error details
}
```
*Current Status: Documentation (`37_...`) shows a slightly different structure (`error` singular object instead of `errors` array). Code implementation consistency TBD. Structured metadata like `request_id` and `pagination` is likely aspirational.*

### Error Handling

*Target* error responses are standardized:

```json
// Example from 12_Security_Architecture.md
{
  "request_id": "unique-error-id",
  "code": "VALIDATION_ERROR",
  "message": "Request validation error",
  "details": [ { "loc": ["body", "email"], "msg": "Invalid format", "type": "value_error" } ]
}
```
Error codes *should* follow a consistent pattern (VALIDATION_ERROR, AUTHENTICATION_ERROR, etc.).

*Current Status: Partially implemented. Code in `digital_twins.py` catches specific domain exceptions and raises `HTTPException` with basic details. The documented structured error response with `request_id`, standard `code`, and detailed `details` array using FastAPI exception handlers appears unimplemented.*

## Implementation

### Core Components (Target)

The API layer *should consist* of:

1.  **Router** (FastAPI `APIRouter`) *(Implemented)*
2.  **Controller** (Endpoint functions) *(Implemented)*
3.  **Request Validator** (Pydantic Schemas) *(Implemented)*
4.  **Authentication Middleware** *(Implemented: `presentation/middleware/authentication_middleware.py` - Registered Globally)*
5.  **Authorization Middleware** *(Implemented: `presentation/middleware/rbac_middleware.py` - **NOT Registered Globally in main.py; usage TBD**)*
6.  **Response Formatter** *(Partial/Aspirational: Basic JSON, structured format TBD)*
7.  **Error Handler** (FastAPI Exception Handlers) *(Partial/Aspirational: Basic `HTTPException`, structured handling missing)*
8.  **Rate Limiting Middleware** *(Implemented: `presentation/middleware/rate_limiting_middleware.py` - Registered Globally)*
9.  **PHI Scrubbing Middleware** *(Implemented: `presentation/middleware/phi_middleware.py` - **EXISTS BUT DISABLED in main.py**)*

### FastAPI Implementation

The API is implemented using FastAPI.
*Current Status: Confirmed. However, endpoint implementations (`patients.py`, `digital_twins.py`) contain significant logic, in-memory data stores, and test-specific patching, deviating from the principle of thin controllers calling application services.*

```python
# Example structure (Illustrative - actual code varies)
from fastapi import FastAPI, Depends, HTTPException, status
# ... other imports ...

app = FastAPI(...) # Or router = APIRouter(...)

# --- Authentication (Aspirational/Missing) ---
# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token") # Defined but /token endpoint missing
async def get_current_user(...): ... # Dependency likely exists but implementation TBD/missing -> *(Implemented: `presentation/dependencies/auth.py`)*

# --- Authorization (Aspirational/Missing) ---
# async def verify_patient_access(...): ...

# --- Endpoints ---
# @router.get("/api/v1/patients/{patient_id}", ...)
# async def get_patient(patient_id: str, ...):
#     # ACTUAL CODE currently uses in-memory store or mocks
#     # TARGET: Should call application service
#     # try:
#     #     patient_dto = await application_service.get_patient(patient_id, current_user)
#     #     return patient_dto
#     # except PatientNotFound:
#     #     raise HTTPException(status_code=404)
#     # except NotAuthorized:
#     #     raise HTTPException(status_code=403)
#     # except Exception as e:
#     #     # Log e securely
#     #     raise HTTPException(status_code=500, detail="Internal Error") # Needs proper handler
#     pass
```

## Authentication and Authorization (Largely Aspirational)

### Authentication Options (Target)
1.  JWT Authentication *(Intended primary method, implementation missing)*
2.  API Key Authentication *(Aspirational)*
3.  OAuth2 *(Aspirational)*

### JWT Implementation (Example/Aspirational)
*Code examples provided in documentation exist, using `jose` library, but the actual implementation (e.g., `/token` endpoint, `get_current_user` logic) is missing or incomplete.*

### Authorization Framework (Aspirational)
*RBAC system described with Roles (Admin, Clinician, etc.) and Permissions is aspirational. No authorization checks (`check_role`, `check_resource_permission`) found in reviewed endpoint code.* -> *(Partially Implemented: `rbac_middleware.py` exists, **but not registered globally; integration/use in endpoints TBD**)*

## API Rate Limiting (Aspirational)
*Rate limiting middleware described in documentation is aspirational. Implementation TBD.* -> *(Implemented: `rate_limiting_middleware.py` exists and **is registered globally**)*

## API Endpoints (Documented vs. Implemented Reality)

*This section lists the **documented** endpoints from `11_...` and `37_...`. The **actual implemented endpoints** in `presentation/api/v1/endpoints/` differ significantly. Many documented endpoints are **MISSING**, and many implemented endpoints are **UNDOCUMENTED** or have placeholder logic.* See `37_Digital_Twin_API.md` (pending updates) for a more detailed (but still partially inaccurate) list focused on Digital Twins.

### Core Endpoints (Documented / Target)

1.  **Authentication Endpoints**
    ```
    POST /api/v1/auth/token     # MISSING
    POST /api/v1/auth/refresh   # MISSING
    POST /api/v1/auth/logout    # MISSING
    ```
    *(`auth.py` is placeholder)*

2.  **Patient Endpoints**
    ```
    GET /api/v1/patients          # MISSING
    POST /api/v1/patients         # Implemented (in patients.py, uses mock store)
    GET /api/v1/patients/{patient_id} # Implemented (in patients.py, uses mock store)
    PUT /api/v1/patients/{patient_id} # MISSING (PATCH is implemented)
    DELETE /api/v1/patients/{patient_id} # Implemented (in patients.py, uses mock store)
    ```

3.  **Digital Twin Endpoints** *(Note Path Inconsistencies)*
    *Paths below are from docs (`/digital-twins/{id}` or `/patients/{pid}/twins/{id}`). Actual code uses `/digital-twins/{patient_id}` for many actions.* 
    ```
    # --- Creation/Basic Retrieval (Documented) --- 
    POST /api/v1/digital-twins                      # MISSING
    GET /api/v1/digital-twins/{twin_id}             # MISSING (Code has GET /digital-twins/{patient_id})
    GET /api/v1/patients/{patient_id}/digital-twin  # MISSING (Alternative documented path)
    GET /api/v1/patients/{patient_id}/twins         # MISSING
    POST /api/v1/patients/{patient_id}/twins        # MISSING
    GET /api/v1/patients/{patient_id}/twins/{twin_id} # MISSING
    PUT /api/v1/patients/{patient_id}/twins/{twin_id} # MISSING
    PATCH /api/v1/patients/{patient_id}/twins/{twin_id} # MISSING
    
    # --- Data/State/History (Documented) ---
    POST /api/v1/digital-twins/{twin_id}/data       # MISSING 
    GET /api/v1/digital-twins/{twin_id}/data        # MISSING (Alternative documented path)
    POST /api/v1/digital-twins/{twin_id}/data-points # MISSING (Code has POST /digital-twins/{patient_id}/events)
    GET /api/v1/digital-twins/{twin_id}/data-points # MISSING
    GET /api/v1/digital-twins/{twin_id}/state       # MISSING 
    GET /api/v1/digital-twins/{twin_id}/history     # MISSING
    
    # --- Insights (Documented) ---
    POST /api/v1/digital-twins/{twin_id}/insights/generate # MISSING (Code has GET /digital-twins/{patient_id}/insights)
    GET /api/v1/digital-twins/{twin_id}/insights           # MISSING (Code has GET /digital-twins/{patient_id}/insights)
    
    # --- Models/Features (Documented) ---
    GET /api/v1/digital-twins/{twin_id}/features    # MISSING
    GET /api/v1/digital-twins/{twin_id}/models      # MISSING
    POST /api/v1/digital-twins/{twin_id}/models/train # MISSING
    
    # --- Simulation/Archive (Documented) ---
    POST /api/v1/digital-twins/{twin_id}/simulate   # MISSING
    POST /api/v1/digital-twins/{twin_id}/archive    # MISSING
    ```
    *Actual implemented endpoints in `digital_twins.py` (under `/digital-twins/{patient_id}/`) include: `status`, `insights`, `analyze-text`, `forecast`, `correlations`, `medication-response`, `treatment-plan`, `events`, `recommendations`, `visualization`, `compare`, `summary`. These are **UNDOCUMENTED** in the main API docs.*

### Additional Features (Documented / Target)

1.  **Bulk Operations** *(Aspirational)*
2.  **Export Operations** *(Aspirational)*
3.  **Webhooks** *(Aspirational)*

## Health Checks and Monitoring (Partially Implemented / Aspirational)

Health check endpoints *are intended*:
```
GET /health           # TBD
GET /health/detailed  # TBD
```
*Current Status: Implementation status TBD. Monitoring integration (Prometheus, etc.) is aspirational.*

## Documentation (Inconsistent)
The API *is intended to be* documented using OpenAPI.
*Current Status: FastAPI provides automatic `/docs` and `/openapi.json`. However, the generated documentation will reflect the inconsistent/incomplete state of the code and won't align with the manually written Markdown documentation until the code and docstrings are fixed.*

## HIPAA Compliance (Largely Aspirational)
The API *is intended to implement* HIPAA compliance measures:

1.  **Authentication & Authorization** *(Missing)*
2.  **Audit Logging** *(Missing)*
3.  **Data Protection**
    -   No PHI in URLs/query parameters *(Implemented - uses UUIDs)*
    -   No PHI in logs or error messages *(Aspirational/TBD - requires PHI scrubbing, secure error handling)* -> *(Partially Implemented: `phi_middleware.py` exists, **but is currently DISABLED in main.py**)*
    -   TLS encryption for all communications *(Aspirational/TBD - requires infrastructure setup)*
4.  **Session Management** *(Aspirational/Missing)*

*Current Status: Only the use of non-PHI identifiers in URLs is confirmed. Other technical safeguards are missing or TBD.*

## Performance Optimizations (Aspirational)
*Caching, Database Optimizations, Asynchronous Processing (FastAPI provides async, but benefits depend on non-blocking infrastructure calls which are currently missing/mocked).* Status: Aspirational.

## Future Enhancements (Aspirational)
*GraphQL Interface, Websocket Support, Advanced Authentication.* Status: Aspirational.

## Appendix
*(Standard HTTP codes, headers - Generally applicable)*

## Presentation Layer
*(This section accurately describes the structure found in `backend/app/presentation/`, including API, Web, Middleware components. However, the descriptions of implemented features within this layer need tempering based on the analysis above - e.g., Auth/PHI/RateLimit Middleware are TBD/missing, ML Integration endpoints exist but underlying logic is placeholder/aspirational)*

Last Updated: 2025-04-20
