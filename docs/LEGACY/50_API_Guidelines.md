# API Guidelines

This document outlines the standards and best practices for API design and implementation in the Novamind Digital Twin platform. It provides guidance on RESTful design, versioning, security, and other aspects of API development.

---

## 1. API Design Principles

### 1.1. RESTful Design

All APIs should follow RESTful principles:

- Use resources (nouns) as the basis for endpoints
- Use HTTP methods appropriately:
  - `GET`: Retrieve resources
  - `POST`: Create resources
  - `PUT`: Replace resources
  - `PATCH`: Update resources
  - `DELETE`: Remove resources
- Use HTTP status codes correctly
- Implement HATEOAS (Hypermedia as the Engine of Application State) where appropriate

### 1.2. API Versioning

All APIs must be versioned to allow for future changes:

- Include the version in the URL path: `/api/v1/resource`
- Major version changes (v1 → v2) indicate breaking changes
- Minor version changes can be handled via headers or query parameters

### 1.3. HIPAA Compliance

APIs must comply with HIPAA regulations:

- Never include PHI in URLs or query parameters
- Encrypt all data in transit
- Implement proper authentication and authorization
- Maintain comprehensive audit logs of all PHI access
- **Note**: Ensure appropriate mechanisms (e.g., PHI middleware, careful response modeling) are active and correctly implemented to prevent PHI disclosure. Verify the status of PHI-specific middleware (observed as potentially disabled during initial analysis of `main.py`). *(Update: `phi_middleware.py` exists; its activation status and effectiveness need verification)* -> *(Update: `phi_middleware.py` exists **but is DISABLED in main.py**; activation status and effectiveness need verification)*

### 1.4. Security-First Approach

Security is a primary concern for all APIs:

- Validate all input data
- Sanitize all output data
- Implement rate limiting and throttling
- Use TLS for all communications
- Follow the principle of least privilege

## 2. URL Structure

### 2.1. Path Format

API paths should follow a consistent format:

```
/api/v{version}/{resource}
```

Where:
- `version` is the API version number (e.g., `v1`)
- `resource` is the plural form of the resource name

Examples:
- `/api/v1/patients`
- `/api/v1/digital-twins`
- `/api/v1/clinicians`

### 2.2. Resource Naming

Resource naming guidelines:

- Use plural nouns for collections: `/patients` not `/patient`
- Use kebab-case for multi-word resources: `/digital-twins` not `/digitalTwins`
- Be concise but descriptive
- Avoid verbs in resource names

### 2.3. Nested Resources

For representing resource relationships:

```
/api/v1/{resource}/{id}/{nested-resource}
```

Examples:
- `/api/v1/patients/123/assessments`
- `/api/v1/digital-twins/456/predictions`

### 2.4. Query Parameters

Query parameters should be used for:

- Filtering: `/api/v1/patients?status=active`
- Sorting: `/api/v1/assessments?sort=date_desc`
- Pagination: `/api/v1/patients?page=2&limit=20`
- Fields selection: `/api/v1/patients?fields=id,name,status`

**Security Note**: Never include PHI in query parameters.

## 3. Request and Response Format

### 3.1. Data Format

- Use JSON (`application/json`) for all request and response bodies
- Use consistent casing (*Aspirational Goal*):
  - Use `camelCase` for JSON properties (Requires Pydantic alias configuration)
  - Use `snake_case` for query parameters (Generally default Python/FastAPI style)

### 3.2. Request Structure

For POST, PUT, and PATCH operations:

```json
{
  "propertyName": "value",
  "nestedObject": {
    "nestedProperty": "value"
  }
}
```

### 3.3. Response Structure

Standard success response (*Target Structure*):

```json
{
  "data": {
    "id": "123",
    "propertyName": "value",
    "createdAt": "2025-04-20T10:30:00Z"
  },
  "meta": {
    "timestamp": "2025-04-20T10:30:05Z"
  }
}
```

Collection response (*Target Structure*):

```json
{
  "data": [
    { "id": "123", "name": "Resource 1" },
    { "id": "456", "name": "Resource 2" }
  ],
  "meta": {
    "pagination": {
      "page": 1,
      "limit": 20,
      "total": 45,
      "pages": 3
    }
  }
}
```

**Note**: Implementing this consistent `data`/`meta` envelope requires custom middleware or response handling logic. Current implementations may return data directly or use FastAPI's default serialization based on Pydantic response models. Adherence to this target structure should be pursued during refactoring. Refer to the OpenAPI specification for the most accurate current response formats (See Section 6).

### 3.4. Error Responses

Standard error response (*Target Structure*):

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input parameters",
    "details": [
      {
        "field": "email",
        "message": "Invalid email format"
      }
    ],
    "requestId": "abcd1234"
  }
}
```

**Security Note**: Error responses must never include PHI or sensitive internal system details.

**Note**: Achieving this standardized error format requires implementing custom FastAPI exception handlers. Without these handlers (not observed as globally registered in `main.py` during initial analysis), error responses may follow FastAPI's default format for HTTPExceptions or Pydantic validation errors. Implementing consistent, informative, yet secure error handling is a key goal.

## 4. Authentication and Authorization

### 4.1. Authentication

All APIs must be authenticated using:

- OAuth 2.0 with JWT tokens *(Implementation likely based on `presentation/dependencies/auth.py` and `presentation/middleware/authentication_middleware.py` - **Middleware is registered globally**)*
- Token-based authentication via Authorization header: `Bearer {token}`
- Support for refresh tokens to maintain sessions *(Implementation status TBD)*

### 4.2. Authorization

Access control should be implemented:

- Role-based access control (RBAC) *(Implementation likely based on `presentation/middleware/rbac_middleware.py` - **Middleware exists but is NOT registered globally**)*
- Attribute-based access control (ABAC) for fine-grained permissions *(Implementation status TBD/Aspirational)*
- Proper validation of user permissions for each API call *(Implementation status TBD)*

## 5. Performance Patterns

### 5.1. Pagination

Implement pagination for all collection endpoints:

- Page-based: `?page=2&limit=20`
- Cursor-based: `?cursor=abc123&limit=20`
- Return pagination metadata in responses

### 5.2. Filtering and Sorting

Support flexible data retrieval:

- Filtering: `?status=active&type=initial`
- Sorting: `?sort=lastUpdated_desc,name_asc`
- Complex filtering: `?filter=lastUpdated:gt:2023-01-01`

### 5.3. Caching

Implement appropriate caching mechanisms:

- Use ETag headers for conditional requests
- Use Cache-Control headers to indicate cacheability
- Implement server-side caching where appropriate

**Note**: Global HTTP caching headers (ETag, Cache-Control) are not currently added via middleware in `main.py`. Implementation would likely occur at the endpoint level or via dedicated caching middleware/dependencies.

### 5.4. Rate Limiting

Protect APIs from abuse:

- Implement rate limiting based on client ID or IP address *(Implemented via `presentation/middleware/rate_limiting_middleware.py` - **Middleware is registered globally**)*.
- Return rate limit information in headers (*Target Standard*):
  - `X-RateLimit-Limit`
  - `X-RateLimit-Remaining`
  - `X-RateLimit-Reset`

**Note**: While rate limiting middleware exists **and is registered**, the specific inclusion of `X-RateLimit-*` headers in responses depends on the configured `slowapi` strategy and response customization, which needs verification.

## 6. Documentation

### 6.1. OpenAPI Specification

All APIs must be documented using the OpenAPI specification:

- Define all endpoints, parameters, and responses accurately using FastAPI route decorators, Pydantic models (including `response_model`), and docstrings.
- Include detailed descriptions and examples within docstrings and model definitions.
- Use tags to organize APIs by domain.
- Document security requirements (e.g., using `Security` dependencies).

### 6.2. Documentation Tools

API documentation is automatically generated and made available through:

- Swagger UI: Interactive API documentation (typically at `/docs`).
- ReDoc: Alternative API documentation view (typically at `/redoc`).

**Note**: Given that standardized response/error structures (Section 3.3, 3.4) may not yet be globally enforced, the auto-generated OpenAPI documentation (Swagger/ReDoc) based on endpoint definitions and Pydantic models serves as the **most reliable source of truth** for current API contracts.

### 6.3. Documentation Standards

Documentation should include:

- Purpose of each endpoint
- Required permissions
- Request and response schemas
- Example requests and responses
- Error codes and handling
- Rate limiting information

## 7. Implementation Guidelines

### 7.1. FastAPI Implementation

The API layer is implemented using FastAPI:

```python
# Example API endpoint
@router.get("/patients/{patient_id}", response_model=PatientResponse)
async def get_patient(
    patient_id: UUID,
    current_user: User = Depends(get_current_user)
) -> PatientResponse:
    """
    Retrieve a patient by ID.
    
    Requires permission: READ_PATIENT
    """
    # Authorization check
    if not current_user.has_permission(Permission.READ_PATIENT):
        raise HTTPException(status_code=403, detail="Not authorized")
        
    # Get patient from application layer
    patient_service = PatientService()
    patient = await patient_service.get_patient(patient_id)
    
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
        
    # Return response
    return PatientResponse.from_domain(patient)
```

### 7.2. Input Validation

Use Pydantic for input validation:

```python
class PatientCreateRequest(BaseModel):
    first_name: str
    last_name: str
    date_of_birth: date
    gender: Optional[str] = None
    email: Optional[EmailStr] = None
    
    class Config:
        schema_extra = {
            "example": {
                "first_name": "John",
                "last_name": "Doe",
                "date_of_birth": "1980-01-01",
                "gender": "male",
                "email": "john.doe@example.com"
            }
        }
```

### 7.3. Response Models

Define explicit response models:

```python
class PatientResponse(BaseModel):
    id: UUID
    first_name: str
    last_name: str
    date_of_birth: date
    gender: Optional[str]
    created_at: datetime
    updated_at: datetime
    
    @classmethod
    def from_domain(cls, patient: Patient) -> "PatientResponse":
        return cls(
            id=patient.id,
            first_name=patient.first_name,
            last_name=patient.last_name,
            date_of_birth=patient.date_of_birth,
            gender=patient.gender,
            created_at=patient.created_at,
            updated_at=patient.updated_at
        )
```

## 8. Testing API Endpoints

### 8.1. Testing Strategy

Each API endpoint should be tested for:

- Successful operations
- Input validation
- Error handling
- Authentication and authorization
- Performance and load handling

### 8.2. Test Example

```python
async def test_get_patient_endpoint():
    # Arrange
    patient_id = UUID("00000000-0000-0000-0000-000000000001")
    mock_patient = Patient(
        id=patient_id,
        first_name="Test",
        last_name="Patient",
        date_of_birth=date(1980, 1, 1)
    )
    patient_service_mock.get_patient.return_value = mock_patient
    
    # Act
    response = await client.get(
        f"/api/v1/patients/{patient_id}",
        headers={"Authorization": f"Bearer {test_token}"}
    )
    
    # Assert
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["id"] == str(patient_id)
    assert data["firstName"] == "Test"
    assert data["lastName"] == "Patient"
```

## 9. API Versioning and Evolution

### 9.1. Versioning Strategy

- Major version changes in URL path: `/api/v1/` → `/api/v2/`
- Minor changes through backward-compatible additions
- Deprecation notices for older versions
- Scheduled sunset dates for deprecated versions

### 9.2. Backward Compatibility

When evolving APIs:

- Add new fields but don't remove existing ones
- Don't change field meanings or types
- Don't change URL structures or response formats
- Use feature flags for new functionality

## 10. API Security Checklist

Ensure all APIs implement:

- [ ] TLS for all communications
- [ ] Input validation for all parameters
- [ ] Output sanitization to prevent PHI exposure
- [ ] Proper authentication and authorization
- [ ] Rate limiting and throttling
- [ ] CORS configuration
- [ ] Content Security Policy
- [ ] No PHI in URLs, query parameters, or headers
- [ ] Audit logging of all access
- [ ] Secure error handling

---

This API Guidelines document is maintained alongside the codebase and updated as API standards evolve. Always refer to the latest version when developing new API endpoints.

Last Updated: 2025-04-20
