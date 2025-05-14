# HIPAA Compliance in FastAPI

This document outlines how the Clarity AI Backend ensures HIPAA compliance throughout its FastAPI implementation. It covers the technical measures, code patterns, and architectural decisions made to protect Protected Health Information (PHI).

## HIPAA Compliance Overview

The Health Insurance Portability and Accountability Act (HIPAA) establishes national standards for protecting sensitive patient health information. As a digital twin platform for psychiatric care, Clarity AI handles substantial amounts of PHI and implements comprehensive safeguards.

## Key HIPAA Requirements Implemented

### 1. Access Controls

#### Technical Implementation

```python
# app/presentation/middleware/authentication.py
class AuthenticationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Extract and validate JWT token
        token = self._extract_token(request)
        if not token:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Not authenticated"}
            )
        
        try:
            # Decode and validate token
            user_data = await self.jwt_service.decode_access_token(token)
            
            # Set user in request state
            request.state.user = User(**user_data)
            
            # Proceed with request
            response = await call_next(request)
            return response
            
        except JWTError:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Invalid authentication credentials"}
            )
```

#### Role-Based Access Control

```python
# app/presentation/dependencies/auth.py
async def verify_has_role(
    required_roles: List[str],
    current_user: User = Depends(get_current_user)
) -> User:
    """Verify that the current user has at least one of the required roles."""
    if not any(role in current_user.roles for role in required_roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"User does not have required role(s): {', '.join(required_roles)}"
        )
    return current_user

# Usage in endpoints
@router.get("/{patient_id}")
async def get_patient(
    patient_id: UUID,
    current_user: User = Depends(Depends(lambda: verify_has_role(["clinician", "admin"])))
):
    # Endpoint implementation...
```

### 2. Audit Controls

The system maintains comprehensive audit logs of all PHI access and modifications:

```python
# app/infrastructure/security/audit/middleware.py
class AuditLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        
        # Create audit log entry
        audit_entry = {
            "request_id": request.state.request_id,
            "timestamp": datetime.utcnow().isoformat(),
            "method": request.method,
            "path": request.url.path,
            "user_id": getattr(request.state, "user", {}).get("id", "anonymous"),
            "user_ip": request.client.host if request.client else None,
            "status_code": None,
            "duration_ms": None,
            "resource_type": self._determine_resource_type(request.url.path),
            "resource_id": self._extract_resource_id(request.url.path),
            "action": self._determine_action(request.method, request.url.path)
        }
        
        try:
            # Process the request
            response = await call_next(request)
            
            # Update audit entry with response info
            audit_entry["status_code"] = response.status_code
            audit_entry["duration_ms"] = round((time.time() - start_time) * 1000, 2)
            
            # Write audit log asynchronously
            background_tasks = BackgroundTasks()
            background_tasks.add_task(self._write_audit_log, audit_entry)
            response.background = background_tasks
            
            return response
            
        except Exception as e:
            # Log error in audit trail
            audit_entry["status_code"] = 500
            audit_entry["error"] = str(e)
            audit_entry["duration_ms"] = round((time.time() - start_time) * 1000, 2)
            
            # Write audit log
            await self._write_audit_log(audit_entry)
            
            # Re-raise the exception
            raise
```

### 3. PHI Encryption

PHI is encrypted both at rest and in transit:

#### Database Encryption

```python
# app/domain/value_objects/encrypted_phi.py
from app.infrastructure.security.encryption import get_encryption_service

class EncryptedPHI:
    """Value object for encrypted PHI data."""
    
    def __init__(self, plaintext: str = None, ciphertext: str = None):
        self._encryption_service = get_encryption_service()
        
        if plaintext is not None:
            self.ciphertext = self._encryption_service.encrypt(plaintext)
        elif ciphertext is not None:
            self.ciphertext = ciphertext
        else:
            raise ValueError("Either plaintext or ciphertext must be provided")
    
    def get_decrypted(self) -> str:
        """Decrypt and return the PHI."""
        return self._encryption_service.decrypt(self.ciphertext)
```

#### Usage in Models

```python
# app/infrastructure/persistence/sqlalchemy/models/patient.py
class PatientModel(Base):
    __tablename__ = "patients"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    # Non-PHI fields stored normally
    status = Column(String, nullable=False)
    
    # PHI fields stored encrypted
    _first_name = Column("first_name_encrypted", String, nullable=False)
    _last_name = Column("last_name_encrypted", String, nullable=False)
    _date_of_birth = Column("date_of_birth_encrypted", String, nullable=False)
    
    @hybrid_property
    def first_name(self) -> str:
        return EncryptedPHI(ciphertext=self._first_name).get_decrypted()
    
    @first_name.setter
    def first_name(self, value: str) -> None:
        self._first_name = EncryptedPHI(plaintext=value).ciphertext
    
    # Similar for other PHI fields...
```

### 4. Transmission Security

All API communications are secured with TLS:

```python
# main.py
import uvicorn

if __name__ == "__main__":
    # In production, always use HTTPS
    if settings.ENVIRONMENT == "production":
        uvicorn.run(
            "app.main:app",
            host=settings.HOST,
            port=settings.PORT,
            ssl_keyfile=settings.SSL_KEYFILE,
            ssl_certfile=settings.SSL_CERTFILE,
            ssl_ca_certs=settings.SSL_CA_CERTS
        )
    else:
        uvicorn.run(
            "app.main:app",
            host=settings.HOST,
            port=settings.PORT
        )
```

### 5. Integrity Controls

Data integrity is ensured through validation and checksums:

```python
# app/presentation/api/v1/schemas/biometric.py
class BiometricDataCreate(BaseModel):
    patient_id: UUID
    timestamp: datetime
    data_type: str
    value: float
    unit: str
    device_id: Optional[str] = None
    
    @validator("data_type")
    def validate_data_type(cls, v):
        allowed_types = ["heart_rate", "blood_pressure", "respiratory_rate", "temperature"]
        if v not in allowed_types:
            raise ValueError(f"Data type must be one of: {', '.join(allowed_types)}")
        return v
    
    @validator("value")
    def validate_value(cls, v, values):
        if "data_type" in values:
            # Apply type-specific validation
            if values["data_type"] == "heart_rate" and (v < 30 or v > 220):
                raise ValueError("Heart rate must be between 30 and 220")
            # Add other validations...
        return v
```

### 6. PHI Sanitization in Logs

PHI is removed from logs using pattern matching:

```python
# app/presentation/middleware/logging.py
class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Create sanitized request data
        sanitized_headers = self._sanitize_headers(dict(request.headers))
        sanitized_query_params = self._sanitize_data(dict(request.query_params))
        
        # Log the request with sanitized data
        request_log = {
            "request_id": request.state.request_id,
            "method": request.method,
            "path": request.url.path,
            "headers": sanitized_headers,
            "query_params": sanitized_query_params
        }
        
        # Log request body for POST/PUT/PATCH, but sanitize it
        if request.method in ["POST", "PUT", "PATCH"]:
            body = await request.body()
            body_text = body.decode("utf-8")
            
            # Sanitize the body content
            sanitized_body = self._sanitize_data(body_text)
            request_log["body"] = sanitized_body
        
        # Log request data
        logger.info(f"Request: {json.dumps(request_log)}")
        
        # Continue processing the request
        response = await call_next(request)
        
        # Similar sanitization for response logging...
        return response
    
    def _sanitize_data(self, data):
        """Sanitize potential PHI from data."""
        if isinstance(data, str):
            # Sanitize patterns like SSNs, phone numbers, email addresses
            data = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]", data)
            data = re.sub(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", "[REDACTED_PHONE]", data)
            data = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "[REDACTED_EMAIL]", data)
            
            # Sanitize names, DOB, etc. by looking for known field names
            data = re.sub(r'"(first_name|last_name|dob)":\s*"[^"]*"', r'"\1":"[REDACTED]"', data)
            
            return data
        elif isinstance(data, dict):
            # Recursively sanitize dictionary values
            sanitized = {}
            for key, value in data.items():
                # Skip sanitizing authentication tokens
                if key.lower() in ["authorization", "password", "token"]:
                    sanitized[key] = "[REDACTED]"
                # Identify and redact PHI fields
                elif key.lower() in ["first_name", "last_name", "dob", "date_of_birth", "ssn", "address"]:
                    sanitized[key] = "[REDACTED]"
                else:
                    sanitized[key] = self._sanitize_data(value)
            return sanitized
        elif isinstance(data, list):
            # Recursively sanitize list items
            return [self._sanitize_data(item) for item in data]
        else:
            return data
```

### 7. Error Handling to Prevent PHI Leakage

Custom error handlers prevent PHI from appearing in error responses:

```python
# app/app_factory.py
@app_instance.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # Log the full, internal error for debugging
    logger.error(f"Unhandled exception: {str(exc)}", exc_info=True)
    
    # Generate a unique error reference for tracking
    error_id = str(uuid4())
    
    # Return a sanitized error response with no PHI
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "An unexpected error occurred",
            "error_id": error_id,  # For correlating with logs
        }
    )
```

### 8. Session Management

Automatic session timeout for security:

```python
# app/infrastructure/security/jwt/jwt_service.py
class JWTService(JWTServiceInterface):
    def __init__(self, settings: Settings):
        self.secret_key = settings.JWT_SECRET_KEY
        self.algorithm = settings.JWT_ALGORITHM
        self.access_token_expire_minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES
        self.refresh_token_expire_days = settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS
        self.issuer = settings.JWT_ISSUER
        self.audience = settings.JWT_AUDIENCE
    
    async def create_access_token(self, data: dict) -> str:
        """Create a JWT access token with appropriate expiration."""
        to_encode = data.copy()
        
        # Set expiration time
        expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        
        # Add claims
        to_encode.update({
            "exp": expire,
            "iat": datetime.utcnow(),
            "iss": self.issuer,
            "aud": self.audience
        })
        
        # Create signed token
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
```

### 9. Emergency Access Procedure

The system supports emergency access to PHI with special logging:

```python
# app/presentation/api/v1/routes/emergency.py
@router.post("/emergency-access/{patient_id}")
async def emergency_access(
    patient_id: UUID,
    reason: EmergencyAccessReason,
    current_user: User = Depends(get_current_user),
    audit_service = Depends(get_audit_service)
):
    """Emergency access endpoint for authorized clinicians."""
    
    # Record emergency access with detailed audit
    await audit_service.record_emergency_access(
        user_id=current_user.id,
        patient_id=str(patient_id),
        reason=reason.reason,
        justification=reason.justification
    )
    
    # Fetch patient data with elevated permissions
    patient_data = await emergency_service.get_patient_data(patient_id)
    
    return patient_data
```

## HIPAA-Compliant API Design Patterns

### 1. Use UUIDs, Not Personal Identifiers

```python
# Good - Uses UUID
@router.get("/patients/{patient_id}")
async def get_patient(patient_id: UUID):
    # Implementation...

# Bad - Uses MRN or name
@router.get("/patients/by-mrn/{medical_record_number}")  # Avoid this pattern
async def get_patient_by_mrn(medical_record_number: str):
    # Implementation...
```

### 2. Minimize PHI in Responses

```python
# app/presentation/api/v1/schemas/patient.py
class PatientPublicResponse(BaseModel):
    """Public view with minimal PHI."""
    id: UUID
    status: str
    created_at: datetime
    
class PatientDetailedResponse(BaseModel):
    """Detailed view with PHI, requires proper authorization."""
    id: UUID
    first_name: str
    last_name: str
    date_of_birth: datetime
    status: str
    created_at: datetime
    # Other PHI fields...

# Usage in endpoints
@router.get("/patients", response_model=List[PatientPublicResponse])
async def list_patients():
    # Returns minimal PHI

@router.get("/patients/{patient_id}", response_model=PatientDetailedResponse)
async def get_patient_details(
    patient_id: UUID,
    current_user: User = Depends(verify_patient_access)
):
    # Returns full PHI with authorization check
```

### 3. Parameterized Database Queries

```python
# app/infrastructure/persistence/sqlalchemy/repositories/patient_repository.py
async def search_patients(self, search_term: str) -> List[Patient]:
    """Search patients using parameterized queries."""
    search_pattern = f"%{search_term}%"
    
    # Use parameterized queries, never string interpolation
    result = await self._session.execute(
        select(PatientModel).where(
            or_(
                PatientModel.first_name.like(search_pattern),
                PatientModel.last_name.like(search_pattern)
            )
        )
    )
    
    patient_models = result.scalars().all()
    return [Patient.from_orm(model) for model in patient_models]
```

## HIPAA Compliance Testing

The codebase includes tests specifically for verifying HIPAA compliance:

```python
# app/tests/security/test_phi_protection.py
@pytest.mark.asyncio
async def test_no_phi_in_error_responses(authenticated_client):
    """Test that PHI is not leaked in error responses."""
    # Attempt to cause an error with PHI in the request
    payload = {
        "first_name": "John",
        "last_name": "Doe",
        "date_of_birth": "1980-01-01",
        "invalid_field": "This should cause an error"
    }
    
    response = await authenticated_client.post("/api/v1/patients/", json=payload)
    
    # Verify error response doesn't contain PHI
    assert response.status_code == 422
    error_content = response.json()
    
    # Ensure no PHI values appear in the error message
    assert "John" not in json.dumps(error_content)
    assert "Doe" not in json.dumps(error_content)
    assert "1980-01-01" not in json.dumps(error_content)

@pytest.mark.asyncio
async def test_phi_encryption_at_rest(db_session):
    """Test that PHI is encrypted in the database."""
    # Create a patient with PHI
    patient = PatientModel(
        id=uuid4(),
        first_name="Jane",
        last_name="Smith",
        date_of_birth=datetime(1990, 5, 15)
    )
    
    db_session.add(patient)
    await db_session.commit()
    
    # Query the database directly to check raw data
    result = await db_session.execute(
        text("SELECT first_name_encrypted FROM patients WHERE id = :id"),
        {"id": str(patient.id)}
    )
    encrypted_first_name = result.scalar_one()
    
    # Verify data is actually encrypted
    assert "Jane" != encrypted_first_name
    assert len(encrypted_first_name) > 0
    
    # Verify decryption works properly
    assert patient.first_name == "Jane"
```

## Conclusion

The Clarity AI Backend implements a comprehensive HIPAA compliance strategy through:

1. **Technical Controls**: Authentication, encryption, TLS
2. **Architectural Patterns**: Clean separation of concerns, proper abstraction
3. **Code Practices**: Input validation, output sanitization, secure error handling
4. **Audit Mechanisms**: Comprehensive logging of all PHI access
5. **Testing Strategy**: Specific tests for HIPAA compliance requirements

This approach ensures that PHI is properly protected throughout the system, meeting both the letter and spirit of HIPAA regulations while maintaining application performance and developer productivity. 