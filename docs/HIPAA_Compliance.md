# HIPAA Compliance

## Core HIPAA Requirements

Clarity AI implements comprehensive HIPAA compliance measures across all system components:

### Access Controls (§164.312(a)(1))

Authentication and authorization mechanisms:

```python
# JWT-based authentication with role-based access control
async def get_current_user(
    token: str = Depends(get_token_from_header),
    jwt_service: JWTService = Depends(get_jwt_service)
) -> User:
    """
    Extracts and validates the current user from a JWT token.
    """
    try:
        # Validate the token
        payload = jwt_service.validate_token(token)
        
        # Extract user information
        user_id = payload.get("user_id")
        if not user_id:
            raise credentials_exception
            
        return User(
            id=user_id,
            email=payload.get("email"),
            role=payload.get("role"),
            permissions=payload.get("permissions", [])
        )
    except Exception:
        raise credentials_exception
```

### Audit Controls (§164.312(b))

Comprehensive audit logging:

```python
# Audit logging for PHI access
class AuditLogger:
    """Implementation of audit logging for HIPAA compliance."""
    
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session
    
    async def log_phi_access(
        self,
        user_id: UUID,
        resource_type: str,
        resource_id: str,
        action: str,
        reason: str
    ) -> None:
        """Log PHI access for audit trail."""
        log_entry = AuditLogModel(
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            reason=reason,
            timestamp=datetime.now(UTC),
            ip_address=get_client_ip(),
            success=True
        )
        
        self.db_session.add(log_entry)
        await self.db_session.commit()
```

### Integrity Controls (§164.312(c)(1))

Data validation and protection:

```python
# Pydantic models for request validation
class PatientCreateRequest(BaseModel):
    """Request model for patient creation with validation."""
    
    name: str = Field(..., min_length=2, max_length=100)
    date_of_birth: date = Field(..., lt=date.today())
    status: PatientStatus
    
    class Config:
        extra = "forbid"  # Prevent additional fields
```

### Transmission Security (§164.312(e)(1))

Secure data transmission:

```python
# HTTPS enforcement middleware
@app.middleware("http")
async def https_redirect(request: Request, call_next):
    """Redirect HTTP requests to HTTPS in production."""
    if (
        settings.ENVIRONMENT == "production" and
        request.url.scheme == "http"
    ):
        url = request.url.replace(scheme="https")
        return RedirectResponse(url=str(url), status_code=301)
    
    response = await call_next(request)
    
    # Set security headers
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    
    return response
```

## PHI Protection Mechanisms

### PHI Sanitization

Response sanitization to prevent PHI leakage:

```python
# Sanitize error responses
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError
) -> JSONResponse:
    """
    Handle validation errors without exposing PHI.
    """
    # Create safe error details without exposing PHI
    safe_errors = []
    for error in exc.errors():
        # Extract location and message but sanitize values
        safe_error = {
            "loc": error["loc"],
            "msg": error["msg"],
            "type": error["type"]
        }
        safe_errors.append(safe_error)
    
    return JSONResponse(
        status_code=422,
        content={"detail": safe_errors}
    )
```

### Data Encryption

Field-level encryption for PHI:

```python
# Field encryption for sensitive data
class EncryptedString(TypeDecorator):
    """SQLAlchemy type for encrypted string fields."""
    
    impl = String
    cache_ok = False
    
    def __init__(self, length=None, **kwargs):
        super().__init__(length, **kwargs)
        self.fernet = Fernet(settings.ENCRYPTION_KEY)
    
    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return self.fernet.encrypt(value.encode()).decode()
    
    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return self.fernet.decrypt(value.encode()).decode()
```

### Access Control

Role-based access control for PHI:

```python
# Role-based access control
def require_permission(required_permission: str):
    """
    Creates a dependency that checks if the user has the required permission.
    """
    def permission_dependency(
        current_user: User = Depends(get_current_user),
        rbac_service: IRBACService = Depends(get_rbac_service)
    ) -> None:
        if not rbac_service.has_permission(
            user_id=current_user.id,
            permission=required_permission
        ):
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions"
            )
        return None
    
    return permission_dependency
```

### Session Management

Secure session handling:

```python
# JWT token service with secure defaults
class JWTService:
    """Service for JWT token operations."""
    
    def __init__(
        self,
        secret_key: str,
        algorithm: str = "HS256",
        access_token_expire_minutes: int = 30,
        refresh_token_expire_days: int = 7,
        token_blacklist_repository: Optional[ITokenBlacklistRepository] = None,
        audit_logger: IAuditLogger = None
    ):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.access_token_expire_minutes = access_token_expire_minutes
        self.refresh_token_expire_days = refresh_token_expire_days
        self.token_blacklist_repository = token_blacklist_repository
        self.audit_logger = audit_logger
    
    def create_access_token(self, data: Dict[str, Any]) -> str:
        """Create a new JWT access token."""
        to_encode = data.copy()
        
        # Set expiration
        expire = datetime.now(UTC) + timedelta(
            minutes=self.access_token_expire_minutes
        )
        to_encode.update({"exp": expire})
        
        # Create token
        token = jwt.encode(
            to_encode,
            self.secret_key,
            algorithm=self.algorithm
        )
        
        # Audit log token creation
        if self.audit_logger and "user_id" in data:
            asyncio.create_task(
                self.audit_logger.log_phi_access(
                    user_id=data["user_id"],
                    resource_type="token",
                    resource_id=str(uuid4()),
                    action="create",
                    reason="User authentication"
                )
            )
        
        return token
```

## HIPAA-Compliant API Design

### Patient Data Endpoint

```python
@router.get("/{patient_id}/records", response_model=List[MedicalRecordResponse])
async def get_patient_records(
    patient_id: UUID,
    current_user: User = Depends(get_current_user),
    hipaa_consent: bool = Depends(verify_hipaa_consent),
    record_service: IMedicalRecordService = Depends(get_medical_record_service),
    audit_logger: IAuditLogger = Depends(get_audit_logger)
) -> List[MedicalRecordResponse]:
    """
    Get all medical records for a patient.
    
    This endpoint enforces:
    1. Authentication via current_user dependency
    2. HIPAA consent verification
    3. Audit logging of PHI access
    4. Response data validation and sanitization
    """
    # Verify user has permission to access this patient's records
    await verify_patient_access(
        patient_id=patient_id,
        user=current_user,
        access_type="read"
    )
    
    # Log PHI access for audit trail
    await audit_logger.log_phi_access(
        user_id=current_user.id,
        resource_type="medical_records",
        resource_id=str(patient_id),
        action="view_all",
        reason="Clinical review"
    )
    
    # Retrieve records with required security checks
    records = await record_service.get_patient_records(
        patient_id=patient_id,
        requesting_user_id=current_user.id
    )
    
    # Convert domain entities to response models (sanitizes data)
    return [MedicalRecordResponse.from_entity(record) for record in records]
```

## Error Handling for HIPAA Compliance

```python
# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(
    request: Request,
    exc: Exception
) -> JSONResponse:
    """
    Global exception handler that prevents PHI leakage.
    """
    # Generate error ID for traceability
    error_id = str(uuid4())
    
    # Log detailed error for internal use
    logger.error(
        f"Unhandled exception ID={error_id}: {str(exc)}",
        exc_info=True,
        extra={
            "error_id": error_id,
            "path": request.url.path,
            "method": request.method
        }
    )
    
    # Return safe response without PHI
    return JSONResponse(
        status_code=500,
        content={
            "detail": "An unexpected error occurred",
            "error_id": error_id
        }
    )
```

## Security Testing

### PHI Leak Tests

```python
@pytest.mark.asyncio
async def test_no_phi_in_error_response():
    """Test that PHI is not leaked in error responses."""
    # Create a patient with PHI
    patient = Patient(
        id=uuid4(),
        name="Test Patient",
        date_of_birth=date(1980, 1, 1),
        status=PatientStatus.ACTIVE,
        provider_id=uuid4(),
        medical_record_number="PHI123456"
    )
    
    # Setup a mock repository that raises an exception with PHI
    mock_repo = Mock()
    mock_repo.get_by_id.side_effect = Exception(
        f"Error processing patient {patient.name} with MRN {patient.medical_record_number}"
    )
    
    # Create app with the mock
    app = create_test_app()
    app.dependency_overrides[get_patient_repository] = lambda: mock_repo
    
    # Make request
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.get(f"/api/v1/patients/{patient.id}")
    
    # Verify PHI is not in the response
    assert response.status_code == 500
    assert "error_id" in response.json()
    assert "detail" in response.json()
    assert patient.name not in response.text
    assert patient.medical_record_number not in response.text
```

## Audit Logging

```python
# Decorator for PHI access logging
def audit_phi_access(resource_type: str, action: str, reason: str):
    """
    Decorator to audit PHI access in repository methods.
    """
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(self, *args, **kwargs):
            # Extract user ID from context
            requesting_user_id = kwargs.get("requesting_user_id")
            
            # Get resource ID from args or kwargs
            resource_id = None
            if args and isinstance(args[0], UUID):
                resource_id = str(args[0])
            elif "id" in kwargs:
                resource_id = str(kwargs["id"])
            
            # Log access before operation
            if hasattr(self, "audit_logger") and requesting_user_id and resource_id:
                await self.audit_logger.log_phi_access(
                    user_id=requesting_user_id,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    action=action,
                    reason=reason
                )
            
            # Execute the repository method
            result = await func(self, *args, **kwargs)
            
            return result
        return wrapper
    return decorator
```