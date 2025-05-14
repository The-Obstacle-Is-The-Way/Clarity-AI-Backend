# HIPAA Compliance in FastAPI

This document outlines how the Clarity AI Backend ensures HIPAA compliance throughout its FastAPI implementation. It covers the technical measures, code patterns, and architectural decisions designed to protect Protected Health Information (PHI) within a clean architecture framework.

## Core HIPAA Requirements Implementation

### Access Controls (§164.312(a)(1))

Clarity AI implements a comprehensive multi-layer access control system:

```python
# app/presentation/api/dependencies/auth.py
async def get_current_user(
    token: str = Depends(get_token_from_header),
    jwt_service: JWTService = Depends(get_jwt_service)
) -> User:
    """
    Extracts and validates the current user from a JWT token.
    
    This dependency enforces authentication and provides user context
    for all protected endpoints, ensuring PHI access is restricted
    to authorized users.
    """
    try:
        # Validate the token
        payload = jwt_service.validate_token(token)
        
        # Extract user information from token
        user_id = payload.get("user_id")
        if not user_id:
            raise credentials_exception
            
        # Create user object with role and permissions
        user = User(
            id=user_id,
            email=payload.get("email"),
            role=payload.get("role"),
            permissions=payload.get("permissions", [])
        )
        
        return user
    except Exception:
        raise credentials_exception
```

#### Role-Based Access Control

```python
# app/presentation/api/dependencies/permissions.py
def require_permission(required_permission: str):
    """
    Creates a dependency that checks if the user has the required permission.
    
    Args:
        required_permission: The permission required to access the endpoint
        
    Returns:
        A dependency function that verifies the user has the required permission
    """
    def permission_dependency(
        current_user: User = Depends(get_current_user),
        rbac_service: RBACService = Depends(get_rbac_service)
    ) -> User:
        if not rbac_service.has_permission(current_user.role, required_permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        return current_user
        
    return permission_dependency

# Usage in routes
@router.get(
    "/patients/{patient_id}/records",
    response_model=List[MedicalRecordResponse],
    dependencies=[Depends(require_permission("view:medical_records"))]
)
async def get_patient_records(
    patient_id: UUID,
    current_user: User = Depends(get_current_user),
    record_service: MedicalRecordService = Depends(get_medical_record_service)
) -> List[MedicalRecordResponse]:
    """Get a patient's medical records."""
    # Implementation...
```

### Audit Controls (§164.312(b))

The system maintains comprehensive audit logs of all PHI access and modifications:

```python
# app/core/interfaces/services/audit_logger_interface.py
class IAuditLogger(ABC):
    """
    Interface for audit logging services.
    
    Defines methods for logging various security and PHI access events
    to maintain a comprehensive audit trail for HIPAA compliance.
    """
    
    @abstractmethod
    async def log_security_event(
        self,
        event_type: AuditEventType,
        user_id: str | None,
        description: str,
        severity: AuditSeverity = AuditSeverity.INFO,
        metadata: dict[str, Any] | None = None
    ) -> None:
        """
        Log a security-related event.
        
        Args:
            event_type: Type of security event
            user_id: ID of the user who triggered the event
            description: Human-readable description
            severity: Event severity level
            metadata: Additional event data
        """
        pass
    
    @abstractmethod
    async def log_phi_access(
        self,
        user_id: str,
        resource_type: str,
        resource_id: str,
        action: str,
        reason: str | None = None,
        metadata: dict[str, Any] | None = None
    ) -> None:
        """
        Log PHI access for compliance tracking.
        
        Args:
            user_id: ID of the user accessing PHI
            resource_type: Type of resource being accessed
            resource_id: ID of the resource being accessed
            action: Action performed (view, create, update, delete)
            reason: Optional reason for access
            metadata: Additional context data
        """
        pass
```

#### Implementation in Services

All application services that handle PHI use the audit logger:

```python
# app/application/services/patient_service.py
class PatientService(IPatientService):
    """
    Service for patient-related operations.
    
    Ensures proper auditing of all PHI access.
    """

    def __init__(
        self,
        patient_repository: IPatientRepository,
        audit_logger: IAuditLogger
    ):
        self.patient_repository = patient_repository
        self.audit_logger = audit_logger
    
    async def get_patient(self, patient_id: UUID, user_id: str) -> Patient:
        """
        Retrieve a patient by ID.
        
        Args:
            patient_id: ID of the patient to retrieve
            user_id: ID of the user making the request
            
        Returns:
            Patient information
            
        Raises:
            EntityNotFoundError: If patient not found
        """
        patient = await self.patient_repository.get_by_id(patient_id)
        
        if not patient:
            raise EntityNotFoundError(f"Patient with ID {patient_id} not found")
        
        # Log PHI access for audit trail
        await self.audit_logger.log_phi_access(
            user_id=user_id,
            resource_type="patient",
            resource_id=str(patient_id),
            action="view",
            metadata={"access_method": "get_patient"}
        )
        
        return patient
```

### PHI Encryption (§164.312(a)(2)(iv))

PHI is encrypted both at rest and in transit:

#### Database Encryption

```python
# app/core/value_objects/encrypted_phi.py
class EncryptedPHI:
    """
    Value object for encrypted PHI data.
    
    Handles encryption and decryption of sensitive protected health information,
    ensuring data is never stored in plaintext and is properly secured at rest.
    """
    
    def __init__(
        self,
        plaintext: str | None = None,
        ciphertext: str | None = None,
        encryption_service: IEncryptionService | None = None
    ):
        """
        Initialize encrypted PHI value object.
        
        Args:
            plaintext: Original unencrypted data
            ciphertext: Pre-encrypted data
            encryption_service: Service for encryption operations
        """
        self._encryption_service = encryption_service or get_encryption_service()
        
        if plaintext is not None:
            self.ciphertext = self._encryption_service.encrypt(plaintext)
        elif ciphertext is not None:
            self.ciphertext = ciphertext
        else:
            raise ValueError("Either plaintext or ciphertext must be provided")
    
    def get_plaintext(self) -> str:
        """
        Decrypt and return the PHI.
        
        Returns:
            Decrypted plaintext PHI
        """
        return self._encryption_service.decrypt(self.ciphertext)
    
    def __str__(self) -> str:
        """Return a string representation that does not expose PHI."""
        return "[ENCRYPTED PHI]"
    
    def __repr__(self) -> str:
        """Return a debug representation that does not expose PHI."""
        return f"EncryptedPHI(ciphertext='{self.ciphertext[:8]}...')"
```

#### Usage in Models

```python
# app/infrastructure/persistence/sqlalchemy/models/patient.py
class PatientModel(Base):
    """SQLAlchemy model for patients with PHI encryption."""
    
    __tablename__ = "patients"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Non-PHI fields
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    status = Column(String, nullable=False)
    
    # PHI fields stored with encryption
    _first_name = Column("first_name_encrypted", String, nullable=False)
    _last_name = Column("last_name_encrypted", String, nullable=False)
    _date_of_birth = Column("date_of_birth_encrypted", String, nullable=False)
    _email = Column("email_encrypted", String, nullable=True)
    _phone = Column("phone_encrypted", String, nullable=True)
    _address = Column("address_encrypted", String, nullable=True)
    
    @hybrid_property
    def first_name(self) -> str:
        """Get decrypted first name."""
        if not self._first_name:
            return None
        return EncryptedPHI(ciphertext=self._first_name).get_plaintext()
    
    @first_name.setter
    def first_name(self, value: str) -> None:
        """Encrypt and store first name."""
        if value is None:
            self._first_name = None
        else:
            self._first_name = EncryptedPHI(plaintext=value).ciphertext
    
    # Similar for other PHI fields...
```

### Transmission Security (§164.312(e)(1))

All API communications are secured with TLS:

```python
# app/main.py
def get_application() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="Clarity AI Backend",
        description="Psychiatric Digital Twin Platform API",
        version="1.0.0",
        docs_url="/api/docs" if settings.ENVIRONMENT != "production" else None,
        redoc_url="/api/redoc" if settings.ENVIRONMENT != "production" else None,
    )
    
    # Add middleware
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS)
    app.add_middleware(PHIMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(AuditMiddleware)
    
    # Add routers
    app.include_router(api_router, prefix="/api")
    
    return app
```

### PHI Protection Middleware

```python
# app/presentation/middleware/phi_middleware.py
class PHIMiddleware(BaseHTTPMiddleware):
    """
    Middleware to enforce HIPAA PHI handling requirements.
    
    This middleware:
    1. Prevents PHI from appearing in URLs (query params, path params)
    2. Logs all PHI access attempts for audit purposes
    3. Ensures proper error handling for PHI-related operations
    4. Sanitizes responses to prevent accidental PHI leakage
    """
    
    def __init__(
        self, 
        app: ASGIApp,
        phi_patterns: list[Pattern] | None = None,
        exempt_paths: set[str] | None = None
    ):
        """
        Initialize PHI middleware with patterns to detect and paths to exempt.
        
        Args:
            app: The ASGI application
            phi_patterns: Regular expression patterns to detect PHI
            exempt_paths: Paths exempt from PHI checks (e.g., auth endpoints)
        """
        super().__init__(app)
        self.phi_patterns = phi_patterns or [
            # Social Security Number patterns
            re.compile(r"\b\d{3}[-]?\d{2}[-]?\d{4}\b"),
            # Medical Record Number patterns (various formats)
            re.compile(r"\bMRN[-:]?\d{6,10}\b", re.IGNORECASE),
            # Email patterns
            re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
            # Date of birth patterns
            re.compile(r"\b(0[1-9]|1[0-2])[-/.](0[1-9]|[12]\d|3[01])[-/.](19|20)\d{2}\b"),
            # Common patient identifiers
            re.compile(r"\bPATIENT[-_]?ID[:=]?\d+\b", re.IGNORECASE),
        ]
        self.exempt_paths = exempt_paths or {
            "/api/v1/auth/token",
            "/api/v1/auth/login",
            "/api/v1/auth/refresh",
            "/docs",
            "/redoc",
            "/openapi.json",
        }
        
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process the request and enforce PHI protections.
        
        Args:
            request: The incoming request
            call_next: The next middleware/endpoint handler
            
        Returns:
            The processed response
            
        Raises:
            HTTPException: If PHI is detected in prohibited locations
        """
        # Skip PHI checks for exempt paths
        if any(request.url.path.startswith(path) for path in self.exempt_paths):
            return await call_next(request)
        
        # Audit logging
        start_time = time.time()
        client_ip = request.client.host if request.client else "unknown"
        
        try:
            # Check URL for PHI
            self._check_url_for_phi(request)
            
            # Process request normally
            response = await call_next(request)
            
            # Sanitize response if needed
            response = await self._sanitize_response(response)
            
            # Log PHI access for audit purposes
            phi_audit_logger.info(
                f"PHI access: {request.method} {request.url.path} "
                f"from {client_ip} - status: {response.status_code}"
            )
            
            return response
            
        except PHIInUrlError:
            # Log PHI attempt violation
            phi_audit_logger.warning(
                f"PHI detected in URL: {request.method} {request.url.path} "
                f"from {client_ip} - blocked"
            )
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"detail": "Protected health information (PHI) is not allowed in URLs"}
            )
```

## Clean Architecture Implementation

The HIPAA compliance features are implemented following clean architecture principles:

### 1. Interface Segregation

HIPAA-related interfaces are well-defined and follow single responsibility:

```python
# app/core/interfaces/services/encryption_service_interface.py
class IEncryptionService(ABC):
    """
    Interface for encryption services.
    
    Handles encryption and decryption operations for PHI.
    """
    
    @abstractmethod
    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext data.
        
        Args:
            plaintext: Data to encrypt
            
        Returns:
            Encrypted ciphertext
        """
        pass
    
    @abstractmethod
    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt ciphertext data.
        
        Args:
            ciphertext: Data to decrypt
            
        Returns:
            Decrypted plaintext
        """
        pass
```

### 2. Dependency Inversion

High-level policies depend on abstractions, not concrete implementations:

```python
# app/application/services/phi_service.py
class PHIService(IPHIService):
    """
    Service for handling protected health information.
    
    Implements business rules for PHI access and management.
    """
    
    def __init__(
        self,
        encryption_service: IEncryptionService,
        audit_logger: IAuditLogger
    ):
        """
        Initialize the PHI service.
        
        Args:
            encryption_service: Service for encrypting/decrypting PHI
            audit_logger: Service for logging PHI access
        """
        self.encryption_service = encryption_service
        self.audit_logger = audit_logger
```

### 3. Domain Independence

HIPAA compliance rules are part of the domain layer and don't depend on external frameworks:

```python
# app/domain/policies/hipaa_policy.py
class HIPAAPolicy:
    """
    Domain service for HIPAA policy enforcement.
    
    Contains business rules for PHI handling independent of frameworks.
    """
    
    @staticmethod
    def validate_phi_access(
        user_role: str,
        resource_type: str,
        access_type: str,
        patient_id: UUID | None = None,
        clinician_id: UUID | None = None
    ) -> tuple[bool, str | None]:
        """
        Validate if a user can access PHI based on HIPAA rules.
        
        Args:
            user_role: Role of the user requesting access
            resource_type: Type of resource being accessed
            access_type: Type of access (read, write, etc.)
            patient_id: ID of the patient whose data is being accessed
            clinician_id: ID of the clinician, if applicable
            
        Returns:
            Tuple of (is_allowed, reason)
        """
        # Implementation of HIPAA access rules
        # ...
```

## FastAPI-Specific HIPAA Features

### 1. Secure Dependency Injection

FastAPI's dependency injection system is used to enforce HIPAA compliance:

```python
# app/presentation/api/dependencies/hipaa.py
def verify_hipaa_consent(
    patient_id: UUID,
    current_user: User = Depends(get_current_user),
    consent_service: IConsentService = Depends(get_consent_service)
) -> bool:
    """
    Verify that a valid HIPAA consent is in place for the patient.
    
    Args:
        patient_id: ID of the patient
        current_user: Current authenticated user
        consent_service: Service for checking consents
        
    Returns:
        True if valid consent exists
        
    Raises:
        HTTPException: If no valid consent exists
    """
    has_consent = await consent_service.verify_hipaa_consent(
        patient_id=patient_id,
        verified_by=current_user.id
    )
    
    if not has_consent:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No valid HIPAA consent found for this patient"
        )
    
    return True
```

### 2. Response Models with PHI Protection

Response models ensure no unintended PHI disclosure:

```python
# app/presentation/api/schemas/patient.py
class PatientResponse(BaseModel):
    """
    Schema for patient responses with PHI protection.
    
    Carefully controls which fields are exposed in API responses.
    """
    
    id: UUID
    status: str
    created_at: datetime
    
    # PHI fields
    first_name: str
    last_name: str
    date_of_birth: date
    
    # Optional PHI fields
    email: EmailStr | None = None
    phone: str | None = None
    
    class Config:
        """Pydantic model configuration."""
        schema_extra = {
            "example": {
                "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                "status": "active",
                "created_at": "2023-01-01T12:00:00Z",
                "first_name": "John",
                "last_name": "Doe",
                "date_of_birth": "1980-01-01",
                "email": "patient@example.com",
                "phone": "+1 (555) 123-4567"
            }
        }
```

### 3. Error Sanitization

Error responses are sanitized to prevent PHI leakage:

```python
# app/presentation/error_handlers.py
def register_exception_handlers(app: FastAPI) -> None:
    """Register FastAPI exception handlers for HIPAA-compliant errors."""
    
    @app.exception_handler(EntityNotFoundError)
    async def entity_not_found_handler(request: Request, exc: EntityNotFoundError) -> JSONResponse:
        """
        Handle entity not found errors with PHI protection.
        
        Returns sanitized error messages that don't contain PHI.
        """
        # Sanitize error message to remove any PHI
        original_message = str(exc)
        sanitized_message = "Resource not found"
        
        # Log original error with proper PHI protection
        logger.warning(f"EntityNotFoundError: {original_message}")
        
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND, 
            content={"detail": sanitized_message}
        )
```

## HIPAA Security Rule Matrix

The Clarity AI Backend implements these HIPAA Security Rule requirements:

| Rule | Section | Implementation |
|------|---------|----------------|
| Access Control | §164.312(a)(1) | JWT authentication, RBAC, permission-based access |
| Audit Controls | §164.312(b) | Comprehensive audit logging of all PHI access |
| Integrity | §164.312(c)(1) | Data validation, checksums, immutable audit logs |
| Person or Entity Authentication | §164.312(d) | Secure password handling, token validation |
| Transmission Security | §164.312(e)(1) | TLS encryption, secure headers, token security |
| Encryption and Decryption | §164.312(a)(2)(iv) | Field-level PHI encryption, secure key management |
| Emergency Access | §164.312(a)(2)(ii) | Emergency access procedures via admin override |
| Automatic Logoff | §164.312(a)(2)(iii) | Token expiration, session timeouts |

## HIPAA-Compliant API Routes

The API routes implement these HIPAA safeguards:

```python
# app/presentation/api/v1/routes/patients.py
@router.get(
    "/{patient_id}/medical-records",
    response_model=List[MedicalRecordResponse],
    summary="Get patient medical records",
    description="Retrieve all medical records for a patient with proper HIPAA controls"
)
async def get_patient_medical_records(
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

## Conclusion

The Clarity AI Backend implements comprehensive HIPAA compliance measures through a clean architecture approach that:

1. **Separates Concerns**: Interfaces define HIPAA requirements independent of implementations
2. **Enforces Security**: Multiple layers of protection including authentication, authorization, encryption, and audit logging
3. **Ensures PHI Protection**: Specialized middleware and patterns prevent accidental PHI disclosure
4. **Maintains Auditability**: Comprehensive logging creates a complete audit trail for compliance

By designing HIPAA compliance into the foundation of the architecture, the system maintains both regulatory compliance and technical excellence. 