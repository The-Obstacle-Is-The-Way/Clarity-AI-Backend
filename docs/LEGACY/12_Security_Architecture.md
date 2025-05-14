# Security Architecture

**Status:** This document outlines the **target** security architecture. The current implementation is **minimal**, and many critical controls described here are **aspirational or missing**. A summary of the implementation status is provided in Section 10.

## Overview

The Novamind platform *is intended to prioritize* security at every level, with special attention to HIPAA compliance and protection of Patient Health Information (PHI). This document outlines the *target* comprehensive security architecture.

## Security Principles

The *target* security architecture adheres to these fundamental principles:

1. **Defense in Depth** - Multiple security controls at different layers
2. **Least Privilege** - Access limited to only what is necessary
3. **Zero Trust** - Continuous verification regardless of location
4. **Secure by Design** - Security integrated from the beginning, not added later
5. **Privacy by Default** - PHI protection as the default state
6. **Principle of Fail Secure** - Systems fail into a secure state
7. **Continuous Verification** - Ongoing monitoring and testing

## HIPAA Compliance Framework

As a healthcare platform handling PHI, Novamind *must implement* a comprehensive HIPAA compliance framework:

### Administrative Safeguards *(Organizational Policies/Procedures - Status TBD)*
*(Details omitted for brevity - relate to policies, training, risk analysis, etc.)*

### Physical Safeguards *(Infrastructure Dependent - Status TBD)*
*(Details omitted for brevity - relate to facility/workstation/media security)*

### Technical Safeguards (Target)

1. **Access Control**
   - Unique user identification *(Partially exists via user models, but auth/session missing)*
   - Emergency access procedure *(Aspirational)*
   - Automatic logoff *(Aspirational)*
   - Encryption and decryption *(Aspirational)*
2. **Audit Controls**
   - Recording and examining activity *(Aspirational/Missing)*
3. **Integrity Controls**
   - Data authentication *(Aspirational)*
4. **Transmission Security**
   - Integrity controls *(Aspirational)*
   - Encryption *(Aspirational: TLS requires infrastructure)*

*Current Status (Technical Safeguards): Largely aspirational. Basic user identification might exist, but core technical controls like implemented AuthN/AuthZ, Audit Logging, and Encryption are missing.*

## Data Security (Target/Aspirational)

### Data Classification *(Policy - Status TBD)*
*Classification scheme defined, implementation TBD.*

### Data Encryption (Aspirational)
Encryption *is required* at multiple levels:
1. **Encryption at Rest** (AES-256 for DB, Files, Backups) *(Aspirational)*
2. **Encryption in Transit** (TLS 1.3) *(Aspirational)*
3. **End-to-End Encryption** *(Aspirational)*
4. **Key Management** (Secure storage, rotation, HSM) *(Aspirational)*

*Current Status: Encryption is not implemented.*

## Identity and Access Management (Largely Aspirational)

### Authentication (Aspirational)
Multiple *target* methods:
1. Password-Based (Hashing, Policies) *(Hashing functions might exist in `core/security`, full flow missing)*
2. MFA (TOTP, Push) *(Aspirational)*
3. SSO (SAML, OIDC) *(Aspirational)*
4. API Authentication (JWT, API Keys, OAuth2) *(Aspirational: Core implementation missing)*

*Current Status: Authentication system is not implemented. Placeholder auth files and dependencies exist, but no functional login/token validation.* 

### Authorization (Aspirational)
Role-based access control (RBAC) *is the target*:
1. **Core Roles** (Admin, Clinician, Researcher, Patient, Support) *(Roles might be defined in models, TBD)*
2. **Permission Model** (Granular, Resource-based) *(Aspirational)*
3. **Context-Aware Authorization** *(Aspirational)*

*Current Status: Authorization checks are missing from API endpoints. The RBAC framework is not implemented.*

### Identity Lifecycle Management *(Policy/Process - Status TBD)*
*Provisioning, Access Reviews, etc. are policy/process dependent.*

## Application Security

### Secure Development Lifecycle *(Process - Status TBD)*
*Requires implementing processes like threat modeling, secure code reviews, SAST/DAST scanning.*

### Common Security Controls (Target/Partial)

1. **Input Validation**
   - Strict schema validation with Pydantic *(Implemented in API layer)*
   - Input sanitization *(TBD)*
   - Output encoding *(TBD)*
2. **Authentication & Authorization** *(Aspirational/Missing)*
3. **Session Management** *(Aspirational/Missing)*
4. **Error Handling**
   - Security-aware error handling *(Partially Implemented: Basic exception catching, but lacks secure formatting, PHI scrubbing, correlation IDs)*
   - No sensitive information in errors *(Partially Implemented: Basic HTTPExceptions used, but needs proper handlers)*
   - Detailed internal logging *(TBD)*
5. **Secrets Management** *(Aspirational)*
   - No hardcoded secrets *(Needs verification)*
   - Secure storage (Vault) *(Aspirational)*

### Specific HIPAA Protections (Target/Partial)

1. **PHI Access Controls** *(Aspirational/Missing)*
2. **PHI in URLs**
   - No PHI in URLs or query parameters *(Implemented: Uses UUIDs)*
3. **PHI in Logs**
   - Automated PHI detection and redaction *(Partially Implemented: PHI detection service logic exists in `infrastructure/ml/phi_detection/`, but integration with logging/middleware TBD)*

*Current Status: Pydantic input validation and use of non-PHI URL identifiers are implemented. Secure error handling is basic. PHI detection logic exists but is not fully integrated. Core AuthN/AuthZ, Session Management, Secrets Management, and PHI Logging/Access Controls are missing.*

## API Security (Largely Aspirational)

### API Protection Mechanisms (Aspirational)
1. Request Validation *(Implemented via Pydantic)*
2. Rate Limiting *(Aspirational)*
3. API Firewall *(Aspirational)*

### API Security Standards (Aspirational)
1. OAuth 2.0 & OpenID Connect *(Aspirational)*
2. API Keys & JWT *(Aspirational: Implementation missing)*

*Current Status: Only basic request validation via Pydantic is confirmed. Rate limiting, API firewalls, and standard authentication mechanisms are missing.*

## Infrastructure Security (Aspirational)
*(Details omitted for brevity - Network Segmentation, WAF, TLS, Cloud Security, Container Security, Host Security require infrastructure implementation)*

*Current Status: Aspirational.*

## Logging and Monitoring (Largely Aspirational)

### Security Logging (Aspirational)
*Log Sources, Log Management, Audit Logging definitions are aspirational. Requires implementation.*

### Security Monitoring (Aspirational)
*Real-time Monitoring, Incident Detection, Compliance Monitoring definitions are aspirational. Requires implementation.*

*Current Status: Centralized logging, audit logging, and security monitoring are not implemented.*

## Incident Response (Policy/Process - Status TBD)
*(Details omitted for brevity - Relates to IR plans, breach notification procedures)*

## Vulnerability Management (Policy/Process - Status TBD)
*(Details omitted for brevity - Relates to scanning, pen testing, remediation workflows)*

## Third-Party Security (Policy/Process - Status TBD)
*(Details omitted for brevity - Relates to vendor assessment, integration security)*

## Security Implementation Examples
*Note: The following code examples illustrate the **target** implementation. The actual codebase currently lacks these complete implementations.*

### Authentication Implementation (Target Example)
*(Code snippet showing JWT flow remains as a target example)*
```python
from jose import jwt, JWTError
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, timedelta
from typing import Optional

from core.config import settings
from core.security import verify_password
from domain.users.models import User
from infrastructure.repositories.users import get_user_by_username

# Token URL (used for docs)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")

def authenticate_user(username: str, password: str) -> Optional[User]:
    """Authenticate a user by username and password."""
    user = get_user_by_username(username)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user

def create_access_token(
    subject: str, 
    expires_delta: Optional[timedelta] = None
) -> str:
    """Create a new JWT access token."""
    # Use settings from configuration
    expiration = datetime.utcnow() + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    
    to_encode = {
        "sub": subject,
        "exp": expiration,
        "iat": datetime.utcnow(),
    }
    
    # Use settings from secure configuration
    encoded_jwt = jwt.encode(
        to_encode, 
        settings.SECRET_KEY, 
        algorithm=settings.ALGORITHM
    )
    
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """Validate the token and return the current user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Decode the token
        payload = jwt.decode(
            token, 
            settings.SECRET_KEY, 
            algorithms=[settings.ALGORITHM]
        )
        
        # Extract the subject (username)
        username: str = payload.get("sub")
        
        if username is None:
            raise credentials_exception
            
    except JWTError:
        # Invalid token
        raise credentials_exception
    
    # Get the user from database
    user = get_user_by_username(username)
    
    if user is None:
        raise credentials_exception
    
    # Check if user is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    
    return user
```

### Secure Data Access (Target Example)
*(Code snippet showing permission checks and audit logging remains as a target example)*
```python
from fastapi import Depends, HTTPException, status
from typing import List

from api.dependencies import get_current_user
from domain.users.models import User
from domain.patients.models import Patient
from infrastructure.repositories.patients import get_patient_by_id
from application.services.audit_service import record_phi_access

async def get_patient_with_audit(
    patient_id: str,
    current_user: User = Depends(get_current_user)
) -> Patient:
    """
    Get a patient by ID with proper authorization checks and audit logging.
    """
    # Check if user has permission to access this patient
    if not await user_can_access_patient(current_user.id, patient_id):
        # Log failed access attempt but don't reveal existence
        record_phi_access(
            user_id=current_user.id,
            resource_type="patient",
            resource_id=patient_id,
            action="read",
            success=False,
            reason="unauthorized"
        )
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this resource"
        )
    
    # Get patient from database
    patient = await get_patient_by_id(patient_id)
    
    if not patient:
        # Return 403 instead of 404 to prevent information disclosure
        # This prevents user enumeration
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this resource"
        )
    
    # Record successful access for audit trail
    record_phi_access(
        user_id=current_user.id,
        resource_type="patient",
        resource_id=patient_id,
        action="read",
        success=True
    )
    
    return patient
```

### Error Handling with PHI Protection (Target Example)
*(Code snippet showing secure FastAPI exception handlers remains as a target example)*
```python
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel
from typing import List, Optional
import logging
import uuid

# Setup secure logger
logger = logging.getLogger("security")

# Create app
app = FastAPI()

# Error response model without PHI
class ErrorDetail(BaseModel):
    loc: List[str]
    msg: str
    type: str

class ErrorResponse(BaseModel):
    request_id: str
    code: str
    message: str
    details: Optional[List[ErrorDetail]] = None

# Exception handler for validation errors
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, 
    exc: RequestValidationError
) -> JSONResponse:
    # Generate unique ID for the error
    request_id = str(uuid.uuid4())
    
    # Create safe error details
    details = []
    for error in exc.errors():
        # Ensure no PHI in error details
        sanitized_error = {
            "loc": error["loc"],
            "msg": error["msg"],
            "type": error["type"]
        }
        details.append(ErrorDetail(**sanitized_error))
    
    # Log detailed error with request ID for correlation
    logger.error(
        f"Validation error {request_id}: {exc.errors()}",
        extra={
            "request_id": request_id,
            "path": request.url.path,
            "method": request.method,
            "errors": exc.errors()
        }
    )
    
    # Return sanitized error to client
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=ErrorResponse(
            request_id=request_id,
            code="VALIDATION_ERROR",
            message="Request validation error",
            details=details
        ).dict()
    )

# Generic exception handler for unexpected errors
@app.exception_handler(Exception)
async def generic_exception_handler(
    request: Request, 
    exc: Exception
) -> JSONResponse:
    # Generate unique ID for the error
    request_id = str(uuid.uuid4())
    
    # Log detailed error internally
    logger.exception(
        f"Unexpected error {request_id}: {str(exc)}",
        extra={
            "request_id": request_id,
            "path": request.url.path,
            "method": request.method
        },
        exc_info=exc
    )
    
    # Return sanitized error to client (no exception details)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(
            request_id=request_id,
            code="INTERNAL_ERROR",
            message="An internal server error occurred"
        ).dict()
    )
```

### Audit Logging (Target Example)
*(Code snippet showing audit log class remains as a target example)*
```python
from datetime import datetime
import json
import logging
from typing import Any, Dict, Optional
import uuid
from fastapi import Depends, Request

from core.config import settings
from domain.users.models import User
from api.dependencies import get_current_user

# Setup audit logger
audit_logger = logging.getLogger("audit")

class AuditLog:
    """Class to handle audit logging for HIPAA compliance."""
    
    @staticmethod
    async def log_access(
        request: Request,
        resource_type: str,
        resource_id: str,
        action: str,
        current_user: User = Depends(get_current_user),
        success: bool = True,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log an access event to the audit log.
        
        Args:
            request: The HTTP request
            resource_type: Type of resource being accessed
            resource_id: ID of the resource
            action: Action being performed (read, write, delete)
            current_user: User performing the action
            success: Whether the access was successful
            details: Additional details about the access
        """
        # Create unique event ID
        event_id = str(uuid.uuid4())
        
        # Prepare log data
        log_data = {
            "event_id": event_id,
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": current_user.id,
            "username": current_user.username,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "action": action,
            "success": success,
            "ip_address": request.client.host,
            "user_agent": request.headers.get("User-Agent", "Unknown"),
            "request_id": request.headers.get("X-Request-ID", str(uuid.uuid4()))
        }
        
        # Add additional details if provided
        if details:
            log_data["details"] = details
            
        # Write to audit log
        audit_logger.info(
            f"ACCESS: {current_user.username} {action} {resource_type} {resource_id}",
            extra={"audit_data": log_data}
        )
        
        # If configured for high compliance, also write to database
        if settings.AUDIT_DATABASE_ENABLED:
            await store_audit_log_in_database(log_data)
```

## 10. Current Implementation Status Summary

This section summarizes the current security posture based on codebase analysis (as of [Current Date]).

**Implemented:**
- **Input Validation:** Pydantic schemas used in API endpoints.
- **Non-PHI Identifiers:** UUIDs used in API URL paths.
- **Basic Exception Handling:** Specific exceptions caught in some endpoints, returning basic HTTP errors.

**Partially Implemented / Basic:**
- *(None identified beyond the above)*

**Missing / Aspirational:**
- **Authentication:** Complete JWT/OAuth2/API Key implementation (login, token validation, refresh, logout).
- **Authorization:** RBAC framework, permission checks in endpoints.
- **Audit Logging:** Comprehensive logging of security-relevant events (PHI access, admin actions, auth events).
- **Secure Error Handling:** Standardized, sanitized error responses with correlation IDs; PHI scrubbing.
- **Session Management:** Secure session handling, timeouts.
- **Secrets Management:** Secure storage and rotation (e.g., Vault integration).
- **Encryption:** Data encryption at rest and in transit (TLS).
- **Rate Limiting:** API rate limiting middleware.
- **PHI Scrubbing:** Middleware/logic to prevent PHI in logs *(PHI detection service exists, integration missing)*.
- **Infrastructure Security:** Network controls, WAF, OS hardening, etc.
- **Monitoring & Alerting:** Security monitoring, SIEM integration.
- **Vulnerability Management:** Processes and tooling integration (scanning, patching).
- **Secure Development Practices:** Formal threat modeling, security reviews, SAST/DAST integration.

**Overall Assessment:** The current security implementation is minimal and falls significantly short of the documented architecture and HIPAA requirements. Security must be a primary focus during refactoring.

## Security Testing (Target)
*(Section outlining target testing strategies remains)*

## Appendix
*(Security Controls Matrix and Regulatory Requirements Mapping remain as targets/references)*

### Security Controls Matrix

| Control Category | Control | Implementation | Testing Method |
|------------------|---------|----------------|---------------|
| Access Control | Authentication | JWT/OAuth2 | Unit tests, penetration testing |
| Access Control | Authorization | RBAC | Unit tests, integration tests |
| Cryptography | Data Encryption | AES-256 | Encryption validation tests |
| Cryptography | Transport Security | TLS 1.3 | TLS configuration tests |
| Audit | PHI Access Logging | Centralized logging | Log verification tests |
| Data Protection | Input Validation | Pydantic schemas | Fuzzing, boundary tests |

### Regulatory Requirements Mapping

| Requirement | Control | Implementation |
|-------------|---------|----------------|
| HIPAA §164.312(a)(1) | Access Control | Role-based access control |
| HIPAA §164.312(b) | Audit Controls | Comprehensive audit logging |
| HIPAA §164.312(c)(1) | Integrity | Data validation, checksums |
| HIPAA §164.312(d) | Authentication | Multi-factor authentication |
| HIPAA §164.312(e)(1) | Transmission Security | TLS encryption | 

Last Updated: 2025-04-20
