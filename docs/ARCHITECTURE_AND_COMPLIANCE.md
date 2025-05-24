# Clarity-AI Architecture and HIPAA Compliance

> **Last Updated**: May 19, 2025

[![Clean Architecture](https://img.shields.io/badge/architecture-clean-blue)](https://github.com/Clarity-AI-Backend/) [![HIPAA Compliant](https://img.shields.io/badge/HIPAA-compliant-blue)](https://github.com/Clarity-AI-Backend/)

## Clean Architecture Implementation

The Clarity-AI backend implements a rigorous clean architecture approach with perfect separation of concerns across four distinct layers. This architecture ensures maintainability, testability, and scalability while supporting the complex needs of a digital twin platform for psychiatric care.

### Layer Structure

```
┌───────────────────┐      ┌───────────────────┐
│  Presentation     │─▶───▶│  Application      │
│ (FastAPI + Schemas│      │ (Use‑Cases)       │
│  + Middleware)    │      └───────────────────┘
└───────────────────┘              │
        ▲                          ▼
        │                  ┌───────────────────┐
┌───────────────────┐      │  Domain           │
│ Infrastructure    │◀────▶│ (Pydantic Models) │
│ (DB, ML, Cache,   │      └───────────────────┘
│  Messaging, Auth) │
└───────────────────┘
```

### Domain Layer

The domain layer encapsulates the core business logic and entities of the system without external dependencies. It includes:

- **Entities**: Core business objects (Patient, BiometricAlertRule, Treatment, etc.)
- **Value Objects**: Immutable objects with equality defined by their attributes
- **Domain Services**: Services that operate on multiple entities
- **Domain Events**: Events that domain experts care about
- **Repositories Interfaces**: Abstract interfaces for data access

### Application Layer

The application layer orchestrates the flow of data and coordinates high-level business operations:

- **Use Cases**: Application-specific business rules
- **Services**: Orchestration of domain entities to accomplish specific tasks
- **Interfaces**: Abstract definitions of operations needed from infrastructure
- **DTOs**: Data Transfer Objects for passing data between layers
- **Validators**: Input validation logic
- **Exception Handling**: Application-specific error handling

### Infrastructure Layer

The infrastructure layer provides technical capabilities to support the application:

- **Repositories**: Concrete implementations of repository interfaces
- **Data Access**: Database and ORM configuration
- **External APIs**: Integration with external services
- **Messaging**: Message queues and event handling
- **Caching**: Cache implementation
- **ML Models**: Machine learning model execution
- **Security**: Authentication and authorization mechanisms

### Presentation Layer

The presentation layer handles the delivery of the application to users:

- **API Controllers**: FastAPI endpoints
- **Middleware**: Request/response processing
- **Request Models**: Input validation schemas
- **Response Models**: Output formatting schemas
- **Error Handling**: HTTP-specific error responses
- **Documentation**: OpenAPI/Swagger docs

## HIPAA Compliance Framework

The Clarity-AI backend implements a comprehensive HIPAA compliance framework to protect Protected Health Information (PHI) while providing sophisticated digital twin capabilities for psychiatric care.

### Key Compliance Areas

#### 1. Access Controls

- **Authentication**: JWT-based authentication with refresh token rotation
- **Authorization**: Role-based access control (RBAC) for all endpoints
- **Session Management**: Secure session handling with timeouts
- **Audit Logging**: Comprehensive audit logging of all PHI access

#### 2. Data Protection

- **Encryption**: Data encrypted at rest and in transit
- **Anonymization**: PHI anonymization for analytics
- **Secure Storage**: Secured database with access controls
- **Data Minimization**: Only essential PHI collected

#### 3. Technical Safeguards

- **Input Validation**: Strict schema validation for all inputs
- **Output Sanitization**: Ensure no PHI in error messages
- **HTTPS Enforcement**: TLS 1.3 required for all communications
- **Rate Limiting**: Protection against brute force attacks

#### 4. Administrative Safeguards

- **Audit Trails**: Comprehensive activity logging
- **Access Reviews**: Automated access review processes
- **Incident Response**: Automated security incident detection
- **Training**: Developer security awareness training

### PHI Protection Mechanisms

#### URL Safety

- No PHI in URLs
- All identifiers are UUIDs
- No sensitive query parameters

#### Error Handling

- Generic error messages without PHI
- Detailed logs only in secure environments
- Exception filtering middleware

#### Database Security

- Parameterized queries only
- ORM with SQL injection protection
- Database encryption at rest
- Connection pooling with timeouts

#### API Security

- Rate limiting
- API keys with short validity
- Request throttling
- Anti-automation measures

## Design Patterns

The Clarity-AI backend implements several key design patterns to ensure clean architecture and maintainability:

### 1. Repository Pattern

Abstracts data access logic and provides a collection-like interface for domain entities:

```python
class BiometricAlertRuleRepository(AbstractRepository[BiometricAlertRule]):
    async def get_by_id(self, id: UUID) -> Optional[BiometricAlertRule]:
        """Get a rule by its ID."""
        # Implementation
    
    async def get_by_patient_id(self, patient_id: UUID) -> List[BiometricAlertRule]:
        """Get all rules for a patient."""
        # Implementation
```

### 2. Dependency Injection

Services register dependencies through interfaces, not concrete implementations:

```python
def get_rule_service(
    rule_repo: BiometricRuleRepoDep,
    db_session = Depends(get_db_session),
) -> BiometricAlertRuleService:
    """Get alert rule service with proper repositories."""
    template_repo = get_repository_instance(BiometricAlertTemplateRepository, db_session)
    return BiometricAlertRuleService(rule_repo, template_repo)
```

### 3. Factory Pattern

Creates complex objects without exposing creation logic:

```python
def create_biometric_correlation_model(
    model_type: str,
    config: Dict[str, Any]
) -> BiometricCorrelationModel:
    """Factory method to create the appropriate model instance."""
    if model_type == "lstm":
        return LSTMBiometricModel(config)
    elif model_type == "transformer":
        return TransformerBiometricModel(config)
    else:
        raise ValueError(f"Unknown model type: {model_type}")
```

### 4. Strategy Pattern

Allows selecting algorithms at runtime:

```python
class AlertNotificationStrategy(Protocol):
    async def send_notification(self, alert: Alert) -> bool:
        """Send notification for the given alert."""
        ...

class EmailNotificationStrategy:
    async def send_notification(self, alert: Alert) -> bool:
        """Send notification via email."""
        # Implementation

class SMSNotificationStrategy:
    async def send_notification(self, alert: Alert) -> bool:
        """Send notification via SMS."""
        # Implementation
```

### 5. Decorator Pattern

Adds responsibilities to objects dynamically:

```python
def audit_log_decorator(func):
    """Decorator to add audit logging to repository methods."""
    @functools.wraps(func)
    async def wrapper(self, *args, **kwargs):
        # Log access before operation
        result = await func(self, *args, **kwargs)
        # Log result after operation
        return result
    return wrapper
```

## System Health Monitoring

The Clarity-AI backend includes comprehensive monitoring for system health and HIPAA compliance:

1. **Performance Metrics**:
   - Request latency
   - Database query performance
   - ML model execution time
   - Memory and CPU utilization

2. **Security Monitoring**:
   - Failed authentication attempts
   - Unusual access patterns
   - PHI access logging
   - Authorization failures

3. **Data Quality Metrics**:
   - Biometric data completeness
   - Patient record integrity
   - Digital twin model accuracy
   - Alert rule effectiveness

4. **Operational Health**:
   - Service availability
   - Database connection pool status
   - Background task completion rates
   - Cache hit/miss ratios

## Further Documentation

For more details, see the following documentation:

- [TEST_STATUS.md](./TEST_STATUS.md): Current test coverage and status
- [DEVELOPMENT_ROADMAP.md](./DEVELOPMENT_ROADMAP.md): Strategic implementation plan
- [BIOMETRIC_ALERTS_IMPLEMENTATION.md](./BIOMETRIC_ALERTS_IMPLEMENTATION.md): Biometric alerts system details

---

⚡ Generated by Clarity-AI Documentation System
