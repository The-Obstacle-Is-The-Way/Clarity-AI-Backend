# HIPAA-Compliant Audit Logging System

The Clarity AI Backend implements a comprehensive, HIPAA-compliant audit logging system that tracks all access to Protected Health Information (PHI) and system events. This system is designed to meet the requirements of HIPAA's Security Rule (45 CFR § 164.312(b)) for audit controls.

## Key Features

### 1. Comprehensive PHI Access Tracking

- **Automatic PHI Access Logging**: All API endpoints that access PHI are automatically logged
- **Manual Logging API**: Service layer can explicitly log PHI access with detailed context
- **Request Context Capture**: IP addresses, user agents, and locations are securely captured
- **PHI Field Tracking**: Specific PHI fields accessed are logged for granular auditing

### 2. Advanced Security Features

- **Anomaly Detection**: Identifies suspicious access patterns:
  - Unusual access volumes
  - Geographic anomalies (rapid location changes)
  - Time-based anomalies (accessing outside normal hours)
  - Resource access anomalies (unusual resource access patterns)
- **Real-time Security Alerts**: Triggers notifications for suspicious activities
- **IP Reputation Tracking**: Maintains history of suspicious IP addresses
- **Secure Hashing**: Sensitive data is securely hashed for audit trail without storing PHI

### 3. Compliance Features

- **Tamper-Evident Logs**: Logs are cryptographically secured against tampering
- **Immutable Storage**: All audit events are stored in an append-only manner
- **Complete Audit Trail**: All system events are logged with full context
- **Access Control**: Audit logs have strict access controls with segregation of duties
- **Retention Policies**: Configurable retention periods in compliance with HIPAA

### 4. Export and Reporting

- **Compliance Reporting**: Generate reports for HIPAA compliance audits
- **Flexible Export**: Export logs in various formats (JSON, CSV)
- **Filtering Capabilities**: Search and filter logs by various criteria
- **Statistics and Metrics**: Generate insights from audit data

## Architecture

The audit logging system follows clean architecture principles with:

1. **Domain Layer**:
   - `AuditLog` entity representing core audit log data
   - `AuditEventType` enum defining the types of auditable events

2. **Application Layer**:
   - `AuditLogService` implementing business logic for logging and analysis
   - Anomaly detection algorithms
   - Export and reporting functionality

3. **Infrastructure Layer**:
   - `AuditLogRepository` for persistence operations
   - `AuditLogMiddleware` for automatic logging
   - Secure storage mechanisms

4. **Presentation Layer**:
   - REST API endpoints for audit log management
   - Authentication and authorization controls

## Using the Audit System

### 1. Automatic Logging

The system automatically logs PHI access for API routes via middleware. No additional code is required for most use cases.

### 2. Manual Logging in Services

For service-level operations, explicitly log events:

```python
# Log PHI access
await audit_logger.log_phi_access(
    actor_id=user_id,
    patient_id=patient_id,
    resource_type="medical_record",
    action="view",
    status="success",
    phi_fields=["diagnoses", "medications"],
    reason="treatment"
)

# Log general event
await audit_logger.log_event(
    event_type=AuditEventType.AUTHENTICATION,
    actor_id=user_id,
    action="login",
    status="success",
    details={"method": "password"}
)

# Log security event
await audit_logger.log_security_event(
    description="Failed login attempt",
    actor_id=user_id,
    severity=AuditSeverity.MEDIUM,
    status="failure"
)
```

### 3. Retrieving Audit Logs

```python
# Get audit trail for a user
logs = await audit_service.get_audit_trail(
    filters={"actor_id": user_id},
    start_time=datetime.now(timezone.utc) - timedelta(days=30),
    end_time=datetime.now(timezone.utc)
)

# Export audit logs
file_path = await audit_service.export_audit_logs(
    format="csv",
    filters={"resource_type": "patient"},
    start_time=datetime.now(timezone.utc) - timedelta(days=90),
    end_time=datetime.now(timezone.utc)
)
```

## HIPAA Compliance Details

This audit logging system is designed to meet the following HIPAA requirements:

1. **Audit Controls (§164.312(b))**: Implements hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use electronic protected health information.

2. **Information System Activity Review (§164.308(a)(1)(ii)(D))**: Regularly reviews records of information system activity, such as audit logs, access reports, and security incident tracking reports.

3. **Access Authorization (§164.308(a)(4)(ii)(B))**: Implements policies and procedures for granting access to electronic protected health information.

4. **Access Establishment and Modification (§164.308(a)(4)(ii)(C))**: Implements policies and procedures that establish, document, review, and modify a user's right of access to a workstation, transaction, program, or process.

5. **Security Incident Procedures (§164.308(a)(6))**: Implement policies and procedures to address security incidents.

## Configuration

Audit logging behavior can be configured in the application settings:

```python
# app/core/config/settings.py
AUDIT_LOG_RETENTION_DAYS = 2555  # 7 years (HIPAA requirement)
AUDIT_LOG_ENABLED = True
AUDIT_LOG_ANOMALY_DETECTION = True
AUDIT_LOG_ALERT_EMAIL = "security@example.com"
``` 