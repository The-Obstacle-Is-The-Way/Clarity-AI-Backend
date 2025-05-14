# Audit Logger Interface

## Overview

The Audit Logger Interface (`IAuditLogger`) is a cornerstone of the Clarity AI Backend's compliance and security architecture. This interface defines the contract for recording security-relevant events and access to Protected Health Information (PHI) to maintain HIPAA compliance and support security forensics.

## Architectural Significance

In a psychiatric digital twin platform subject to HIPAA regulations, comprehensive audit logging is mandatory. The `IAuditLogger` interface:

1. **Enforces Compliance**: Ensures all PHI access is recorded as required by HIPAA
2. **Enables Security Analysis**: Provides data necessary for detecting unauthorized access
3. **Supports Investigations**: Creates an immutable record of system interactions 
4. **Maintains Data Lineage**: Tracks who accessed what data and when

## Interface Definition

The `IAuditLogger` interface is defined in the core layer (`app/core/interfaces/services/audit_logger_interface.py`):

```python
from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum, auto
from typing import Any, Dict, Optional, Union, List

class AuditEventType(str, Enum):
    """Types of auditable events in the system."""
    
    # Authentication events
    LOGIN = "login"
    LOGOUT = "logout"
    LOGIN_FAILED = "login_failed"
    # [Other event types omitted for brevity]

class AuditSeverity(str, Enum):
    """Severity level of audit events."""
    
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class IAuditLogger(ABC):
    """Interface for audit logging services.
    
    This interface defines the contract that all audit logging implementations
    must fulfill to ensure HIPAA compliance and proper security tracking.
    """
    
    @abstractmethod
    async def log_event(
        self,
        event_type: AuditEventType,
        actor_id: Optional[str] = None,
        target_resource: Optional[str] = None,
        target_id: Optional[str] = None,
        action: Optional[str] = None,
        status: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        severity: AuditSeverity = AuditSeverity.INFO,
        metadata: Optional[Dict[str, Any]] = None,
        timestamp: Optional[datetime] = None,
        request: Optional[Any] = None,
    ) -> str:
        """Log an audit event in the system."""
        pass
    
    @abstractmethod
    async def log_security_event(
        self,
        description: str,
        actor_id: Optional[str] = None,
        status: Optional[str] = None,
        severity: AuditSeverity = AuditSeverity.HIGH,
        details: Optional[Dict[str, Any]] = None,
        request: Optional[Any] = None,
    ) -> str:
        """Log a security-related event."""
        pass
    
    @abstractmethod
    async def log_phi_access(
        self,
        actor_id: str,
        patient_id: str,
        resource_type: str,
        action: str,
        status: str,
        phi_fields: Optional[List[str]] = None,
        reason: Optional[str] = None,
        request: Optional[Any] = None,
        request_context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Log PHI access event specifically."""
        pass
    
    @abstractmethod
    async def get_audit_trail(
        self,
        filters: Optional[Dict[str, Any]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Retrieve audit trail entries based on filters."""
        pass
    
    @abstractmethod
    async def export_audit_logs(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        format: str = "json",
        file_path: Optional[str] = None,
        filters: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Export audit logs to a file in the specified format."""
        pass
    
    @abstractmethod
    async def get_security_dashboard_data(
        self,
        days: int = 7
    ) -> Dict[str, Any]:
        """Get summary data for security dashboard."""
        pass
```

## Current Implementations

The codebase contains several audit logger implementations, but there are significant discrepancies between the interface and the actual implementations:

### 1. `AuditLogger` in `app/infrastructure/logging/audit_logger.py`

This implementation provides basic logging functionality but does not fully implement the `IAuditLogger` interface. It offers:

- Class methods for logging transactions, PHI access, and security events
- File-based logging with JSON formatting
- Support for testing environments with fallbacks

However, this implementation:
- Is class-based with static methods rather than instance methods
- Uses synchronous methods instead of async methods defined in the interface
- Does not implement several required interface methods like `get_audit_trail`, `export_audit_logs`, and `get_security_dashboard_data`
- Has a different method signature for `log_phi_access`

```python
class AuditLogger(IAuditLogger):  # Claims to implement IAuditLogger but doesn't fully
    """
    HIPAA-compliant audit logger for PHI operations.
    """
    
    @classmethod
    def setup(cls, log_dir: str | None = None) -> None:
        """Set up the audit logger with appropriate handlers."""
        # [Implementation details omitted]
    
    @classmethod
    def log_transaction(cls, metadata: dict[str, Any]) -> None:
        """Log a transaction for audit purposes."""
        # [Implementation details omitted]
    
    @classmethod
    def log_phi_access(cls, user_id: str, patient_id: str, action: str, details: dict[str, Any] | None = None) -> None:
        """Log PHI access for audit purposes."""
        # [Implementation details omitted]
    
    @classmethod
    def log_security_event(cls, event_type: str, user_id: str | None = None, details: dict[str, Any] | None = None) -> None:
        """Log a security event for audit purposes."""
        # [Implementation details omitted]
```

### 2. `AuditLogger` in `app/infrastructure/security/audit_logger.py`

This implementation is more comprehensive but still does not fully implement the interface:

- Provides tamper-evident logging with HMAC signatures and hash chains
- Includes methods for log integrity verification
- Supports searching and exporting logs
- Has role-based access control for audit log access

However, this implementation:
- Uses different method signatures than the interface
- Includes additional methods not in the interface
- Some methods are sync instead of async

### 3. `AuditLogMiddleware` in `app/infrastructure/security/audit/middleware.py`

This middleware automatically logs PHI access via API requests:

- Integrates with FastAPI middleware stack
- Detects PHI access based on URL patterns
- Records user ID, resource type, resource ID, and status
- Handles errors gracefully to avoid blocking requests

## Dependency Injection

A dependency injection provider exists, but the implementation may not match the interface fully:

```python
async def get_audit_logger() -> IAuditLogger:
    """
    Dependency provider for Audit Logger.
    
    Returns:
        IAuditLogger implementation
    """
    # Implementation may vary from what's documented
    return AuditLogger()
```

## Implementation Status

### Current Status

- ✅ Core interface defined in the proper layer
- ⚠️ **Implementation Discrepancy**: Multiple implementations exist with different approaches
- ⚠️ **Interface Compliance**: Existing implementations do not fully comply with the interface
- ✅ Core PHI logging functionality works through middleware
- ⚠️ **Async/Sync Mismatch**: Interface defines async methods but some implementations use sync methods
- ⚠️ **Method Signature Mismatch**: Implementations use different parameter names and types than interface

### Architectural Gaps

- 🔄 Standardize on a single implementation that fully implements the interface
- 🔄 Align method signatures between interface and implementations
- 🔄 Ensure all implementations use async methods as defined in the interface
- 🔄 Complete missing interface methods in implementations

## HIPAA Compliance Requirements

The Audit Logger implementation needs to satisfy these HIPAA requirements:

1. **§164.308(a)(1)(ii)(D)**: Information system activity review
2. **§164.312(b)**: Audit controls to record and examine activity
3. **§164.308(a)(5)(ii)(C)**: Log-in monitoring
4. **§164.312(c)(2)**: Mechanism to authenticate that data hasn't been altered
5. **§164.316(b)(1)**: Records retention requirements

Current implementations partially address these requirements, but the inconsistencies between interface and implementation may create compliance gaps.

## Conclusion

The Audit Logger Interface is a critical security component for HIPAA compliance. While the interface definition is comprehensive, the actual implementations show significant divergence from the interface. This creates potential security and compliance risks that should be addressed by aligning the implementations with the interface and consolidating the multiple approaches into a single, consistent implementation.
