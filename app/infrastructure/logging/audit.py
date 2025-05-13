"""
HIPAA-compliant audit logging utility.

This module provides a centralized way to access the audit logger
for HIPAA-compliant tracking of PHI access and modifications.
It implements the requirements of HIPAA §164.312(b) - Audit controls.

Key features:
- Thread-local context for tracking current user and access reason
- Decorators for auditing PHI access in both sync and async functions
- Intelligent parameter extraction for accurate audit trails
- Tamper-evident logging with HMAC signatures
- Compliance with HIPAA audit requirements
"""

import asyncio
import datetime
import functools
import logging
import threading
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union, cast

from app.core.interfaces.services.audit_logger_interface import (
    AuditEventType, AuditSeverity, IAuditLogger
)
from app.infrastructure.security.audit_logger import AuditLogger

# Configure logger
logger = logging.getLogger(__name__)

# Thread-local storage for audit context
_thread_local = threading.local()

# Global audit logger instance (singleton)
_audit_logger = None

# Type variables for decorators
F = TypeVar('F', bound=Callable[..., Any])
AsyncF = TypeVar('AsyncF', bound=Callable[..., Any])

def get_audit_logger() -> AuditLogger:
    """
    Get the singleton audit logger instance.
    
    Returns:
        AuditLogger: The application's audit logger
    """
    global _audit_logger
    
    if _audit_logger is None:
        _audit_logger = AuditLogger()
        
    return _audit_logger

def get_current_user_id() -> Optional[str]:
    """
    Get the current user ID from thread-local storage.
    
    Returns:
        Optional[str]: Current user ID or None if not set
    """
    return getattr(_thread_local, 'user_id', None)

def get_current_access_reason() -> Optional[str]:
    """
    Get the current access reason from thread-local storage.
    
    Returns:
        Optional[str]: Current access reason or None if not set
    """
    return getattr(_thread_local, 'access_reason', None)

def set_current_user(user_id: str, access_reason: Optional[str] = None) -> None:
    """
    Set the current user ID and access reason in thread-local storage.
    This allows audit logging to be context-aware without passing user IDs everywhere.
    
    Args:
        user_id: ID of the current user
        access_reason: Business reason for accessing PHI (e.g., "treatment", "payment", "operations")
    """
    _thread_local.user_id = user_id
    if access_reason:
        _thread_local.access_reason = access_reason
    
def clear_current_user() -> None:
    """Clear the current user ID and access reason from thread-local storage."""
    if hasattr(_thread_local, 'user_id'):
        delattr(_thread_local, 'user_id')
    if hasattr(_thread_local, 'access_reason'):
        delattr(_thread_local, 'access_reason')

class AuditedFunction(Enum):
    """Types of functions that can be audited."""
    
    PHI_ACCESS = "phi_access"
    DATA_MODIFICATION = "data_modification"
    SECURITY_EVENT = "security_event"
    SYSTEM_EVENT = "system_event"
    ADMIN_ACTION = "admin_action"

def audit_phi_access(
    resource_type: str, 
    action: str, 
    phi_fields: Optional[List[str]] = None,
    default_reason: Optional[str] = None
) -> Callable[[F], F]:
    """
    Decorator for auditing PHI access in functions.
    
    This decorator provides comprehensive audit logging for any function that
    accesses Protected Health Information (PHI). It automatically extracts
    entity IDs from various parameter patterns and creates a complete audit
    trail required by HIPAA regulations.
    
    Usage example:
        @audit_phi_access(resource_type="patient", action="view", phi_fields=["name", "dob"])
        def get_patient_data(patient_id: str) -> Dict:
            # Function implementation...
    
    The decorator will automatically detect that 'patient_id' is the entity ID
    and include it in the audit trail.
    
    Args:
        resource_type: Type of resource being accessed (e.g., "patient", "medical_record")
        action: Action being performed (e.g., "view", "update")
        phi_fields: List of PHI fields being accessed
        default_reason: Default reason if none provided in context
        
    Returns:
        Decorator function
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Get the audit logger
            audit_logger = get_audit_logger()
            
            # Get user ID and access reason from thread-local or kwargs
            user_id = kwargs.pop('audit_user_id', get_current_user_id())
            access_reason = kwargs.pop('audit_reason', get_current_access_reason() or default_reason)
            
            # Get resource ID from kwargs or args based on function signature
            resource_id = None
            
            # Look for resource ID in kwargs based on common parameter names
            for key in ['id', 'patient_id', 'record_id', 'entity_id', f"{resource_type}_id"]:
                if key in kwargs:
                    resource_id = kwargs[key]
                    break
            
            # If not found in kwargs, check the first positional argument
            # (common pattern is function(resource_id, ...))
            if resource_id is None and len(args) > 0:
                # Check if the first arg is an object with an id
                if hasattr(args[0], 'id'):
                    resource_id = getattr(args[0], 'id')
                # Otherwise assume the first arg itself is the ID (most common case)
                elif not isinstance(args[0], (dict, list, tuple, set)):
                    resource_id = args[0]
                
            if not user_id:
                logger.warning(f"PHI access without user ID: {resource_type}:{resource_id} {action}")
                
            # Log the PHI access before executing the function
            try:
                audit_logger.log_data_modification(
                    user_id=user_id or "anonymous",
                    action=action,
                    entity_type=resource_type,
                    entity_id=str(resource_id) if resource_id else "unknown",
                    status="initiated",
                    details=f"Access reason: {access_reason or 'Not specified'}",
                    phi_fields=phi_fields
                )
            except Exception as e:
                logger.error(f"Error logging PHI access audit: {e}")
                
            # Execute the function
            try:
                result = func(*args, **kwargs)
                
                # Log successful access
                audit_logger.log_data_modification(
                    user_id=user_id or "anonymous",
                    action=action,
                    entity_type=resource_type,
                    entity_id=str(resource_id) if resource_id else "unknown",
                    status="success",
                    details=f"Access reason: {access_reason or 'Not specified'}",
                    phi_fields=phi_fields
                )
                
                return result
            except Exception as e:
                # Log failed access
                audit_logger.log_data_modification(
                    user_id=user_id or "anonymous",
                    action=action,
                    entity_type=resource_type,
                    entity_id=str(resource_id) if resource_id else "unknown",
                    status="failed",
                    details=f"Error: {str(e)}",
                    phi_fields=phi_fields
                )
                raise  # Re-raise the exception
                
        return cast(F, wrapper)
    return decorator

def audit_async_phi_access(
    resource_type: str, 
    action: str, 
    phi_fields: Optional[List[str]] = None,
    default_reason: Optional[str] = None
) -> Callable[[AsyncF], AsyncF]:
    """
    Decorator for auditing PHI access in async functions.
    
    This decorator provides comprehensive audit logging for any async function that
    accesses Protected Health Information (PHI). It automatically extracts
    entity IDs from various parameter patterns and creates a complete audit
    trail required by HIPAA regulations.
    
    Usage example:
        @audit_async_phi_access(resource_type="medical_record", action="update")
        async def update_medical_record(record_id: str, data: Dict) -> Dict:
            # Async function implementation...
    
    The decorator will automatically detect that 'record_id' is the entity ID
    and include it in the audit trail.
    
    Args:
        resource_type: Type of resource being accessed (e.g., "patient", "medical_record")
        action: Action being performed (e.g., "view", "update")
        phi_fields: List of PHI fields being accessed
        default_reason: Default reason if none provided in context
        
    Returns:
        Async decorator function
    """
    def decorator(func: AsyncF) -> AsyncF:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Get the audit logger
            audit_logger = get_audit_logger()
            
            # Get user ID and access reason from thread-local or kwargs
            user_id = kwargs.pop('audit_user_id', get_current_user_id())
            access_reason = kwargs.pop('audit_reason', get_current_access_reason() or default_reason)
            
            # Get resource ID from kwargs or args based on function signature
            resource_id = None
            
            # Look for resource ID in kwargs based on common parameter names
            for key in ['id', 'patient_id', 'record_id', 'entity_id', f"{resource_type}_id"]:
                if key in kwargs:
                    resource_id = kwargs[key]
                    break
            
            # If not found in kwargs, check the first positional argument
            # (common pattern is function(resource_id, ...))
            if resource_id is None and len(args) > 0:
                # Check if the first arg is an object with an id
                if hasattr(args[0], 'id'):
                    resource_id = getattr(args[0], 'id')
                # Otherwise assume the first arg itself is the ID (most common case)
                elif not isinstance(args[0], (dict, list, tuple, set)):
                    resource_id = args[0]
                
            if not user_id:
                logger.warning(f"PHI access without user ID: {resource_type}:{resource_id} {action}")
                
            # Log the PHI access before executing the function
            try:
                audit_logger.log_data_modification(
                    user_id=user_id or "anonymous",
                    action=action,
                    entity_type=resource_type,
                    entity_id=str(resource_id) if resource_id else "unknown",
                    status="initiated",
                    details=f"Access reason: {access_reason or 'Not specified'}",
                    phi_fields=phi_fields
                )
            except Exception as e:
                logger.error(f"Error logging PHI access audit: {e}")
                
            # Execute the function
            try:
                result = await func(*args, **kwargs)
                
                # Log successful access
                audit_logger.log_data_modification(
                    user_id=user_id or "anonymous",
                    action=action,
                    entity_type=resource_type,
                    entity_id=str(resource_id) if resource_id else "unknown",
                    status="success",
                    details=f"Access reason: {access_reason or 'Not specified'}",
                    phi_fields=phi_fields
                )
                
                return result
            except Exception as e:
                # Log failed access
                audit_logger.log_data_modification(
                    user_id=user_id or "anonymous",
                    action=action,
                    entity_type=resource_type,
                    entity_id=str(resource_id) if resource_id else "unknown",
                    status="failed",
                    details=f"Error: {str(e)}",
                    phi_fields=phi_fields
                )
                raise  # Re-raise the exception
                
        return cast(AsyncF, wrapper)
    return decorator

async def search_audit_trail(
    start_date: Optional[datetime.datetime] = None,
    end_date: Optional[datetime.datetime] = None,
    user_id: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    action: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
) -> List[Dict[str, Any]]:
    """
    Search the audit trail with various filters.
    
    Args:
        start_date: Filter by minimum timestamp
        end_date: Filter by maximum timestamp
        user_id: Filter by user ID
        resource_type: Filter by resource type
        resource_id: Filter by resource ID
        action: Filter by action performed
        status: Filter by status (success, failed, etc.)
        limit: Maximum number of results to return
        offset: Offset for pagination
        
    Returns:
        List of matching log entries
    """
    audit_logger = get_audit_logger()
    
    # Prepare filters for the search
    filters = {}
    if user_id:
        filters['user_id'] = user_id
    if resource_type:
        filters['entity_type'] = resource_type
    if resource_id:
        filters['entity_id'] = resource_id
    if action:
        filters['action'] = action
    if status:
        filters['status'] = status
        
    # Use the interface method for searching
    return await audit_logger.get_audit_trail(
        filters=filters,
        start_time=start_date,
        end_time=end_date,
        limit=limit,
        offset=offset
    )

def verify_audit_integrity(log_id: str) -> bool:
    """
    Verify the integrity of a specific audit log entry.
    
    Args:
        log_id: ID of the log entry to verify
        
    Returns:
        bool: True if the log entry is intact, False if tampered with or missing
    """
    audit_logger = get_audit_logger()
    return audit_logger.verify_log_integrity(log_id)

def export_audit_logs(
    start_date: Optional[datetime.datetime] = None,
    end_date: Optional[datetime.datetime] = None,
    format: str = "json"
) -> str:
    """
    Export audit logs for a specified time period.
    
    Args:
        start_date: Start date for the export (optional)
        end_date: End date for the export (optional)
        format: Export format ('json' or 'csv')
        
    Returns:
        str: Exported logs in the requested format
    """
    audit_logger = get_audit_logger()
    return audit_logger.export_logs(
        start_date=start_date,
        end_date=end_date,
        format=format,
        verify_integrity=True
    ) 