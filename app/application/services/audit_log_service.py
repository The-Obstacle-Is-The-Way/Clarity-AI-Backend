"""
HIPAA-compliant audit logging service.

This service centralizes audit logging operations, implementing HIPAA's audit controls
requirements (§164.312(b)) and providing a clean API for recording and retrieving
audit logs throughout the application.
"""

import hashlib
import ipaddress
import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Union, Set

import aiofiles
from cryptography.hazmat.primitives import hashes
from fastapi import Request

from app.core.config.settings import get_settings
from app.core.interfaces.repositories.audit_log_repository_interface import IAuditLogRepository
from app.core.interfaces.services.audit_logger_interface import (
    IAuditLogger, AuditEventType, AuditSeverity
)
from app.domain.entities.audit_log import AuditLog

# Get settings once during module import
settings = get_settings()
logger = logging.getLogger(__name__)


class AuditLogService(IAuditLogger):
    """
    HIPAA-compliant audit logging service that implements the IAuditLogger interface.
    
    This service provides a robust implementation of audit logging capabilities required
    for HIPAA compliance. It ensures all PHI access and system security events are
    properly logged, tracked, and searchable.
    
    Features:
    - Comprehensive audit trail for all PHI access
    - Security event logging
    - Anomaly detection for suspicious activity
    - Integrity protection with hash chaining
    - Secure export capabilities for compliance reporting
    """
    
    def __init__(self, repository: IAuditLogRepository):
        """
        Initialize the audit logging service.
        
        Args:
            repository: Repository for storing and retrieving audit logs
        """
        self._repository = repository
        self._previous_hash = hashlib.sha256(b"AUDIT_LOG_INIT").hexdigest()
        self._anomaly_detection_enabled = True
        
        # Track velocity by user for anomaly detection
        self._user_access_history: Dict[str, List[datetime]] = {}
        self._suspicious_ips: Set[str] = set()
        
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
        request: Optional[Request] = None,
    ) -> str:
        """
        Log an audit event in the system.
        
        Args:
            event_type: Type of audit event
            actor_id: ID of the user/system performing the action
            target_resource: Type of resource being acted upon (e.g., "patient")
            target_id: ID of the specific resource instance
            action: Specific action taken (e.g., "view", "update")
            status: Result status of the action (e.g., "success", "failure")
            details: Additional details about the event
            severity: Severity level of the event
            metadata: Additional metadata for the event
            timestamp: When the event occurred (defaults to now if None)
            request: Optional FastAPI request object for extracting IP and headers
            
        Returns:
            str: Unique identifier for the audit log entry
        """
        # Create a new audit log entry
        audit_log = AuditLog(
            id=str(uuid.uuid4()),
            timestamp=timestamp or datetime.now(timezone.utc),
            event_type=event_type,
            actor_id=actor_id,
            resource_type=target_resource,
            resource_id=target_id,
            action=action or str(event_type),
            status=status or "success",
            ip_address=self._extract_ip_from_request(request) if request else None,
            details={
                **(details or {}),
                **(metadata or {}),
                "severity": severity,
                "hash_chain": self._calculate_chain_hash(
                    str(uuid.uuid4()), 
                    timestamp or datetime.now(timezone.utc).isoformat(), 
                    actor_id, 
                    action or str(event_type)
                )
            },
            success=status == "success" if status else True
        )
        
        # Check for anomalies if enabled
        if self._anomaly_detection_enabled and actor_id:
            await self._check_for_anomalies(actor_id, audit_log)
        
        # Store the audit log
        log_id = await self._repository.create(audit_log)
        
        # Update chain hash
        self._previous_hash = audit_log.details.get("hash_chain", self._previous_hash)
        
        # Log to standard logger at appropriate level
        log_method = getattr(logger, severity.lower(), logger.info)
        log_method(f"AUDIT: {event_type} - {action} by {actor_id} on {target_resource}:{target_id}")
        
        return log_id
    
    async def log_security_event(
        self,
        description: str,
        actor_id: Optional[str] = None,
        status: Optional[str] = None,
        severity: AuditSeverity = AuditSeverity.HIGH,
        details: Optional[Dict[str, Any]] = None,
        request: Optional[Request] = None,
    ) -> str:
        """
        Log a security-related event.
        
        Args:
            description: Description of the security event
            actor_id: ID of the user/system involved
            status: Status of the security event
            severity: Severity level of the event
            details: Additional details about the event
            request: Optional FastAPI request object for extracting IP and headers
            
        Returns:
            str: Unique identifier for the audit log entry
        """
        # Map to a standard event type
        if "login" in description.lower():
            event_type = AuditEventType.LOGIN if status == "success" else AuditEventType.LOGIN_FAILED
        elif "logout" in description.lower():
            event_type = AuditEventType.LOGOUT
        elif "password" in description.lower():
            event_type = AuditEventType.PASSWORD_CHANGED
        elif "permission" in description.lower() or "role" in description.lower():
            event_type = AuditEventType.PERMISSION_CHANGED
        elif "access denied" in description.lower():
            event_type = AuditEventType.ACCESS_DENIED
        else:
            event_type = AuditEventType.OTHER
            
        # Include the description in the details
        full_details = {"description": description, **(details or {})}
        
        # Log the security event using the general log_event method
        return await self.log_event(
            event_type=event_type,
            actor_id=actor_id,
            action="security_event",
            status=status,
            details=full_details,
            severity=severity,
            request=request
        )
    
    async def log_phi_access(
        self,
        actor_id: str,
        patient_id: str,
        resource_type: str,
        action: str,
        status: str,
        phi_fields: Optional[List[str]] = None,
        reason: Optional[str] = None,
        request: Optional[Request] = None,
    ) -> str:
        """
        Log PHI access event specifically.
        
        Args:
            actor_id: ID of the user accessing PHI
            patient_id: ID of the patient whose PHI was accessed
            resource_type: Type of resource containing PHI (e.g., "medical_record")
            action: Action performed on PHI (e.g., "view", "modify")
            status: Outcome of the access attempt
            phi_fields: Specific PHI fields accessed (without values)
            reason: Business reason for accessing the PHI
            request: Optional FastAPI request object for extracting IP and headers
            
        Returns:
            str: Unique identifier for the audit log entry
        """
        # Map the action to an event type
        if action.lower() in ["view", "read", "get"]:
            event_type = AuditEventType.PHI_ACCESSED
        elif action.lower() in ["update", "modify", "edit", "patch", "put"]:
            event_type = AuditEventType.PHI_MODIFIED
        elif action.lower() in ["delete", "remove"]:
            event_type = AuditEventType.PHI_DELETED
        elif action.lower() in ["export", "download", "print"]:
            event_type = AuditEventType.PHI_EXPORTED
        else:
            event_type = AuditEventType.PHI_ACCESSED  # Default
        
        # Ensure we have a reason for access (required by HIPAA)
        reason = reason or "Not specified (HIPAA requires a reason for PHI access)"
        
        # Build details including PHI fields accessed (without values)
        details = {
            "reason": reason,
            "phi_fields": phi_fields or ["all"],
        }
        
        # Log the PHI access event
        return await self.log_event(
            event_type=event_type,
            actor_id=actor_id,
            target_resource=resource_type,
            target_id=patient_id,
            action=action,
            status=status,
            details=details,
            severity=AuditSeverity.HIGH,  # PHI access is always high severity
            request=request
        )
    
    async def get_audit_trail(
        self,
        filters: Optional[Dict[str, Any]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve audit trail entries based on filters.
        
        Args:
            filters: Optional filters to apply (e.g., event_type, actor_id)
            start_time: Optional start time for the audit trail
            end_time: Optional end time for the audit trail
            limit: Maximum number of entries to return
            offset: Offset for pagination
            
        Returns:
            List[Dict[str, Any]]: List of audit log entries matching the criteria
        """
        # Search the repository
        logs = await self._repository.search(
            filters=filters,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
            offset=offset
        )
        
        # Convert to dictionaries for API response
        return [log.model_dump() for log in logs]
    
    async def get_security_dashboard_data(
        self,
        days: int = 7
    ) -> Dict[str, Any]:
        """
        Get data for a security dashboard.
        
        Args:
            days: Number of days to include in the dashboard
            
        Returns:
            Dict[str, Any]: Dashboard data
        """
        # Calculate time range
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days)
        
        # Get statistics
        stats = await self._repository.get_statistics(
            start_time=start_time,
            end_time=end_time
        )
        
        # Get recent security events
        security_filters = {
            "event_type": [
                AuditEventType.ACCESS_DENIED,
                AuditEventType.LOGIN_FAILED,
                AuditEventType.PERMISSION_CHANGED
            ]
        }
        security_events = await self._repository.search(
            filters=security_filters,
            start_time=start_time,
            end_time=end_time,
            limit=10
        )
        
        # Get recent PHI access events
        phi_filters = {
            "event_type": [
                AuditEventType.PHI_ACCESSED,
                AuditEventType.PHI_MODIFIED,
                AuditEventType.PHI_DELETED,
                AuditEventType.PHI_EXPORTED
            ]
        }
        phi_events = await self._repository.search(
            filters=phi_filters,
            start_time=start_time,
            end_time=end_time,
            limit=10
        )
        
        # Return dashboard data
        return {
            "statistics": stats,
            "recent_security_events": [log.model_dump() for log in security_events],
            "recent_phi_access": [log.model_dump() for log in phi_events],
            "anomalies_detected": len(self._suspicious_ips),
            "time_range": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat(),
                "days": days
            }
        }
    
    async def export_audit_logs(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        format: str = "json",
        file_path: Optional[str] = None
    ) -> str:
        """
        Export audit logs for compliance reporting.
        
        Args:
            start_time: Start time for the export
            end_time: End time for the export
            format: Format for the export (json, csv)
            file_path: Path to save the export (if None, uses a default path)
            
        Returns:
            str: Path to the exported file
        """
        # Default time range if not specified
        end_time = end_time or datetime.now(timezone.utc)
        start_time = start_time or (end_time - timedelta(days=30))
        
        # Get logs for the time range (all of them)
        logs = await self._repository.search(
            start_time=start_time,
            end_time=end_time,
            limit=10000  # Large limit, in practice would use pagination
        )
        
        # Create a default file path if not specified
        if not file_path:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            file_path = f"audit_export_{timestamp}.{format}"
        
        # Convert to dictionaries for export
        # IMPORTANT: Anonymize PHI before export
        log_dicts = [log.anonymize_phi().model_dump() for log in logs]
        
        # Export in the specified format
        if format.lower() == "json":
            async with aiofiles.open(file_path, "w") as f:
                await f.write(json.dumps(
                    {
                        "metadata": {
                            "start_time": start_time.isoformat(),
                            "end_time": end_time.isoformat(),
                            "exported_at": datetime.now(timezone.utc).isoformat(),
                            "total_logs": len(logs)
                        },
                        "logs": log_dicts
                    },
                    indent=2
                ))
        else:
            # Default to JSON if format not supported
            logger.warning(f"Unsupported export format: {format}, defaulting to JSON")
            await self.export_audit_logs(
                start_time=start_time,
                end_time=end_time,
                format="json",
                file_path=file_path.replace(f".{format}", ".json")
            )
        
        # Return the file path
        return file_path
    
    # Private methods
    
    def _extract_ip_from_request(self, request: Request) -> str:
        """
        Extract IP address from a FastAPI request.
        
        Args:
            request: FastAPI request object
            
        Returns:
            str: IP address
        """
        if not request:
            return "127.0.0.1"
        
        # Try to get the real IP from forwarded headers
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # Get the first IP in the list (client IP)
            ip = forwarded.split(",")[0].strip()
            try:
                # Validate it's a real IP
                ipaddress.ip_address(ip)
                return ip
            except ValueError:
                pass
        
        # Fall back to client host
        return request.client.host if request.client else "127.0.0.1"
    
    def _calculate_chain_hash(
        self,
        log_id: str,
        timestamp: str,
        user_id: Optional[str],
        action: str
    ) -> str:
        """
        Calculate hash chain value for tamper evidence.
        
        Args:
            log_id: ID of the log entry
            timestamp: Timestamp of the log entry
            user_id: ID of the user
            action: Action being logged
            
        Returns:
            str: Hash chain value
        """
        # Combine previous hash with current log data
        data = f"{self._previous_hash}:{log_id}:{timestamp}:{user_id or 'system'}:{action}"
        
        # Calculate new hash
        return hashlib.sha256(data.encode()).hexdigest()
    
    async def _check_for_anomalies(self, user_id: str, log: AuditLog) -> None:
        """
        Check for anomalous access patterns.
        
        Args:
            user_id: ID of the user to check
            log: Current audit log entry
        """
        # Initialize user history if not exists
        if user_id not in self._user_access_history:
            self._user_access_history[user_id] = []
        
        # Add current access time
        self._user_access_history[user_id].append(log.timestamp)
        
        # Keep only recent history (last 24 hours)
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        self._user_access_history[user_id] = [
            ts for ts in self._user_access_history[user_id] if ts >= cutoff
        ]
        
        # Check for velocity anomalies (too many requests in a short time)
        history = self._user_access_history[user_id]
        if len(history) > 100:  # More than 100 accesses in 24 hours
            # Calculate time between consecutive requests
            if len(history) >= 2:
                for i in range(1, min(20, len(history))):  # Check up to last 20
                    time_diff = (history[-i] - history[-(i+1)]).total_seconds()
                    if time_diff < 0.5:  # Less than 0.5 seconds between requests
                        # Log the anomaly
                        await self.log_security_event(
                            description="Anomalous access pattern detected: High velocity",
                            actor_id=user_id,
                            status="detected",
                            severity=AuditSeverity.HIGH,
                            details={
                                "anomaly_type": "velocity",
                                "requests_in_24h": len(history),
                                "fastest_interval_ms": int(time_diff * 1000)
                            }
                        )
                        break
        
        # Check for unusual IP addresses
        if log.ip_address and log.ip_address not in self._suspicious_ips:
            try:
                ip = ipaddress.ip_address(log.ip_address)
                
                # Check if it's a private IP accessing from outside (potential VPN bypass)
                if ip.is_private and log.details and log.details.get("request_context", {}).get("origin") == "external":
                    self._suspicious_ips.add(log.ip_address)
                    await self.log_security_event(
                        description="Anomalous access pattern detected: Private IP from external origin",
                        actor_id=user_id,
                        status="detected",
                        severity=AuditSeverity.CRITICAL,
                        details={
                            "anomaly_type": "suspicious_ip",
                            "ip_address": log.ip_address
                        }
                    )
            except ValueError:
                # Invalid IP address, could be suspicious
                self._suspicious_ips.add(log.ip_address)
                await self.log_security_event(
                    description="Invalid IP address in audit log",
                    actor_id=user_id,
                    status="detected",
                    severity=AuditSeverity.MEDIUM,
                    details={
                        "anomaly_type": "invalid_ip",
                        "ip_address": log.ip_address
                    }
                ) 