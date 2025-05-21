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
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import Request

from app.core.config.settings import get_settings
from app.core.interfaces.repositories.audit_log_repository_interface import (
    IAuditLogRepository,
)
from app.core.interfaces.services.audit_logger_interface import (
    AuditEventType,
    AuditSeverity,
    IAuditLogger,
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
    - API request logging
    - Data access auditing
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
        self._user_access_history: dict[str, list[datetime]] = {}
        self._suspicious_ips: set[str] = set()

    async def log_security_event(
        self,
        event_type: AuditEventType | str,
        description: str = None,
        severity: AuditSeverity = AuditSeverity.HIGH,
        actor_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Log a security-related event for audit purposes.

        Args:
            event_type: Type of security event (e.g., LOGIN, LOGOUT, TOKEN_ISSUED)
            description: Human-readable description of the event
            severity: Severity level of the event
            user_id: User ID associated with the event (if applicable)
            metadata: Additional contextual information about the event
        """
        if isinstance(event_type, AuditEventType):
            event_type_str = event_type.value
        else:
            event_type_str = event_type

        log = await self.log_event(
            event_type=event_type_str,
            actor_id=actor_id,
            action="security_event",
            status="info",
            details={
                "description": description,
                "metadata": metadata or {},
            },
            severity=severity,
        )
        return log.id

    async def log_data_access(
        self,
        resource_type: str,
        resource_id: str,
        action: str,
        user_id: str,
        reason: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log access to sensitive data for HIPAA compliance.
        
        Args:
            resource_type: Type of resource being accessed (e.g., PATIENT, RECORD)
            resource_id: Identifier of the resource
            action: Action performed (e.g., VIEW, EDIT, DELETE)
            user_id: User who performed the action
            reason: Optional reason for access
            metadata: Additional contextual information about the access
        """
        # Leverage our existing PHI access logging infrastructure
        phi_fields = None
        if metadata and "phi_fields" in metadata:
            phi_fields = metadata.pop("phi_fields")
            
        status = "success"  # Default status if not provided in metadata
        if metadata and "status" in metadata:
            status = metadata.pop("status")
            
        # Create request context
        request_context = metadata or {}
        
        # Use our existing PHI access logging method
        await self.log_phi_access(
            actor_id=user_id,
            resource_id=resource_id,
            resource_type=resource_type,
            action=action,
            status=status,
            phi_fields=phi_fields,
            reason=reason,
            request_context=request_context
        )
        
    async def log_api_request(
        self,
        endpoint: str,
        method: str,
        status_code: int,
        user_id: Optional[str] = None,
        request_id: Optional[str] = None,
        duration_ms: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log API request information for audit trails.
        
        Args:
            endpoint: API endpoint that was accessed
            method: HTTP method used (GET, POST, etc.)
            status_code: HTTP status code of the response
            user_id: Optional user identifier who made the request
            request_id: Optional unique identifier for the request
            duration_ms: Optional request duration in milliseconds
            metadata: Additional contextual information about the request
        """
        # Create a unique request ID if not provided
        if not request_id:
            request_id = str(uuid.uuid4())
            
        # Determine severity based on status code
        if status_code >= 500:
            severity = AuditSeverity.ERROR
        elif status_code >= 400:
            severity = AuditSeverity.WARNING
        else:
            severity = AuditSeverity.INFO
            
        # Build event details
        details = {
            "endpoint": endpoint,
            "method": method,
            "status_code": status_code,
            "request_id": request_id,
            "duration_ms": duration_ms
        }
        
        # Add additional metadata if provided
        if metadata:
            details.update(metadata)
            
        # Log the event using our existing event logging infrastructure
        await self.log_event(
            event_type=AuditEventType.API_REQUEST.value if isinstance(AuditEventType.API_REQUEST, AuditEventType) else "API_REQUEST",
            actor_id=user_id,
            action=f"{method} {endpoint}",
            status="success" if status_code < 400 else "failure",
            details=details,
            severity=severity
        )
        
    async def log_system_event(
        self,
        event_type: str,
        description: str,
        severity: AuditSeverity = AuditSeverity.INFO,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log system-level events for operational auditing.
        
        Args:
            event_type: Type of system event
            description: Human-readable description of the event
            severity: Severity level (INFO, WARNING, ERROR)
            metadata: Additional contextual information about the event
        """
        # Prepend 'SYSTEM_' to the event type if not already present
        if not event_type.startswith("SYSTEM_"):
            event_type = f"SYSTEM_{event_type}"
            
        # Log the event using our existing event logging infrastructure
        await self.log_event(
            event_type=event_type,
            actor_id=None,  # System events often don't have a user
            action="system_operation",
            status="info",
            details={
                "description": description,
                "metadata": metadata or {}
            },
            severity=severity
        )

    async def log_event(
        self,
        event_type: str,
        actor_id: Optional[str] = None,
        action: Optional[str] = None,
        status: str = "success",
        details: Optional[Dict[str, Any]] = None,
        severity: AuditSeverity = AuditSeverity.INFO,
        request: Optional[Request] = None,
        _skip_anomaly_check: bool = False,
    ) -> AuditLog:
        """
        Create and store a new audit log entry.

        Args:
            event_type: Type of event being logged
            actor_id: ID of the user performing the action (if applicable)
            action: Action being performed
            status: Result of the action (success, failure, etc.)
            details: Additional details about the event
            severity: Severity level of the event
            request: FastAPI request object (for extracting client info)
            _skip_anomaly_check: Internal flag to prevent recursive anomaly checks

        Returns:
            The created audit log entry
        """
        # Create a log entry with timestamp and event ID
        timestamp = datetime.now(timezone.utc)
        event_id = str(uuid.uuid4())
        
        # Extract client information from request if available
        client_info = await self._get_client_information(request) if request else {}
        
        # Ensure details is a dictionary even if None was passed
        if details is None:
            details = {}
            
        # Add client information to details
        if client_info:
            details["client"] = client_info
            
        # Create the audit log entry
        log = AuditLog(
            id=event_id,
            timestamp=timestamp,
            event_type=event_type,
            actor_id=actor_id,
            action=action,
            status=status,
            details=details,
            severity=severity.value if hasattr(severity, "value") else severity,
            previous_hash=self._previous_hash,
        )
        
        # Calculate and store hash for this entry (for tamper detection)
        self._previous_hash = self._calculate_hash(log)
        log.hash = self._previous_hash
        
        # Store the log entry
        await self._repository.create(log)
        
        # Check for anomalies if enabled and not explicitly skipped
        if self._anomaly_detection_enabled and not _skip_anomaly_check:
            # Run anomaly detection for this log (non-blocking)
            if actor_id:
                await self._check_velocity_anomalies(actor_id, timestamp)
                
                # If client IP is available, check for location anomalies
                if client_info and "ip_address" in client_info:
                    await self._check_location_anomalies(
                        actor_id, 
                        client_info["ip_address"], 
                        log
                    )
        
        # Return the created log entry
        return log

    async def log_phi_access(
        self,
        resource_id: str,
        resource_type: str,
        action: str,
        actor_id: str = None,
        phi_fields: list[str] | None = None,
        reason: str | None = None,
        status: str = "success",
        request: Any | None = None,
        request_context: dict[str, Any] | None = None,
    ) -> str:
        """
        Log PHI access events in compliance with HIPAA requirements.

        Args:
            user_id: ID of the user accessing PHI
            resource_id: ID of the resource being accessed
            resource_type: Type of resource (e.g., patient, record)
            action: Action being performed (e.g., view, edit)
            status: Result of the access attempt (success, failure)
            phi_fields: Specific PHI fields accessed (if applicable)
            reason: Reason for accessing PHI
            request: Original request object (for extraction of additional context)
            request_context: Additional request context (IP, user agent, etc.)

        Returns:
            The generated audit event ID
        """
        details = {
            "resource_id": resource_id,
            "resource_type": resource_type,
            "phi_fields": phi_fields or [],
            "reason": reason,
            "context": request_context or {},
        }
        
        # Log the PHI access event
        log = await self.log_event(
            event_type=AuditEventType.PHI_ACCESS.value,
            actor_id=actor_id,
            action=action,
            status=status,
            details=details,
            severity=AuditSeverity.INFO if status == "success" else AuditSeverity.WARNING,
            request=request if isinstance(request, Request) else None,
        )
        
        # Return the event ID
        return log.id

    async def get_audit_trail(
        self,
        filters: dict[str, Any] | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditLog]:
        """
        Retrieve audit log entries based on filters and time range.

        Args:
            filters: Dictionary of field-value pairs to filter logs by
            start_time: Start of time range to retrieve logs from
            end_time: End of time range to retrieve logs from
            limit: Maximum number of log entries to return
            offset: Number of entries to skip (for pagination)

        Returns:
            List of matching audit log entries
        """
        # Delegate to repository method
        return await self._repository.search(
            filters=filters,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
            offset=offset,
        )

    async def export_audit_logs(
        self,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        format: str = "json",
        file_path: str | None = None,
        filters: dict[str, Any] | None = None,
    ) -> str:
        """
        Export audit logs to a file in the specified format.

        Args:
            start_time: Start of time range to export logs from
            end_time: End of time range to export logs from
            format: Export format (json, csv, etc.)
            file_path: Path to save exported logs
            filters: Dictionary of field-value pairs to filter logs by

        Returns:
            Path to the exported file
        """
        # Get logs to export
        logs = await self.get_audit_trail(
            filters=filters,
            start_time=start_time,
            end_time=end_time,
            limit=10000,  # Export with high limit
            offset=0,
        )
        
        # Generate default file path if not provided
        if not file_path:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            file_path = f"audit_logs_export_{timestamp}.{format}"
            
        # Ensure directory exists
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        
        # Convert logs to serializable format
        serializable_logs = [log.dict() for log in logs]
        
        # Export logs in the requested format
        if format.lower() == "json":
            with open(file_path, "w") as f:
                json.dump(serializable_logs, f, indent=2, default=str)
        elif format.lower() == "csv":
            # Simple CSV export implementation
            import csv
            with open(file_path, "w", newline="") as f:
                # Define CSV columns
                fieldnames = [
                    "id", "timestamp", "event_type", "actor_id", 
                    "action", "status", "severity"
                ]
                
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                
                # Write each log as a CSV row
                for log in logs:
                    log_dict = log.dict()
                    # Convert timestamp to string
                    log_dict["timestamp"] = log_dict["timestamp"].isoformat()
                    # Extract just the fields we want for the CSV
                    row = {field: log_dict.get(field, "") for field in fieldnames}
                    writer.writerow(row)
        else:
            logger.error(f"Unsupported export format: {format}")
            return ""
        
        return file_path

    async def get_security_dashboard_data(self, days: int = 7) -> dict[str, Any]:
        """
        Get summary statistics for security dashboard.

        Args:
            days: Number of days to include in the summary

        Returns:
            Dictionary of security metrics and statistics
        """
        # Calculate start time based on days parameter
        start_time = datetime.now(timezone.utc) - timedelta(days=days)
        
        # Get relevant audit logs for the time period
        logs = await self.get_audit_trail(
            start_time=start_time,
            limit=10000,  # High limit to ensure we get all logs
        )
        
        # Count different event types
        total_events = len(logs)
        security_incidents = sum(1 for log in logs 
                             if log.severity in [AuditSeverity.HIGH.value, AuditSeverity.ERROR.value, AuditSeverity.CRITICAL.value])
        phi_access_count = sum(1 for log in logs if log.event_type == "PHI_ACCESS")
        failed_logins = sum(
            1 for log in logs
            if log.event_type == AuditEventType.LOGIN.value and log.status == "failure"
        )
        
        # Additional metrics - login count by day
        login_by_day = {}
        for log in logs:
            if log.event_type == AuditEventType.LOGIN.value:
                day = log.timestamp.date().isoformat()
                login_by_day[day] = login_by_day.get(day, 0) + 1
        
        # Calculate active users
        unique_users = set(log.actor_id for log in logs if log.actor_id)
        active_users = len(unique_users)
        
        return {
            "total_events": total_events,
            "security_incidents": security_incidents,
            "phi_access_count": phi_access_count,
            "failed_logins": failed_logins,
            "login_by_day": login_by_day,
            "active_users": active_users,
            "days": days,
        }

    async def _check_for_anomalies(self, user_id: str, timestamp: datetime, ip_address: str = None, log: AuditLog = None) -> bool:
        """Check for various anomalies in audit logs.
        
        This method integrates various anomaly checks including velocity and geographic anomalies.
        
        Args:
            user_id: User ID to check for anomalies
            timestamp: Current event timestamp
            ip_address: IP address of the request, if available
            log: Audit log entry to analyze
            
        Returns:
            True if anomalies were detected, False otherwise
        """
        # First check velocity anomalies
        velocity_anomaly = await self._check_velocity_anomalies(user_id, timestamp)
        
        # Then check location anomalies if IP address is provided
        location_anomaly = False
        if ip_address and log:
            location_anomaly = await self._check_location_anomalies(user_id, ip_address, log)
            
        # Return True if any anomaly was detected
        return velocity_anomaly or location_anomaly
        
    async def _check_velocity_anomalies(self, user_id: str, timestamp: datetime) -> bool:
        """
        Check for velocity-based anomalies for a specific user.

        Args:
            user_id: ID of the user to check
            timestamp: Timestamp of the current event

        Returns:
            True if an anomaly was detected, False otherwise
        """
        # Create user history if it doesn't exist
        if user_id not in self._user_access_history:
            self._user_access_history[user_id] = []
            
        # Add current timestamp to history
        self._user_access_history[user_id].append(timestamp)
        
        # Keep only the last 100 timestamps to limit memory usage
        if len(self._user_access_history[user_id]) > 100:
            self._user_access_history[user_id] = self._user_access_history[user_id][-100:]
            
        # Get timestamps within the last minute
        one_minute_ago = timestamp - timedelta(minutes=1)
        recent_accesses = [t for t in self._user_access_history[user_id] if t >= one_minute_ago]
        
        # Check if access frequency exceeds threshold
        # In a real system, this would be configurable and more sophisticated
        if len(recent_accesses) > 30:  # More than 30 accesses in 1 minute is suspicious
            # Log an anomaly event
            anomaly_detail = {
                "type": "velocity",
                "description": f"excessive access rate: {len(recent_accesses)} in 1 minute",
                "user_id": user_id,
                "threshold": 30,
                "actual": len(recent_accesses),
            }
            
            await self.log_event(
                event_type=AuditEventType.SECURITY_ALERT.value,
                actor_id=user_id,
                action="velocity_anomaly",
                status="warning",
                details=anomaly_detail,
                severity=AuditSeverity.HIGH,
                _skip_anomaly_check=True,  # Prevent recursion
            )
            
            return True
            
        return False

    async def _check_location_anomalies(
        self, user_id: str, ip_address: str, log: AuditLog
    ) -> bool:
        """
        Check for location-based anomalies for a specific user.

        Args:
            user_id: ID of the user to check
            ip_address: IP address to check
            log: The audit log entry to analyze

        Returns:
            True if an anomaly was detected, False otherwise
        """
        # Skip if IP is None
        if not ip_address:
            return False
            
        # Track suspicious IPs
        anomalies_detected = []
        
        # Check if IP is in suspicious list
        if ip_address in self._suspicious_ips:
            # Known suspicious IP - log immediately
            anomaly_detail = {
                "type": "location",
                "description": "access from known suspicious IP",
                "ip_address": ip_address,
                "user_id": user_id,
            }
            
            anomalies_detected.append(anomaly_detail)
            
            # Log a security event for the anomaly
            await self.log_event(
                event_type=AuditEventType.SECURITY_ALERT.value,
                actor_id=user_id,
                action="geographic_anomaly",
                status="warning",
                details=anomaly_detail,
                severity=AuditSeverity.HIGH,
                _skip_anomaly_check=True,  # Prevent recursion
            )
            
            # Return true to indicate anomaly was detected
            return True
            
        # Normal case for real applications
        elif hasattr(log, "details") and log.details:
            # Get location info from details if available
            location_info = log.details.get("client", {}).get("location", {})
            
            # For this example, we'll use a simple check - in a real system this would be more sophisticated
            if location_info and not location_info.get("is_private", True):
                # Consider it an anomaly if the user is accessing from a non-private IP
                # In a real system, we'd check against known locations, impossible travel, etc.
                anomaly_detail = {
                    "type": "geographic",
                    "description": "access from unusual location",
                    "ip_address": ip_address,
                    "user_id": user_id,
                }
                
                anomalies_detected.append(anomaly_detail)
                
                # Log a security event for the anomaly - pass _skip_anomaly_check=True to prevent recursion
                await self.log_event(
                    event_type=AuditEventType.SECURITY_ALERT.value,
                    actor_id=user_id,
                    action="geographic_anomaly",
                    status="warning",
                    details=anomaly_detail,
                    severity=AuditSeverity.HIGH,
                    _skip_anomaly_check=True,  # Prevent recursion
                )
        
        # Return True if any anomalies were detected
        return len(anomalies_detected) > 0

    async def _get_client_information(self, request: Request | None) -> dict[str, Any]:
        """
        Extract relevant client information from a request for audit logging.

        Args:
            request: FastAPI request object

        Returns:
            Dictionary containing client information
        """
        if not request:
            return {}

        try:
            # Extract basic request information
            client_info = {
                "ip_address": request.client.host if hasattr(request, "client") else None,
                "user_agent": request.headers.get("user-agent"),
                "method": request.method if hasattr(request, "method") else None,
                "url": str(request.url) if hasattr(request, "url") else None,
                "referer": request.headers.get("referer"),
            }

            # Add location information (in a real system, we would use a GeoIP lookup)
            if client_info["ip_address"]:
                try:
                    ip = ipaddress.ip_address(client_info["ip_address"])
                    client_info["location"] = {
                        "is_private": ip.is_private,
                        "is_global": ip.is_global,
                        # In a real implementation, we would include country, city, etc.
                        # based on GeoIP lookup
                    }
                except Exception as e:
                    logger.warning(f"Error processing IP address: {str(e)}")

            return client_info
        except Exception as e:
            logger.warning(f"Error extracting client information: {str(e)}")
            return {"error": str(e)}

    def _calculate_hash(self, log: AuditLog) -> str:
        """
        Calculate a hash for an audit log entry for tamper detection.

        Args:
            log: The audit log entry to hash

        Returns:
            SHA-256 hash of the log entry
        """
        # Create a string representation of the log
        log_str = (
            f"{log.id}|{log.timestamp.isoformat()}|{log.event_type}|"
            f"{log.actor_id or ''}|{log.action or ''}|{log.status}|"
            f"{json.dumps(log.details) if log.details else '{}'}|"
            f"{log.severity}|{log.previous_hash}"
        )
        
        # Calculate SHA-256 hash
        return hashlib.sha256(log_str.encode()).hexdigest()