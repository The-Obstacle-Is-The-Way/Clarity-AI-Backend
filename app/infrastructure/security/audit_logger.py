"""
HIPAA-compliant audit logging service for healthcare applications.

This module provides the audit logging functionality required by HIPAA regulations,
specifically §164.312(b) - Audit controls, which requires implementing:
"Hardware, software, and/or procedural mechanisms that record and examine 
activity in information systems that contain or use electronic protected health information."

This implementation creates tamper-resistant audit logs that track all PHI access events,
with features for searching, exporting, and verifying log integrity.
"""

import json
import os
import uuid
import time
import hashlib
import hmac
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union, Set

import secrets
import base64
import aiofiles
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from app.core.interfaces.services.audit_logger_interface import (
    IAuditLogger, AuditEventType, AuditSeverity
)
from app.infrastructure.logging.logger import get_logger

logger = get_logger(__name__)

class AuditLogger:
    """
    HIPAA-compliant audit logging system that tracks all PHI access events.
    
    Features:
    - Records user, resource, action, and reason for all PHI access
    - Maintains tamper-evident logs with HMAC signatures
    - Provides cryptographic integrity verification
    - Supports searching and exporting logs for compliance reporting
    - Enforces role-based access control for audit log access
    - Implements §164.312(b) audit controls
    """
    
    def __init__(self, store_path: str = None):
        """
        Initialize the audit logger with a storage mechanism.
        
        Args:
            store_path: Optional file path for storage. If None, uses in-memory storage.
        """
        # In production, this would use a secure database with encryption
        self._logs: Dict[str, Dict[str, Any]] = {}
        self._store_path = store_path
        
        # Secure key generation for HMAC signing
        # In production, this would use a key management service
        if not hasattr(self, '_hmac_key') or not self._hmac_key:
            # Generate a cryptographically secure key
            self._hmac_key = secrets.token_bytes(32)
        
        # Track the hash chain for tamper evidence
        self._previous_hash = hashlib.sha256(b"AUDIT_LOG_INIT").hexdigest()
        
        # Cache of users allowed to access audit logs by role
        self._allowed_roles: Set[str] = {"admin", "security_officer", "compliance_officer"}
        
        # Validate configuration
        if store_path and not os.path.exists(os.path.dirname(store_path)):
            os.makedirs(os.path.dirname(store_path), exist_ok=True)
            logger.info(f"Created audit log directory: {os.path.dirname(store_path)}")

    def log_access(
        self,
        resource_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        field_name: Optional[str] = None,
        action: str = "field_access",
        user_id: Optional[str] = None,
        ip_address: str = "127.0.0.1",
        reason: Optional[str] = None
    ) -> str:
        """
        Log PHI field access to the audit trail.
        
        Args:
            resource_id: ID of the specific resource (e.g., patient ID)
            resource_type: Type of resource (e.g., Patient)
            field_name: Name of the field being accessed
            action: Action performed (default: field_access)
            user_id: ID of the user accessing PHI (if available)
            ip_address: IP address of the user (default for testing)
            reason: Reason for the access (required by HIPAA)
            
        Returns:
            log_id: Unique ID of the created audit log entry
        """
        log_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        
        # Create the log entry
        log_entry = {
            "log_id": log_id,
            "timestamp": timestamp,
            "user_id": user_id,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "field_name": field_name,
            "action": action,
            "ip_address": ip_address,
            "reason": reason or "Not specified",  # HIPAA requires a reason
            "hash_chain": self._calculate_chain_hash(log_id, timestamp, user_id, action)
        }
        
        # Add HMAC signature for integrity verification
        log_entry["signature"] = self._sign_log_entry(log_entry)
        
        # Store the log entry
        self._logs[log_id] = log_entry
        self._save_log_entry(log_entry)
        
        # Update the hash chain
        self._previous_hash = log_entry["hash_chain"]
        
        logger.info(f"PHI Access: {action} {resource_type}:{resource_id} field:{field_name} by:{user_id}")
        
        return log_id

    def log_phi_access(
        self,
        user_id: str,
        resource_type: str,
        resource_id: str,
        action: str,
        reason: str,
        ip_address: str = "127.0.0.1",  # Default for testing
        additional_context: Optional[Dict[str, Any]] = None,
        access_reason: str = None
    ) -> str:
        """
        Log PHI access event to the audit trail.
        
        Args:
            user_id: ID of the user accessing PHI
            resource_type: Type of resource (e.g., patient_record, medication_history)
            resource_id: ID of the specific resource 
            action: Action performed (view, update, delete, etc.)
            reason: Reason for operation (e.g., treatment, payment, healthcare operations)
            ip_address: IP address of the user (default provided for testing)
            additional_context: Any additional context to include in the log
            access_reason: Legacy parameter for backward compatibility
            
        Returns:
            log_id: Unique ID of the created audit log entry
        """
        log_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        
        # Support legacy reason parameter
        actual_reason = reason or access_reason or "Not specified"
        
        # Create the log entry with HIPAA-required fields
        log_entry = {
            "log_id": log_id,
            "timestamp": timestamp,
            "user_id": user_id,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "action": action,
            "reason": actual_reason,
            "ip_address": ip_address,
            "additional_context": additional_context or {},
            "hash_chain": self._calculate_chain_hash(log_id, timestamp, user_id, action)
        }
        
        # Add HMAC signature for integrity verification (RFC 2104 compliance)
        log_entry["signature"] = self._sign_log_entry(log_entry)
        
        # Store the log entry
        self._logs[log_id] = log_entry
        self._save_log_entry(log_entry)
        
        # Update the hash chain
        self._previous_hash = log_entry["hash_chain"]
        
        # Log the event
        logger.info(f"Audit: PHI access: {action} {resource_type}:{resource_id} by user:{user_id} for {actual_reason}")
        
        return log_id

    def log_data_modification(
        self,
        user_id: str,
        action: str,
        entity_type: str,
        entity_id: str,
        status: str,
        details: Optional[str] = None,
        phi_fields: Optional[list[str]] = None
    ) -> str:
        """
        Log data modification events for HIPAA-compliant audit trails.
        
        Args:
            user_id: ID of the user modifying the data
            action: Type of modification (create, update, delete)
            entity_type: Type of entity being modified
            entity_id: ID of the entity being modified
            status: Outcome of the operation (success, failed)
            details: Details about the modifications
            phi_fields: List of PHI fields that were modified (without values)
            
        Returns:
            log_id: Unique ID of the created audit log entry
        """
        log_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        
        # Create the log entry specifically for data modifications
        log_entry = {
            "log_id": log_id,
            "timestamp": timestamp,
            "user_id": user_id,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "action": action,
            "status": status,
            "details": details or "No details provided",
            "phi_fields": phi_fields or [],
            "log_type": "data_modification",
            "hash_chain": self._calculate_chain_hash(log_id, timestamp, user_id, action)
        }
        
        # Add HMAC signature for integrity verification
        log_entry["signature"] = self._sign_log_entry(log_entry)
        
        # Store the log entry
        self._logs[log_id] = log_entry
        self._save_log_entry(log_entry)
        
        # Update the hash chain
        self._previous_hash = log_entry["hash_chain"]
        
        # Log the event
        logger.info(f"Audit: Data modification: {action} {entity_type}:{entity_id} by user:{user_id} status:{status}")
        
        return log_id

    async def log_event(
        self,
        event_type: Union[AuditEventType, str],
        actor_id: Optional[str] = None,
        target_resource: Optional[str] = None,
        target_id: Optional[str] = None,
        action: Optional[str] = None,
        status: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        severity: Optional[Union[AuditSeverity, str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        timestamp: Optional[datetime] = None,
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
            
        Returns:
            str: Unique identifier for the audit log entry
        """
        log_id = str(uuid.uuid4())
        actual_timestamp = timestamp or datetime.now(timezone.utc)
        timestamp_iso = actual_timestamp.isoformat()
        
        # Normalize event_type and severity to strings if they are enums
        event_type_str = event_type.value if hasattr(event_type, 'value') else str(event_type)
        severity_str = severity.value if hasattr(severity, 'value') else (str(severity) if severity else "info")
        
        # Create the log entry
        log_entry = {
            "log_id": log_id,
            "event_type": event_type_str,
            "timestamp": timestamp_iso,
            "actor_id": actor_id,
            "target_resource": target_resource,
            "target_id": target_id,
            "action": action,
            "status": status,
            "details": details or {},
            "severity": severity_str,
            "metadata": metadata or {},
            "log_type": "event",
            "hash_chain": self._calculate_chain_hash(log_id, timestamp_iso, actor_id, event_type_str)
        }
        
        # Add HMAC signature for integrity verification
        log_entry["signature"] = self._sign_log_entry(log_entry)
        
        # Store the log entry
        self._logs[log_id] = log_entry
        self._save_log_entry(log_entry)
        
        # Update the hash chain
        self._previous_hash = log_entry["hash_chain"]
        
        # Log the event
        if severity == "critical" or severity == AuditSeverity.CRITICAL:
            logger.critical(f"AUDIT ({event_type_str}): {action} {target_resource}:{target_id} by {actor_id} - {status}")
        elif severity == "high" or severity == AuditSeverity.HIGH:
            logger.error(f"AUDIT ({event_type_str}): {action} {target_resource}:{target_id} by {actor_id} - {status}")
        else:
            logger.info(f"AUDIT ({event_type_str}): {action} {target_resource}:{target_id} by {actor_id} - {status}")
        
        return log_id

    async def log_security_event(
        self,
        description: str,
        actor_id: Optional[str] = None,
        status: Optional[str] = None,
        severity: Union[AuditSeverity, str] = AuditSeverity.HIGH,
        details: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Log a security-related event.
        
        Args:
            description: Description of the security event
            actor_id: ID of the user/system involved
            status: Status of the security event
            severity: Severity level of the event
            details: Additional details about the event
            
        Returns:
            str: Unique identifier for the audit log entry
        """
        # Use the generic log_event method with security-specific defaults
        return await self.log_event(
            event_type=AuditEventType.OTHER,
            actor_id=actor_id,
            target_resource="security",
            action="security_event",
            status=status,
            details={"description": description, **(details or {})},
            severity=severity,
        )

    async def log_phi_access(
        self,
        actor_id: str,
        patient_id: str,
        resource_type: str,
        action: str,
        status: str,
        phi_fields: Optional[list[str]] = None,
        reason: Optional[str] = None,
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
            
        Returns:
            str: Unique identifier for the audit log entry
        """
        # Use the generic log_event method with PHI-specific defaults
        details = {
            "phi_fields": phi_fields or [],
            "reason": reason or "Not specified"
        }
        
        return await self.log_event(
            event_type=AuditEventType.PHI_ACCESSED,
            actor_id=actor_id,
            target_resource=resource_type,
            target_id=patient_id,
            action=action,
            status=status,
            details=details,
            severity=AuditSeverity.HIGH,
        )

    async def get_audit_trail(
        self,
        filters: Optional[Dict[str, Any]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Dict[str, Any]]:
        """
        Retrieve audit trail entries based on filters.
        
        Args:
            filters: Optional filters to apply (e.g., event_type, actor_id)
            start_time: Optional start time for the audit trail
            end_time: Optional end time for the audit trail
            limit: Maximum number of entries to return
            offset: Offset for pagination
            
        Returns:
            list[Dict[str, Any]]: List of audit log entries matching the criteria
        """
        # Start with all logs
        result = list(self._logs.values())
        
        # Apply filters if provided
        if filters:
            filtered_result = []
            for log in result:
                match = True
                for key, value in filters.items():
                    if key not in log or log[key] != value:
                        match = False
                        break
                if match:
                    filtered_result.append(log)
            result = filtered_result
        
        # Apply time range filter if provided
        if start_time or end_time:
            time_filtered = []
            for log in result:
                try:
                    log_time = datetime.fromisoformat(log["timestamp"])
                    if start_time and log_time < start_time:
                        continue
                    if end_time and log_time > end_time:
                        continue
                    time_filtered.append(log)
                except (ValueError, KeyError):
                    continue
            result = time_filtered
        
        # Sort by timestamp (most recent first)
        result.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        
        # Apply pagination
        return result[offset:offset + limit]

    def get_log_entry(self, log_id: str) -> Dict[str, Any]:
        """
        Retrieve a specific log entry by ID.
        
        Args:
            log_id: ID of the log entry to retrieve
            
        Returns:
            The log entry as a dictionary
        """
        if log_id not in self._logs:
            logger.warning(f"Audit log entry {log_id} not found")
            return {}
            
        return self._logs[log_id].copy()  # Return a copy to prevent modification

    def search_logs(
        self,
        user_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        action: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        reason: Optional[str] = None,
        log_type: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Search audit logs with various filters.
        
        Args:
            user_id: Filter by user ID
            resource_id: Filter by resource ID
            resource_type: Filter by resource type
            action: Filter by action performed
            start_date: Filter by minimum timestamp
            end_date: Filter by maximum timestamp
            reason: Filter by access reason
            log_type: Filter by log type (event, data_modification, etc.)
            limit: Maximum number of results to return
            
        Returns:
            List of matching log entries
        """
        results = []
        count = 0
        
        for log_entry in self._logs.values():
            # Apply filters (if provided)
            if user_id and log_entry.get("user_id", log_entry.get("actor_id")) != user_id:
                continue
                
            if resource_id and (
                log_entry.get("resource_id", log_entry.get("target_id", log_entry.get("entity_id"))) != resource_id
            ):
                continue
                
            if resource_type and (
                log_entry.get("resource_type", log_entry.get("target_resource", log_entry.get("entity_type"))) != resource_type
            ):
                continue
                
            if action and log_entry.get("action") != action:
                continue
                
            if reason and log_entry.get("reason") != reason:
                continue
                
            if log_type and log_entry.get("log_type") != log_type:
                continue
                
            # Date range filtering
            if start_date or end_date:
                try:
                    log_date = datetime.fromisoformat(log_entry.get("timestamp", ""))
                    
                    if start_date and log_date < start_date:
                        continue
                        
                    if end_date and log_date > end_date:
                        continue
                except (ValueError, TypeError):
                    # If timestamp parsing fails, skip date filtering
                    pass
                    
            # First verify log integrity before including in results
            if not self.verify_log_integrity(log_entry.get("log_id")):
                logger.warning(f"Log entry {log_entry.get('log_id')} failed integrity check during search")
                continue
                
            # All filters passed, include in results
            results.append(log_entry.copy())  # Copy to prevent modification
            count += 1
            
            if count >= limit:
                break
            
        return results

    def verify_log_integrity(self, log_id: str) -> bool:
        """
        Verify that a log entry has not been tampered with.
        
        Args:
            log_id: ID of the log entry to verify
            
        Returns:
            True if the log entry is intact, False if tampered with or missing
        """
        if log_id not in self._logs:
            logger.warning(f"Audit log entry {log_id} not found during integrity check")
            return False
            
        log_entry = self._logs[log_id]
        original_signature = log_entry.get("signature")
        
        if not original_signature:
            logger.warning(f"Audit log entry {log_id} is missing signature")
            return False
            
        # Create a copy without the signature to compute a new signature
        log_copy = log_entry.copy()
        log_copy.pop("signature")
        
        # Generate a new signature based on the current content
        new_signature = self._sign_log_entry(log_copy)
        
        # Compare signatures
        if original_signature != new_signature:
            logger.warning(f"Audit log entry {log_id} signature mismatch - possible tampering detected")
            return False
            
        return True

    def check_log_access(self, user_id: str, role: str) -> Union[bool, str]:
        """
        Check if a user has permission to access audit logs.
        
        Args:
            user_id: ID of the user requesting access
            role: Role of the user
            
        Returns:
            bool or str: True if access is allowed, or error message if denied
        """
        # Check if role is allowed to access logs
        if role in self._allowed_roles:
            # Log the access attempt (successful)
            self.log_access(
                action="audit_log_access",
                user_id=user_id,
                resource_type="audit_logs",
                reason="Authorized access to audit logs"
            )
            return True
        
        # Log the access attempt (failed)
        self.log_access(
            action="audit_log_access_denied",
            user_id=user_id,
            resource_type="audit_logs",
            reason="Unauthorized access attempt to audit logs"
        )
        
        return f"Access denied: role '{role}' is not authorized to access audit logs"

    def export_logs(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        format: str = "json",
        verify_integrity: bool = True
    ) -> str:
        """
        Export audit logs for a time period.
        
        Args:
            start_date: Optional start date for export
            end_date: Optional end date for export
            format: Export format ('json' or 'csv')
            verify_integrity: Whether to verify log integrity during export
            
        Returns:
            str: Exported logs in the requested format
        """
        # Filter logs by date range
        filtered_logs = []
        
        for log_entry in self._logs.values():
            try:
                log_date = datetime.fromisoformat(log_entry.get("timestamp", ""))
                
                if start_date and log_date < start_date:
                    continue
                    
                if end_date and log_date > end_date:
                    continue
                    
                # Verify integrity if requested
                if verify_integrity and not self.verify_log_integrity(log_entry.get("log_id")):
                    logger.warning(f"Log entry {log_entry.get('log_id')} failed integrity check during export")
                    continue
                
                filtered_logs.append(log_entry)
            except (ValueError, TypeError):
                # Skip logs with invalid timestamps
                continue
                
        # Sort logs by timestamp
        filtered_logs.sort(key=lambda x: x.get("timestamp", ""))
        
        # Export in requested format
        if format.lower() == "json":
            return json.dumps(filtered_logs, indent=2)
        elif format.lower() == "csv":
            # Basic CSV export
            if not filtered_logs:
                return "No logs to export"
                
            # Get all possible headers from all logs
            headers = set()
            for log in filtered_logs:
                headers.update(log.keys())
            headers = sorted(list(headers))
            
            csv_lines = [",".join(headers)]
            
            for log in filtered_logs:
                csv_line = [str(log.get(header, "")) for header in headers]
                csv_lines.append(",".join(csv_line))
                
            return "\n".join(csv_lines)
        else:
            raise ValueError(f"Unsupported export format: {format}")

    def _sign_log_entry(self, log_entry: Dict[str, Any]) -> str:
        """
        Create an HMAC signature for a log entry to ensure integrity.
        
        Args:
            log_entry: The log entry to sign
            
        Returns:
            str: The HMAC signature as a hex string
        """
        # Sort keys for consistent serialization
        sorted_entry = {k: log_entry[k] for k in sorted(log_entry.keys())}
        
        # Serialize to JSON with minimal whitespace
        json_str = json.dumps(sorted_entry, separators=(',', ':'))
        
        # Create HMAC signature using SHA-256
        hmac_obj = hmac.new(
            key=self._hmac_key,
            msg=json_str.encode('utf-8'),
            digestmod=hashlib.sha256
        )
        
        return hmac_obj.hexdigest()

    def _calculate_chain_hash(self, log_id: str, timestamp: str, user_id: Optional[str], action: str) -> str:
        """
        Calculate a hash chain value for tamper evidence.
        
        Args:
            log_id: ID of the current log entry
            timestamp: Timestamp of the log entry
            user_id: User ID associated with the log
            action: Action being logged
            
        Returns:
            str: Hash chain value
        """
        # Combine the previous hash with the current log data
        data = f"{self._previous_hash}{log_id}{timestamp}{user_id or 'anonymous'}{action}"
        
        # Calculate a new hash
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    def _save_log_entry(self, log_entry: Dict[str, Any]) -> None:
        """
        Save a log entry to persistent storage if configured.
        
        Args:
            log_entry: The log entry to save
        """
        if not self._store_path:
            return  # No persistent storage configured
            
        try:
            # Append to the log file
            with open(self._store_path, 'a') as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            logger.error(f"Failed to write audit log to storage: {e}")

    def modify_log_entry_for_testing(self, log_id: str, changes: Dict[str, Any]) -> bool:
        """
        Modify a log entry for testing purposes only.
        
        WARNING: This method should NEVER be used in production as it breaks the 
        integrity of the audit trail and violates HIPAA requirements.
        
        Args:
            log_id: ID of the log entry to modify
            changes: Dictionary of changes to apply
            
        Returns:
            bool: True if the log was modified, False otherwise
        """
        # Only allow in testing environments
        if os.environ.get("ENVIRONMENT", "").lower() != "test":
            logger.error("Attempted to modify audit log outside of testing environment")
            return False
            
        if log_id not in self._logs:
            return False
            
        # Apply changes
        for key, value in changes.items():
            self._logs[log_id][key] = value
            
        return True 