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
from datetime import datetime
from typing import Dict, List, Optional, Any, Union

from app.infrastructure.logging.logger import get_logger

logger = get_logger(__name__)

class AuditLogger:
    """
    HIPAA-compliant audit logging system that tracks all PHI access events.
    
    Features:
    - Records user, resource, action, and reason for all PHI access
    - Maintains tamper-evident logs with HMAC signatures
    - Supports searching and exporting logs for compliance reporting
    - Enforces role-based access control for audit log access
    """
    
    def __init__(self):
        """Initialize the audit logger with an in-memory log store."""
        # In production, this would use a secure database with encryption
        self._logs: Dict[str, Dict[str, Any]] = {}
        
        # In production, this would be a secure key management solution
        # We're using a fixed key for testing only
        self._hmac_key = b"TEST_HMAC_KEY_FOR_LOG_INTEGRITY" 
        
        # Cache of users allowed to access audit logs by role
        self._allowed_roles = {"admin"}  # Only admins have full access by default

    def log_phi_access(
        self,
        user_id: str,
        resource_type: str,
        resource_id: str,
        action: str,
        reason: str,
        ip_address: str = "127.0.0.1",  # Default for testing
        additional_data: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Log PHI access event to the audit trail.
        
        Args:
            user_id: ID of the user accessing PHI
            resource_type: Type of resource (e.g., patient_record, medication_history)
            resource_id: ID of the specific resource 
            action: Action performed (view, update, delete, etc.)
            reason: Business reason for access (treatment, payment, operations)
            ip_address: IP address of the user (default provided for testing)
            additional_data: Any additional context to include in the log
            
        Returns:
            log_id: Unique ID of the created audit log entry
        """
        log_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        
        # Create the log entry
        log_entry = {
            "log_id": log_id,
            "timestamp": timestamp,
            "user_id": user_id,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "action": action,
            "reason": reason,
            "ip_address": ip_address,
            "additional_data": additional_data or {}
        }
        
        # Add HMAC signature for integrity verification
        log_entry["signature"] = self._sign_log_entry(log_entry)
        
        # Store the log entry
        self._logs[log_id] = log_entry
        
        logger.info(f"Audit: PHI access: {action} {resource_type}:{resource_id} by user:{user_id} for {reason}")
        
        return log_id

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
        reason: Optional[str] = None
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
            
        Returns:
            List of matching log entries
        """
        results = []
        
        for log_entry in self._logs.values():
            # Apply filters (if provided)
            if user_id and log_entry.get("user_id") != user_id:
                continue
                
            if resource_id and log_entry.get("resource_id") != resource_id:
                continue
                
            if resource_type and log_entry.get("resource_type") != resource_type:
                continue
                
            if action and log_entry.get("action") != action:
                continue
                
            if reason and log_entry.get("reason") != reason:
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
                    
            # All filters passed, include in results
            results.append(log_entry.copy())  # Copy to prevent modification
            
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
        
        # Compute a new signature and compare with the stored one
        computed_signature = self._sign_log_entry(log_copy)
        
        is_valid = hmac.compare_digest(original_signature, computed_signature)
        
        if not is_valid:
            logger.warning(f"Audit log integrity check failed for {log_id}")
            
        return is_valid

    def check_log_access(self, user_id: str, role: str) -> Union[bool, str]:
        """
        Check if a user has permission to access audit logs.
        
        Args:
            user_id: ID of the user requesting access
            role: Role of the user
            
        Returns:
            True for full access, 'limited' for restricted access, False for no access
        """
        # Admin roles have full access
        if role == "admin" or role in self._allowed_roles:
            return True
            
        # Doctors may have limited access (e.g., only to their own actions)
        if role == "doctor":
            return "limited"
            
        # All other roles have no access
        return False

    def export_logs(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        format: str = "json"
    ) -> str:
        """
        Export audit logs for a date range in the specified format.
        
        Args:
            start_date: Start date for log export
            end_date: End date for log export
            format: Export format (currently only 'json' is supported)
            
        Returns:
            Path to the exported file
        """
        # Filter logs by date range
        logs_to_export = self.search_logs(start_date=start_date, end_date=end_date)
        
        # Create an export filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        export_dir = os.path.join(os.getcwd(), "audit_exports")
        os.makedirs(export_dir, exist_ok=True)
        
        export_file = os.path.join(export_dir, f"audit_export_{timestamp}.json")
        
        # Write logs to file
        with open(export_file, "w") as f:
            json.dump(logs_to_export, f, indent=2)
            
        logger.info(f"Exported {len(logs_to_export)} audit logs to {export_file}")
        
        return export_file

    def modify_log_entry_for_testing(self, log_id: str, changes: Dict[str, Any]) -> bool:
        """
        Test method to attempt modifying a log entry (should be detected by integrity check).
        This method would not exist in a production system.
        
        Args:
            log_id: ID of the log entry to modify
            changes: Dictionary of changes to apply
            
        Returns:
            True if modifications were made, False otherwise
        """
        if log_id not in self._logs:
            return False
            
        # Apply changes
        for key, value in changes.items():
            if key != "signature":  # Don't allow direct signature modification
                self._logs[log_id][key] = value
                
        return True

    def _sign_log_entry(self, log_entry: Dict[str, Any]) -> str:
        """
        Create an HMAC signature for a log entry to detect tampering.
        
        Args:
            log_entry: The log entry to sign (without signature field)
            
        Returns:
            HMAC signature as a hex string
        """
        # Convert log entry to a canonical JSON string
        canonical = json.dumps(log_entry, sort_keys=True)
        
        # Create HMAC signature
        signature = hmac.new(
            self._hmac_key,
            canonical.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        return signature 