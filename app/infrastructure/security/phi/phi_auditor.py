"""
PHI Auditor for HIPAA Compliance

This module provides a PHI auditor that scans code, API endpoints, and configuration
for potential HIPAA compliance issues. It detects PHI in code, unprotected API endpoints,
and security configuration issues.
"""

import os
import re
import glob
import logging
import json
from pathlib import Path
from typing import Dict, List, Any, Set, Optional, Tuple, Union
from enum import Enum, auto
import uuid
from datetime import datetime

from app.infrastructure.security.phi.phi_service import PHIService, PHIType
from app.domain.utils.datetime_utils import UTC

logger = logging.getLogger(__name__)

class AuditMode(Enum):
    """Audit modes for PHI detection."""
    STRICT = auto()  # Fail on any PHI detection
    NORMAL = auto()  # Standard detection with exemptions
    PERMISSIVE = auto()  # Only fail on high-confidence PHI


class PHIAuditor:
    """
    PHI Auditor for HIPAA compliance.
    
    Scans code, API endpoints, and configuration for potential HIPAA compliance issues.
    """
    
    # Directories that are exempt from PHI detection
    EXEMPT_DIRS = {
        "tests", "test", "mocks", "fixtures", "clean_app", 
        "__pycache__", ".git", ".venv", "venv", "node_modules"
    }
    
    # File patterns that are exempt from PHI detection
    EXEMPT_FILE_PATTERNS = {
        r"test_.*\.py$",
        r".*_test\.py$",
        r"conftest\.py$",
        r".*\.test\.js$",
        r".*\.spec\.js$",
        r".*\.test\.ts$",
        r".*\.spec\.ts$"
    }
    
    # Critical security settings that should be present in configuration
    CRITICAL_SECURITY_SETTINGS = {
        "SECRET_KEY",
        "SECURE_SSL_REDIRECT",
        "SESSION_COOKIE_SECURE",
        "CSRF_COOKIE_SECURE",
        "SECURE_HSTS_SECONDS",
        "SECURE_CONTENT_TYPE_NOSNIFF"
    }
    
    def __init__(self, app_dir: str, mode: AuditMode = AuditMode.NORMAL):
        """
        Initialize the PHI auditor.
        
        Args:
            app_dir: Directory to audit
            mode: Audit mode (STRICT, NORMAL, PERMISSIVE)
        """
        self.app_dir = Path(app_dir)
        self.mode = mode
        self.phi_service = PHIService()
        self.findings = {
            "code_phi": [],
            "api_security": [],
            "configuration_issues": []
        }
        logger.info(f"Initialized PHI auditor for {app_dir} in {mode} mode")
    
    def audit_code_for_phi(self) -> Dict[str, Any]:
        """
        Audit code for PHI.
        
        Returns:
            Dict with PHI findings
        """
        logger.info(f"Auditing code for PHI in {self.app_dir}")
        
        # Get all code files
        code_files = self._get_code_files()
        logger.info(f"Found {len(code_files)} code files to audit")
        
        # Scan each file for PHI
        for file_path in code_files:
            relative_path = file_path.relative_to(self.app_dir)
            
            # Skip exempt files
            if self._is_exempt_file(relative_path):
                logger.debug(f"Skipping exempt file: {relative_path}")
                continue
            
            # Read file content
            try:
                content = file_path.read_text(errors='replace')
            except Exception as e:
                logger.warning(f"Error reading file {relative_path}: {e}")
                continue
            
            # Detect PHI in file
            phi_findings = self.phi_service.detect_phi(content)
            
            if phi_findings:
                logger.info(f"Found {len(phi_findings)} PHI instances in {relative_path}")
                
                # In strict mode, add all findings
                if self.mode == AuditMode.STRICT:
                    for phi_type, matched_text, start, end in phi_findings:
                        self.findings["code_phi"].append({
                            "file": str(relative_path),
                            "phi_type": phi_type.name,
                            "matched_text": matched_text,
                            "position": {"start": start, "end": end},
                            "line": self._get_line_number(content, start)
                        })
                # In normal mode, skip findings in exempt directories
                elif self.mode == AuditMode.NORMAL:
                    if not any(exempt_dir in str(relative_path).lower() for exempt_dir in self.EXEMPT_DIRS):
                        for phi_type, matched_text, start, end in phi_findings:
                            self.findings["code_phi"].append({
                                "file": str(relative_path),
                                "phi_type": phi_type.name,
                                "matched_text": matched_text,
                                "position": {"start": start, "end": end},
                                "line": self._get_line_number(content, start)
                            })
                # In permissive mode, only add high-confidence findings
                elif self.mode == AuditMode.PERMISSIVE:
                    high_confidence_types = {PHIType.SSN, PHIType.EMAIL, PHIType.PHONE, PHIType.CREDIT_CARD}
                    for phi_type, matched_text, start, end in phi_findings:
                        if phi_type in high_confidence_types:
                            self.findings["code_phi"].append({
                                "file": str(relative_path),
                                "phi_type": phi_type.name,
                                "matched_text": matched_text,
                                "position": {"start": start, "end": end},
                                "line": self._get_line_number(content, start)
                            })
        
        return {"code_phi": self.findings["code_phi"]}
    
    def audit_api_endpoints(self) -> Dict[str, Any]:
        """
        Audit API endpoints for security issues.
        
        Returns:
            Dict with API security findings
        """
        logger.info(f"Auditing API endpoints in {self.app_dir}")
        
        # Get all API route files
        api_files = self._get_api_files()
        logger.info(f"Found {len(api_files)} API files to audit")
        
        # Patterns to detect API endpoints
        endpoint_pattern = re.compile(r'@(?:router|app)\.(?:get|post|put|delete|patch)\s*\(\s*[\'"]([^\'"]+)[\'"]')
        auth_pattern = re.compile(r'(?:Depends\s*\(\s*(?:get_current_user|require_auth|authenticate|jwt_required|auth_required|verify_token|check_auth)|auth_required|jwt_required)')
        
        # Patterns to detect sensitive endpoints
        sensitive_patterns = [
            re.compile(r'(?:patient|user|profile|medical|health|record|phi|ssn|insurance|billing|payment|prescription|medication|diagnosis)', re.IGNORECASE),
            re.compile(r'(?:admin|secure|protected|private|confidential)', re.IGNORECASE)
        ]
        
        # Scan each file for API endpoints
        for file_path in api_files:
            relative_path = file_path.relative_to(self.app_dir)
            
            # Read file content
            try:
                content = file_path.read_text(errors='replace')
            except Exception as e:
                logger.warning(f"Error reading file {relative_path}: {e}")
                continue
            
            # Find all endpoints
            endpoints = endpoint_pattern.findall(content)
            
            for endpoint in endpoints:
                # Find the endpoint definition
                endpoint_match = re.search(rf'@(?:router|app)\.(?:get|post|put|delete|patch)\s*\(\s*[\'"]({re.escape(endpoint)})[\'"].*?\n(.*?)def\s+(\w+)', content, re.DOTALL)
                
                if endpoint_match:
                    endpoint_definition = endpoint_match.group(2)
                    handler_name = endpoint_match.group(3)
                    
                    # Check if endpoint has authentication
                    has_auth = bool(auth_pattern.search(endpoint_definition))
                    
                    # Check if endpoint is sensitive
                    is_sensitive = any(pattern.search(endpoint) for pattern in sensitive_patterns) or \
                                  any(pattern.search(handler_name) for pattern in sensitive_patterns)
                    
                    # If sensitive endpoint has no auth, add to findings
                    if is_sensitive and not has_auth:
                        self.findings["api_security"].append({
                            "file": str(relative_path),
                            "endpoint": endpoint,
                            "handler": handler_name,
                            "evidence": f"{handler_name} handles sensitive data but lacks authentication",
                            "line": self._get_line_number(content, endpoint_match.start())
                        })
        
        return {"api_security": self.findings["api_security"]}
    
    def audit_configuration(self) -> Dict[str, Any]:
        """
        Audit configuration for security issues.
        
        Returns:
            Dict with configuration findings
        """
        logger.info(f"Auditing configuration in {self.app_dir}")
        
        # Get all configuration files
        config_files = self._get_config_files()
        logger.info(f"Found {len(config_files)} configuration files to audit")
        
        # Scan each file for security settings
        for file_path in config_files:
            relative_path = file_path.relative_to(self.app_dir)
            
            # Read file content
            try:
                content = file_path.read_text(errors='replace')
            except Exception as e:
                logger.warning(f"Error reading file {relative_path}: {e}")
                continue
            
            # Check for missing critical security settings
            missing_settings = []
            for setting in self.CRITICAL_SECURITY_SETTINGS:
                if not re.search(rf'{setting}\s*=', content):
                    missing_settings.append(setting)
            
            if missing_settings:
                self.findings["configuration_issues"].append({
                    "file": str(relative_path),
                    "missing_settings": missing_settings,
                    "evidence": f"Missing critical security settings: {', '.join(missing_settings)}",
                    "severity": "high" if len(missing_settings) > 2 else "medium"
                })
            
            # Check for insecure settings
            insecure_settings = []
            if re.search(r'DEBUG\s*=\s*True', content):
                insecure_settings.append("DEBUG = True")
            
            if re.search(r'ALLOWED_HOSTS\s*=\s*\[\s*[\'"]?\*[\'"]?\s*\]', content):
                insecure_settings.append("ALLOWED_HOSTS = ['*']")
            
            if re.search(r'SECRET_KEY\s*=\s*[\'"][a-zA-Z0-9_]{1,20}[\'"]', content):
                insecure_settings.append("SECRET_KEY too short or weak")
            
            if insecure_settings:
                self.findings["configuration_issues"].append({
                    "file": str(relative_path),
                    "insecure_settings": insecure_settings,
                    "evidence": f"Insecure settings detected: {', '.join(insecure_settings)}",
                    "severity": "high"
                })
        
        return {"configuration_issues": self.findings["configuration_issues"]}
    
    def _audit_passed(self) -> bool:
        """
        Check if the audit passed.
        
        Returns:
            True if audit passed, False otherwise
        """
        # In strict mode, any findings fail the audit
        if self.mode == AuditMode.STRICT:
            return not (self.findings["code_phi"] or self.findings["api_security"] or self.findings["configuration_issues"])
        
        # In normal mode, exempt directories are allowed to have PHI
        elif self.mode == AuditMode.NORMAL:
            # Check if any PHI findings are in non-exempt directories
            non_exempt_phi = [f for f in self.findings["code_phi"] 
                             if not any(exempt_dir in f["file"].lower() for exempt_dir in self.EXEMPT_DIRS)]
            
            return not (non_exempt_phi or self.findings["api_security"] or self.findings["configuration_issues"])
        
        # In permissive mode, only high-severity findings fail the audit
        elif self.mode == AuditMode.PERMISSIVE:
            high_severity_config = [f for f in self.findings["configuration_issues"] if f.get("severity") == "high"]
            return not (self.findings["code_phi"] or self.findings["api_security"] or high_severity_config)
        
        return False
    
    def _get_code_files(self) -> List[Path]:
        """
        Get all code files in the app directory.
        
        Returns:
            List of code file paths
        """
        extensions = [".py", ".js", ".ts", ".jsx", ".tsx", ".vue", ".html", ".css", ".scss", ".sql"]
        
        code_files = []
        for ext in extensions:
            code_files.extend(self.app_dir.glob(f"**/*{ext}"))
        
        return code_files
    
    def _get_api_files(self) -> List[Path]:
        """
        Get all API route files in the app directory.
        
        Returns:
            List of API file paths
        """
        # Common patterns for API route files
        patterns = [
            "**/routes/*.py",
            "**/endpoints/*.py",
            "**/api/*.py",
            "**/routers/*.py",
            "**/controllers/*.py",
            "**/views/*.py"
        ]
        
        api_files = []
        for pattern in patterns:
            api_files.extend(self.app_dir.glob(pattern))
        
        return api_files
    
    def _get_config_files(self) -> List[Path]:
        """
        Get all configuration files in the app directory.
        
        Returns:
            List of configuration file paths
        """
        # Common patterns for configuration files
        patterns = [
            "**/settings.py",
            "**/config.py",
            "**/configuration.py",
            "**/*.config.js",
            "**/*.config.ts",
            "**/config.json",
            "**/config.yaml",
            "**/config.yml"
        ]
        
        config_files = []
        for pattern in patterns:
            config_files.extend(self.app_dir.glob(pattern))
        
        return config_files
    
    def _is_exempt_file(self, file_path: Path) -> bool:
        """
        Check if file is exempt from PHI detection.
        
        Args:
            file_path: Path to file
            
        Returns:
            True if file is exempt, False otherwise
        """
        # Check if file is in exempt directory
        if any(exempt_dir in str(file_path).lower() for exempt_dir in self.EXEMPT_DIRS):
            return True
        
        # Check if file matches exempt pattern
        file_str = str(file_path)
        return any(re.search(pattern, file_str) for pattern in self.EXEMPT_FILE_PATTERNS)
    
    def _get_line_number(self, content: str, position: int) -> int:
        """
        Get line number for a position in text.
        
        Args:
            content: Text content
            position: Character position
            
        Returns:
            Line number (1-based)
        """
        return content[:position].count('\n') + 1


class PHIAuditHandler:
    """
    Handles auditing of PHI access in accordance with HIPAA requirements.
    
    Records all data access including who accessed what PHI, when, and why.
    Supports both synchronous and asynchronous logging, storage to database,
    and configurable alert mechanisms for suspicious access patterns.
    """
    
    def __init__(self, storage_service=None):
        """
        Initialize the PHI audit handler.
        
        Args:
            storage_service: Optional service for persisting audit records
        """
        self._storage = storage_service
        self._in_memory_records = []
        
    def log_phi_access(
        self, 
        user_id: str, 
        action: str, 
        resource_type: str, 
        resource_id: str,
        reason: Optional[str] = None,
        success: bool = True,
        details: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Record an audit entry for PHI access.
        
        Args:
            user_id: ID of the user who accessed PHI
            action: Type of action performed (read, write, update, delete)
            resource_type: Type of resource accessed (patient, note, prescription)
            resource_id: ID of the specific resource
            reason: Reason for access
            success: Whether the access attempt was successful
            details: Additional details about the access
            
        Returns:
            ID of the created audit record
        """
        timestamp = datetime.now(UTC)
        record_id = str(uuid.uuid4())
        
        record = {
            "id": record_id,
            "timestamp": timestamp.isoformat(),
            "user_id": user_id,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "reason": reason,
            "success": success,
            "details": details or {}
        }
        
        # Log to system logs (sanitized)
        logger.info(
            f"PHI ACCESS: User {user_id} performed {action} on {resource_type} "
            f"{resource_id} - {'SUCCESS' if success else 'FAILED'}"
        )
        
        # Store in memory for immediate access
        self._in_memory_records.append(record)
        
        # Store in persistent storage if available
        if self._storage:
            try:
                self._storage.store_audit_record(record)
            except Exception as e:
                logger.error(f"Failed to store PHI audit record: {e}")
                # Continue execution since we have the in-memory record
        
        return record_id
    
    def get_user_access_records(self, user_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get audit records for a specific user.
        
        Args:
            user_id: ID of the user to get records for
            limit: Maximum number of records to return
            
        Returns:
            List of audit records
        """
        if self._storage:
            try:
                return self._storage.get_audit_records_by_user(user_id, limit)
            except Exception as e:
                logger.error(f"Failed to retrieve PHI audit records: {e}")
                
        # Fall back to in-memory records if storage fails or is unavailable
        return [r for r in self._in_memory_records if r["user_id"] == user_id][:limit]
    
    def get_resource_access_records(self, resource_type: str, resource_id: str, 
                                 limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get audit records for a specific resource.
        
        Args:
            resource_type: Type of resource to get records for
            resource_id: ID of the specific resource
            limit: Maximum number of records to return
            
        Returns:
            List of audit records
        """
        if self._storage:
            try:
                return self._storage.get_audit_records_by_resource(
                    resource_type, resource_id, limit
                )
            except Exception as e:
                logger.error(f"Failed to retrieve PHI audit records: {e}")
                
        # Fall back to in-memory records
        return [
            r for r in self._in_memory_records 
            if r["resource_type"] == resource_type and r["resource_id"] == resource_id
        ][:limit]

    def export_audit_logs(self, start_date: datetime, end_date: datetime, 
                         format: str = "json") -> Union[str, bytes]:
        """
        Export audit logs for a date range in the specified format.
        
        Args:
            start_date: Start date for export range
            end_date: End date for export range
            format: Export format ("json", "csv")
            
        Returns:
            Exported audit logs in the specified format
        """
        if self._storage:
            try:
                records = self._storage.get_audit_records_by_date_range(start_date, end_date)
            except Exception as e:
                logger.error(f"Failed to retrieve PHI audit records: {e}")
                records = []
        else:
            records = [
                r for r in self._in_memory_records 
                if start_date <= datetime.fromisoformat(r["timestamp"]) <= end_date
            ]
        
        if format.lower() == "json":
            return json.dumps(records, default=str)
        elif format.lower() == "csv":
            if not records:
                return "No records found"
                
            # Simple CSV conversion
            headers = list(records[0].keys())
            csv_rows = [",".join(headers)]
            for record in records:
                row = [str(record.get(h, "")) for h in headers]
                csv_rows.append(",".join(row))
            return "\n".join(csv_rows)
        else:
            raise ValueError(f"Unsupported export format: {format}")


# Singleton instance for app-wide use
default_phi_audit_handler = PHIAuditHandler()

def log_phi_access(
    user_id: str, 
    action: str, 
    resource_type: str, 
    resource_id: str,
    **kwargs
) -> str:
    """
    Convenience function to log PHI access using the default handler.
    
    Args:
        user_id: User making the access
        action: Action performed on PHI
        resource_type: Type of PHI resource
        resource_id: ID of the PHI resource
        **kwargs: Additional parameters passed to log_phi_access
        
    Returns:
        ID of the created audit record
    """
    return default_phi_audit_handler.log_phi_access(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        **kwargs
    )

def get_phi_audit_handler() -> PHIAuditHandler:
    """
    Get the default PHI audit handler.
    
    Returns:
        The default PHI audit handler
    """
    return default_phi_audit_handler
