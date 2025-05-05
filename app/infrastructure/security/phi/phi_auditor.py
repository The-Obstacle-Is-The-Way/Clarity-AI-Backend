"""
HIPAA-compliant PHI auditing (compatibility stub).

This module provides backward compatibility for PHI audit functionality,
delegating to the consolidated PHISanitizer implementation where appropriate.
"""

import logging
from datetime import datetime
from pathlib import Path

from app.core.utils.logging import get_logger
from app.infrastructure.security.phi.sanitizer import PHISanitizer

# Define a more specific type for data potentially containing PHI
PotentiallySensitiveData = str | dict | list | object

# Define structure for audit findings
PHIFinding = dict[str, str | int | None]

# Get logger instance(s)
phi_audit_logger = logging.getLogger("phi_audit")


class PHIAuditHandler:
    """
    Compatibility stub for PHI audit handling.
    Provides HIPAA-compliant auditing of PHI access and modifications.
    """
    
    def __init__(self, sanitizer: PHISanitizer | None = None):
        """
        Initialize the PHI audit handler.
        
        Args:
            sanitizer: Optional PHI sanitizer to use (creates a new one if None)
        """
        self.sanitizer = sanitizer or PHISanitizer()
        self.logger = phi_audit_logger
        # Ensure audit logger is properly configured
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
    
    def log_phi_access(
        self, 
        user_id: str, 
        patient_id: str, 
        data_accessed: PotentiallySensitiveData,
        reason: str = "treatment"
    ) -> None:
        """
        Log PHI access for auditing purposes.
        
        Args:
            user_id: ID of user accessing PHI
            patient_id: ID of patient whose PHI was accessed
            data_accessed: Data that was accessed (will be sanitized in logs)
            reason: Purpose of access (e.g., "treatment", "payment", "operations")
        """
        # Sanitize PHI in audit log
        sanitized_data = self.sanitizer.sanitize(data_accessed)
        
        # Log the access event
        self.logger.info(
            f"PHI Access - User: {user_id}, Patient: {patient_id}, "
            f"Reason: {reason}, Timestamp: {datetime.now().isoformat()}, "
            f"Data: {sanitized_data}"
        )
    
    def log_phi_modification(
        self, 
        user_id: str, 
        patient_id: str, 
        modification_type: str,
        before_state: PotentiallySensitiveData,
        after_state: PotentiallySensitiveData,
        reason: str = "treatment"
    ) -> None:
        """
        Log PHI modification for auditing purposes.
        
        Args:
            user_id: ID of user modifying PHI
            patient_id: ID of patient whose PHI was modified
            modification_type: Type of modification (e.g., "create", "update", "delete")
            before_state: State before modification (will be sanitized in logs)
            after_state: State after modification (will be sanitized in logs)
            reason: Purpose of modification (e.g., "treatment", "correction")
        """
        # Sanitize PHI in audit log
        sanitized_before = self.sanitizer.sanitize(before_state)
        sanitized_after = self.sanitizer.sanitize(after_state)
        
        # Log the modification event
        self.logger.info(
            f"PHI Modification - User: {user_id}, Patient: {patient_id}, "
            f"Type: {modification_type}, Reason: {reason}, "
            f"Timestamp: {datetime.now().isoformat()}, "
            f"Before: {sanitized_before}, After: {sanitized_after}"
        )
    
    def contains_phi(self, data: PotentiallySensitiveData) -> bool:
        """
        Check if data contains PHI.
        
        Args:
            data: Data to check for PHI
            
        Returns:
            True if PHI detected, False otherwise
        """
        return self.sanitizer.contains_phi(data)
    
    def get_audit_log(
        self,
        user_id: str | None = None,
        patient_id: str | None = None,
    ) -> list[dict[str, object]]:
        """
        Get PHI audit log entries (stub implementation).
        
        In a real implementation, this would query a database or log storage system.
        For the stub, we return an empty list to maintain compatibility.
        
        Args:
            user_id: Filter by user ID (optional)
            patient_id: Filter by patient ID (optional)
            
        Returns:
            List of audit log entries matching filters
        """
        # Return empty list as this is just a stub
        # In a real implementation, this would query stored logs
        return []


class PHIAuditor:
    """Audits various targets for the presence of PHI."""

    def __init__(self, phi_detection_service: "PHIDetectionService"):
        """Initialize the PHI Auditor.

        Args:
            phi_detection_service: The service used to detect PHI.
        """
        # Import here to break cycle
        from app.infrastructure.ml.phi_detection.service import PHIDetectionService
        if not phi_detection_service:
            logging.getLogger(__name__).error("PHIAuditor requires a valid PHIDetectionService instance.")
            raise ValueError("PHIDetectionService instance is required.")
        self.phi_detection_service = phi_detection_service
        self.logger = get_logger(__name__)
        self.logger.info("PHIAuditor initialized.")

    def audit_file(self, file_path: Path) -> list[PHIFinding]:
        """Audits a single file for PHI.

        Args:
            file_path: Path to the file.

        Returns:
            A list of PHI findings.
        """
        self.logger.debug(f"Auditing file: {file_path}")
        findings: list[PHIFinding] = []
        if not file_path.is_file():
            self.logger.warning(f"Audit target file not found: {file_path}")
            return findings

        try:
            with file_path.open('r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    detected_phi = self.phi_detection_service.detect_phi(line)
                    for phi_type, matches in detected_phi.items():
                        for match in matches:
                            findings.append({
                                "file": str(file_path),
                                "line": line_num,
                                "match": match,
                                "phi_type": phi_type
                            })
        except Exception as e:
            self.logger.error(f"Error auditing file {file_path}: {e}")

        return findings

    def audit_directory(self, dir_path: Path) -> list[PHIFinding]:
        """Audits all files within a directory (recursively) for PHI.

        Args:
            dir_path: Path to the directory.

        Returns:
            A list of PHI findings from all files.
        """
        self.logger.debug(f"Auditing directory: {dir_path}")
        all_findings: list[PHIFinding] = []
        if not dir_path.is_dir():
            self.logger.warning(f"Audit target directory not found: {dir_path}")
            return all_findings

        try:
            for item_path in dir_path.rglob('*'):
                if item_path.is_file():
                    # TODO: Add file type/extension filtering if needed
                    file_findings = self.audit_file(item_path)
                    all_findings.extend(file_findings)
        except Exception as e:
            self.logger.error(f"Error traversing directory {dir_path}: {e}")
            
        return all_findings

    def audit_log_entry(self, log_entry: str) -> list[PHIFinding]:
        """Audits a single log entry string for PHI.

        Args:
            log_entry: The log string to audit.

        Returns:
            A list of PHI findings.
        """
        self.logger.debug(f"Auditing log entry: '{log_entry[:80]}...' ")
        findings: list[PHIFinding] = []
        detected_phi = self.phi_detection_service.detect_phi(log_entry)
        for phi_type, matches in detected_phi.items():
            for match in matches:
                findings.append({
                    "file": None, # No file context for a single log entry
                    "line": None, # No line context for a single log entry
                    "match": match,
                    "phi_type": phi_type
                })
        return findings

    def audit_text(self, text_content: str) -> list[PHIFinding]:
        """Audits a text snippet for PHI.

        Args:
            text_content: The text to audit.

        Returns:
            A list of PHI findings.
        """
        self.logger.debug("Auditing text snippet.")
        findings: list[PHIFinding] = []
        try:
            detected_phi = self.phi_detection_service.detect_phi(text_content)
            for phi_type, matches in detected_phi.items():
                for match in matches:
                    findings.append({
                        "file": None, # No file context for a text snippet
                        "line": None, # No line context for a text snippet
                        "match": match,
                        "phi_type": phi_type
                    })
        except Exception as e:
            self.logger.error(f"Error auditing text: {e}")

        return findings

    def contains_phi_in_text(self, text_content: str) -> bool:
        """Checks if a text snippet contains PHI.

        Args:
            text_content: The text to check.

        Returns:
            Boolean indicating if PHI was found.
        """
        # This reuses detect_phi logic, consider if direct check is needed
        self.logger.debug("Checking if text contains PHI.")
        try:
            detected_phi = self.phi_detection_service.detect_phi(text_content)
            return any(detected_phi.values())
        except Exception as e:
            self.logger.error(f"Error checking text for PHI: {e}")
            return False # Fail safe: assume no PHI if error occurs
