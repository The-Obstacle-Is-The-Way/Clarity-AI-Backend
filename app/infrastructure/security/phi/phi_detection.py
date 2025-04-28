"""
HIPAA-compliant PHI detection service.

This module provides robust PHI detection capabilities to scan various sources
for Protected Health Information (PHI) to help ensure compliance with HIPAA regulations.
"""

import os
import re
import logging
import json
from typing import Dict, List, Optional, Set, Tuple, Any, Union, Pattern
from enum import Enum

from .phi_service import PHIService, PHIType
from .code_analyzer import PHICodeAnalyzer


class PHIDetectionService:
    """
    Service for detecting PHI in various contexts.
    
    This service provides a unified interface for detecting PHI in text,
    code, databases, and other sources, leveraging the specialized components
    within the security infrastructure.
    """
    
    def __init__(self, phi_service: Optional[PHIService] = None):
        """
        Initialize the PHI detection service.
        
        Args:
            phi_service: Optional PHIService for PHI detection
        """
        self.phi_service = phi_service or PHIService()
        self.code_analyzer = PHICodeAnalyzer(phi_service=self.phi_service)
        self._initialized = True
        self.logger = logging.getLogger(__name__)
    
    def detect_phi(self, text: str, include_matches: bool = True) -> Dict[str, Any]:
        """
        Detect PHI in text.
        
        Args:
            text: Text to scan for PHI
            include_matches: Whether to include the actual matches in the result
            
        Returns:
            Dictionary with detection results
        """
        return self.phi_service.detect_phi(text, include_matches)
    
    def contains_phi(self, text: str) -> bool:
        """
        Check if text contains PHI.
        
        Args:
            text: Text to check for PHI
            
        Returns:
            True if text contains PHI, False otherwise
        """
        if not text or not isinstance(text, str):
            return False
        
        result = self.phi_service.detect_phi(text, include_matches=False)
        return result.get("contains_phi", False)
    
    def sanitize_text(self, text: str, replacement: str = "[REDACTED]") -> str:
        """
        Sanitize text by redacting PHI.
        
        Args:
            text: Text to sanitize
            replacement: Replacement text for PHI
            
        Returns:
            Sanitized text
        """
        return self.phi_service.sanitize_string(text)
    
    def get_phi_types(self, text: str) -> List[PHIType]:
        """
        Get types of PHI present in text.
        
        Args:
            text: Text to analyze
            
        Returns:
            List of PHI types found
        """
        result = self.phi_service.detect_phi(text, include_matches=False)
        return result.get("phi_types", [])
    
    def get_statistics(self, text: str) -> Dict[str, Any]:
        """
        Get PHI statistics for text.
        
        Args:
            text: Text to analyze
            
        Returns:
            Dictionary with PHI statistics
        """
        result = self.phi_service.detect_phi(text, include_matches=True)
        stats = {
            "contains_phi": result.get("contains_phi", False),
            "phi_count": len(result.get("matches", [])),
            "phi_types": {phi_type.name: 0 for phi_type in PHIType}
        }
        
        for match in result.get("matches", []):
            phi_type = match.get("phi_type")
            if phi_type:
                stats["phi_types"][phi_type.name] = stats["phi_types"].get(phi_type.name, 0) + 1
                
        return stats
    
    def audit_code_for_phi(self, target_path: str, **kwargs) -> Dict[str, Any]:
        """
        Audit code for PHI patterns.
        
        Args:
            target_path: Path to scan (file or directory)
            **kwargs: Additional arguments to pass to the code analyzer
            
        Returns:
            Dictionary with audit results
        """
        return self.code_analyzer.audit_code_for_phi(target_path, **kwargs)
    
    def audit_api_endpoints(self, app_directory: str, **kwargs) -> Dict[str, Any]:
        """
        Audit API endpoints for potential PHI exposure.
        
        Args:
            app_directory: Path to the application directory
            **kwargs: Additional arguments to pass to the code analyzer
            
        Returns:
            Dictionary with audit results
        """
        return self.code_analyzer.audit_api_endpoints(app_directory, **kwargs)
    
    def audit_configuration(self, app_directory: str, **kwargs) -> Dict[str, Any]:
        """
        Audit configuration files for potential PHI and security issues.
        
        Args:
            app_directory: Path to the application directory
            **kwargs: Additional arguments to pass to the code analyzer
            
        Returns:
            Dictionary with audit results
        """
        return self.code_analyzer.audit_configuration(app_directory, **kwargs)
    

# Create a singleton instance
def get_phi_detection_service(phi_service: Optional[PHIService] = None) -> PHIDetectionService:
    """
    Get a PHI detection service instance.
    
    Args:
        phi_service: Optional PHIService to use
        
    Returns:
        PHIDetectionService instance
    """
    return PHIDetectionService(phi_service=phi_service)