"""
HIPAA-compliant PHI (Protected Health Information) protection.

This package provides a comprehensive and consolidated implementation for detecting,
sanitizing, and protecting PHI in accordance with HIPAA regulations, following
clean architecture principles.
"""

from enum import Enum

# Middleware for API protection
from .middleware import PHIMiddleware, add_phi_middleware, get_phi_middleware

# Core PHI protection components
from .sanitizer import (
    PHISafeLogger,
    get_sanitizer,
    get_sanitized_logger,
)

# PHI Service
from .phi_service import PHIService, RedactionMode, contains_phi, get_phi_service, sanitize_phi


# PHI types for categorization
class PHIType(str, Enum):
    """Standard PHI types for categorization."""
    SSN = "SSN"
    NAME = "NAME"
    DOB = "DOB"
    ADDRESS = "ADDRESS"
    PHONE = "PHONE"
    EMAIL = "EMAIL"
    IP_ADDRESS = "IP_ADDRESS"
    MEDICAL_RECORD_NUMBER = "MRN"
    HEALTH_PLAN_NUMBER = "HEALTH_PLAN_NUMBER"
    DATE = "DATE"
    ACCOUNT_NUMBER = "ACCOUNT_NUMBER"
    CREDIT_CARD = "CREDIT_CARD"


# Create adapters for backward compatibility
class PHISanitizer:
    """
    Adapter class that forwards to PHIService for backward compatibility.
    
    This class provides the same interface as the old PHISanitizer class
    but delegates to the new PHIService implementation.
    """
    def __init__(self, *args, **kwargs):
        """Initialize with a PHIService instance and the original sanitizer."""
        self._service = PHIService()
        # Also import the original sanitizer implementation for methods
        # that aren't available in the PHIService
        from .sanitizer import PHISanitizer as OriginalSanitizer
        self._original_sanitizer = OriginalSanitizer()
    
    def sanitize(self, data: any, sensitivity: str = None, *args, **kwargs) -> any:
        """
        Sanitize any data by removing PHI. Main entry point for sanitization.
        
        Args:
            data: The data to sanitize (string, dict, list, etc.)
            sensitivity: Optional sensitivity level (not used)
            
        Returns:
            Sanitized data with PHI redacted
        """
        if data is None:
            return None
        
        if isinstance(data, str):
            return self.sanitize_text(data)
        elif isinstance(data, dict):
            return self.sanitize_dict(data)
        elif isinstance(data, list):
            return self.sanitize_list(data)
        
        # Default case, try to stringify
        try:
            str_data = str(data)
            return self.sanitize_text(str_data)
        except:
            # If we can't stringify it, return as is
            return data
    
    def sanitize_text(self, text: str, sensitivity: str = None, *args, **kwargs) -> str:
        """
        Sanitize a string by removing PHI.
        
        Args:
            text: The text to sanitize
            sensitivity: Optional sensitivity level (not used)
            
        Returns:
            Sanitized text with PHI redacted
        """
        if text is None:
            return None
        
        # Use string sanitization from the original sanitizer
        return self._original_sanitizer.sanitize_string(text)
    
    def sanitize_json(self, json_str: str, *args, **kwargs) -> str:
        """
        Sanitize a JSON string by removing PHI.
        
        Args:
            json_str: The JSON string to sanitize
            
        Returns:
            Sanitized JSON string with PHI redacted
        """
        if json_str is None:
            return None
        
        # Use JSON sanitization from the PHIService
        return self._service.sanitize_json(json_str)
    
    def sanitize_dict(self, data: dict, *args, **kwargs) -> dict:
        """
        Sanitize a dictionary by removing PHI from values.
        
        Args:
            data: The dictionary to sanitize
            
        Returns:
            Sanitized dictionary with PHI redacted
        """
        if data is None:
            return None
        
        result = {}
        for key, value in data.items():
            if isinstance(value, str):
                result[key] = self.sanitize_text(value)
            elif isinstance(value, dict):
                result[key] = self.sanitize_dict(value)
            elif isinstance(value, list):
                result[key] = self.sanitize_list(value)
            else:
                result[key] = value
        
        return result
    
    def sanitize_list(self, data: list, *args, **kwargs) -> list:
        """
        Sanitize a list by removing PHI from elements.
        
        Args:
            data: The list to sanitize
            
        Returns:
            Sanitized list with PHI redacted
        """
        if data is None:
            return None
        
        result = []
        for item in data:
            if isinstance(item, str):
                result.append(self.sanitize_text(item))
            elif isinstance(item, dict):
                result.append(self.sanitize_dict(item))
            elif isinstance(item, list):
                result.append(self.sanitize_list(item))
            else:
                result.append(item)
        
        return result
    
    def contains_phi(self, text: str) -> bool:
        """
        Check if a string contains PHI.
        
        Args:
            text: The text to check
            
        Returns:
            True if PHI is found, False otherwise
        """
        if text is None:
            return False
        
        # Use the PHI detection from the original sanitizer
        sanitized = self._original_sanitizer.sanitize_string(text)
        return sanitized != text


__all__ = [
    # Core components
    'PHISanitizer',
    'PHISafeLogger',
    # Service
    'PHIService',
    'RedactionMode',
    'sanitize_phi',
    'contains_phi',
    'get_phi_service',
    # Sanitizer utilities
    'get_sanitizer',
    'get_sanitized_logger',
    
    # Middleware components
    'PHIMiddleware',
    'add_phi_middleware',
    'get_phi_middleware',
    
    # Types
    'PHIType',
]