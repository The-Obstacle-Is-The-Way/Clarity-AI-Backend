"""
PHI (Protected Health Information) service for HIPAA compliance.

Clean implementation that uses the consolidated PHI sanitizer to detect and redact
Protected Health Information in accordance with HIPAA Security Rule requirements.
"""

from enum import Enum
from typing import Any

from .sanitizer import PHISanitizer, get_sanitized_logger

# Configure logger
logger = get_sanitized_logger(__name__)


class RedactionMode(str, Enum):
    """Redaction modes for handling PHI."""
    FULL = "full"  # Replace entire value
    PARTIAL = "partial"  # Replace only the matched pattern
    HASH = "hash"  # Replace with hash of the value


class PHIService:
    """
    Service for detecting and sanitizing PHI in various data formats.
    
    This is a clean implementation that uses the consolidated PHISanitizer
    to handle all PHI-related functionality.
    """
    
    def __init__(self):
        """Initialize with the consolidated PHI sanitizer."""
        self._sanitizer = PHISanitizer()
    
    def sanitize(self, data: Any, sensitivity: str | None = None) -> Any:
        """
        Sanitize any data type by redacting PHI.
        
        Args:
            data: Data to sanitize (string, dict, list, etc.)
            sensitivity: Optional sensitivity level (ignored, for backward compatibility)
            
        Returns:
            Sanitized data with PHI redacted
        """
        return self._sanitizer.sanitize(data)
    
    def sanitize_text(self, text: str) -> str:
        """
        Sanitize a string by redacting PHI.
        
        Args:
            text: Text to sanitize
            
        Returns:
            Sanitized text with PHI redacted
        """
        return self._sanitizer.sanitize_text(text)
    
    def sanitize_string(self, text: str) -> str:
        """
        Sanitize a string by redacting PHI.
        
        Args:
            text: Text to sanitize
            
        Returns:
            Sanitized text with PHI redacted
        """
        return self._sanitizer.sanitize_text(text)
    
    def sanitize_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Sanitize all string values in a dictionary.
        
        Args:
            data: Dictionary to sanitize
            
        Returns:
            Dictionary with PHI values sanitized
        """
        return self._sanitizer.sanitize_dict(data)
    
    def sanitize_list(self, data: list[Any]) -> list[Any]:
        """
        Sanitize all values in a list.
        
        Args:
            data: List to sanitize
            
        Returns:
            List with PHI values sanitized
        """
        return self._sanitizer.sanitize_list(data)
    
    def contains_phi(self, text: str) -> bool:
        """
        Check if text contains PHI.
        
        Args:
            text: Text to check
            
        Returns:
            True if PHI found, False otherwise
        """
        return self._sanitizer.contains_phi(text)
    
    def sanitize_json(self, json_str: str) -> str:
        """
        Sanitize a JSON string by redacting PHI.
        
        Args:
            json_str: JSON string to sanitize
            
        Returns:
            Sanitized JSON string
        """
        if not json_str or not isinstance(json_str, str):
            return json_str
            
        try:
            # Parse JSON
            import json
            data = json.loads(json_str)
            
            # Sanitize the parsed data
            sanitized_data = self.sanitize_dict(data)
            
            # Convert back to JSON
            return json.dumps(sanitized_data)
        except json.JSONDecodeError:
            # Not valid JSON, sanitize as string
            return self.sanitize_string(json_str)


# Utility functions for convenience
def sanitize_phi(data: Any) -> Any:
    """
    Sanitize PHI in any data type.
    
    Args:
        data: Data to sanitize
        
    Returns:
        Sanitized data
    """
    sanitizer = PHISanitizer()
    return sanitizer.sanitize(data)
    
def contains_phi(text: str) -> bool:
    """
    Check if text contains PHI.
    
    Args:
        text: Text to check
        
    Returns:
        True if PHI found, False otherwise
    """
    sanitizer = PHISanitizer()
    return sanitizer.contains_phi(text)
    
def get_phi_service() -> PHIService:
    """
    Get a PHI service instance.
    
    Returns:
        PHIService instance
    """
    return PHIService()
