"""
PHI (Protected Health Information) service for HIPAA compliance.

This module provides a comprehensive service for detecting, sanitizing, 
and protecting PHI in accordance with HIPAA Security Rule requirements.
"""

import re
import logging
import json
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Union, Pattern

from .patterns import PHI_PATTERNS, PHI_PATTERN_CATEGORIES

# Configure logger
logger = logging.getLogger(__name__)


class PHIType(str, Enum):
    """Enumeration of PHI types for categorization and handling."""
    SSN = "SSN"
    NAME = "NAME"
    DOB = "DOB"
    ADDRESS = "ADDRESS"
    PHONE = "PHONE"
    EMAIL = "EMAIL"
    IP_ADDRESS = "IP_ADDRESS"
    URL = "URL"
    ACCOUNT_NUMBER = "ACCOUNT_NUMBER"
    MEDICAL_RECORD_NUMBER = "MRN"
    HEALTH_PLAN_NUMBER = "HEALTH_PLAN_NUMBER"
    LICENSE_NUMBER = "LICENSE_NUMBER"
    VEHICLE_IDENTIFIER = "VEHICLE_IDENTIFIER"
    DEVICE_IDENTIFIER = "DEVICE_IDENTIFIER"
    BIOMETRIC_IDENTIFIER = "BIOMETRIC_IDENTIFIER"
    PHOTO = "PHOTO"
    DATE = "DATE"
    AGE = "AGE"
    INSURANCE = "INSURANCE"
    CREDIT_CARD = "CREDIT_CARD"
    OTHER = "OTHER"


class RedactionMode(str, Enum):
    """Redaction modes for handling PHI."""
    FULL = "full"  # Replace entire value
    PARTIAL = "partial"  # Replace only the matched pattern
    HASH = "hash"  # Replace with hash of the value


class PHIPattern:
    """Represents a pattern for detecting a specific type of PHI."""
    
    def __init__(self, 
                 name: str, 
                 pattern: str, 
                 replacement: str = '[REDACTED]',
                 category: str = 'generic',
                 risk_level: str = 'high',
                 phi_type: Optional[PHIType] = None):
        """
        Initialize a PHI pattern.
        
        Args:
            name: Descriptive name for the pattern (e.g., 'SSN', 'EMAIL')
            pattern: Regular expression pattern as a string
            replacement: Replacement text to use when redacting
            category: Category this pattern belongs to (e.g., 'identifier', 'contact')
            risk_level: Risk level if exposed ('high', 'medium', 'low')
            phi_type: PHIType enum value for this pattern
        """
        self.name = name
        self.pattern_str = pattern
        self.replacement = replacement
        self.category = category
        self.risk_level = risk_level
        
        # Determine PHI type from name if not specified
        if phi_type is None:
            try:
                self.phi_type = PHIType[name.upper()]
            except (KeyError, ValueError):
                self.phi_type = PHIType.OTHER
        else:
            self.phi_type = phi_type
        
        # Compile the pattern for efficiency
        try:
            self.pattern = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            logger.error(f"Invalid pattern '{name}': {str(e)}. Using default pattern.")
            # Fallback to a basic pattern that won't match anything sensitive
            self.pattern = re.compile(r'^$')

    def find_matches(self, text: str) -> List[Dict[str, Any]]:
        """
        Find all matches of this pattern in the text.
        
        Args:
            text: Text to search for PHI
            
        Returns:
            List of dictionaries with match details
        """
        if not text or not isinstance(text, str):
            return []
            
        matches = []
        for match in self.pattern.finditer(text):
            matches.append({
                'pattern_name': self.name,
                'phi_type': self.phi_type,
                'start': match.start(),
                'end': match.end(),
                'match': match.group(0),
                'risk_level': self.risk_level
            })
            
        return matches
        
    def redact(self, text: str, custom_replacement: Optional[str] = None) -> str:
        """
        Redact PHI in text matching this pattern.
        
        Args:
            text: Text to redact
            custom_replacement: Optional replacement text override
            
        Returns:
            Redacted text
        """
        if not text or not isinstance(text, str):
            return text
            
        replacement = custom_replacement if custom_replacement is not None else self.replacement
        
        # Replace the pattern with the appropriate marker
        if "{phi_type}" in replacement:
            # Handle template replacement
            actual_replacement = replacement.format(phi_type=self.name.upper())
        else:
            actual_replacement = replacement
            
        return self.pattern.sub(actual_replacement, text)


class PHIService:
    """Service for detecting and sanitizing PHI in various data formats."""
    
    def __init__(self, patterns: Optional[List[PHIPattern]] = None, strict_mode: bool = False):
        """
        Initialize the PHI service.
        
        Args:
            patterns: Optional list of PHIPattern objects. If None, uses default patterns.
            strict_mode: If True, uses stricter PHI detection rules.
        """
        self.strict_mode = strict_mode
        self._processed_strings = set()  # Track processed strings to avoid recursive replacements
        
        # Initialize with default patterns if none provided
        if patterns is None:
            self.patterns = self._load_default_patterns()
        else:
            self.patterns = patterns
            
        # Create lookup for patterns by name
        self.pattern_by_name = {p.name: p for p in self.patterns}
            
    def _load_default_patterns(self) -> List[PHIPattern]:
        """
        Load the default PHI patterns.
        
        Returns:
            List of PHIPattern objects
        """
        patterns = []
        
        # Create patterns from the predefined patterns
        for name, pattern_str in PHI_PATTERNS.items():
            # Determine category from name
            category = 'generic'
            for cat, pattern_names in PHI_PATTERN_CATEGORIES.items():
                if name in pattern_names:
                    category = cat
                    break
                    
            # Determine replacement text based on name
            replacement = f"[REDACTED {name.upper()}]"
            
            # Determine PHI type from name
            phi_type = None
            try:
                phi_type = PHIType[name.upper()]
            except (KeyError, ValueError):
                # Find closest match
                for phi_type_enum in PHIType:
                    if name.upper() in phi_type_enum.value:
                        phi_type = phi_type_enum
                        break
                if phi_type is None:
                    phi_type = PHIType.OTHER
            
            # Create and add the pattern
            pattern = PHIPattern(
                name=name,
                pattern=pattern_str,
                replacement=replacement,
                category=category,
                phi_type=phi_type
            )
            patterns.append(pattern)
            
        return patterns
        
    def detect_phi(self, text: str, include_matches: bool = True) -> Dict[str, Any]:
        """
        Detect PHI in text.
        
        Args:
            text: Text to analyze for PHI
            include_matches: Whether to include the matched text in the results
            
        Returns:
            Dictionary with detection results
        """
        if not text or not isinstance(text, str):
            return {'contains_phi': False, 'phi_types': [], 'matches': []}
            
        # Find all matches
        all_matches = []
        for pattern in self.patterns:
            matches = pattern.find_matches(text)
            all_matches.extend(matches)
            
        # Sort matches by position
        all_matches.sort(key=lambda m: m['start'])
        
        # Extract unique PHI types
        phi_types = set()
        for match in all_matches:
            if hasattr(match['phi_type'], 'value'):
                phi_types.add(match['phi_type'].value)
            else:
                phi_types.add(str(match['phi_type']))
            
        # Build the result
        result = {
            'contains_phi': len(all_matches) > 0,
            'phi_types': list(phi_types)
        }
        
        # Include matches if requested
        if include_matches:
            result['matches'] = all_matches
            
        return result
        
    def contains_phi(self, text: str) -> bool:
        """
        Check if text contains any PHI.
        
        Args:
            text: Text to check for PHI
            
        Returns:
            True if PHI is detected, False otherwise
        """
        if not text or not isinstance(text, str):
            return False
            
        # Check each pattern until a match is found
        for pattern in self.patterns:
            if pattern.pattern.search(text):
                return True
                
        return False
        
    def _is_already_redacted(self, text: str) -> bool:
        """
        Check if text already contains redaction markers.
        
        Args:
            text: Text to check
            
        Returns:
            True if already redacted
        """
        return bool(re.search(r'\[REDACTED.*?\]', text))
        
    def sanitize_string(self, text: str, sensitivity: Optional[str] = None, 
                      replacement_template: Optional[str] = None) -> str:
        """
        Sanitize a string by redacting all PHI.
        
        Args:
            text: Text to sanitize
            sensitivity: Optional sensitivity level to control sanitization strictness
            replacement_template: Optional replacement template
            
        Returns:
            Sanitized text with PHI redacted
        """
        if not text or not isinstance(text, str):
            return text
            
        # Avoid recursive redaction
        text_hash = hash(text)
        if text_hash in self._processed_strings:
            return text
            
        self._processed_strings.add(text_hash)
        
        # Check if already contains redaction patterns
        if self._is_already_redacted(text):
            self._processed_strings.remove(text_hash)
            return text
            
        result = text
        # Apply each pattern
        for pattern in self.patterns:
            replacement = replacement_template or pattern.replacement
            if "{phi_type}" in replacement:
                actual_replacement = replacement.format(phi_type=pattern.name.upper())
            else:
                actual_replacement = replacement
                
            result = pattern.pattern.sub(actual_replacement, result)
            
        self._processed_strings.remove(text_hash)
        return result
    
    # Alias for sanitize_string
    sanitize_text = sanitize_string
    
    def sanitize_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize a dictionary by redacting PHI in string values.
        
        Args:
            data: Dictionary to sanitize
            
        Returns:
            Sanitized dictionary
        """
        if not data or not isinstance(data, dict):
            return data
            
        result = {}
        for key, value in data.items():
            if isinstance(value, str):
                result[key] = self.sanitize_string(value)
            elif isinstance(value, dict):
                result[key] = self.sanitize_dict(value)
            elif isinstance(value, list):
                result[key] = self.sanitize_list(value)
            else:
                result[key] = value
                
        return result
    
    def sanitize_list(self, data: List[Any]) -> List[Any]:
        """
        Sanitize a list by redacting PHI in string values.
        
        Args:
            data: List to sanitize
            
        Returns:
            Sanitized list
        """
        if not data or not isinstance(data, list):
            return data
            
        result = []
        for item in data:
            if isinstance(item, str):
                result.append(self.sanitize_string(item))
            elif isinstance(item, dict):
                result.append(self.sanitize_dict(item))
            elif isinstance(item, list):
                result.append(self.sanitize_list(item))
            else:
                result.append(item)
                
        return result
    
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
            data = json.loads(json_str)
            
            # Sanitize data
            if isinstance(data, dict):
                sanitized_data = self.sanitize_dict(data)
            elif isinstance(data, list):
                sanitized_data = self.sanitize_list(data)
            else:
                # Convert primitive value to string and sanitize
                sanitized_data = self.sanitize_string(str(data))
                
            # Serialize back to JSON
            return json.dumps(sanitized_data)
        except json.JSONDecodeError:
            # Not valid JSON, sanitize as string
            return self.sanitize_string(json_str)
    
    def sanitize(self, data: Any, sensitivity: Optional[str] = None) -> Any:
        """
        Sanitize any data structure by redacting PHI.
        
        This is a convenience method that handles different data types.
        
        Args:
            data: Data to sanitize
            sensitivity: Optional sensitivity level
            
        Returns:
            Sanitized data
        """
        if data is None:
            return None
            
        if isinstance(data, str):
            return self.sanitize_string(data, sensitivity)
        elif isinstance(data, dict):
            return self.sanitize_dict(data)
        elif isinstance(data, list):
            return self.sanitize_list(data)
        elif isinstance(data, (int, float, bool)):
            # Don't modify primitive types
            return data
        elif hasattr(data, 'to_dict') and callable(getattr(data, 'to_dict')):
            # Handle objects with to_dict method
            try:
                dict_data = data.to_dict()
                return self.sanitize_dict(dict_data)
            except Exception:
                # Fall back to string representation
                return self.sanitize_string(str(data), sensitivity)
        else:
            # For other types, convert to string and sanitize if it's not a simple type
            if not isinstance(data, (int, float, bool)):
                return self.sanitize_string(str(data), sensitivity)
            return data

    # Legacy/compatibility methods
    def redact_phi(self, text: str, replacement_template: str = "[REDACTED {phi_type}]") -> str:
        """Legacy method for redacting PHI in text."""
        return self.sanitize_string(text, replacement_template=replacement_template)
    
    def get_phi_types(self) -> List[str]:
        """Get all available PHI types."""
        return [phi_type.value for phi_type in PHIType]