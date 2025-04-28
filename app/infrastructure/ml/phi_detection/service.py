# -*- coding: utf-8 -*-
"""
PHI Detection Service.

This module provides a service for detecting and redacting Protected Health Information
(PHI) in text data, ensuring HIPAA compliance for all content stored and logged.
"""

import re
import os
import yaml
import logging
from typing import Dict, List, Set, Pattern, Optional, Tuple, Union
from dataclasses import dataclass

from app.core.utils.logging import get_logger
from app.core.exceptions.ml_exceptions import PHIDetectionError, PHISecurityError


logger = get_logger(__name__)


@dataclass
class PHIPattern:
    """
    PHI pattern configuration.
    
    This dataclass represents a pattern for detecting a specific type of PHI.
    """
    
    name: str
    pattern: str
    description: str
    category: str
    risk_level: str = "high"  # Default risk level is high
    regex: Optional[Pattern] = None
    
    def __post_init__(self):
        """Compile the regex pattern after initialization."""
        try:
            if self.pattern:
                # Handle possible double escaping from YAML parsing
                clean_pattern = self.pattern.replace('\\', '\\')
                self.regex = re.compile(clean_pattern, re.IGNORECASE)
                logger.debug(f"Compiled regex for {self.name}: {clean_pattern}")
        except re.error as e:
            logger.error(f"Invalid regex pattern for {self.name}: {e}")
            # Fall back to a pattern that will never match
            self.regex = re.compile(r"a^")


class PHIDetectionService:
    """
    Service for detecting and redacting PHI in text.
    
    This service loads PHI detection patterns from configuration and provides
    methods to detect and redact PHI in text data.
    """
    
    def __init__(self, pattern_file: Optional[str] = None):
        """
        Initialize the PHI detection service.
        
        Args:
            pattern_file: Path to pattern file, or None to use default
        """
        self.pattern_file = pattern_file or os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))),
            "phi_patterns.yaml"
        )
        self.patterns: List[PHIPattern] = []
        self._initialized = False
        
    def initialize(self) -> None:
        """
        Initialize the PHI detection service by loading patterns.
        
        Raises:
            PHISecurityError: If patterns cannot be loaded
        """
        self._load_patterns()
        self._initialized = True
    
    @property    
    def initialized(self) -> bool:
        """Return whether the service is initialized."""
        return self._initialized
            
    def ensure_initialized(self) -> None:
        """
        Ensure the service is initialized.
        
        This method lazy-loads the patterns when needed by calling initialize().
        
        Raises:
            PHISecurityError: If patterns cannot be loaded
        """
        if not self._initialized:
            self.initialize()
            
    def _load_patterns(self) -> None:
        """
        Load PHI detection patterns from file.
        
        This method reads the pattern configuration file and initializes
        the PHI detection patterns.
        
        Raises:
            PHIDetectionError: If patterns cannot be loaded
        """
        try:
            with open(self.pattern_file, "r") as f:
                config = yaml.safe_load(f)
                
            self.patterns = []
            
            # Handle different formats (YAML or JSON)
            if isinstance(config, dict):
                for category, patterns in config.items():
                    if isinstance(patterns, list):
                        for pattern_info in patterns:
                            if isinstance(pattern_info, dict):
                                self.patterns.append(
                                    PHIPattern(
                                        name=pattern_info.get("name", "Unnamed Pattern"),
                                        pattern=pattern_info.get("pattern", ""),
                                        description=pattern_info.get("description", ""),
                                        category=category,
                                        risk_level=pattern_info.get("risk_level", "high")
                                    )
                                )
                    
            logger.info(f"Loaded {len(self.patterns)} PHI detection patterns")
            
        except Exception as e:  # Catch all exceptions
            logger.error(f"Error loading PHI patterns: {e}")
            # Load some basic default patterns
            self.patterns = self._get_default_patterns()
            
    def _get_default_patterns(self) -> List[PHIPattern]:
        """
        Get default PHI patterns.
        
        This method provides a fallback set of patterns if the pattern file
        cannot be loaded.
        
        Returns:
            List of default PHI patterns
        """
        return [
            PHIPattern(
                name="US Phone Number",
                pattern=r"\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
                description="US phone number with or without formatting",
                category="contact"
            ),
            PHIPattern(
                name="Email Address",
                pattern=r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                description="Email address",
                category="contact"
            ),
            PHIPattern(
                name="SSN",
                pattern=r"\d{3}[-\s]?\d{2}[-\s]?\d{4}",
                description="Social Security Number",
                category="government_id"
            ),
            PHIPattern(
                name="Full Name",
                pattern=r"(?:[A-Z][a-z]+\s+){1,2}[A-Z][a-z]+",
                description="Full name with 2-3 parts",
                category="name"
            ),
            PHIPattern(
                name="Address",
                pattern=r"\d+\s+[A-Za-z\s]+,\s+[A-Za-z\s]+,\s+[A-Z]{2}\s+\d{5}",
                description="US street address",
                category="location"
            ),
            PHIPattern(
                name="Date",
                pattern=r"\d{1,2}[/-]\d{1,2}[/-]\d{2,4}",
                description="Date in MM/DD/YYYY format",
                category="date"
            ),
            PHIPattern(
                name="Credit Card",
                pattern=r"\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}",
                description="Credit card number",
                category="financial"
            )
        ]
            
    def contains_phi(self, text: str) -> bool:
        """
        Check if text contains PHI.
        
        Args:
            text: Text to check
            
        Returns:
            True if PHI is detected, False otherwise
            
        Raises:
            PHISecurityError: If PHI detection fails
        """
        if not text:
            return False
            
        try:
            self.ensure_initialized()
            
            for pattern in self.patterns:
                if pattern.regex and pattern.regex.search(text):
                    return True
                    
            return False
        except Exception as e:
            logger.error(f"Error detecting PHI: {e}")
            raise PHISecurityError(f"Failed to detect PHI: {str(e)}")
        
    def detect_phi(self, text: str) -> List[Dict]:
        """
        Detect PHI in text and return details of matches.
        
        Args:
            text: Text to check
            
        Returns:
            List of dictionaries with PHI match details
            
        Raises:
            PHISecurityError: If PHI detection fails
        """
        if not text:
            return []
            
        try:
            self.ensure_initialized()
            
            results = []
            
            for pattern in self.patterns:
                if not pattern.regex:
                    continue
                    
                for match in pattern.regex.finditer(text):
                    results.append({
                        "type": pattern.name,
                        "category": pattern.category,
                        "risk_level": pattern.risk_level,
                        "start": match.start(),
                        "end": match.end(),
                        "value": match.group(0),
                        "description": pattern.description
                    })
                    
            # Sort by position
            results.sort(key=lambda x: x["start"])
            
            return results
        except Exception as e:
            logger.error(f"Error detecting PHI: {e}")
            raise PHISecurityError(f"Failed to detect PHI details: {str(e)}")
    
    def redact_phi(self, text: str, replacement: str = "[REDACTED]") -> str:
        """
        Redact PHI in text by replacing with a placeholder.
        
        Args:
            text: Text to redact
            replacement: String to replace PHI with
            
        Returns:
            Text with PHI redacted
            
        Raises:
            PHISecurityError: If PHI redaction fails
        """
        if not text:
            return ""
            
        try:
            # Detect PHI first
            phi_matches = self.detect_phi(text)
            
            # If no PHI detected, return the original text
            if not phi_matches:
                return text
                
            # Sort matches by position in reverse order to avoid offset issues
            phi_matches.sort(key=lambda x: x["start"], reverse=True)
            
            # Copy the original text
            redacted_text = text
            
            # Replace each PHI match with the replacement string
            for match in phi_matches:
                start = match["start"]
                end = match["end"]
                redacted_text = redacted_text[:start] + replacement + redacted_text[end:]
                
            return redacted_text
        except Exception as e:
            logger.error(f"Error redacting PHI: {e}")
            raise PHISecurityError(f"Failed to redact PHI: {str(e)}")
    
    def anonymize_phi(self, text: str) -> str:
        """
        Anonymize PHI in text by replacing with synthetic data.
        
        Args:
            text: Text to anonymize
            
        Returns:
            Text with PHI anonymized
            
        Raises:
            PHISecurityError: If PHI anonymization fails
        """
        if not text:
            return ""
            
        try:
            # Detect PHI first
            phi_matches = self.detect_phi(text)
            
            # If no PHI detected, return the original text
            if not phi_matches:
                return text
                
            # Sort matches by position in reverse order to avoid offset issues
            phi_matches.sort(key=lambda x: x["start"], reverse=True)
            
            # Copy the original text
            anonymized_text = text
            
            # Replace each PHI match with synthetic data
            for match in phi_matches:
                start = match["start"]
                end = match["end"]
                category = match["category"]
                original = match["value"]
                
                # Get a synthetic replacement based on the PHI category
                replacement = self._get_synthetic_replacement(category, original)
                
                anonymized_text = anonymized_text[:start] + replacement + anonymized_text[end:]
                
            return anonymized_text
        except Exception as e:
            logger.error(f"Error anonymizing PHI: {e}")
            raise PHISecurityError(f"Failed to anonymize PHI: {str(e)}")
    
    def _get_synthetic_replacement(self, category: str, original: str) -> str:
        """
        Get a synthetic replacement for a PHI value.
        
        Args:
            category: Category of the PHI
            original: Original PHI value
            
        Returns:
            Synthetic replacement value
        """
        # Simple synthetic data generation
        # In production, this could use Faker or other libraries
        # for more realistic synthetic data
        replacements = {
            "name": "PERSON_NAME",
            "contact": "CONTACT_INFO",
            "government_id": "ID_NUMBER",
            "location": "ADDRESS",
            "date": "DATE",
            "financial": "FINANCIAL_INFO",
            "medical": "MEDICAL_INFO"
        }
        
        # Use category-specific replacement or a generic one
        return replacements.get(category, f"REDACTED_{category.upper()}")
    
    def get_phi_types(self) -> List[str]:
        """
        Get a list of all PHI types loaded in the service.
        
        Returns:
            List of PHI type names
        """
        self.ensure_initialized()
        return [pattern.name for pattern in self.patterns]
    
    def get_statistics(self) -> Dict:
        """
        Get statistics about the loaded PHI patterns.
        
        Returns:
            Dictionary with pattern statistics
        """
        self.ensure_initialized()
        
        categories = {}
        risk_levels = {}
        
        for pattern in self.patterns:
            # Count by category
            categories[pattern.category] = categories.get(pattern.category, 0) + 1
            
            # Count by risk level
            risk_levels[pattern.risk_level] = risk_levels.get(pattern.risk_level, 0) + 1
            
        return {
            "total_patterns": len(self.patterns),
            "categories": categories,
            "risk_levels": risk_levels
        }