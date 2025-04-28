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
    regex: Optional[Pattern] = None
    
    def __post_init__(self):
        """Compile the regex pattern after initialization."""
        try:
            if self.pattern:
                self.regex = re.compile(self.pattern, re.IGNORECASE)
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
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))),
            "phi_patterns.yaml"
        )
        self.patterns: List[PHIPattern] = []
        self._initialized = False
        
    def ensure_initialized(self) -> None:
        """
        Ensure the service is initialized.
        
        This method lazy-loads the patterns when needed.
        """
        if not self._initialized:
            self._load_patterns()
            self._initialized = True
            
    def _load_patterns(self) -> None:
        """
        Load PHI detection patterns from file.
        
        This method reads the pattern configuration file and initializes
        the PHI detection patterns.
        """
        try:
            with open(self.pattern_file, "r") as f:
                config = yaml.safe_load(f)
                
            self.patterns = []
            
            for category, patterns in config.items():
                for pattern_info in patterns:
                    self.patterns.append(
                        PHIPattern(
                            name=pattern_info["name"],
                            pattern=pattern_info["pattern"],
                            description=pattern_info.get("description", ""),
                            category=category
                        )
                    )
                    
            logger.info(f"Loaded {len(self.patterns)} PHI detection patterns")
            
        except (yaml.YAMLError, IOError) as e:
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
        """
        self.ensure_initialized()
        
        for pattern in self.patterns:
            if pattern.regex and pattern.regex.search(text):
                return True
                
        return False
        
    def detect_phi(self, text: str) -> List[Tuple[str, str, int, int]]:
        """
        Detect PHI in text and return details of matches.
        
        Args:
            text: Text to check
            
        Returns:
            List of tuples (category, match_text, start_pos, end_pos)
        """
        self.ensure_initialized()
        
        results = []
        
        for pattern in self.patterns:
            if not pattern.regex:
                continue
                
            for match in pattern.regex.finditer(text):
                results.append((
                    pattern.category,
                    match.group(0),
                    match.start(),
                    match.end()
                ))
                
        # Sort by position
        results.sort(key=lambda x: x[2])
        
        return results
        
    def redact_phi(self, text: str) -> str:
        """
        Redact PHI from text.
        
        Args:
            text: Text to redact
            
        Returns:
            Text with PHI replaced by [REDACTED]
        """
        self.ensure_initialized()
        
        # Get all PHI matches
        matches = self.detect_phi(text)
        
        # No PHI found
        if not matches:
            return text
            
        # Redact PHI
        result = ""
        last_end = 0
        
        for _, match_text, start, end in matches:
            # Add text before match
            result += text[last_end:start]
            # Add redaction
            result += f"[REDACTED:{len(match_text)}]"
            # Update last end position
            last_end = end
            
        # Add remaining text after last match
        result += text[last_end:]
        
        return result
        
    def anonymize_phi(self, text: str) -> str:
        """
        Anonymize PHI in text by replacing it with synthetic data.
        
        Args:
            text: Text to anonymize
            
        Returns:
            Text with PHI replaced by synthetic data
        """
        self.ensure_initialized()
        
        # Get all PHI matches
        matches = self.detect_phi(text)
        
        # No PHI found
        if not matches:
            return text
            
        # Anonymize PHI
        result = list(text)
        
        for category, match_text, start, end in matches:
            replacement = self._get_synthetic_replacement(category, match_text)
            
            # Replace in result
            for i in range(start, min(end, len(result))):
                if i == start:
                    # Add replacement at start position
                    result[i] = replacement
                else:
                    # Clear other positions
                    result[i] = ""
                    
        return "".join(result)
        
    def _get_synthetic_replacement(self, category: str, original: str) -> str:
        """
        Get synthetic replacement for PHI.
        
        Args:
            category: PHI category
            original: Original PHI text
            
        Returns:
            Synthetic replacement text
        """
        # Simple replacements
        replacements = {
            "name": "JOHN DOE",
            "contact": "CONTACT-INFO",
            "location": "ADDRESS",
            "government_id": "ID-NUMBER",
            "date": "DATE-VALUE",
            "financial": "FINANCIAL-INFO",
            "medical": "MEDICAL-INFO"
        }
        
        return replacements.get(category, "REDACTED")