"""
Self-contained test for PHI Sanitizer functionality.

This module contains both the PHI sanitizer implementation and tests in a single file,
making it completely independent of the rest of the application.
"""

import json
import logging
import re
import unittest
from collections.abc import Callable
from enum import Enum
from typing import Any

import pytest

# ============= PHI Sanitizer Implementation =============

class RedactionStrategy(Enum):
    """Redaction strategy for PHI."""
    FULL = "full"  # Completely replace with [REDACTED]
    PARTIAL = "partial"  # Replace part of the data (e.g., last 4 digits visible)
    HASH = "hash"  # Replace with a hash of the data


class PHIPattern:
    """Represents a pattern for detecting PHI."""
    
    def __init__(
        self,
        name: str,
        regex: str = None,
        exact_match: list[str] = None,
        fuzzy_match: list[str] = None,
        context_patterns: list[str] = None,
        strategy: RedactionStrategy = RedactionStrategy.FULL
    ):
        self.name = name
        self.strategy = strategy
        
        # Initialize matchers
        self._regex_pattern = re.compile(regex) if regex else None
        self._exact_matches = set(exact_match) if exact_match else set()
        self._fuzzy_patterns = [re.compile(pattern, re.IGNORECASE) 
                               for pattern in fuzzy_match] if fuzzy_match else []
        self._context_patterns = [re.compile(pattern, re.IGNORECASE) 
                                 for pattern in context_patterns] if context_patterns else []
    
    def matches(self, text: str) -> bool:
        """Check if this pattern matches the given text."""
        if not text:
            return False
            
        # Check exact matches
        if text in self._exact_matches:
            return True
            
        # Check regex pattern
        if self._regex_pattern and self._regex_pattern.search(text):
            return True
            
        # Check fuzzy patterns
        for pattern in self._fuzzy_patterns:
            if pattern.search(text):
                return True
                
        # Check context patterns
        for pattern in self._context_patterns:
            if pattern.search(text):
                return True
                
        return False
        
    def redact(self, text: str) -> str:
        """Redact the PHI in the text according to the strategy."""
        if not self.matches(text):
            return text
            
        if self.strategy == RedactionStrategy.FULL:
            return "[REDACTED]"
            
        elif self.strategy == RedactionStrategy.PARTIAL:
            # For SSN, show last 4 digits
            if self.name == "SSN" and self._regex_pattern:
                return self._regex_pattern.sub(r"XXX-XX-\1", text)
            # For phone numbers, show last 4 digits
            elif self.name == "PHONE" and self._regex_pattern:
                return self._regex_pattern.sub(r"(XXX) XXX-\1", text)
            else:
                return f"[PARTIALLY REDACTED: {self.name}]"
                
        elif self.strategy == RedactionStrategy.HASH:
            # Simple hash for demonstration
            import hashlib
            hashed = hashlib.md5(text.encode()).hexdigest()[:8]
            return f"[HASHED:{hashed}]"
            
        return "[REDACTED]"


class PHISanitizer:
    """Sanitizes text by identifying and redacting PHI."""
    
    def __init__(self, patterns: list[PHIPattern] = None):
        self.patterns = patterns or []
        self._initialize_default_patterns()
        
    def _initialize_default_patterns(self):
        """Initialize default PHI patterns if none provided."""
        if not self.patterns:
            self.patterns = [
                # SSN pattern (e.g., 123-45-6789)
                PHIPattern(
                    name="SSN",
                    regex=r"\b\d{3}-\d{2}-(\d{4})\b",
                    context_patterns=[r"\bssn\b", r"\bsocial security\b"],
                    strategy=RedactionStrategy.PARTIAL
                ),
                
                # Phone number pattern
                PHIPattern(
                    name="PHONE",
                    regex=r"\(\d{3}\)\s*\d{3}-(\d{4})",
                    context_patterns=[r"\bphone\b", r"\bcall\b", r"\btel\b"],
                    strategy=RedactionStrategy.PARTIAL
                ),
                
                # Email pattern
                PHIPattern(
                    name="EMAIL",
                    regex=r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
                    context_patterns=[r"\bemail\b", r"\bcontact\b"],
                    strategy=RedactionStrategy.FULL
                ),
                
                # Address pattern - simplified for demonstration
                PHIPattern(
                    name="ADDRESS",
                    context_patterns=[r"\baddress\b", r"\blive[sd]\b", r"\bst\.\b", r"\bstreet\b", 
                                     r"\bavenue\b", r"\bave\.\b", r"\bapt\b"],
                    strategy=RedactionStrategy.FULL
                ),
                
                # Patient ID pattern
                PHIPattern(
                    name="PATIENT_ID",
                    context_patterns=[r"\bpatient id\b", r"\bpatient number\b", r"\bpatient #\b"],
                    fuzzy_match=[r"\bP\d{6}\b", r"\bPATIENTID:\s*\w+"],
                    strategy=RedactionStrategy.HASH
                ),
            ]
    
    def sanitize(self, text: str) -> str:
        """Sanitize the input text by redacting all detected PHI."""
        if not text:
            return text
            
        # Check each pattern and apply redaction
        for pattern in self.patterns:
            if pattern.matches(text):
                return pattern.redact(text)
                
        return text


class SanitizedLogger:
    """A logger wrapper that sanitizes PHI before logging."""
    
    def __init__(self, name: str, sanitizer: PHISanitizer = None):
        self.logger = logging.getLogger(name)
        self.sanitizer = sanitizer or PHISanitizer()
        
    def _sanitize_args(self, args: tuple) -> tuple:
        """Sanitize all string arguments."""
        return tuple(self.sanitizer.sanitize(arg) if isinstance(arg, str) else arg 
                    for arg in args)
    
    def _sanitize_kwargs(self, kwargs: dict) -> dict:
        """Sanitize all string values in kwargs."""
        return {key: self.sanitizer.sanitize(value) if isinstance(value, str) else value 
                for key, value in kwargs.items()}
    
    def debug(self, msg, *args, **kwargs):
        """Log a debug message with PHI sanitized."""
        sanitized_msg = self.sanitizer.sanitize(msg)
        sanitized_args = self._sanitize_args(args)
        sanitized_kwargs = self._sanitize_kwargs(kwargs)
        return self.logger.debug(sanitized_msg, *sanitized_args, **sanitized_kwargs)
    
    def info(self, msg, *args, **kwargs):
        """Log an info message with PHI sanitized."""
        sanitized_msg = self.sanitizer.sanitize(msg)
        sanitized_args = self._sanitize_args(args)
        sanitized_kwargs = self._sanitize_kwargs(kwargs)
        return self.logger.info(sanitized_msg, *sanitized_args, **sanitized_kwargs)
    
    def warning(self, msg, *args, **kwargs):
        """Log a warning message with PHI sanitized."""
        sanitized_msg = self.sanitizer.sanitize(msg)
        sanitized_args = self._sanitize_args(args)
        sanitized_kwargs = self._sanitize_kwargs(kwargs)
        return self.logger.warning(sanitized_msg, *sanitized_args, **sanitized_kwargs)
    
    def error(self, msg, *args, **kwargs):
        """Log an error message with PHI sanitized."""
        sanitized_msg = self.sanitizer.sanitize(msg)
        sanitized_args = self._sanitize_args(args)
        sanitized_kwargs = self._sanitize_kwargs(kwargs)
        return self.logger.error(sanitized_msg, *sanitized_args, **sanitized_kwargs)
    
    def critical(self, msg, *args, **kwargs):
        """Log a critical message with PHI sanitized."""
        sanitized_msg = self.sanitizer.sanitize(msg)
        sanitized_args = self._sanitize_args(args)
        sanitized_kwargs = self._sanitize_kwargs(kwargs)
        return self.logger.critical(sanitized_msg, *sanitized_args, **sanitized_kwargs)
    
    def exception(self, msg, *args, exc_info=True, **kwargs):
        """Log an exception message with PHI sanitized."""
        sanitized_msg = self.sanitizer.sanitize(msg)
        sanitized_args = self._sanitize_args(args)
        sanitized_kwargs = self._sanitize_kwargs(kwargs)
        return self.logger.exception(sanitized_msg, *sanitized_args, exc_info=exc_info, **sanitized_kwargs)


# Function to get a sanitized logger
def get_sanitized_logger(name: str) -> SanitizedLogger:
    """Get a sanitized logger instance."""
    return SanitizedLogger(name)


# ============= PHI Sanitizer Tests =============

@pytest.mark.standalone()
class TestPHIPattern:
    """Test the PHI pattern detection functionality."""
    
    def test_init(self):
        """Test initialization."""
        pattern = PHIPattern(
            name="SSN",
            regex=r"\b\d{3}-\d{2}-\d{4}\b",
            exact_match=["123-45-6789"],
            fuzzy_match=[r"SSN"],
            context_patterns=[r"social security"]
        )
        
        assert pattern.name == "SSN"
        assert pattern.strategy == RedactionStrategy.FULL
        assert pattern._regex_pattern is not None
        assert "123-45-6789" in pattern._exact_matches
        assert len(pattern._fuzzy_patterns) == 1
        assert len(pattern._context_patterns) == 1
    
    def test_matches_exact(self):
        """Test exact matching."""
        pattern = PHIPattern(name="TEST", exact_match=["secret-value"])
        assert pattern.matches("secret-value")
        assert not pattern.matches("not-a-secret")
    
    def test_matches_regex(self):
        """Test regex matching."""
        pattern = PHIPattern(name="SSN", regex=r"\b\d{3}-\d{2}-\d{4}\b")
        assert pattern.matches("My SSN is 123-45-6789")
        assert not pattern.matches("My number is 12345")
    
    def test_matches_fuzzy(self):
        """Test fuzzy matching."""
        pattern = PHIPattern(name="PATIENT", fuzzy_match=[r"P\d{6}"])
        assert pattern.matches("Patient P123456 has arrived")
        assert not pattern.matches("Patient has arrived")
    
    def test_matches_context(self):
        """Test context pattern matching."""
        pattern = PHIPattern(name="ADDRESS", context_patterns=[r"\baddress\b"])
        assert pattern.matches("The patient's address is 123 Main St")
        assert not pattern.matches("The patient lives somewhere")
    
    def test_redact_full(self):
        """Test full redaction."""
        pattern = PHIPattern(name="SSN", regex=r"\b\d{3}-\d{2}-\d{4}\b")
        assert pattern.redact("My SSN is 123-45-6789") == "[REDACTED]"
    
    def test_redact_partial_ssn(self):
        """Test partial redaction for SSN."""
        pattern = PHIPattern(
            name="SSN",
            regex=r"\b\d{3}-\d{2}-(\d{4})\b",
            strategy=RedactionStrategy.PARTIAL
        )
        assert pattern.redact("My SSN is 123-45-6789") == "XXX-XX-6789"
    
    def test_redact_partial_phone(self):
        """Test partial redaction for phone."""
        pattern = PHIPattern(
            name="PHONE",
            regex=r"\(\d{3}\)\s*\d{3}-(\d{4})",
            strategy=RedactionStrategy.PARTIAL
        )
        assert pattern.redact("My phone is (555) 123-4567") == "(XXX) XXX-4567"
    
    def test_redact_hash(self):
        """Test hash redaction."""
        pattern = PHIPattern(
            name="PATIENT_ID",
            regex=r"P\d{6}",
            strategy=RedactionStrategy.HASH
        )
        # We can't assert exact hash value since it's dynamic
        result = pattern.redact("Patient ID P123456")
        assert result.startswith("[HASHED:")
        assert len(result) > 10  # Make sure something was hashed


@pytest.mark.standalone()
class TestPHISanitizer:
    """Test the PHI sanitizer functionality."""
    
    def test_init_default_patterns(self):
        """Test initialization with default patterns."""
        sanitizer = PHISanitizer()
        assert len(sanitizer.patterns) > 0
        
        # Check if default patterns were created
        pattern_names = [p.name for p in sanitizer.patterns]
        assert "SSN" in pattern_names
        assert "PHONE" in pattern_names
        assert "EMAIL" in pattern_names
    
    def test_init_custom_patterns(self):
        """Test initialization with custom patterns."""
        custom_patterns = [
            PHIPattern(name="CUSTOM", regex=r"CUSTOM\d+")
        ]
        sanitizer = PHISanitizer(patterns=custom_patterns)
        assert len(sanitizer.patterns) == 1
        assert sanitizer.patterns[0].name == "CUSTOM"
    
    def test_sanitize_ssn(self):
        """Test sanitizing SSN."""
        sanitizer = PHISanitizer()
        text = "Patient SSN: 123-45-6789"
        sanitized = sanitizer.sanitize(text)
        assert "123-45-6789" not in sanitized
    
    def test_sanitize_phone(self):
        """Test sanitizing phone number."""
        sanitizer = PHISanitizer()
        text = "Call me at (555) 123-4567"
        sanitized = sanitizer.sanitize(text)
        assert "(555) 123-4567" not in sanitized
    
    def test_sanitize_email(self):
        """Test sanitizing email."""
        sanitizer = PHISanitizer()
        text = "My email is patient@example.com"
        sanitized = sanitizer.sanitize(text)
        assert "patient@example.com" not in sanitized
    
    def test_sanitize_patient_id(self):
        """Test sanitizing patient ID."""
        sanitizer = PHISanitizer()
        text = "PATIENTID: P123456"
        sanitized = sanitizer.sanitize(text)
        assert "P123456" not in sanitized
    
    def test_sanitize_address(self):
        """Test sanitizing address."""
        sanitizer = PHISanitizer()
        text = "I live at 123 Main St., Anytown, USA"
        sanitized = sanitizer.sanitize(text)
        assert "123 Main St" not in sanitized or "Anytown" not in sanitized
    
    def test_sanitize_no_phi(self):
        """Test sanitizing text with no PHI."""
        sanitizer = PHISanitizer()
        text = "The weather is nice today"
        sanitized = sanitizer.sanitize(text)
        assert sanitized == text  # Unchanged
    
    def test_sanitize_empty(self):
        """Test sanitizing empty text."""
        sanitizer = PHISanitizer()
        assert sanitizer.sanitize("") == ""
        assert sanitizer.sanitize(None) is None


@pytest.mark.standalone()
class TestSanitizedLogger:
    """Test the sanitized logger functionality."""
    
    def test_init(self):
        """Test logger initialization."""
        logger = SanitizedLogger("test_logger")
        assert logger.logger.name == "test_logger"
        assert isinstance(logger.sanitizer, PHISanitizer)
        
        # Test with custom sanitizer
        custom_sanitizer = PHISanitizer([PHIPattern(name="CUSTOM", regex=r"CUSTOM\d+")])
        logger = SanitizedLogger("test_logger", sanitizer=custom_sanitizer)
        assert logger.sanitizer is custom_sanitizer
    
    def test_sanitize_args(self):
        """Test sanitizing arguments."""
        logger = SanitizedLogger("test_logger")
        args = ("Normal text", "SSN: 123-45-6789", 42)
        sanitized_args = logger._sanitize_args(args)
        
        assert sanitized_args[0] == "Normal text"  # Unchanged
        assert "123-45-6789" not in sanitized_args[1]  # Sanitized
        assert sanitized_args[2] == 42  # Non-string unchanged
    
    def test_sanitize_kwargs(self):
        """Test sanitizing keyword arguments."""
        logger = SanitizedLogger("test_logger")
        kwargs = {
            "normal": "Normal text",
            "phi": "SSN: 123-45-6789",
            "number": 42
        }
        sanitized_kwargs = logger._sanitize_kwargs(kwargs)
        
        assert sanitized_kwargs["normal"] == "Normal text"  # Unchanged
        assert "123-45-6789" not in sanitized_kwargs["phi"]  # Sanitized
        assert sanitized_kwargs["number"] == 42  # Non-string unchanged
    
    def test_log_methods(self, caplog):
        """Test all log methods sanitize correctly."""
        caplog.set_level(logging.DEBUG)
        
        logger = SanitizedLogger("test_logger")
        
        # Test all log levels
        logger.debug("Debug with SSN: 123-45-6789")
        logger.info("Info with SSN: 123-45-6789")
        logger.warning("Warning with SSN: 123-45-6789")
        logger.error("Error with SSN: 123-45-6789")
        logger.critical("Critical with SSN: 123-45-6789")
        
        # Check log records
        for record in caplog.records:
            assert "123-45-6789" not in record.message
            assert "[" in record.message  # Some form of redaction marker
    
    def test_exception_method(self, caplog):
        """Test exception method sanitizes correctly."""
        caplog.set_level(logging.ERROR)
        
        logger = SanitizedLogger("test_logger")
        
        try:
            raise ValueError("Error with SSN: 123-45-6789")
        except ValueError:
            logger.exception("Exception with SSN: 123-45-6789")
        
        # Check log record
        for record in caplog.records:
            assert "123-45-6789" not in record.message
            assert "[" in record.message  # Some form of redaction marker


def test_get_sanitized_logger():
    """Test get_sanitized_logger function."""
    logger = get_sanitized_logger("test_app")
    assert isinstance(logger, SanitizedLogger)
    assert logger.logger.name == "test_app"


if __name__ == "__main__":
    pytest.main(["-v", __file__])
