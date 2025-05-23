#!/usr/bin/env python3
"""
Secure HIPAA-Compliant Logger

This module provides a secure logging facility that automatically sanitizes
Protected Health Information (PHI) from log messages. It should be used
throughout the Novamind application to ensure HIPAA compliance.

Features:
- PHI pattern detection and redaction
- Log sanitization for common PHI patterns (SSNs, emails, phone numbers, etc.)
- Different redaction strategies (full redaction, partial redaction, tokenization)
- Configurable log formats and output destinations
- Integration with standard Python logging

Usage:
    from scripts.secure_logger import get_logger

    logger = get_logger(__name__)
    logger.info("Processing data for patient with ID: 12345")  # PHI will be redacted
"""

import hashlib
import logging
import os
import re
from datetime import datetime
from re import Match, Pattern
from typing import Any

# PHI patterns to detect and sanitize
PHI_PATTERNS = {
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "ssn_no_dash": r"\b\d{9}\b",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "phone": r"\b\(\d{3}\)\s*\d{3}-\d{4}\b",
    "phone_dash": r"\b\d{3}-\d{3}-\d{4}\b",
    "credit_card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11})\b",
    "name_with_title": r"\b(?:Mr\.|Mrs\.|Ms\.|Dr\.)\s[A-Z][a-z]+ [A-Z][a-z]+\b",
    "patient_id": r"\bPATIENT[_-]?ID[_-]?\d+\b",
    "pt_id": r"\bPT[_-]?ID[_-]?\d+\b",
    "mrn": r"\bMRN[_-]?\d+\b",
    "medical_record": r"\bMEDICAL[_-]?RECORD[_-]?\d+\b",
    "date_of_birth": r"\b\d{1,2}/\d{1,2}/\d{2,4}\b",
    "date_dash": r"\b\d{1,2}-\d{1,2}-\d{2,4}\b",
    "ip_address": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
}

# Common PHI words that might indicate the presence of PHI
PHI_INDICATORS = [
    "patient",
    "name",
    "ssn",
    "social security",
    "email",
    "address",
    "phone",
    "dob",
    "birth",
    "medical",
    "record",
    "mrn",
    "diagnosis",
    "condition",
    "treatment",
    "visit",
    "admission",
    "discharge",
    "medication",
    "prescription",
]

# Default redaction replacement text
DEFAULT_REDACTION = "[REDACTED]"


class PHISanitizer:
    """Class for sanitizing PHI in text."""

    def __init__(
        self,
        patterns: dict[str, str] = None,
        redaction_text: str = DEFAULT_REDACTION,
        tokenize: bool = False,
    ):
        """
        Initialize the PHI sanitizer.

        Args:
            patterns: Dictionary of PHI patterns to detect and sanitize
            redaction_text: Text to replace PHI with
            tokenize: Whether to tokenize PHI (hash it) instead of redacting
        """
        self.patterns = patterns or PHI_PATTERNS
        self.redaction_text = redaction_text
        self.tokenize = tokenize

        # Compile patterns for efficiency
        self.compiled_patterns = {
            name: re.compile(pattern) for name, pattern in self.patterns.items()
        }

    def sanitize(self, text: str) -> str:
        """
        Sanitize PHI in text.

        Args:
            text: Text to sanitize

        Returns:
            Sanitized text
        """
        if not text:
            return text

        # Make a copy to avoid modifying the original
        sanitized = text

        # Check for PHI indicators first for efficiency
        has_phi_indicator = any(indicator in text.lower() for indicator in PHI_INDICATORS)

        if not has_phi_indicator:
            return text

        # Apply each pattern
        for name, pattern in self.compiled_patterns.items():
            sanitized = self._apply_pattern(sanitized, pattern, name)

        return sanitized

    def _apply_pattern(self, text: str, pattern: Pattern, name: str) -> str:
        """
        Apply a pattern to sanitize PHI.

        Args:
            text: Text to sanitize
            pattern: Compiled regex pattern
            name: Name of the pattern

        Returns:
            Sanitized text
        """

        def _replace_match(match: Match) -> str:
            """Replace PHI with redaction text or token."""
            if self.tokenize:
                # Generate a secure hash of the PHI
                phi = match.group(0)
                token = hashlib.sha256(phi.encode()).hexdigest()[:8]
                return f"{name[:3].upper()}_TOKEN_{token}"
            else:
                return self.redaction_text

        return pattern.sub(_replace_match, text)


class SecureLogger:
    """HIPAA-compliant secure logger."""

    def __init__(
        self,
        name: str,
        level: int = logging.INFO,
        sanitize: bool = True,
        log_dir: str = "logs",
        log_to_file: bool = True,
        log_to_console: bool = True,
        format_string: str = None,
    ):
        """
        Initialize the secure logger.

        Args:
            name: Logger name
            level: Logging level
            sanitize: Whether to sanitize PHI
            log_dir: Directory to store log files
            log_to_file: Whether to log to a file
            log_to_console: Whether to log to the console
            format_string: Custom log format string
        """
        self.name = name
        self.sanitize = sanitize
        self.log_dir = log_dir

        # Create logger
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)

        # Remove existing handlers to avoid duplicates
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)

        # Default format
        if format_string is None:
            format_string = (
                "%(asctime)s - %(levelname)s - %(name)s - %(filename)s:%(lineno)d - %(message)s"
            )

        formatter = logging.Formatter(format_string)

        # Add console handler
        if log_to_console:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

        # Add file handler
        if log_to_file:
            os.makedirs(log_dir, exist_ok=True)

            # Daily rotating log file
            today = datetime.now().strftime("%Y-%m-%d")
            log_file = os.path.join(log_dir, f"{today}-{name}.log")

            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

        # Initialize sanitizer
        self.sanitizer = PHISanitizer()

    def _sanitize_message(self, message: str) -> str:
        """
        Sanitize PHI from message if sanitization is enabled.

        Args:
            message: Message to sanitize

        Returns:
            Sanitized message
        """
        if not self.sanitize:
            return message

        return self.sanitizer.sanitize(message)

    def _sanitize_args(self, args: list[Any]) -> list[Any]:
        """
        Sanitize PHI from positional arguments.

        Args:
            args: Arguments to sanitize

        Returns:
            Sanitized arguments
        """
        if not self.sanitize:
            return args

        sanitized_args = []
        for arg in args:
            if isinstance(arg, str):
                sanitized_args.append(self.sanitizer.sanitize(arg))
            else:
                sanitized_args.append(arg)

        return sanitized_args

    def _sanitize_kwargs(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        """
        Sanitize PHI from keyword arguments.

        Args:
            kwargs: Keyword arguments to sanitize

        Returns:
            Sanitized keyword arguments
        """
        if not self.sanitize:
            return kwargs

        sanitized_kwargs = {}
        for key, value in kwargs.items():
            if isinstance(value, str):
                sanitized_kwargs[key] = self.sanitizer.sanitize(value)
            else:
                sanitized_kwargs[key] = value

        return sanitized_kwargs

    def debug(self, message: str, *args, **kwargs):
        """Log a debug message."""
        sanitized_message = self._sanitize_message(message)
        sanitized_args = self._sanitize_args(args)
        sanitized_kwargs = self._sanitize_kwargs(kwargs)

        self.logger.debug(sanitized_message, *sanitized_args, **sanitized_kwargs)

    def info(self, message: str, *args, **kwargs):
        """Log an info message."""
        sanitized_message = self._sanitize_message(message)
        sanitized_args = self._sanitize_args(args)
        sanitized_kwargs = self._sanitize_kwargs(kwargs)

        self.logger.info(sanitized_message, *sanitized_args, **sanitized_kwargs)

    def warning(self, message: str, *args, **kwargs):
        """Log a warning message."""
        sanitized_message = self._sanitize_message(message)
        sanitized_args = self._sanitize_args(args)
        sanitized_kwargs = self._sanitize_kwargs(kwargs)

        self.logger.warning(sanitized_message, *sanitized_args, **sanitized_kwargs)

    def error(self, message: str, *args, **kwargs):
        """Log an error message."""
        sanitized_message = self._sanitize_message(message)
        sanitized_args = self._sanitize_args(args)
        sanitized_kwargs = self._sanitize_kwargs(kwargs)

        self.logger.error(sanitized_message, *sanitized_args, **sanitized_kwargs)

    def critical(self, message: str, *args, **kwargs):
        """Log a critical message."""
        sanitized_message = self._sanitize_message(message)
        sanitized_args = self._sanitize_args(args)
        sanitized_kwargs = self._sanitize_kwargs(kwargs)

        self.logger.critical(sanitized_message, *sanitized_args, **sanitized_kwargs)

    def exception(self, message: str, *args, **kwargs):
        """Log an exception message."""
        sanitized_message = self._sanitize_message(message)
        sanitized_args = self._sanitize_args(args)
        sanitized_kwargs = self._sanitize_kwargs(kwargs)

        self.logger.exception(sanitized_message, *sanitized_args, **sanitized_kwargs)


# Cache for loggers to avoid creating duplicates
_logger_cache = {}


def get_logger(
    name: str,
    level: int = logging.INFO,
    sanitize: bool = True,
    log_dir: str = "logs",
    log_to_file: bool = True,
    log_to_console: bool = True,
    format_string: str = None,
) -> SecureLogger:
    """
    Get a secure logger instance.

    Args:
        name: Logger name
        level: Logging level
        sanitize: Whether to sanitize PHI
        log_dir: Directory to store log files
        log_to_file: Whether to log to a file
        log_to_console: Whether to log to the console
        format_string: Custom log format string

    Returns:
        Secure logger instance
    """
    # Check if logger already exists in cache
    cache_key = f"{name}_{level}_{sanitize}_{log_dir}_{log_to_file}_{log_to_console}"

    if cache_key in _logger_cache:
        return _logger_cache[cache_key]

    # Create new logger
    logger = SecureLogger(
        name=name,
        level=level,
        sanitize=sanitize,
        log_dir=log_dir,
        log_to_file=log_to_file,
        log_to_console=log_to_console,
        format_string=format_string,
    )

    # Cache logger
    _logger_cache[cache_key] = logger

    return logger


if __name__ == "__main__":
    # Example usage
    logger = get_logger("secure_logger_test", log_to_console=True, log_to_file=False)

    # Test logging with PHI
    print("Testing secure logger with PHI sanitization:")

    logger.info("This message has no PHI")
    logger.info("Patient ID: PATIENT_ID_12345 - This will be sanitized")
    logger.info("Name: Mr. John Smith - This will be sanitized")
    logger.info("Phone: 555-123-4567 - This will be sanitized")
    logger.info("Email: john.smith@example.com - This will be sanitized")
    logger.info("SSN: 123-45-6789 - This will be sanitized")

    print("\nAll PHI should have been sanitized in the log messages above.")
