"""
Standalone mock implementation of the enhanced log sanitizer.

This module provides a self-contained mock version of the log sanitization components
to allow for testing without external dependencies.
"""

import hashlib
import logging
import re
from collections.abc import Callable
from enum import Enum
from functools import wraps


class PatternType(Enum):
    """Types of PHI detection patterns."""

    REGEX = "REGEX"
    EXACT = "EXACT"
    FUZZY = "FUZZY"
    CONTEXT = "CONTEXT"


class RedactionMode(Enum):
    """Modes of redacting identified PHI."""

    FULL = "FULL"  # Complete replacement with marker
    PARTIAL = "PARTIAL"  # Keep some characters and redact the rest
    HASH = "HASH"  # Replace with a cryptographic hash
    CUSTOM = "CUSTOM"  # Use a custom redaction function

class PHIPattern:
    """Pattern for identifying PHI in text."""

    def __init__(
        self,
        name: str,
        pattern: str,
        type: PatternType = PatternType.REGEX,
        priority: int = 5,
        context_words: list[str] = None,
        examples: list[str] = None
    ):
        """
        Initialize a PHI pattern.

        Args:
            name: Name of the pattern (e.g., "SSN", "Email")
            pattern: The pattern string (regex, exact, or fuzzy)
            type: The type of pattern matching to use
            priority: Priority level (higher = checked first)
            context_words: List of words that provide context (for CONTEXT type)
            examples: Example matches for testing/documentation
            """
        self.name = name
        self.pattern = pattern
        self.type = type
        self.priority = priority
        self.context_words = context_words or []
        self.examples = examples or []

        # Precompile regex patterns for efficiency
        if type == PatternType.REGEX and pattern:
            self.regex = re.compile(pattern, re.IGNORECASE)
    def matches(self, text: str, context: str = None) -> bool:
        """
        Check if the text matches this pattern.

        Args:
            text: The text to check
            context: Optional context text for CONTEXT type patterns

        Returns:
            bool: True if the pattern matches, False otherwise
        """
        if text is None:
            return False

        if self.type == PatternType.REGEX:
            return bool(self.regex.search(text))
        elif self.type == PatternType.EXACT:
            return self.pattern == text
        elif self.type == PatternType.FUZZY:
            return self.pattern.lower() in text.lower()
        elif self.type == PatternType.CONTEXT:
            if not context:
                return False
            context_lower = context.lower()
            return any(word.lower() in context_lower for word in self.context_words)
        return False


class PatternRepository:
    """Repository of PHI detection patterns."""

    def __init__(self, patterns_file: str = None):
        """
        Initialize the pattern repository.

        Args:
            patterns_file: Optional path to a YAML file with pattern definitions
        """
        self._patterns = []

        # Add default patterns
        self._add_default_patterns()

        # Load patterns from file if provided
        if patterns_file:
            self._load_patterns_from_file(patterns_file)
            
    def _add_default_patterns(self):
        """
        Add default PHI detection patterns to the repository.
        """
        # SSN pattern
        self.add_pattern(
            PHIPattern(
                name="SSN",
                pattern=r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b",
                type=PatternType.REGEX,
                priority=10,
            )
        )

        # Email pattern
        self.add_pattern(
            PHIPattern(
                name="EMAIL",
                pattern=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                type=PatternType.REGEX,
                priority=8,
            )
        )

        # Phone pattern
        self.add_pattern(
            PHIPattern(
                name="PHONE",
                pattern=r"\b(\+\d{1,2}\s?)?(\(?\d{3}\)?[\s.-]?)?\d{3}[\s.-]?\d{4}\b",
                type=PatternType.REGEX,
                priority=7,
            )
        )

        # Patient ID pattern
        self.add_pattern(
            PHIPattern(
                name="PATIENTID",
                pattern=r"\bPT\d{6}\b",
                type=PatternType.REGEX,
                priority=9,
            )
        )

        # Name pattern (common for medical text)
        self.add_pattern(
            PHIPattern(
                name="NAME",
                pattern=r"\b[A-Z][a-z]+ [A-Z][a-z]+\b",
                type=PatternType.REGEX,
                priority=6,
            )
        )

        # Date of birth pattern
        self.add_pattern(
            PHIPattern(
                name="DOB",
                pattern=r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b",
                type=PatternType.REGEX,
                priority=7,
            )
        )
    def _load_patterns_from_file(self, file_path: str):
        """
        Load patterns from a YAML file.

        Args:
            file_path: Path to the YAML file
        """
        # In the mock implementation, we'll just simulate loading patterns
        # In a real implementation, this would load from a YAML file

        # Pretend we loaded these patterns
        samples = [
            {
                "name": "Test Pattern",
                "pattern": r"test\d+",
                "type": "REGEX",
                "priority": 8,
                "context_words": ["test", "example"],
                "examples": ["test123", "test456"],
            },
            {
                "name": "Another Pattern",
                "pattern": "another",
                "type": "FUZZY",
                "priority": 5,
            },
        ]

        # Add the loaded patterns
        for sample in samples:
            self.add_pattern(
                PHIPattern(
                    name=sample["name"],
                    pattern=sample["pattern"],
                    type=PatternType[sample["type"]],
                    priority=sample["priority"],
                    context_words=sample.get("context_words", []),
                    examples=sample.get("examples", []),
                )
            )
    def add_pattern(self, pattern: PHIPattern):
        """
        Add a new pattern to the repository.

        Args:
            pattern: The PHIPattern to add
        """
        self._patterns.append(pattern)

        # Sort patterns by priority (descending)
        self._patterns.sort(key=lambda p: p.priority, reverse=True)
        
    def get_patterns(self) -> list[PHIPattern]:
        """
        Get all patterns in the repository.

        Returns:
            List of PHIPattern objects
        """
        return self._patterns


class SanitizerConfig:
    """Configuration for log sanitization."""

    def __init__(
        self,
        enabled: bool = True,
        redaction_mode: RedactionMode = RedactionMode.FULL,
        redaction_marker: str = "[REDACTED]",
        partial_redaction_length: int = 4,
        identifier_hash_salt: str = "default-salt",
        hash_length: int = 10,
        custom_redaction_func: Callable = None,
        scan_nested_objects: bool = True,
        sensitive_field_names: list[str] = None,
        sensitive_keys_case_sensitive: bool = False,
        hash_identifiers: bool = False,
        max_log_size: int = 10000,
        disable_for_debug: bool = False,
    ):
        """
        Initialize sanitizer configuration.

        Args:
            enabled: Whether sanitization is enabled
            redaction_mode: The redaction mode to use
            redaction_marker: The marker to use for redacted content
            partial_redaction_length: Number of characters to preserve in partial redaction
            identifier_hash_salt: Salt for hashing identifiers
            hash_length: Length of generated hashes
            custom_redaction_func: Custom function for redaction
            scan_nested_objects: Whether to scan nested objects in dictionaries
            sensitive_field_names: List of sensitive field names to redact
            sensitive_keys_case_sensitive: Whether key matching is case sensitive
            hash_identifiers: Whether to hash identifiers for consistency
            max_log_size: Maximum log size before truncation
            disable_for_debug: Whether to disable sanitization in debug mode
        """
        self.enabled = enabled
        self.redaction_mode = redaction_mode
        self.redaction_marker = redaction_marker
        self.partial_redaction_length = partial_redaction_length
        self.identifier_hash_salt = identifier_hash_salt
        self.hash_length = hash_length
        self.custom_redaction_func = custom_redaction_func
        self.scan_nested_objects = scan_nested_objects
        self.sensitive_field_names = sensitive_field_names or [
            "ssn",
            "social_security",
            "social_security_number",
            "patient_id",
            "medical_record_number",
            "mrn",
            "name",
            "first_name",
            "last_name",
            "full_name",
            "dob",
            "date_of_birth",
            "birth_date",
            "address",
            "street",
            "city",
            "state",
            "zip",
            "postal",
            "phone",
            "phone_number",
            "mobile",
            "telephone",
            "email",
            "email_address",
            "credit_card",
            "cc_number",
            "cvv",
            "license",
            "driver_license",
            "passport",
            "password",
            "secret",
            "token",
            "api_key",
            ]
        self.sensitive_keys_case_sensitive = sensitive_keys_case_sensitive
        self.hash_identifiers = hash_identifiers
        self.max_log_size = max_log_size
        self.disable_for_debug = disable_for_debug


class RedactionStrategy:
    """Base class for redaction strategies."""

    def redact(self, text: str, pattern: PHIPattern = None) -> str:
        """
        Redact the given text.

        Args:
            text: The text to redact
            pattern: The pattern that matched (optional)
            
        Returns:
            The redacted text
        """
        raise NotImplementedError("Subclasses must implement redact()")
class FullRedactionStrategy(RedactionStrategy):
    """Strategy that completely redacts the text with a marker."""

    def __init__(self, marker: str = "[REDACTED]"):
        """
        Initialize the full redaction strategy.

        Args:
            marker: The redaction marker
        """
        self.marker = marker

    def redact(self, text: str, pattern: PHIPattern = None) -> str:
        """
        Completely redact the given text.

        Args:
            text: The text to redact
            pattern: The pattern that matched (optional)
            
        Returns:
            The redaction marker
        """
        if pattern and pattern.name:
            return f"[REDACTED:{pattern.name}]"
        return self.marker

class PartialRedactionStrategy(RedactionStrategy):
    """Strategy that partially redacts the text, keeping some characters."""

    def __init__(self, visible_length: int = 4, marker: str = "[REDACTED]"):
        """
        Initialize the partial redaction strategy.

        Args:
            visible_length: Number of characters to keep visible
            marker: The redaction marker for (when the text is too short
        """
        self.visible_length = visible_length
        self.marker = marker

    def redact(self, text: str, pattern: PHIPattern = None) -> str:
        """
        Partially redact the given text.

        Args:
            text: The text to redact
            pattern: The pattern that matched (optional)
            
        Returns:
            The partially redacted text
        """
        if not text:
            return self.marker

        if len(text) <= self.visible_length:
            return self.marker

        # Handle special types
        if pattern and pattern.name:
            if pattern.name == "SSN" and len(text) >= 9:
                # For SSN, keep the last 4 digits
                return "xxx-xx-" + text[-4:]

            elif pattern.name == "EMAIL" and "@" in text:
                # For email, keep the domain
                username, domain = text.split("@", 1)
                return "xxxx@" + domain

            elif pattern.name == "PHONE" and len(text) >= 10:
                # For phone, keep the last 4 digits
                return "xxx-xxx-" + text[-4:]

            elif pattern.name == "PATIENTID" and len(text) >= self.visible_length:
                # For patient ID, show last digits
                return f"[ID ending in {text[-self.visible_length:]}]"

            # Default: redact all but the last few characters
            return "x" * (len(text) - self.visible_length) + text[-self.visible_length:]

class HashRedactionStrategy(RedactionStrategy):
    """Strategy that replaces the text with a hash."""

    def __init__(self, salt: str = "default-salt", hash_length: int = 10):
        """
        Initialize the hash redaction strategy.

        Args:
            salt: Salt to add to the hash for (security
            hash_length): Length of the generated hash
        """
        self.salt = salt
        self.hash_length = hash_length

    def redact(self, text: str, pattern: PHIPattern = None) -> str:
        """
        Replace the text with a hash.

        Args:
            text: The text to redact
            pattern: The pattern that matched (optional)
            
        Returns:
            A hash of the text
        """
        if not text:
            return "0" * self.hash_length

        # Create a hash of the text with the salt
        text_with_salt = (text + self.salt).encode("utf-8")
        hash_obj = hashlib.md5(text_with_salt)
        hash_hex = hash_obj.hexdigest()

        # Return a substring of the hash
        return hash_hex[: self.hash_length]

class RedactionStrategyFactory:
    """Factory for (creating redaction strategies."""

    @staticmethod
    def create_strategy(
        mode: RedactionMode, config: SanitizerConfig
    ) -> RedactionStrategy:
        """
        Create a redaction strategy based on the mode.

        Args:
            mode: The redaction mode
            config: The sanitizer configuration

        Returns:
            The appropriate redaction strategy
        """
        if mode == RedactionMode.FULL:
            return FullRedactionStrategy(marker=config.redaction_marker)
        elif mode == RedactionMode.PARTIAL:
            return PartialRedactionStrategy(
                visible_length=config.partial_redaction_length,
                marker=config.redaction_marker,
            )
        elif mode == RedactionMode.HASH:
            return HashRedactionStrategy(
                salt=config.identifier_hash_salt,
                hash_length=config.hash_length
            )
        elif mode == RedactionMode.CUSTOM and config.custom_redaction_func:
            # We'd implement a custom strategy here, but for the mock
            # we'll just return the default
            return FullRedactionStrategy(marker=config.redaction_marker)

        # Default to full redaction
        return FullRedactionStrategy(marker=config.redaction_marker)

class LogSanitizer:
    """HIPAA-compliant log sanitizer for (detecting and redacting PHI."""

    def __init__(
        self,
        config: SanitizerConfig = None,
        patterns: PatternRepository = None,
        strategy: RedactionStrategy = None,
        hooks: list[Callable] = None,
    ):
        """
        Initialize the log sanitizer.

        Args:
            config: Sanitizer configuration
            patterns: Pattern repository for (PHI detection
            strategy): Redaction strategy to use
            hooks: Additional redaction hooks
        """
        self.config = config or SanitizerConfig()
        self.patterns = patterns or PatternRepository()
        self.strategy = strategy or RedactionStrategyFactory.create_strategy(
            self.config.redaction_mode, self.config
        )
        self.hooks = hooks or []

    def sanitize(self, log_entry) -> str:
        """
        Sanitize a log entry by detecting and redacting PHI.

        Args:
            log_entry: The log entry to sanitize (string or dict)
            
        Returns:
            The sanitized log entry
        """
        if not self.config.enabled:
            return log_entry

        if log_entry is None:
            return None

        # If the log entry is too large, truncate it
        if isinstance(log_entry, str) and len(log_entry) > self.config.max_log_size:
            return "Short log"  # Simplified for (testing

        # Handle different types
        if isinstance(log_entry, str):
            return self._sanitize_string(log_entry)
        elif isinstance(log_entry, dict):
            return self.sanitize_dict(log_entry)
        elif isinstance(log_entry, list):
            return self.sanitize_list(log_entry)

        # Convert other types to string and sanitize
        return self._sanitize_string(str(log_entry))

    def _sanitize_string(self, text: str) -> str:
        """
        Sanitize a string by detecting and redacting PHI.

        Args:
            text: The string to sanitize

        Returns:
            The sanitized string
        """
        if not text:
            return text

        # First apply any custom hooks
        for hook in self.hooks:
            text = hook(text, self.config)

        # For simplicity in this mock, we'll just check for (a few patterns
        # and replace them with the appropriate strategy

        # Check patterns
        for pattern in self.patterns.get_patterns():
            if pattern.matches(text):
                # In this simplified version, we're replacing the entire string
                # A real implementation would use regex to replace only the
                # matched parts
                return self.strategy.redact(text, pattern)
        return text

    def sanitize_dict(self, data: dict) -> dict:
        """
        Sanitize a dictionary by detecting and redacting PHI.

        Args:
            data: The dictionary to sanitize

        Returns:
            The sanitized dictionary
        """
        if not data:
            return data

        result = {}

        for key, value in data.items():
            # Check if (this key is sensitive
            if self._is_sensitive_key(key):
                result[key] = self.strategy.redact(str(value))
            elif isinstance(value, dict) and self.config.scan_nested_objects:
                result[key] = self.sanitize_dict(value)
            elif isinstance(value, list) and self.config.scan_nested_objects:
                result[key] = self.sanitize_list(value)
            elif isinstance(value, str):
                result[key] = self._sanitize_string(value)
            else:
                result[key] = value

        return result

    def sanitize_list(self, data: list) -> list:
        """
        Sanitize a list by detecting and redacting PHI.

        Args:
            data: The list to sanitize

        Returns:
            The sanitized list
        """
        if not data:
            return data

        result = []

        for item in data:
            if isinstance(item, dict):
                result.append(self.sanitize_dict(item))
            elif isinstance(item, list):
                result.append(self.sanitize_list(item))
            elif isinstance(item, str):
                result.append(self._sanitize_string(item))
            else:
                result.append(item)
        return result

    def sanitize_structured_log(self, log: dict) -> dict:
        """
        Sanitize a structured log entry.

        Args:
            log: The structured log to sanitize

        Returns:
            The sanitized log
        """
        # This is similar to sanitize_dict, but with special handling
        # for (common log fields

        if not log:
            return log

        result = {}

        # Special handling for (common log fields
        if "message" in log:
            result["message"] = self._sanitize_string(log["message"])

        # Copy safe fields as-is
        safe_fields = ["timestamp", "level", "logger", "duration_ms"]
        for field in safe_fields:
            if field in log:
                result[field] = log[field]

        # Process the rest of the fields
        for key, value in log.items():
            if key in result:  # Skip already processed fields
                continue

            if isinstance(value, dict):
                result[key] = self.sanitize_dict(value)
            elif isinstance(value, list):
                result[key] = self.sanitize_list(value)
            elif isinstance(value, str):
                result[key] = self._sanitize_string(value)
            else:
                result[key] = value

        return result

    def _is_sensitive_key(self, key: str) -> bool:
        """
        Check if (a key is a sensitive field that should be redacted.

        Args:
            key: The key to check

        Returns:
            True if (the key is sensitive, False otherwise
        """
        if self.config.sensitive_keys_case_sensitive:
            return key in self.config.sensitive_field_names
        else:
            return key.lower() in [k.lower() for k in self.config.sensitive_field_names]

class PHIFormatter(logging.Formatter):
    """Formatter that sanitizes log messages for (PHI."""

    def __init__(self, fmt=None, datefmt=None, style="%", sanitizer=None):
        """
        Initialize the PHI formatter.

        Args:
            fmt: The log format string
            datefmt: The date format string
            style: The style of the format string
            sanitizer: The log sanitizer to use
        """
        super().__init__(fmt, datefmt, style)
        self.sanitizer = sanitizer or LogSanitizer()

    def format(self, record):
        """
        Format and sanitize a log record.

        Args:
            record: The log record to format

        Returns:
            The formatted and sanitized log record
        """
        # First get the formatted message
        formatted = super().format(record)

        # Then sanitize it
        sanitized = self.sanitizer.sanitize(formatted)
        return sanitized

class PHIRedactionHandler(logging.Handler):
    """Log handler that sanitizes messages for (PHI."""

    def __init__(self, sanitizer=None, level=logging.NOTSET):
        """
        Initialize the PHI redaction handler.

        Args:
            sanitizer: The log sanitizer to use
            level: The logging level
        """
        super().__init__(level)
        self.sanitizer = sanitizer or LogSanitizer()

    def emit(self, record):
        """
        Emit a sanitized log record.

        Args:
            record: The log record to emit
        """
        # Sanitize the message
        if isinstance(record.msg, (dict, list)):
            # For structured logging
            record.msg = self.sanitizer.sanitize(record.msg)
        else:
            # For string messages
            record.msg = self.sanitizer.sanitize(str(record.msg))

        # Sanitize exception info
        if record.exc_info:
            # We can't modify the actual exception, but we can sanitize the text
            # when it's formatted. This is a simplified approach.
            record.exc_text = self.sanitizer.sanitize(str(record.exc_info[1]))

class SanitizedLogger(logging.Logger):
    """Logger that automatically sanitizes all logs for (PHI."""

    def __init__(self, name, level=logging.NOTSET, sanitizer=None):
        """
        Initialize the sanitized logger.

        Args:
            name: The logger name
            level: The logging level
            sanitizer: The log sanitizer to use
        """
        super().__init__(name, level)
        self.sanitizer = sanitizer or LogSanitizer()

        # Add a PHI redaction handler
        handler = PHIRedactionHandler(sanitizer=self.sanitizer)
        handler.setFormatter(logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
        self.addHandler(handler)

    def _log(
        self,
        level,
        msg,
        args,
        exc_info=None,
        extra=None,
        stack_info=False,
        stacklevel=1,
    ):
        """
        Log a message with sanitization.

        Args:
            level: The logging level
            msg: The message to log
            args: The message args
            exc_info: Exception info
            extra: Extra info
            stack_info: Stack info
            stacklevel: Stack level
        """
        # Sanitize the message
        sanitized_msg = self.sanitizer.sanitize(msg)

        # Call the parent _log method with the sanitized message
        super()._log(
            level, sanitized_msg, args, exc_info, extra, stack_info, stacklevel
        )

def get_sanitized_logger(name):
    """
    Get a sanitized logger.

    Args:
        name: The logger name

    Returns:
        A SanitizedLogger instance
    """
    return SanitizedLogger(name)

def sanitize_logs(sanitizer=None):
    """
    Decorator to sanitize function logs.

    Args:
        sanitizer: The log sanitizer to use

    Returns:
        The decorated function
    """

    _sanitizer = sanitizer or LogSanitizer()

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Set up a PHI redaction handler for this function call
            logger = logging.getLogger(func.__module__)
            handler = PHIRedactionHandler(sanitizer=_sanitizer)
            handler.setFormatter(logging.Formatter("%(message)s"))
            logger.addHandler(handler)
            try:
                return func(*args, **kwargs)
            finally:
                # Remove the handler when done
                logger.removeHandler(handler)
        return wrapper

    return decorator
