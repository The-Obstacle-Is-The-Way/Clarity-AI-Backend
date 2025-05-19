"""
PHI Detection Service Implementation.

This module provides implementations for detecting and redacting
Protected Health Information (PHI) to ensure HIPAA compliance.
"""

import json
import re
from typing import Any

from app.core.exceptions import (
    InvalidConfigurationError,
    InvalidRequestError,
    ServiceUnavailableError,
)
from app.core.services.ml.interface import PHIDetectionInterface
from app.core.utils.logging import get_logger
from app.domain.utils.datetime_utils import now_utc

# Create logger (no PHI logging)
logger = get_logger(__name__)


class MockPHIDetection(PHIDetectionInterface):
    """
    Mock PHI detection service.

    This class provides a rule-based implementation for detecting and redacting
    PHI using regular expressions and pattern matching. It is intended for
    testing and fallback purposes only.
    """

    def __init__(self) -> None:
        """Initialize MockPHIDetection instance."""
        self._initialized = False
        self._config = None
        self._patterns = {}
        self._detection_levels = {"strict", "moderate", "relaxed"}
        self._default_level = "moderate"

    def initialize(self, config: dict[str, Any]) -> None:
        """
        Initialize the service with configuration.

        Args:
            config: Configuration dictionary

        Raises:
            InvalidConfigurationError: If configuration is invalid
        """
        try:
            self._config = config or {}

            # Load default PHI detection patterns
            self._load_default_patterns()

            # Load custom patterns if provided
            custom_patterns = self._config.get("patterns")
            if custom_patterns and isinstance(custom_patterns, dict):
                for level, patterns in custom_patterns.items():
                    if level in self._detection_levels and isinstance(patterns, dict):
                        for category, pattern_list in patterns.items():
                            if isinstance(pattern_list, list):
                                # Add to existing patterns
                                if level in self._patterns and category in self._patterns[level]:
                                    self._patterns[level][category].extend(pattern_list)
                                # Create new category
                                elif level in self._patterns:
                                    self._patterns[level][category] = pattern_list

            # Compile regex patterns
            self._compile_patterns()

            # Get default detection level
            default_level = self._config.get("default_level")
            if default_level in self._detection_levels:
                self._default_level = default_level

            self._initialized = True
            logger.info("Mock PHI detection service initialized")

        except Exception as e:
            logger.error(f"Failed to initialize mock PHI detection service: {e!s}")
            self._initialized = False
            self._config = None
            raise InvalidConfigurationError(
                f"Failed to initialize mock PHI detection service: {e!s}"
            )

    def _load_default_patterns(self) -> None:
        """Load default PHI detection patterns."""
        self._patterns = {
            "strict": {
                "names": [
                    r"\b[A-Z][a-z]+\s+[A-Z][a-z]+\b",  # First Last
                    r"\bDr\.\s+[A-Z][a-z]+\b",  # Dr. Last
                    r"\bMr\.\s+[A-Z][a-z]+\b",  # Mr. Last
                    r"\bMrs\.\s+[A-Z][a-z]+\b",  # Mrs. Last
                    r"\bMs\.\s+[A-Z][a-z]+\b",  # Ms. Last
                ],
                "dates": [
                    r"\b\d{1,2}/\d{1,2}/\d{2,4}\b",  # MM/DD/YYYY
                    r"\b\d{1,2}-\d{1,2}-\d{2,4}\b",  # MM-DD-YYYY
                    r"\b[A-Z][a-z]{2,8}\s+\d{1,2},\s+\d{4}\b",  # Month DD, YYYY
                ],
                "phone_numbers": [
                    r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b",  # 123-456-7890
                    r"\b\(\d{3}\)\s*\d{3}[-.\s]?\d{4}\b",  # (123) 456-7890
                ],
                "emails": [
                    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # email@domain.com
                ],
                "addresses": [
                    r"\b\d+\s+[A-Z][a-z]+\s+(?:St|Ave|Rd|Blvd|Dr|Ln|Ct)\b",  # 123 Main St
                    r"\b[A-Z][a-z]+,\s+[A-Z]{2}\s+\d{5}\b",  # City, ST 12345
                ],
                "ids": [
                    r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
                    r"\b\d{9}\b",  # 9-digit ID
                ],
                "ages": [
                    r"\bage\s+\d{1,3}\b",  # age 34
                    r"\b\d{1,3}\s+years\s+old\b",  # 34 years old
                ],
                "locations": [
                    r"\bin\s+[A-Z][a-z]+\b",  # in City
                    r"\bfrom\s+[A-Z][a-z]+\b",  # from City
                ],
            },
            "moderate": {
                "names": [
                    r"\b[A-Z][a-z]+\s+[A-Z][a-z]+\b",  # First Last
                    r"\bDr\.\s+[A-Z][a-z]+\b",  # Dr. Last
                ],
                "dates": [
                    r"\b\d{1,2}/\d{1,2}/\d{2,4}\b",  # MM/DD/YYYY
                    r"\b[A-Z][a-z]{2,8}\s+\d{1,2},\s+\d{4}\b",  # Month DD, YYYY
                ],
                "phone_numbers": [
                    r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b",  # 123-456-7890
                ],
                "emails": [
                    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # email@domain.com
                ],
                "addresses": [
                    r"\b\d+\s+[A-Z][a-z]+\s+(?:St|Ave|Rd|Blvd|Dr|Ln|Ct)\b",  # 123 Main St
                ],
                "ids": [
                    r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
                ],
            },
            "relaxed": {
                "names": [
                    r"\b[A-Z][a-z]+\s+[A-Z][a-z]+\b",  # First Last
                ],
                "dates": [
                    r"\b\d{1,2}/\d{1,2}/\d{4}\b",  # MM/DD/YYYY
                ],
                "phone_numbers": [
                    r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b",  # 123-456-7890
                ],
                "emails": [
                    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # email@domain.com
                ],
                "ids": [
                    r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
                ],
            },
        }

    def _compile_patterns(self) -> None:
        """Compile regex patterns for faster matching."""
        self._compiled_patterns = {}

        for level, categories in self._patterns.items():
            self._compiled_patterns[level] = {}
            for category, patterns in categories.items():
                self._compiled_patterns[level][category] = [
                    re.compile(pattern) for pattern in patterns
                ]

    def is_healthy(self) -> bool:
        """
        Check if the service is healthy.

        Returns:
            True if healthy, False otherwise
        """
        return self._initialized

    def shutdown(self) -> None:
        """Shutdown the service and release resources."""
        self._initialized = False
        self._config = None
        logger.info("Mock PHI detection service shut down")

    def detect_phi(self, text: str, detection_level: str | None = None) -> dict[str, Any]:
        """
        Detect PHI in text.

        Args:
            text: Text to analyze
            detection_level: Detection level (strict, moderate, relaxed)

        Returns:
            Dict containing detection results with PHI locations and types

        Raises:
            ServiceUnavailableError: If service is not initialized
            InvalidRequestError: If text is empty or invalid
        """
        if not self._initialized:
            raise ServiceUnavailableError("Mock PHI detection service is not initialized")

        if not text or not isinstance(text, str):
            raise InvalidRequestError("Text must be a non-empty string")

        # Get detection level (default to configured default)
        level = detection_level or self._default_level
        if level not in self._detection_levels:
            level = self._default_level

        # Get compiled patterns for level
        patterns = self._compiled_patterns.get(level, {})

        # Detect PHI
        phi_detected = []

        # Track positions to avoid duplicates
        positions_seen = set()

        for category, regex_patterns in patterns.items():
            for pattern in regex_patterns:
                for match in pattern.finditer(text):
                    start, end = match.span()

                    # Check if this position overlaps with any existing matches
                    if not any(start < p[1] and end > p[0] for p in positions_seen):
                        positions_seen.add((start, end))

                        phi_detected.append(
                            {
                                "type": category,
                                "value": match.group(),
                                "start": start,
                                "end": end,
                            }
                        )

        # Sort by start position
        phi_detected.sort(key=lambda x: x["start"])

        # Create response
        response = {
            "phi_detected": phi_detected,
            "detection_level": level,
            "phi_count": len(phi_detected),
            "has_phi": len(phi_detected) > 0,
            "timestamp": now_utc().isoformat() + "Z",
        }

        return response

    def redact_phi(
        self,
        text: str,
        replacement: str = "[REDACTED]",
        detection_level: str | None = None,
    ) -> dict[str, Any]:
        """
        Redact PHI from text.

        Args:
            text: Text to redact
            replacement: Replacement text for redacted PHI
            detection_level: Detection level (strict, moderate, relaxed)

        Returns:
            Dict containing redacted text and metadata

        Raises:
            ServiceUnavailableError: If service is not initialized
            InvalidRequestError: If text is empty or invalid
        """
        if not self._initialized:
            raise ServiceUnavailableError("Mock PHI detection service is not initialized")

        if not text or not isinstance(text, str):
            raise InvalidRequestError("Text must be a non-empty string")

        # Detect PHI
        detection_result = self.detect_phi(text, detection_level)

        # Redact PHI
        redacted_text = text
        offset = 0

        for phi in detection_result["phi_detected"]:
            start = phi["start"] + offset
            end = phi["end"] + offset

            # Replace PHI with replacement text
            redacted_text = redacted_text[:start] + replacement + redacted_text[end:]

            # Update offset (replacement text length might differ from original)
            offset += len(replacement) - (end - start)

        # Create response
        response = {
            "original_length": len(text),
            "redacted_length": len(redacted_text),
            "redacted_text": redacted_text,
            "detection_level": detection_result["detection_level"],
            "phi_count": detection_result["phi_count"],
            "has_phi": detection_result["has_phi"],
            "timestamp": now_utc().isoformat() + "Z",
        }

        return response


class OpenAIPHIDetection(PHIDetectionInterface):
    """
    OpenAI-based PHI detection service.

    This class provides a PHI detection implementation using OpenAI models
    for more accurate and context-aware PHI detection and redaction.
    """

    def __init__(self) -> None:
        """Initialize OpenAIPHIDetection instance."""
        self._initialized = False
        self._config = None
        self._api_key = None
        self._organization_id = None
        self._base_url = None
        self._default_model = "gpt-4"
        self._detection_levels = {"strict", "moderate", "relaxed"}
        self._default_level = "moderate"
        self._fallback_service = MockPHIDetection()

        # Import OpenAI client lazily to avoid dependency issues
        try:
            import openai

            self._openai_available = True
        except ImportError:
            self._openai_available = False
            logger.warning("OpenAI package not installed. Install with: pip install openai>=1.0.0")

    def initialize(self, config: dict[str, Any]) -> None:
        """
        Initialize the service with configuration.

        Args:
            config: Configuration dictionary

        Raises:
            InvalidConfigurationError: If configuration is invalid
        """
        try:
            if not self._openai_available:
                logger.warning("OpenAI not available, falling back to mock PHI detection")
                self._fallback_service.initialize(config)
                self._initialized = True
                return

            self._config = config or {}

            # Get OpenAI API configuration
            self._api_key = self._get_config_value("api_key")
            if not self._api_key:
                raise InvalidConfigurationError("OpenAI API key is required")

            # Get optional configuration
            self._organization_id = self._get_config_value("organization_id")
            self._base_url = self._get_config_value("base_url")
            self._default_model = self._get_config_value("default_model") or "gpt-4"

            # Get default detection level
            default_level = self._config.get("default_level")
            if default_level in self._detection_levels:
                self._default_level = default_level

            # Initialize OpenAI client
            import openai

            client_kwargs = {"api_key": self._api_key}

            if self._organization_id:
                client_kwargs["organization"] = self._organization_id

            if self._base_url:
                client_kwargs["base_url"] = self._base_url

            self._client = openai.OpenAI(**client_kwargs)

            # Verify API key
            self._check_api_key()

            # Initialize fallback service
            self._fallback_service.initialize(config)

            self._initialized = True
            logger.info("OpenAI PHI detection service initialized")

        except Exception as e:
            logger.error(f"Failed to initialize OpenAI PHI detection service: {e!s}")
            self._initialized = False
            self._config = None
            self._client = None
            raise InvalidConfigurationError(
                f"Failed to initialize OpenAI PHI detection service: {e!s}"
            )

    def _get_config_value(self, key: str) -> str | None:
        """
        Get configuration value from config or environment variable.

        Args:
            key: Configuration key

        Returns:
            Configuration value or None if not found
        """
        import os

        # Try to get from config
        value = self._config.get(key)
        if value:
            return value

        # Try to get from environment
        env_key = f"OPENAI_{key.upper()}"
        return os.environ.get(env_key)

    def _check_api_key(self) -> None:
        """
        Check if the API key is valid.

        Raises:
            InvalidConfigurationError: If API key is invalid
        """
        try:
            # Test API connection with a minimal request
            self._client.models.list(limit=1)
        except Exception as e:
            logger.error(f"Failed to connect to OpenAI API: {e!s}")
            raise InvalidConfigurationError(f"Failed to connect to OpenAI API: {e!s}")

    def is_healthy(self) -> bool:
        """
        Check if the service is healthy.

        Returns:
            True if healthy, False otherwise
        """
        if not self._initialized:
            return False

        if not self._openai_available:
            return self._fallback_service.is_healthy()

        try:
            # Test API connection
            self._client.models.list(limit=1)
            return True
        except Exception:
            return False

    def shutdown(self) -> None:
        """Shutdown the service and release resources."""
        self._initialized = False
        self._config = None
        self._client = None

        # Shutdown fallback service
        self._fallback_service.shutdown()

        logger.info("OpenAI PHI detection service shut down")

    def detect_phi(self, text: str, detection_level: str | None = None) -> dict[str, Any]:
        """
        Detect PHI in text.

        Args:
            text: Text to analyze
            detection_level: Detection level (strict, moderate, relaxed)

        Returns:
            Dict containing detection results with PHI locations and types

        Raises:
            ServiceUnavailableError: If service is not initialized
            InvalidRequestError: If text is empty or invalid
        """
        if not self._initialized:
            raise ServiceUnavailableError("OpenAI PHI detection service is not initialized")

        if not text or not isinstance(text, str):
            raise InvalidRequestError("Text must be a non-empty string")

        # If OpenAI is not available, use fallback service
        if not self._openai_available:
            return self._fallback_service.detect_phi(text, detection_level)

        # Get detection level (default to configured default)
        level = detection_level or self._default_level
        if level not in self._detection_levels:
            level = self._default_level

        try:
            # Prepare system prompt based on detection level
            system_prompt = self._get_detection_prompt(level)

            # Prepare user prompt
            user_prompt = f"Please analyze the following text for PHI (Protected Health Information):\n\n{text}"

            # Generate completion
            model = self._config.get("model") or self._default_model

            response = self._client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.3,
                response_format={"type": "json_object"},
            )

            # Extract response text
            content = response.choices[0].message.content

            # Parse JSON response
            try:
                result = json.loads(content)

                # Ensure result has required fields
                if not isinstance(result.get("phi_detected"), list):
                    raise ValueError("Invalid response format: missing 'phi_detected' array")

                # Create response
                response = {
                    "phi_detected": result.get("phi_detected", []),
                    "detection_level": level,
                    "phi_count": len(result.get("phi_detected", [])),
                    "has_phi": len(result.get("phi_detected", [])) > 0,
                    "timestamp": now_utc().isoformat() + "Z",
                }

                return response

            except json.JSONDecodeError:
                logger.warning(
                    "Failed to parse JSON response from OpenAI, falling back to rule-based detection"
                )
                return self._fallback_service.detect_phi(text, detection_level)

        except Exception as e:
            logger.error(f"Failed to detect PHI with OpenAI: {e!s}")
            logger.info("Falling back to rule-based PHI detection")
            return self._fallback_service.detect_phi(text, detection_level)

    def _get_detection_prompt(self, level: str) -> str:
        """
        Get detection prompt for the specified level.

        Args:
            level: Detection level (strict, moderate, relaxed)

        Returns:
            Detection prompt
        """
        sensitivity_descriptions = {
            "strict": "You should be extremely thorough and cautious, detecting ANY possible PHI, even if it might be a false positive. This includes ALL names, dates, locations, and any numeric identifiers.",
            "moderate": "You should detect clear instances of PHI including names, specific dates, contact information, and identifiers. Use reasonable judgment to focus on actual PHI rather than common terms.",
            "relaxed": "You should detect only the most obvious PHI such as full names, complete dates, contact information, and explicit identifiers. Ignore partial information or common terms that are unlikely to identify an individual.",
        }

        sensitivity = sensitivity_descriptions.get(level, sensitivity_descriptions["moderate"])

        return f"""You are a HIPAA compliance expert specialized in detecting Protected Health Information (PHI) in medical texts. Your task is to identify ALL instances of PHI in the provided text and return them in a structured JSON format.

PHI Categories to Detect:
1. Names (patient names, relative names, provider names)
2. Dates (birth dates, appointment dates, any date related to an individual)
3. Phone numbers and fax numbers
4. Email addresses
5. Social Security Numbers and other identifiers
6. Addresses (street addresses, cities when connected to individuals)
7. Ages over 89 years
8. Any other unique identifying information

Sensitivity Level: {sensitivity}

Please return your results as a JSON object with the following structure:
{{
  "phi_detected": [
    {{
      "type": "name|date|phone_number|email|address|id|age|other",
      "value": "the actual PHI text",
      "start": starting character position in text (0-based),
      "end": ending character position in text (0-based)
    }}
  ]
}}

If no PHI is detected, return an empty array for "phi_detected".
Do not include any explanations or notes outside of the JSON structure."""

    def redact_phi(
        self,
        text: str,
        replacement: str = "[REDACTED]",
        detection_level: str | None = None,
    ) -> dict[str, Any]:
        """
        Redact PHI from text.

        Args:
            text: Text to redact
            replacement: Replacement text for redacted PHI
            detection_level: Detection level (strict, moderate, relaxed)

        Returns:
            Dict containing redacted text and metadata

        Raises:
            ServiceUnavailableError: If service is not initialized
            InvalidRequestError: If text is empty or invalid
        """
        if not self._initialized:
            raise ServiceUnavailableError("OpenAI PHI detection service is not initialized")

        if not text or not isinstance(text, str):
            raise InvalidRequestError("Text must be a non-empty string")

        # If OpenAI is not available, use fallback service
        if not self._openai_available:
            return self._fallback_service.redact_phi(text, replacement, detection_level)

        try:
            # Detect PHI
            detection_result = self.detect_phi(text, detection_level)

            # Redact PHI
            redacted_text = text
            offset = 0

            for phi in detection_result["phi_detected"]:
                start = phi["start"] + offset
                end = phi["end"] + offset

                # Replace PHI with replacement text
                redacted_text = redacted_text[:start] + replacement + redacted_text[end:]

                # Update offset (replacement text length might differ from original)
                offset += len(replacement) - (end - start)

            # Create response
            response = {
                "original_length": len(text),
                "redacted_length": len(redacted_text),
                "redacted_text": redacted_text,
                "detection_level": detection_result["detection_level"],
                "phi_count": detection_result["phi_count"],
                "has_phi": detection_result["has_phi"],
                "timestamp": now_utc().isoformat() + "Z",
            }

            return response

        except Exception as e:
            logger.error(f"Failed to redact PHI with OpenAI: {e!s}")
            logger.info("Falling back to rule-based PHI redaction")
            return self._fallback_service.redact_phi(text, replacement, detection_level)
