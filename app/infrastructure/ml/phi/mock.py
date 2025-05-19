"""
Mock PHI Detection Implementation.

This module provides a mock implementation of PHI Detection for development and testing.
No actual PHI detection is performed; instead, predefined responses are returned.
"""

import random
import re
import time
from typing import Any

from app.core.exceptions import (
    InvalidConfigurationError,
    InvalidRequestError,
    ServiceUnavailableError,
)
from app.core.services.ml.interface import PHIDetectionInterface  # Corrected import
from app.core.utils.logging import get_logger

# Create logger (no PHI logging)
logger = get_logger(__name__)


class MockPHIDetection(PHIDetectionInterface):  # Corrected class name and inheritance
    """
    Mock implementation of PHI Detection service.

    This implementation simulates PHI detection without any actual analysis,
    returning predefined responses for development and testing.
    """

    def __init__(self) -> None:
        """Initialize MockPHIDetectionService instance."""
        self._initialized = False
        self._config = None
        self._patterns = self._get_default_patterns()

    def initialize(self, config: dict[str, Any]) -> None:
        """
        Initialize the service with configuration.

        Args:
            config: Configuration dictionary

        Raises:
            InvalidConfigurationError: If configuration is invalid
        """
        try:
            if config is None or not isinstance(config, dict):
                raise InvalidConfigurationError(
                    "Invalid configuration: must be a dictionary"
                )

            self._config = config
            self._detection_level = config.get("detection_level", "strict").lower()

            # Set up mockable detection patterns
            if self._detection_level == "strict":
                self._patterns = self._get_strict_patterns()
            elif self._detection_level == "moderate":
                self._patterns = self._get_moderate_patterns()
            elif self._detection_level == "relaxed":
                self._patterns = self._get_relaxed_patterns()
            else:
                self._patterns = self._get_default_patterns()

            self._initialized = True
            logger.info(
                f"Mock PHI detection service initialized with level: {self._detection_level}"
            )

        except Exception as e:
            logger.error(f"Failed to initialize mock PHI detection service: {e!s}")
            self._initialized = False
            self._config = None
            raise InvalidConfigurationError(
                f"Failed to initialize mock PHI detection service: {e!s}"
            )

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

    def detect_phi(
        self, text: str, detection_level: str | None = None, **kwargs
    ) -> dict[str, Any]:
        """
        Detect PHI in text.

        Args:
            text: Text to analyze
            detection_level: Optional detection level (strict, moderate, relaxed)
            **kwargs: Additional parameters

        Returns:
            Dict containing PHI detection results

        Raises:
            ServiceUnavailableError: If service is not initialized
        """
        if not self._initialized:
            raise ServiceUnavailableError("PHI detection service is not initialized")

        # Validate text input
        if not isinstance(text, str) or not text.strip():
            raise InvalidRequestError(
                "Invalid request: text must be a non-empty string"
            )

        # Validate detection level
        if detection_level is not None and detection_level.lower() not in [
            "minimal",
            "moderate",
            "aggressive",
        ]:
            raise InvalidRequestError(
                "Invalid detection level: must be one of minimal, moderate, aggressive"
            )

        logger.info("Performing mock PHI detection")

        # Simulate processing time
        start_time = time.time()
        processing_delay = random.uniform(0.1, 0.5)
        time.sleep(processing_delay)

        # Use provided detection level or fallback to configured level
        level = detection_level.lower() if detection_level else self._detection_level

        # Get patterns based on detection level
        patterns = self._get_patterns_for_level(level)

        # Detect PHI based on patterns
        phi_instances = self._detect_phi_with_patterns(text, patterns)

        # Calculate processing time
        elapsed = time.time() - start_time

        # Create result
        result = {
            "has_phi": len(phi_instances) > 0,
            "phi_count": len(phi_instances),
            "phi_instances": phi_instances,
            "detection_level": level,
            "processing_time": elapsed,
            "metadata": {
                "provider": "mock",
                "confidence": random.uniform(0.85, 0.98),
                "mock": True,
            },
        }

        return result

    def redact_phi(
        self,
        text: str,
        replacement: str = "[REDACTED]",
        redaction_marker: str | None = None,
        detection_level: str | None = None,
        **kwargs,
    ) -> dict[str, Any]:
        """
        Redact PHI from text.

        Args:
            text: Text to redact
            replacement: Replacement text for redacted PHI
            redaction_marker: Alternative name for replacement parameter (for compatibility)
            detection_level: Optional detection level (strict, moderate, relaxed)
            **kwargs: Additional parameters

        Returns:
            Dict containing redacted text and metadata

        Raises:
            ServiceUnavailableError: If service is not initialized
        """
        if not self._initialized:
            raise ServiceUnavailableError("PHI detection service is not initialized")

        # Validate input for redaction
        if not isinstance(text, str) or not text.strip():
            raise InvalidRequestError(
                "Invalid request: text must be a non-empty string"
            )
        if detection_level is not None and detection_level.lower() not in [
            "minimal",
            "moderate",
            "aggressive",
        ]:
            raise InvalidRequestError(
                "Invalid detection level: must be one of minimal, moderate, aggressive"
            )

        # Use redaction_marker if provided (for test compatibility)
        if redaction_marker is not None:
            replacement = redaction_marker

        logger.info("Performing mock PHI redaction")

        # Detect PHI first
        detection_result = self.detect_phi(text, detection_level)
        phi_instances = detection_result["phi_instances"]

        # Make a copy of the original text
        redacted_text = text

        # Sort entities by start position (descending) to avoid position shifts
        sorted_entities = sorted(phi_instances, key=lambda x: x["start"], reverse=True)

        # Redact each entity
        for entity in sorted_entities:
            start = entity["start"]
            end = entity["end"]
            phi_type = entity["type"].upper()  # Use uppercase type for redaction marker

            # Create type-specific redaction if requested in config
            type_specific = self._config.get("type_specific_redaction", False)
            marker = f"[{phi_type}]" if type_specific else replacement

            # Replace the entity with the redaction text
            redacted_text = redacted_text[:start] + marker + redacted_text[end:]

        # Create result
        result = {
            "original_text_length": len(text),
            "redacted_text_length": len(redacted_text),
            "redacted_text": redacted_text,
            "phi_count": len(phi_instances),
            "phi_instances": phi_instances,
            "detection_level": detection_result["detection_level"],
            "processing_time": detection_result["processing_time"],
            "metadata": detection_result["metadata"],
            "replacement_used": replacement,
        }

        return result

    def _detect_phi_with_patterns(
        self, text: str, patterns: dict[str, list[re.Pattern]]
    ) -> list[dict[str, Any]]:
        """
        Detect PHI using regex patterns.

        Args:
            text: Text to analyze
            patterns: Dictionary of PHI types to regex patterns

        Returns:
            List of detected PHI entities
        """
        # List to hold detected entities
        entities = []

        # Track entity IDs for uniqueness
        entity_id = 1

        # Check each pattern type
        for phi_type, pattern_list in patterns.items():
            for pattern in pattern_list:
                # Find all matches
                for match in pattern.finditer(text):
                    # Get the matched text and position
                    start_pos = match.start()
                    end_pos = match.end()
                    matched_text = match.group(0)

                    # Create entity
                    entity = {
                        "id": f"phi-{entity_id}",
                        "type": phi_type,
                        "text": matched_text,
                        "start": start_pos,
                        "end": end_pos,
                        "confidence": round(random.uniform(0.85, 0.99), 2),
                        "position": {"start": start_pos, "end": end_pos},
                    }

                    entities.append(entity)
                    entity_id += 1

        return entities

    def _get_patterns_for_level(self, level: str) -> dict[str, list[re.Pattern]]:
        """
        Get patterns based on detection level.

        Args:
            level: Detection level (strict, moderate, relaxed)

        Returns:
            Dictionary of PHI types to regex patterns
        """
        if level == "strict":
            return self._get_strict_patterns()
        elif level == "moderate":
            return self._get_moderate_patterns()
        elif level == "relaxed":
            return self._get_relaxed_patterns()
        else:
            return self._get_default_patterns()

    def _get_default_patterns(self) -> dict[str, list[re.Pattern]]:
        """
        Get default PHI detection patterns.

        Returns:
            Dictionary of PHI types to regex patterns
        """
        return self._get_moderate_patterns()

    def _get_strict_patterns(self) -> dict[str, list[re.Pattern]]:
        """
        Get strict PHI detection patterns.

        Returns:
            Dictionary of PHI types to regex patterns
        """
        return {
            "NAME": [
                re.compile(r"\b[A-Z][a-z]+ [A-Z][a-z]+\b"),  # Full name: John Doe
                re.compile(r"\bDr\.\s+[A-Z][a-z]+\b"),  # Doctor title: Dr. Smith
                re.compile(
                    r"\b[A-Z][a-z]+\s+[A-Z]\.\s+[A-Z][a-z]+\b"
                ),  # Middle initial: John A. Doe
            ],
            "DATE": [
                re.compile(r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b"),  # Date: 01/01/2020
                re.compile(
                    r"\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2},\s+\d{4}\b"
                ),  # Date: Jan 1, 2020
            ],
            "AGE": [
                re.compile(r"\b\d{1,3}\s+years?\s+old\b"),  # Age: 30 years old
                re.compile(r"\bage\s+\d{1,3}\b", re.IGNORECASE),  # Age: age 30
            ],
            "PHONE": [
                re.compile(r"\b\d{3}[.-]\d{3}[.-]\d{4}\b"),  # Phone: 123-456-7890
                re.compile(r"\b\(\d{3}\)\s*\d{3}[.-]\d{4}\b"),  # Phone: (123) 456-7890
            ],
            "EMAIL": [
                re.compile(
                    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
                )  # Email
            ],
            "SSN": [re.compile(r"\b\d{3}[.-]\d{2}[.-]\d{4}\b")],  # SSN: 123-45-6789
            "ADDRESS": [
                re.compile(
                    r"\b\d+\s+[A-Za-z]+ (Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl)\b",
                    re.IGNORECASE,
                )  # Street address
            ],
            "ZIP_CODE": [
                re.compile(r"\b\d{5}(?:-\d{4})?\b")  # ZIP code: 12345 or 12345-6789
            ],
            "CITY_STATE": [
                re.compile(r"\b[A-Za-z\s]+,\s+[A-Z]{2}\b")  # City, State: New York, NY
            ],
            "MEDICAL_RECORD": [
                re.compile(r"\bMR[N#]\s*\d+\b"),  # Medical record: MRN 123456
                re.compile(
                    r"\bPatient\s+ID\s*[:=]?\s*\d+\b", re.IGNORECASE
                ),  # Patient ID
            ],
            "HEALTH_PLAN": [
                re.compile(
                    r"\b[A-Za-z]+\s+Health\s+Plan\b", re.IGNORECASE
                ),  # Health plan
                re.compile(
                    r"\bInsurance\s+ID\s*[:=]?\s*[A-Z0-9]+\b", re.IGNORECASE
                ),  # Insurance ID
            ],
        }

    def _get_moderate_patterns(self) -> dict[str, list[re.Pattern]]:
        """
        Get moderate PHI detection patterns.

        Returns:
            Dictionary of PHI types to regex patterns
        """
        return {
            "NAME": [re.compile(r"\b[A-Z][a-z]+ [A-Z][a-z]+\b")],  # Full name: John Doe
            "DATE": [
                re.compile(r"\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b")  # Date: 01/01/2020
            ],
            "AGE": [re.compile(r"\b\d{1,3}\s+years?\s+old\b")],  # Age: 30 years old
            "PHONE": [
                re.compile(r"\b\d{3}[.-]\d{3}[.-]\d{4}\b")  # Phone: 123-456-7890
            ],
            "EMAIL": [
                re.compile(
                    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
                )  # Email
            ],
            "SSN": [re.compile(r"\b\d{3}[.-]\d{2}[.-]\d{4}\b")],  # SSN: 123-45-6789
            "ADDRESS": [
                re.compile(
                    r"\b\d+\s+[A-Za-z]+ (Street|St|Avenue|Ave|Road|Rd)\b", re.IGNORECASE
                )  # Street address
            ],
            "MEDICAL_RECORD": [
                re.compile(r"\bMRN\s*\d+\b")  # Medical record: MRN 123456
            ],
        }

    def _get_relaxed_patterns(self) -> dict[str, list[re.Pattern]]:
        """
        Get relaxed PHI detection patterns.

        Returns:
            Dictionary of PHI types to regex patterns
        """
        return {
            "NAME": [re.compile(r"\b[A-Z][a-z]+ [A-Z][a-z]+\b")],  # Full name: John Doe
            "SSN": [re.compile(r"\b\d{3}[.-]\d{2}[.-]\d{4}\b")],  # SSN: 123-45-6789
            "EMAIL": [
                re.compile(
                    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
                )  # Email
            ],
            "PHONE": [
                re.compile(r"\b\d{3}[.-]\d{3}[.-]\d{4}\b")  # Phone: 123-456-7890
            ],
        }

    def _create_mock_phi_instances(self, level: str) -> list[dict[str, Any]]:
        """
        Create mock PHI instances for testing.
        """
        lvl = level.lower()
        if lvl == "minimal":
            patterns = self._get_relaxed_patterns()
        elif lvl == "moderate":
            patterns = self._get_moderate_patterns()
        elif lvl == "aggressive":
            patterns = self._get_strict_patterns()
        else:
            raise InvalidRequestError(
                "Invalid detection level: must be one of minimal, moderate, aggressive"
            )
        instances: list[dict[str, Any]] = []
        for phi_type, pattern_list in patterns.items():
            for _ in pattern_list:
                instances.append(
                    {
                        "type": phi_type,
                        "text": phi_type,
                        "position": 0,
                        "confidence": 1.0,
                    }
                )
        return instances
