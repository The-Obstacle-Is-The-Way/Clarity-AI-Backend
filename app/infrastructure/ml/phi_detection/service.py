# Minimal content for app/infrastructure/ml/phi_detection/service.py
"""
PHI Detection Service (Consolidated).

This module provides a service for detecting Protected Health Information (PHI).
"""

# Standard Library Imports
import re
from collections.abc import Generator
from dataclasses import dataclass
from pathlib import Path
from re import Pattern

# Third-Party Imports
import yaml

# Core Imports
from app.core.domain.entities.phi.phi_match import PHIMatch
from app.core.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class PHIPattern:
    """PHI pattern configuration."""
    name: str
    pattern: str
    description: str
    category: str
    regex: Pattern | None = None

    def __post_init__(self):
        """Compile the regex pattern after initialization."""
        try:
            if self.pattern:
                self.regex = re.compile(self.pattern, re.IGNORECASE)
        except re.error as e:
            logger.error(f"Invalid regex pattern for {self.name}: {e}")
            self.regex = re.compile(r"a^") # Fallback


class PHIDetectionService:
    """Service for detecting PHI in text."""

    def __init__(self, pattern_file: str | None = None):
        """Initialize the PHI detection service."""
        base_dir = Path(__file__).resolve().parent.parent.parent.parent.parent
        default_pattern_path = base_dir / "app/infrastructure/security/phi/phi_patterns.yaml"
        self.pattern_file: Path = Path(pattern_file) if pattern_file else default_pattern_path
        self.patterns: list[PHIPattern] = []
        self._initialized = False
        self._load_patterns() # Initialize on creation
        self._initialized = True

    def initialize(self) -> None:
         """Explicit initialization method."""
         if not self._initialized:
             self._load_patterns()
             self._initialized = True

    def ensure_initialized(self) -> None:
        """Ensure the service is initialized."""
        if not self._initialized:
            self._load_patterns()
            self._initialized = True

    def _load_patterns(self) -> None:
        """Load PHI detection patterns from file."""
        # logger.debug(f"Attempting to load PHI patterns from: {self.pattern_file.resolve()}")
        if not self.pattern_file.is_file():
            logger.error(f"PHI pattern file not found: {self.pattern_file}")
            raise FileNotFoundError(f"PHI pattern file not found: {self.pattern_file}")

        patterns_loaded: list[PHIPattern] = []
        try:
            with self.pattern_file.open("r", encoding="utf-8") as f:
                config = yaml.safe_load(f)

            if not isinstance(config, dict):
                 raise ValueError(f"Invalid format in PHI pattern file: {self.pattern_file}")

            for category, patterns_in_category in config.items():
                 if not isinstance(patterns_in_category, list): continue
                 for pattern_info in patterns_in_category:
                     if (not isinstance(pattern_info, dict) or
                         'name' not in pattern_info or
                         'pattern' not in pattern_info): continue
                     patterns_loaded.append(
                         PHIPattern(
                             name=pattern_info["name"],
                             pattern=pattern_info["pattern"],
                             description=pattern_info.get("description", ""),
                             category=category))
            logger.info(f"Loaded {len(patterns_loaded)} PHI patterns from {self.pattern_file}")
            self.patterns = patterns_loaded
        except (yaml.YAMLError, FileNotFoundError) as e:
            logger.error(f"Error loading PHI patterns from {self.pattern_file}: {e}")
            logger.warning("Falling back to default PHI patterns.")
            self.patterns = self._get_default_patterns()
        except Exception as e:
            logger.exception(f"Unexpected error loading PHI patterns: {e}")
            logger.warning("Falling back to default PHI patterns.")
            self.patterns = self._get_default_patterns()

    def _get_default_patterns(self) -> list[PHIPattern]:
        """Returns a basic set of default PHI patterns as a fallback."""
        logger.warning("Using placeholder default PHI patterns.")
        # Simplified for brevity
        return [
            PHIPattern(name="SSN", pattern=r"\d{3}[-\s]?\d{2}[-\s]?\d{4}", description="Social Security Number", category="government_id"),
            PHIPattern(name="Email Address", pattern=r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", description="Email address", category="contact"),
        ]

    def scan_text(self, text: str) -> Generator[PHIMatch, None, None]:
        """Scans the input text for PHI based on loaded patterns."""
        self.ensure_initialized()
        for pattern in self.patterns:
            if pattern.regex:
                for match in pattern.regex.finditer(text):
                    yield PHIMatch(
                        text=match.group(0),
                        pattern_name=pattern.name,
                        start=match.start(),
                        end=match.end(),
                    )
            else:
                 logger.warning(f"Pattern {getattr(pattern, 'name', 'Unnamed')} has no compiled regex.")

    # --- Other methods like detect_phi, redact_phi, anonymize_phi omitted for brevity ---
