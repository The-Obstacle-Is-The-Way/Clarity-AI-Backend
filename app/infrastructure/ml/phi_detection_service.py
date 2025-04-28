# -*- coding: utf-8 -*-
"""
PHI Detection Service Module.

This module provides a HIPAA-compliant service for detecting and redacting
Protected Health Information (PHI) from text.
"""

import os
import re
import yaml
import logging
import asyncio
import concurrent.futures
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Set, Pattern, Match, Union, cast

from sqlalchemy.orm import Session
from app.infrastructure.persistence.sqlalchemy.models import Patient, User
from app.presentation.api.schemas.ml_schemas import (
    PHIContextEnum, PHIRequest, PHIDetectionRequest, TextProcessingRequest
)
from app.config.settings import get_settings
from app.core.exceptions.ml_exceptions import (
    PHIDetectionException,
    PHIConfigurationError,
    PHIPatternError
)
from app.core.utils.logging import get_logger
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from app.core.services.ml.interface import PHIDetectionInterface


# Setup logger
logger = get_logger(__name__)


class PHIPattern:
    """Class representing a PHI detection pattern."""
    
    def __init__(
        self,
        name: str,
        category: str,
        regex: str,
        confidence: float,
        replacement_format: str,
        case_insensitive: bool = False,
        multi_line: bool = False,
        dot_all: bool = False
    ):
        """
        Initialize a PHI pattern.
        
        Args:
            name: Pattern name
            category: PHI category
            regex: Regular expression pattern
            confidence: Confidence score (0.0-1.0)
            replacement_format: Format for replacement text
            case_insensitive: Whether to ignore case
            multi_line: Whether to use multi-line mode
            dot_all: Whether to use dot-all mode
        """
        self.name = name
        self.category = category
        self.regex_str = regex
        self.confidence = confidence
        self.replacement_format = replacement_format
        self.case_insensitive = case_insensitive
        self.multi_line = multi_line
        self.dot_all = dot_all
        self.compiled_regex: Optional[Pattern] = None
        
        self._compile_regex()
    
    def _compile_regex(self) -> None:
        """
        Compile the regex pattern.
        
        Raises:
            PHIPatternError: If regex compilation fails
        """
        try:
            flags = 0
            if self.case_insensitive:
                flags |= re.IGNORECASE
            if self.multi_line:
                flags |= re.MULTILINE
            if self.dot_all:
                flags |= re.DOTALL
            
            self.compiled_regex = re.compile(self.regex_str, flags)
        except re.error as e:
            error_msg = f"Failed to compile regex pattern '{self.name}': {str(e)}"
            logger.error(error_msg)
            raise PHIPatternError(
                message=error_msg,
                details={
                    "pattern_name": self.name,
                    "category": self.category,
                    "regex": self.regex_str,
                    "error": str(e)
                }
            )
    
    def create_replacement(self, match_text: str) -> str:
        """
        Create replacement text for the matched PHI.
        
        Args:
            match_text: The matched text
            
        Returns:
            Replacement text
        """
        # Use category in replacement format (e.g., [NAME], [DATE], etc.)
        return self.replacement_format.format(category=self.category.upper())
    
    def __repr__(self) -> str:
        """Return string representation of the pattern."""
        return f"PHIPattern(name='{self.name}', category='{self.category}', confidence={self.confidence})"


class PHIDetectionService:
    """Service for detecting and redacting PHI from text."""
    
    def __init__(self):
        """
        Initialize PHI detection service using global settings.
        """
        self.settings = get_settings().ml.phi_detection # Get nested settings
        self.patterns: Dict[str, List[PHIPattern]] = {}
        self.categories: List[str] = []
        
        # Load patterns
        self._load_patterns()
        
        logger.info(
            "Initialized PHI detection service",
            extra={"patterns_count": sum(len(p) for p in self.patterns.values())}
        )
    
    def _load_patterns(self) -> None:
        """
        Load PHI detection patterns from YAML file.
        
        Raises:
            PHIConfigurationError: If pattern loading fails
        """
        try:
            patterns_file = self.settings.patterns_file
            
            with open(patterns_file, "r", encoding="utf-8") as file:
                pattern_data = yaml.safe_load(file)
            
            # Process each category
            for category, data in pattern_data.items():
                if category not in self.patterns:
                    self.patterns[category] = []
                    self.categories.append(category)
                
                # Get replacement format for category
                replacement_format = data.get(
                    "replacement_format",
                    self.settings.default_redaction_format
                )
                
                # Process patterns for this category
                for pattern_name, pattern_info in data.get("patterns", {}).items():
                    self.patterns[category].append(
                        PHIPattern(
                            name=pattern_name,
                            category=category,
                            regex=pattern_info["regex"],
                            confidence=pattern_info["confidence"],
                            replacement_format=replacement_format,
                            case_insensitive=pattern_info.get("case_insensitive", False),
                            multi_line=pattern_info.get("multi_line", False),
                            dot_all=pattern_info.get("dot_all", False)
                        )
                    )
            
            logger.info(
                f"Loaded PHI patterns from {patterns_file}",
                extra={"categories": len(self.categories)}
            )
        except (FileNotFoundError, yaml.YAMLError, KeyError) as e:
            error_msg = f"Failed to load PHI patterns from {self.settings.patterns_file}: {str(e)}"
            logger.error(error_msg)
            raise PHIConfigurationError(
                message=error_msg,
                details={"patterns_file": str(self.settings.patterns_file)}
            )
    
    async def detect_phi(self, request: PHIDetectionRequest) -> PHIDetectionResult:
        """
        Detect PHI in text.
        
        Args:
            request: PHI detection request
            
        Returns:
            PHI detection result
            
        Raises:
            PHIDetectionException: If PHI detection fails
        """
        try:
            # Get filtered categories if specified
            categories_to_check = request.categories or self.categories
            
            # Set confidence threshold
            confidence_threshold = request.confidence_threshold
            
            # Detect PHI
            if self.settings.parallel_processing:
                all_matches = await self._detect_phi_parallel(
                    text=request.text,
                    categories=categories_to_check,
                    confidence_threshold=confidence_threshold
                )
            else:
                all_matches = await self._detect_phi_sequential(
                    text=request.text,
                    categories=categories_to_check,
                    confidence_threshold=confidence_threshold
                )
            
            # Sort matches by position
            all_matches.sort(key=lambda m: (m.start, -m.end))
            
            # Create result with redaction if requested
            result = PHIDetectionResult(
                detected_phi=len(all_matches) > 0,
                confidence=max([match.confidence for match in all_matches], default=0.0),
                detections=all_matches if all_matches else None
            )
            
            # Redact text if requested
            if request.redact and all_matches:
                result.redacted_text = self._redact_text(request.text, all_matches)
            
            return result
        except Exception as e:
            logger.error(f"Error detecting PHI: {str(e)}")
            raise PHIDetectionException(
                message=f"Error detecting PHI: {str(e)}",
                details={"text_length": len(request.text)}
            )
    
    async def _detect_phi_sequential(
        self,
        text: str,
        categories: List[str],
        confidence_threshold: float
    ) -> List[PHIDetectionMatch]:
        """
        Detect PHI sequentially.
        
        Args:
            text: Text to analyze
            categories: Categories to check
            confidence_threshold: Minimum confidence threshold
            
        Returns:
            List of PHI detection matches
        """
        all_matches: List[PHIDetectionMatch] = []
        
        # Check each category
        for category in categories:
            if category not in self.patterns:
                continue
            
            # Check each pattern in the category
            for pattern in self.patterns[category]:
                if pattern.confidence < confidence_threshold:
                    continue
                
                if not pattern.compiled_regex:
                    continue
                
                # Find matches
                for match in pattern.compiled_regex.finditer(text):
                    match_text = match.group(0)
                    
                    # Create match object
                    phi_match = PHIDetectionMatch(
                        match=match_text,
                        start=match.start(),
                        end=match.end(),
                        category=pattern.category,
                        confidence=pattern.confidence,
                        replacement=pattern.create_replacement(match_text)
                    )
                    
                    all_matches.append(phi_match)
        
        return all_matches
    
    async def _detect_phi_parallel(
        self,
        text: str,
        categories: List[str],
        confidence_threshold: float
    ) -> List[PHIDetectionMatch]:
        """
        Detect PHI in parallel.
        
        Args:
            text: Text to analyze
            categories: Categories to check
            confidence_threshold: Minimum confidence threshold
            
        Returns:
            List of PHI detection matches
        """
        all_matches: List[PHIDetectionMatch] = []
        tasks = []
        
        # Create tasks for each category
        for category in categories:
            if category not in self.patterns:
                continue
            
            # Create a task for this category
            task = asyncio.create_task(
                self._detect_phi_category(
                    text=text,
                    category=category,
                    confidence_threshold=confidence_threshold
                )
            )
            tasks.append(task)
        
        # Wait for all tasks to complete
        if tasks:
            category_results = await asyncio.gather(*tasks)
            
            # Combine results
            for matches in category_results:
                all_matches.extend(matches)
        
        return all_matches
    
    async def _detect_phi_category(
        self,
        text: str,
        category: str,
        confidence_threshold: float
    ) -> List[PHIDetectionMatch]:
        """
        Detect PHI for a specific category.
        
        Args:
            text: Text to analyze
            category: Category to check
            confidence_threshold: Minimum confidence threshold
            
        Returns:
            List of PHI detection matches
        """
        matches: List[PHIDetectionMatch] = []
        
        # Run in a thread to avoid blocking
        with concurrent.futures.ThreadPoolExecutor() as executor:
            loop = asyncio.get_running_loop()
            matches = await loop.run_in_executor(
                executor,
                self._detect_phi_category_sync,
                text,
                category,
                confidence_threshold
            )
        
        return matches
    
    def _detect_phi_category_sync(
        self,
        text: str,
        category: str,
        confidence_threshold: float
    ) -> List[PHIDetectionMatch]:
        """
        Detect PHI for a specific category (synchronous version).
        
        Args:
            text: Text to analyze
            category: Category to check
            confidence_threshold: Minimum confidence threshold
            
        Returns:
            List of PHI detection matches
        """
        matches: List[PHIDetectionMatch] = []
        
        # Check each pattern in the category
        for pattern in self.patterns[category]:
            if pattern.confidence < confidence_threshold:
                continue
            
            if not pattern.compiled_regex:
                continue
            
            # Find matches
            for match in pattern.compiled_regex.finditer(text):
                match_text = match.group(0)
                
                # Create match object
                phi_match = PHIDetectionMatch(
                    match=match_text,
                    start=match.start(),
                    end=match.end(),
                    category=pattern.category,
                    confidence=pattern.confidence,
                    replacement=pattern.create_replacement(match_text)
                )
                
                matches.append(phi_match)
        
        return matches
    
    def _redact_text(self, text: str, matches: List[PHIDetectionMatch]) -> str:
        """
        Redact PHI from text.
        
        Args:
            text: Original text
            matches: PHI matches to redact
            
        Returns:
            Redacted text
        """
        # If no matches, return original text
        if not matches:
            return text
        
        # Sort matches by position (from end to start to avoid index issues)
        sorted_matches = sorted(matches, key=lambda m: (m.start, -m.end), reverse=True)
        
        # Create a mutable list of characters
        chars = list(text)
        
        # Replace each match
        for match in sorted_matches:
            # Replace characters with the redaction text
            chars[match.start:match.end] = list(match.replacement)
        
        # Join back into a string
        return ''.join(chars)
    
    def validate_patterns(self) -> Dict[str, Any]:
        """
        Validate all patterns and return metrics.
        
        Returns:
            Validation metrics
        """
        total_patterns = 0
        invalid_patterns = 0
        metrics = {
            "categories": len(self.categories),
            "total_patterns": 0,
            "valid_patterns": 0,
            "invalid_patterns": 0,
            "category_counts": {}
        }
        
        # Check each category
        for category, patterns in self.patterns.items():
            metrics["category_counts"][category] = len(patterns)
            metrics["total_patterns"] += len(patterns)
            
            # Check each pattern
            for pattern in patterns:
                try:
                    if not pattern.compiled_regex:
                        pattern._compile_regex()
                    metrics["valid_patterns"] += 1
                except PHIPatternError:
                    metrics["invalid_patterns"] += 1
        
        return metrics