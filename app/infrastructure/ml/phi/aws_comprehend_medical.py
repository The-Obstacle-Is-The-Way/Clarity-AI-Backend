# -*- coding: utf-8 -*-
"""
PHI Detection Service Implementation.

This module provides a real implementation of PHI detection services using AWS Comprehend Medical
to detect and redact Protected Health Information (PHI) in compliance with HIPAA regulations.

This implementation follows the clean architecture pattern with dependency injection,
using abstracted AWS service interfaces instead of direct boto3 calls.
"""

import re
from typing import Any, Dict, List, Optional
from datetime import datetime
from app.domain.utils.datetime_utils import UTC

from botocore.exceptions import BotoCoreError, ClientError

from app.core.exceptions import (
    InvalidConfigurationError,
    InvalidRequestError,
    ServiceUnavailableError,
)
from app.core.interfaces.aws_service_interface import (
    ComprehendMedicalServiceInterface,
    AWSServiceFactory
)
from app.core.services.ml.interface import PHIDetectionInterface
from app.core.utils.logging import get_logger
from app.infrastructure.aws.service_factory_provider import get_aws_service_factory


# Create logger (no PHI logging)
logger = get_logger(__name__)


class AWSComprehendMedicalPHIDetection(PHIDetectionInterface):
    """
    AWS Comprehend Medical PHI Detection Service.
    
    This class provides a real implementation of PHI detection services using
    AWS Comprehend Medical to detect and redact Protected Health Information (PHI)
    in compliance with HIPAA regulations.
    
    This implementation uses dependency injection with the AWS service factory
    to get the Comprehend Medical service, allowing for better testability.
    """
    
    def __init__(self, aws_service_factory: Optional[AWSServiceFactory] = None) -> None:
        """
        Initialize PHI detection service.
        
        Args:
            aws_service_factory: Factory for AWS services (optional, default: None)
                                If None, the default service factory will be used
        """
        self._initialized = False
        self._config = None
        self._aws_service_factory = aws_service_factory or get_aws_service_factory()
        self._comprehend_medical_service: Optional[ComprehendMedicalServiceInterface] = None
        
        # Audit logging for HIPAA compliance
        self._last_operation_timestamp: Optional[str] = None
        self._audit_log_enabled = True
    
    def initialize(self, config: Dict[str, Any]) -> None:
        """
        Initialize the service with configuration.
        
        Args:
            config: Configuration dictionary containing AWS settings
            
        Raises:
            InvalidConfigurationError: If configuration is invalid
        """
        try:
            self._config = config or {}
            
            # Extract configuration values
            aws_region = self._config.get("aws_region")
            self._audit_log_enabled = self._config.get("enable_audit_logging", True)
            
            # Get Comprehend Medical service from factory
            try:
                self._comprehend_medical_service = self._aws_service_factory.get_comprehend_medical_service()
                
                # Record initialization time for audit logs
                self._last_operation_timestamp = datetime.now(UTC).isoformat()
                self._initialized = True
                
                logger.info("PHI detection service initialized successfully")
                
            except Exception as factory_error:
                logger.error(f"Failed to get Comprehend Medical service from factory: {str(factory_error)}")
                raise InvalidConfigurationError(
                    f"Failed to get Comprehend Medical service: {str(factory_error)}"
                )
                
        except Exception as e:
            logger.error(f"Failed to initialize PHI detection service: {str(e)}")
            self._initialized = False
            self._config = None
            self._comprehend_medical_service = None
            raise InvalidConfigurationError(f"Failed to initialize PHI detection service: {str(e)}")
    
    def is_healthy(self) -> bool:
        """
        Check if the service is healthy.
        
        Returns:
            True if healthy, False otherwise
        """
        return self._initialized and self._comprehend_medical_service is not None
    
    def shutdown(self) -> None:
        """Shutdown the service and release resources."""
        self._initialized = False
        self._config = None
        self._comprehend_medical_service = None
        self._last_operation_timestamp = datetime.now(UTC).isoformat()
        logger.info("PHI detection service shut down")
    
    def _check_service_initialized(self) -> None:
        """
        Check if the service is initialized.
        
        Raises:
            ServiceUnavailableError: If service is not initialized
        """
        if not self._initialized or not self._comprehend_medical_service:
            raise ServiceUnavailableError("PHI detection service is not initialized")
    
    def _validate_text(self, text: str) -> None:
        """
        Validate text input.
        
        Args:
            text: Text to validate
            
        Raises:
            InvalidRequestError: If text is empty or invalid
        """
        if not text or not isinstance(text, str):
            raise InvalidRequestError("Text must be a non-empty string")
            
    def _record_audit_log(self, operation: str, details: Dict[str, Any]) -> None:
        """
        Record audit log for HIPAA compliance.
        
        Args:
            operation: Operation performed (e.g., 'detect_phi', 'redact_phi')
            details: Details about the operation (excluding PHI content)
        """
        if not self._audit_log_enabled:
            return
            
        self._last_operation_timestamp = datetime.now(UTC).isoformat()
        
        # In a real implementation, this would write to a compliant audit log
        # For now, we just log to the application logger without any PHI
        logger.info(
            f"AUDIT: {operation} performed at {self._last_operation_timestamp} "
            f"with metadata: {details}"
        )
    
    def detect_phi(self, text: str) -> Dict[str, Any]:
        """
        Detect PHI in text.
        
        Args:
            text: Text to check for PHI
            
        Returns:
            Dictionary containing PHI detection results
            
        Raises:
            ServiceUnavailableError: If service is not initialized
            InvalidRequestError: If text is empty or invalid
        """
        self._check_service_initialized()
        self._validate_text(text)
        
        try:
            # Call AWS Comprehend Medical service via the interface
            response = self._comprehend_medical_service.detect_phi(text=text)
            
            # Extract PHI entities
            phi_entities = response.get("Entities", [])
            
            # Check if any PHI was detected
            has_phi = len(phi_entities) > 0
            
            # Format results
            result = {
                "has_phi": has_phi,
                "phi_entities": phi_entities,
                "phi_count": len(phi_entities),
                "phi_types": list(set(entity["Type"] for entity in phi_entities)) if has_phi else [],
                "model_version": response.get("ModelVersion", "Unknown"),
                "timestamp": datetime.now(UTC).isoformat()
            }
            
            # Create audit log (without PHI content)
            audit_details = {
                "operation": "detect_phi",
                "has_phi": has_phi,
                "phi_count": len(phi_entities),
                "phi_types": result["phi_types"],
                "text_length": len(text),
                "timestamp": result["timestamp"]
            }
            self._record_audit_log("detect_phi", audit_details)
                
            return result
            
        except (BotoCoreError, ClientError) as e:
            logger.error(f"Error detecting PHI: {str(e)}")
            raise ServiceUnavailableError(f"Error detecting PHI: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error during PHI detection: {str(e)}")
            raise ServiceUnavailableError(f"Unexpected error during PHI detection: {str(e)}")
    
    def redact_phi(self, text: str) -> Dict[str, Any]:
        """
        Redact PHI in text.
        
        Args:
            text: Text to redact PHI from
            
        Returns:
            Dictionary containing redacted text and redaction statistics
            
        Raises:
            ServiceUnavailableError: If service is not initialized
            InvalidRequestError: If text is empty or invalid
        """
        self._check_service_initialized()
        self._validate_text(text)
        
        try:
            # First detect PHI using our AWS service abstraction
            detection_result = self.detect_phi(text)
            phi_entities = detection_result.get("phi_entities", [])
            
            # If no PHI detected, return original text
            if not phi_entities:
                result = {
                    "redacted_text": text,
                    "original_text_length": len(text),
                    "redacted_text_length": len(text),
                    "redaction_count": 0,
                    "redaction_types": [],
                    "timestamp": datetime.now(UTC).isoformat()
                }
                
                # Record audit log for HIPAA compliance
                audit_details = {
                    "operation": "redact_phi",
                    "redaction_count": 0,
                    "text_length": len(text),
                    "timestamp": result["timestamp"]
                }
                self._record_audit_log("redact_phi", audit_details)
                
                return result
            
            # Sort entities by begin_offset in descending order to avoid indexing issues
            # when replacing text
            phi_entities.sort(key=lambda x: x["BeginOffset"], reverse=True)
            
            # Redact PHI entities
            redacted_text = text
            redaction_types = set()
            
            for entity in phi_entities:
                begin_offset = entity["BeginOffset"]
                end_offset = entity["EndOffset"]
                entity_type = entity["Type"]
                redaction_types.add(entity_type)
                
                # Replace entity with redaction marker
                redaction_marker = f"[REDACTED-{entity_type}]"
                redacted_text = (
                    redacted_text[:begin_offset] + 
                    redaction_marker + 
                    redacted_text[end_offset:]
                )
            
            # Prepare result
            timestamp = datetime.now(UTC).isoformat()
            result = {
                "redacted_text": redacted_text,
                "original_text_length": len(text),
                "redacted_text_length": len(redacted_text),
                "redaction_count": len(phi_entities),
                "redaction_types": list(redaction_types),
                "timestamp": timestamp,
                "model_version": detection_result.get("model_version", "Unknown")
            }
            
            # Record audit log for HIPAA compliance (without PHI content)
            audit_details = {
                "operation": "redact_phi",
                "redaction_count": len(phi_entities),
                "redaction_types": list(redaction_types),
                "text_length": len(text),
                "timestamp": result["timestamp"]
            }
            self._record_audit_log("redact_phi", audit_details)
            
            return result
            
        except ServiceUnavailableError:
            # Pass through service errors
            raise
        except Exception as e:
            logger.error(f"Unexpected error during PHI redaction: {str(e)}")
            raise ServiceUnavailableError(f"Unexpected error during PHI redaction: {str(e)}")