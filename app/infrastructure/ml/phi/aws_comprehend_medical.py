"""
PHI Detection Service Implementation.

This module provides a real implementation of PHI detection services using AWS Comprehend Medical
to detect and redact Protected Health Information (PHI) in compliance with HIPAA regulations.

This implementation follows the clean architecture pattern with dependency injection,
using abstracted AWS service interfaces instead of direct boto3 calls.
"""

from datetime import datetime
from typing import Any, List, Dict

from botocore.exceptions import BotoCoreError, ClientError

from app.core.exceptions import (
    InvalidConfigurationError,
    InvalidRequestError,
    ServiceUnavailableError,
)
from app.core.interfaces.aws_service_interface import (
    AWSServiceFactory,
    ComprehendMedicalServiceInterface,
)
from app.core.services.ml.interface import PHIDetectionInterface
from app.core.utils.logging import get_logger
from app.domain.utils.datetime_utils import UTC
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
    
    def __init__(self, aws_service_factory: AWSServiceFactory | None = None) -> None:
        """
        Initialize PHI detection service.
        
        Args:
            aws_service_factory: Factory for AWS services (optional, default: None)
                                If None, the default service factory will be used
        """
        self._initialized = False
        self._config = None
        self._aws_service_factory = aws_service_factory or get_aws_service_factory()
        self._comprehend_medical_service: ComprehendMedicalServiceInterface | None = None
        
        # Audit logging for HIPAA compliance
        self._last_operation_timestamp: str | None = None
        self._audit_log_enabled = True
    
    def initialize(self, config: dict[str, Any]) -> None:
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
            self._audit_log_enabled = self._config.get("enable_audit_logging", True)
            
            # Get Comprehend Medical service from factory
            try:
                self._comprehend_medical_service = self._aws_service_factory.get_comprehend_medical_service()
                
                # Record initialization time for audit logs
                self._last_operation_timestamp = datetime.now(UTC).isoformat()
                self._initialized = True
                
                logger.info("PHI detection service initialized successfully")
                
            except Exception as factory_error:
                logger.error(f"Failed to get Comprehend Medical service from factory: {factory_error!s}")
                raise InvalidConfigurationError(
                    f"Failed to get Comprehend Medical service: {factory_error!s}"
                )
                
        except Exception as e:
            logger.error(f"Failed to initialize PHI detection service: {e!s}")
            self._initialized = False
            self._config = None
            self._comprehend_medical_service = None
            raise InvalidConfigurationError(f"Failed to initialize PHI detection service: {e!s}")
    
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
            
    def _record_audit_log(self, operation: str, details: dict[str, Any]) -> None:
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
    
    def detect_phi(self, text: str) -> list[dict[str, Any]]:
        """
        Detect PHI in text.
        
        Args:
            text: Text to check for PHI
            
        Returns:
            List of dictionaries containing PHI entity information
            
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
            
            # Format entities as required by the interface
            entities_list = []
            
            for entity in phi_entities:
                entities_list.append({
                    "text": entity.get("Text", ""),
                    "type": entity.get("Type", "UNKNOWN"),
                    "score": entity.get("Score", 0.0),
                    "begin_offset": entity.get("BeginOffset", 0),
                    "end_offset": entity.get("EndOffset", 0),
                    "id": f"phi-{len(entities_list)}"
                })
            
            # Create audit log (without PHI content)
            audit_details = {
                "operation": "detect_phi",
                "has_phi": len(entities_list) > 0,
                "phi_count": len(entities_list),
                "phi_types": list(set(entity["type"] for entity in entities_list)) if entities_list else [],
                "text_length": len(text),
                "timestamp": datetime.now(UTC).isoformat()
            }
            self._record_audit_log("detect_phi", audit_details)
                
            return entities_list
            
        except (BotoCoreError, ClientError) as e:
            logger.error(f"Error detecting PHI: {e!s}")
            raise ServiceUnavailableError(f"Error detecting PHI: {e!s}")
        except Exception as e:
            logger.error(f"Unexpected error during PHI detection: {e!s}")
            raise ServiceUnavailableError(f"Unexpected error during PHI detection: {e!s}")
    
    def redact_phi(self, text: str, replacement: str = "[PHI]") -> str:
        """
        Redact PHI in text.
        
        Args:
            text: Text to redact PHI from
            replacement: String to replace PHI with (default: "[PHI]")
            
        Returns:
            Text with PHI redacted
            
        Raises:
            ServiceUnavailableError: If service is not initialized
            InvalidRequestError: If text is empty or invalid
        """
        self._check_service_initialized()
        self._validate_text(text)
        
        try:
            # First detect PHI using our interface method
            entities = self.detect_phi(text)
            
            # If no PHI detected, return original text
            if not entities:
                # Record audit log for no-op
                audit_details = {
                    "operation": "redact_phi",
                    "has_phi": False,
                    "redaction_count": 0,
                    "text_length": len(text),
                    "timestamp": datetime.now(UTC).isoformat()
                }
                self._record_audit_log("redact_phi", audit_details)
                return text
            
            # Sort entities by position from end to beginning to avoid offset issues
            sorted_entities = sorted(entities, key=lambda x: x["begin_offset"], reverse=True)
            
            # Apply redactions
            redacted_text = text
            redaction_types = set()
            
            for entity in sorted_entities:
                entity_type = entity.get("type", "UNKNOWN")
                # Create customized replacement with entity type for more informative redaction
                typed_replacement = f"[REDACTED-{entity_type}]"
                
                # Get the offset positions
                begin = entity.get("begin_offset", 0)
                end = entity.get("end_offset", 0)
                
                # Apply the redaction
                if 0 <= begin < end <= len(redacted_text):
                    redacted_text = redacted_text[:begin] + typed_replacement + redacted_text[end:]
                    redaction_types.add(entity_type)
            
            # Create audit log (without PHI content)
            audit_details = {
                "operation": "redact_phi",
                "has_phi": True,
                "redaction_count": len(sorted_entities),
                "redaction_types": list(redaction_types),
                "text_length": len(text),
                "timestamp": datetime.now(UTC).isoformat()
            }
            self._record_audit_log("redact_phi", audit_details)
            
            return redacted_text
            
        except (BotoCoreError, ClientError) as e:
            logger.error(f"Error redacting PHI: {e!s}")
            raise ServiceUnavailableError(f"Error redacting PHI: {e!s}")
        except InvalidRequestError:
            # Pass through validation errors
            raise
        except ServiceUnavailableError:
            # Pass through service errors
            raise
        except Exception as e:
            logger.error(f"Unexpected error during PHI redaction: {e!s}")
            raise ServiceUnavailableError(f"Unexpected error during PHI redaction: {e!s}")
    
    def contains_phi(self, text: str) -> bool:
        """
        Check if text contains PHI.
        
        Args:
            text: Text to check
            
        Returns:
            True if PHI is detected, False otherwise
            
        Raises:
            ServiceUnavailableError: If service is not initialized
            InvalidRequestError: If text is empty or invalid
        """
        # Empty strings have no PHI
        if not text or not isinstance(text, str):
            return False
            
        self._check_service_initialized()
        
        try:
            # Use our detect_phi method and check if any entities were returned
            entities = self.detect_phi(text)
            return len(entities) > 0
        except InvalidRequestError:
            # Invalid text has no PHI
            return False
        except Exception as e:
            logger.error(f"Error checking for PHI: {e!s}")
            raise ServiceUnavailableError(f"Error checking for PHI: {e!s}")