"""
HIPAA-compliant PHI protection components.

This package provides a comprehensive set of tools for detecting, sanitizing,
and protecting Protected Health Information (PHI) in accordance with HIPAA regulations.
"""

from .patterns import PHI_PATTERNS
from .phi_service import PHIService, PHIType
from .log_sanitizer import LogSanitizer, PHIFormatter, PHIRedactionHandler, SanitizingFilter, get_sanitized_logger
from .sanitized_logger import SanitizedLogger, get_sanitized_logger as get_sanitized_logger_alt
from .api_sanitizer import PHISanitizerMiddleware, RequestBodySanitizerMiddleware, add_phi_sanitizer_middleware
from .code_analyzer import PHICodeAnalyzer, CodeSeverity
from .phi_detection import PHIDetectionService, get_phi_detection_service
from .middleware import PHIMiddleware, add_phi_middleware, get_phi_middleware
from .phi_auditor import PHIAuditHandler, log_phi_access, get_phi_audit_handler

__all__ = [
    # PHI patterns
    'PHI_PATTERNS',
    
    # PHI service and types
    'PHIService',
    'PHIType',
    
    # Log sanitization
    'LogSanitizer',
    'PHIFormatter',
    'PHIRedactionHandler',
    'SanitizingFilter',
    'get_sanitized_logger',
    
    # Sanitized logger
    'SanitizedLogger',
    'get_sanitized_logger_alt',
    
    # API sanitization
    'PHISanitizerMiddleware',
    'RequestBodySanitizerMiddleware',
    'add_phi_sanitizer_middleware',
    
    # Code analysis
    'PHICodeAnalyzer',
    'CodeSeverity',
    
    # PHI detection
    'PHIDetectionService',
    'get_phi_detection_service',
    
    # Middleware
    'PHIMiddleware',
    'add_phi_middleware',
    'get_phi_middleware',
    
    # PHI Auditing
    'PHIAuditHandler',
    'log_phi_access',
    'get_phi_audit_handler',
]