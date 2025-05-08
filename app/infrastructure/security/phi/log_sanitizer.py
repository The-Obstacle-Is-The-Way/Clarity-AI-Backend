"""
HIPAA-compliant PHI log sanitization (compatibility stub).

This module provides backward compatibility for the consolidated PHI sanitization system,
delegating to the primary PHISanitizer implementation to maintain a single source of truth.
"""

import logging
from typing import Any, Dict, List, Optional, Union

from app.infrastructure.security.phi.sanitizer import (
    PHISanitizer,
    PHISafeLogger,
    get_sanitizer,
    get_sanitized_logger,
)


class PHIRedactionHandler:
    """
    Compatibility stub for PHI redaction handling.
    Delegates to the consolidated PHISanitizer implementation.
    """
    
    def __init__(self, sanitizer: Optional[PHISanitizer] = None):
        """
        Initialize the PHI redaction handler.
        
        Args:
            sanitizer: Optional PHI sanitizer to use (creates a new one if None)
        """
        self.sanitizer = sanitizer or get_sanitizer()
    
    def redact_phi(self, text: Union[str, Dict, List, Any]) -> Any:
        """
        Redact PHI from input data.
        
        Args:
            text: Input text or structured data containing potential PHI
            
        Returns:
            Sanitized data with PHI redacted
        """
        try:
            if isinstance(text, str):
                return self.sanitizer.sanitize_string(text)
            elif isinstance(text, dict):
                return self.sanitizer.sanitize_json(text)
            elif isinstance(text, (list, tuple)):
                # Handle list/tuple items individually through sanitize_json
                return self.sanitizer.sanitize_json(text)
            else:
                # For other types, attempt string sanitization
                return self.sanitizer.sanitize_string(str(text))
        except Exception as e:
            logging.warning(f"PHI redaction failed: {type(e).__name__}")
            return "[SANITIZATION_ERROR]"
    
    def redact_dictionary(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Redact PHI from a dictionary.
        
        Args:
            data: Dictionary potentially containing PHI
            
        Returns:
            Sanitized dictionary with PHI redacted
        """
        return self.sanitizer.sanitize_json(data)
    
    def redact_text(self, text: str) -> str:
        """
        Redact PHI from text.
        
        Args:
            text: Text potentially containing PHI
            
        Returns:
            Sanitized text with PHI redacted
        """
        return self.sanitizer.sanitize_string(text)


class PHIFormatter(logging.Formatter):
    """
    PHI-aware log formatter that sanitizes log messages before formatting.
    
    Delegates to PHISanitizer for the actual sanitization work.
    """
    
    def __init__(
        self,
        fmt: Optional[str] = None,
        datefmt: Optional[str] = None,
        style: str = '%',
        sanitizer: Optional[PHISanitizer] = None
    ):
        """
        Initialize PHI formatter.
        
        Args:
            fmt: Log format string
            datefmt: Date format string
            style: Format style ('%', '{', or '$')
            sanitizer: Optional PHI sanitizer to use (creates a new one if None)
        """
        super().__init__(fmt=fmt, datefmt=datefmt, style=style)
        self.sanitizer = sanitizer or get_sanitizer()
        self.redactor = PHIRedactionHandler(self.sanitizer)
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record with PHI sanitization.
        
        Args:
            record: Log record to format
            
        Returns:
            Formatted log message with PHI sanitized
        """
        if hasattr(record, 'msg') and record.msg:
            # Sanitize the message
            record.msg = self.redactor.redact_phi(record.msg)
            
        if hasattr(record, 'args') and record.args:
            # Sanitize args
            if isinstance(record.args, dict):
                record.args = self.redactor.redact_dictionary(record.args)
            elif isinstance(record.args, (tuple, list)):
                # Convert to list for modification
                args_list = list(record.args)
                for i, arg in enumerate(args_list):
                    args_list[i] = self.redactor.redact_phi(arg)
                # Convert back to tuple if it was originally a tuple
                record.args = tuple(args_list) if isinstance(record.args, tuple) else args_list
                
        return super().format(record)


class LogSanitizer:
    """
    Compatibility wrapper for PHISafeLogger.
    
    This class provides backward compatibility with code that uses
    the LogSanitizer interface, while delegating to PHISafeLogger
    for the actual implementation.
    """
    
    def __init__(self, logger_name: Optional[str] = None, sanitizer: Optional[PHISanitizer] = None):
        """
        Initialize log sanitizer.
        
        Args:
            logger_name: Name for the logger
            sanitizer: Optional PHI sanitizer to use (creates a new one if None)
        """
        self.logger_name = logger_name or __name__
        self.sanitizer = sanitizer or get_sanitizer()
        self._logger = get_sanitized_logger(self.logger_name)
        self._redactor = PHIRedactionHandler(self.sanitizer)
    
    def get_sanitized_logger(self) -> PHISafeLogger:
        """
        Get a sanitized logger.
        
        Returns:
            PHI-safe logger instance
        """
        return self._logger
    
    def sanitize(self, message: Union[str, Dict, List, Any]) -> Any:
        """
        Sanitize a log message or any data format.
        
        Args:
            message: Message to sanitize
            
        Returns:
            Sanitized message with PHI redacted
        """
        return self._redactor.redact_phi(message)
    
    def sanitize_log_message(self, message: Union[str, Dict, List, Any]) -> Any:
        """
        Sanitize a log message.
        
        Args:
            message: Message to sanitize
            
        Returns:
            Sanitized message with PHI redacted
        """
        return self.sanitize(message)


# For backward compatibility
def get_phi_safe_logger(name: str) -> PHISafeLogger:
    """Legacy function to get a PHI-safe logger."""
    return get_sanitized_logger(name)

def sanitize_log_message(message: Any) -> Any:
    """Legacy function to sanitize a log message."""
    redactor = PHIRedactionHandler()
    return redactor.redact_phi(message)
