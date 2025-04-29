"""
HIPAA-compliant PHI log sanitization (compatibility stub).

This module provides backward compatibility for the consolidated PHI sanitization system,
delegating to the primary PHISanitizer implementation to maintain a single source of truth.
"""

import logging
import json
from typing import Any, Dict, List, Optional, Tuple, Union

from app.infrastructure.security.phi.sanitizer import (
    PHISanitizer, 
    SanitizedLogger,
    get_sanitized_logger
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
        self.sanitizer = sanitizer or PHISanitizer()
    
    def redact_phi(self, text: Union[str, Dict, List, Any]) -> Any:
        """
        Redact PHI from input data.
        
        Args:
            text: Input text or structured data containing potential PHI
            
        Returns:
            Sanitized data with PHI redacted
        """
        return self.sanitizer.sanitize(text)
    
    def redact_dictionary(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Redact PHI from a dictionary.
        
        Args:
            data: Dictionary potentially containing PHI
            
        Returns:
            Sanitized dictionary with PHI redacted
        """
        return self.sanitizer.sanitize_dict(data)
    
    def redact_text(self, text: str) -> str:
        """
        Redact PHI from text.
        
        Args:
            text: Text potentially containing PHI
            
        Returns:
            Sanitized text with PHI redacted
        """
        return self.sanitizer.sanitize_text(text)


class PHIFormatter(logging.Formatter):
    """
    Compatibility stub for PHI-aware log formatter.
    Ensures log messages have PHI sanitized before formatting.
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
        self.sanitizer = sanitizer or PHISanitizer()
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record with PHI sanitization.
        
        Args:
            record: Log record to format
            
        Returns:
            Formatted log message with PHI sanitized
        """
        # Sanitize message
        if hasattr(record, 'msg') and record.msg:
            if isinstance(record.msg, str):
                record.msg = self.sanitizer.sanitize_text(record.msg)
            else:
                record.msg = self.sanitizer.sanitize(record.msg)
        
        # Sanitize args
        if hasattr(record, 'args') and record.args:
            if isinstance(record.args, dict):
                record.args = self.sanitizer.sanitize_dict(record.args)
            elif isinstance(record.args, (list, tuple)):
                sanitized_args = []
                for arg in record.args:
                    sanitized_args.append(self.sanitizer.sanitize(arg))
                record.args = tuple(sanitized_args)
        
        return super().format(record)


class LogSanitizer:
    """
    Compatibility stub for LogSanitizer.
    Delegates to SanitizedLogger for a consistent implementation.
    """
    
    def __init__(self, logger_name: str = None, sanitizer: Optional[PHISanitizer] = None):
        """
        Initialize log sanitizer.
        
        Args:
            logger_name: Name for the logger
            sanitizer: Optional PHI sanitizer to use (creates a new one if None)
        """
        self.logger_name = logger_name or __name__
        self.sanitizer = sanitizer or PHISanitizer()
        self._logger = get_sanitized_logger(self.logger_name)
    
    def get_sanitized_logger(self) -> SanitizedLogger:
        """
        Get a sanitized logger.
        
        Returns:
            Sanitized logger instance
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
        return self.sanitizer.sanitize(message)
    
    def sanitize_log_message(self, message: Union[str, Dict, List, Any]) -> Any:
        """
        Sanitize a log message.
        
        Args:
            message: Message to sanitize
            
        Returns:
            Sanitized message with PHI redacted
        """
        return self.sanitizer.sanitize(message)
