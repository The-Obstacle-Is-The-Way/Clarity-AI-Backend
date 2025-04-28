"""
HIPAA-compliant log sanitization for PHI protection.

This module provides utilities for sanitizing logs to prevent PHI exposure.
It integrates with the PHI service to detect and redact PHI.
"""

import logging
import inspect
import json
from typing import Any, Dict, List, Optional, Union, Callable

from .phi_service import PHIService


class PHIRedactionHandler:
    """
    Handler for PHI redaction in logs.
    
    This class manages the redaction of PHI in log records by applying
    appropriate replacement patterns based on PHI types.
    """
    
    def __init__(self, phi_service: Optional[PHIService] = None):
        """
        Initialize the PHI redaction handler.
        
        Args:
            phi_service: Optional PHIService for PHI detection and redaction.
                         If None, creates a new instance.
        """
        self.phi_service = phi_service or PHIService()
        
    def redact_phi(self, text: str, replacement_template: str = "[REDACTED {phi_type}]") -> str:
        """
        Redact PHI from text using the PHI service.
        
        Args:
            text: Text to redact
            replacement_template: Template for replacement text
            
        Returns:
            Redacted text
        """
        return self.phi_service.sanitize_string(text)
    
    def redact_phi_from_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Redact PHI from a dictionary.
        
        Args:
            data: Dictionary to redact
            
        Returns:
            Redacted dictionary
        """
        return self.phi_service.sanitize_dict(data)
    
    def redact_phi_from_list(self, data: List[Any]) -> List[Any]:
        """
        Redact PHI from a list.
        
        Args:
            data: List to redact
            
        Returns:
            Redacted list
        """
        return self.phi_service.sanitize_list(data)
    
    def redact_phi_from_object(self, obj: Any) -> Any:
        """
        Redact PHI from an object, converting it to a dictionary first.
        
        Args:
            obj: Object to redact
            
        Returns:
            Redacted object or dictionary
        """
        if hasattr(obj, 'to_dict') and callable(getattr(obj, 'to_dict')):
            try:
                dict_data = obj.to_dict()
                return self.redact_phi_from_dict(dict_data)
            except Exception:
                pass
                
        if hasattr(obj, '__dict__'):
            try:
                obj_dict = vars(obj)
                return self.redact_phi_from_dict(obj_dict)
            except Exception:
                pass
                
        # If all else fails, convert to string and redact
        if isinstance(obj, str):
            return self.redact_phi(obj)
            
        return obj


class PHIFormatter(logging.Formatter):
    """
    Log formatter that sanitizes PHI in log records.
    
    This formatter extends the standard logging.Formatter to apply
    PHI sanitization to log messages and arguments before formatting.
    """
    
    def __init__(
        self,
        fmt: Optional[str] = None,
        datefmt: Optional[str] = None,
        style: str = '%',
        validate: bool = True,
        phi_service: Optional[PHIService] = None
    ):
        """
        Initialize the PHI formatter.
        
        Args:
            fmt: Log format string
            datefmt: Date format string
            style: Style of the format string (%, {, or $)
            validate: Whether to validate the format string
            phi_service: Optional PHIService for PHI detection and redaction
        """
        super().__init__(fmt, datefmt, style, validate)
        self.redaction_handler = PHIRedactionHandler(phi_service)
        
    def format(self, record: logging.LogRecord) -> str:
        """
        Format the specified record, sanitizing PHI.
        
        Args:
            record: Log record to format
            
        Returns:
            Formatted log record with PHI sanitized
        """
        # Make a copy of the record to avoid modifying the original
        record_copy = logging.makeLogRecord(record.__dict__)
        
        # Sanitize the message
        if isinstance(record_copy.msg, str):
            record_copy.msg = self.redaction_handler.redact_phi(record_copy.msg)
        elif isinstance(record_copy.msg, dict):
            record_copy.msg = self.redaction_handler.redact_phi_from_dict(record_copy.msg)
        elif isinstance(record_copy.msg, list):
            record_copy.msg = self.redaction_handler.redact_phi_from_list(record_copy.msg)
        elif hasattr(record_copy.msg, '__dict__'):
            record_copy.msg = self.redaction_handler.redact_phi_from_object(record_copy.msg)
            
        # Sanitize the args if they exist
        if record_copy.args:
            if isinstance(record_copy.args, dict):
                record_copy.args = self.redaction_handler.redact_phi_from_dict(record_copy.args)
            elif isinstance(record_copy.args, (tuple, list)):
                args_list = list(record_copy.args)
                sanitized_args = []
                for arg in args_list:
                    if isinstance(arg, str):
                        sanitized_args.append(self.redaction_handler.redact_phi(arg))
                    elif isinstance(arg, dict):
                        sanitized_args.append(self.redaction_handler.redact_phi_from_dict(arg))
                    elif isinstance(arg, list):
                        sanitized_args.append(self.redaction_handler.redact_phi_from_list(arg))
                    else:
                        sanitized_args.append(arg)
                record_copy.args = tuple(sanitized_args)
                
        # Call the parent class formatter
        return super().format(record_copy)


class LogSanitizer:
    """
    Sanitizes log messages to prevent PHI exposure.
    
    This class provides utilities for sanitizing logs at various levels
    of the application, including standalone functions and integration
    with logging systems.
    """
    
    def __init__(self, phi_service: Optional[PHIService] = None):
        """
        Initialize the log sanitizer.
        
        Args:
            phi_service: Optional PHIService instance for PHI detection and redaction.
                         If None, creates a new instance.
        """
        self.phi_service = phi_service or PHIService()
        
    def sanitize(self, data: Any, sensitivity: str = 'auto') -> Any:
        """
        Sanitize data for logging, handling various data types.
        
        Args:
            data: Data to sanitize (string, dict, list, etc.)
            sensitivity: Sensitivity level ('high', 'medium', 'low', 'auto')
            
        Returns:
            Sanitized data
        """
        if sensitivity == 'auto':
            # Use generic sanitization based on data type
            return self._sanitize_by_type(data)
        elif sensitivity == 'high':
            # Maximum sanitization for highly sensitive contexts
            if isinstance(data, str):
                return self._sanitize_highly_sensitive_string(data)
            else:
                # Convert to string, sanitize, and note the conversion
                return f"[REDACTED: {type(data).__name__}]"
        elif sensitivity == 'medium':
            # Standard PHI sanitization
            return self._sanitize_by_type(data)
        elif sensitivity == 'low':
            # Minimal sanitization for low-risk contexts
            return self._sanitize_by_type(data, allow_more=True)
        else:
            # Invalid sensitivity level, use default
            logging.warning(f"Unknown sensitivity level: {sensitivity}. Using default.")
            return self._sanitize_by_type(data)
            
    def _sanitize_by_type(self, data: Any, allow_more: bool = False) -> Any:
        """
        Sanitize data based on its type.
        
        Args:
            data: Data to sanitize
            allow_more: If True, applies less aggressive sanitization
            
        Returns:
            Sanitized data
        """
        if data is None:
            return None
            
        if isinstance(data, str):
            return self.phi_service.sanitize_string(data)
        elif isinstance(data, dict):
            return self.phi_service.sanitize_dict(data)
        elif isinstance(data, list):
            return self.phi_service.sanitize_list(data)
        elif hasattr(data, 'to_dict') and callable(getattr(data, 'to_dict')):
            # Handle objects with to_dict method (common pattern)
            try:
                dict_data = data.to_dict()
                return self.phi_service.sanitize_dict(dict_data)
            except Exception as e:
                logging.warning(f"Failed to sanitize using to_dict: {str(e)}")
                return str(data)
        elif hasattr(data, '__dict__'):
            # Attempt to sanitize object attributes
            try:
                obj_dict = vars(data)
                sanitized_dict = self.phi_service.sanitize_dict(obj_dict)
                return sanitized_dict
            except Exception as e:
                logging.warning(f"Failed to sanitize object attributes: {str(e)}")
                return str(data)
        else:
            # For non-container types, convert to string if we need to sanitize
            str_data = str(data)
            if self.phi_service.contains_phi(str_data):
                return self.phi_service.sanitize_string(str_data)
            return data
    
    def _sanitize_highly_sensitive_string(self, text: str) -> str:
        """
        Apply maximum sanitization to highly sensitive data.
        
        Args:
            text: String to sanitize
            
        Returns:
            Heavily sanitized string
        """
        # First apply standard PHI sanitization
        sanitized = self.phi_service.sanitize_string(text)
        
        # Then apply additional redactions for high sensitivity
        # Only keep basic identifiers and structural elements
        words = sanitized.split()
        safe_words = []
        for word in words:
            # Keep structural elements and simple words
            if (len(word) <= 3 or 
                word.lower() in {'the', 'and', 'for', 'of', 'to', 'in', 'on', 'is', 'are', 'was'} or
                word.startswith('[REDACTED')):
                safe_words.append(word)
            else:
                # For anything else, check if it contains PHI patterns
                if self.phi_service.contains_phi(word):
                    safe_words.append('[REDACTED]')
                else:
                    safe_words.append(word)
                    
        return ' '.join(safe_words)
        
    def create_sanitized_logger(self, name: str, level: int = logging.INFO) -> 'logging.Logger':
        """
        Create a logger with a sanitizing filter.
        
        Args:
            name: Logger name
            level: Logging level
            
        Returns:
            Logger with sanitizing filter
        """
        logger = logging.getLogger(name)
        logger.setLevel(level)
        
        # Add sanitizing filter if not already present
        has_sanitizer = False
        for handler in logger.handlers:
            for filter in handler.filters:
                if isinstance(filter, SanitizingFilter):
                    has_sanitizer = True
                    break
                    
        if not has_sanitizer:
            sanitizing_filter = SanitizingFilter(self)
            
            # Add filter to all handlers
            for handler in logger.handlers:
                handler.addFilter(sanitizing_filter)
                
            # If no handlers, add a default one
            if not logger.handlers:
                handler = logging.StreamHandler()
                handler.addFilter(sanitizing_filter)
                logger.addHandler(handler)
                
        return logger
    
    def sanitize_exception(self, exception: Exception) -> str:
        """
        Sanitize exception data to prevent PHI exposure in error reports.
        
        Args:
            exception: Exception object
            
        Returns:
            Sanitized exception string
        """
        # Get exception details
        exc_type = type(exception).__name__
        exc_msg = str(exception)
        
        # Sanitize the exception message
        sanitized_msg = self.phi_service.sanitize_string(exc_msg)
        
        # Get sanitized traceback
        tb_frames = []
        tb = exception.__traceback__
        while tb:
            frame = tb.tb_frame
            code = frame.f_code
            filename = code.co_filename
            line_number = tb.tb_lineno
            function_name = code.co_name
            
            # Safe traceback info
            frame_info = {
                'file': filename,
                'line': line_number,
                'function': function_name
            }
            
            # Get local variables, but sanitize them
            if hasattr(frame, 'f_locals'):
                locals_dict = {}
                for key, value in frame.f_locals.items():
                    # Skip internal variables and large objects
                    if key.startswith('__') or not isinstance(value, (str, int, float, bool, dict, list)):
                        continue
                        
                    # Sanitize the value
                    sanitized_value = self._sanitize_by_type(value)
                    locals_dict[key] = sanitized_value
                    
                frame_info['locals'] = locals_dict
                
            tb_frames.append(frame_info)
            tb = tb.tb_next
            
        # Format the sanitized traceback
        sanitized_traceback = f"{exc_type}: {sanitized_msg}\nTraceback (most recent call last):"
        for frame in tb_frames:
            sanitized_traceback += f"\n  File '{frame['file']}', line {frame['line']}, in {frame['function']}"
            
        return sanitized_traceback
        

class SanitizingFilter(logging.Filter):
    """
    Log filter that sanitizes log records.
    
    This filter is applied to log handlers to sanitize all log records
    before they are emitted, preventing PHI exposure.
    """
    
    def __init__(self, sanitizer: LogSanitizer):
        """
        Initialize the sanitizing filter.
        
        Args:
            sanitizer: LogSanitizer instance to use for sanitization
        """
        super().__init__()
        self.sanitizer = sanitizer
        
    def filter(self, record: logging.LogRecord) -> bool:
        """
        Filter and sanitize a log record.
        
        Args:
            record: Log record to sanitize
            
        Returns:
            True to allow the record (always, but sanitized)
        """
        # Sanitize the log message
        if hasattr(record, 'msg') and record.msg:
            record.msg = self.sanitizer.sanitize(record.msg)
            
        # Sanitize the args
        if hasattr(record, 'args') and record.args:
            if isinstance(record.args, dict):
                record.args = self.sanitizer.sanitize(record.args)
            elif isinstance(record.args, (tuple, list)):
                sanitized_args = []
                for arg in record.args:
                    sanitized_args.append(self.sanitizer.sanitize(arg))
                record.args = tuple(sanitized_args)
                
        # Sanitize exception info if present
        if record.exc_info and record.exc_info[1]:
            # We can't modify the exception object, but we can sanitize what's shown
            original_exc = record.exc_info[1]
            sanitized_exc_text = self.sanitizer.sanitize_exception(original_exc)
            # Store the sanitized text in an attribute for use by formatters
            setattr(record, 'sanitized_exc_text', sanitized_exc_text)
            
        return True
        
        
# Convenience function to get a sanitized logger
def get_sanitized_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """
    Get a logger with PHI sanitization capabilities.
    
    Args:
        name: Logger name
        level: Logging level
        
    Returns:
        Logger with PHI sanitization
    """
    sanitizer = LogSanitizer()
    return sanitizer.create_sanitized_logger(name, level)