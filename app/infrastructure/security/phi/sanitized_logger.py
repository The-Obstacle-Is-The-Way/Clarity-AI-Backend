"""
HIPAA-compliant sanitized logger that automatically redacts PHI.

This module provides a wrapper around Python's standard logging module that
automatically sanitizes log messages to prevent accidental logging of PHI.
"""

import logging
from typing import Any, Dict, Optional, Union, Callable

from .phi_service import PHIService

class SanitizedLogger:
    """
    Logger that automatically sanitizes PHI in log messages.
    
    This class wraps a standard Python logger and intercepts all log messages
    to sanitize them using the PHIService before they are logged.
    """
    
    def __init__(self, 
                 name: str, 
                 phi_service: Optional[PHIService] = None,
                 log_level: int = logging.INFO):
        """
        Initialize a sanitized logger.
        
        Args:
            name: Logger name (typically __name__)
            phi_service: Optional PHIService instance. If None, creates a new one.
            log_level: Logging level (defaults to INFO)
        """
        self._logger = logging.getLogger(name)
        self._logger.setLevel(log_level)
        
        # Set up PHI service for sanitization
        self._phi_service = phi_service or PHIService()
        
    def debug(self, msg: str, *args, **kwargs):
        """Log a debug message, sanitizing any PHI."""
        sanitized_msg = self._phi_service.sanitize_string(str(msg))
        sanitized_args = self._sanitize_args(args)
        sanitized_kwargs = self._sanitize_kwargs(kwargs)
        self._logger.debug(sanitized_msg, *sanitized_args, **sanitized_kwargs)
        
    def info(self, msg: str, *args, **kwargs):
        """Log an info message, sanitizing any PHI."""
        sanitized_msg = self._phi_service.sanitize_string(str(msg))
        sanitized_args = self._sanitize_args(args)
        sanitized_kwargs = self._sanitize_kwargs(kwargs)
        self._logger.info(sanitized_msg, *sanitized_args, **sanitized_kwargs)
        
    def warning(self, msg: str, *args, **kwargs):
        """Log a warning message, sanitizing any PHI."""
        sanitized_msg = self._phi_service.sanitize_string(str(msg))
        sanitized_args = self._sanitize_args(args)
        sanitized_kwargs = self._sanitize_kwargs(kwargs)
        self._logger.warning(sanitized_msg, *sanitized_args, **sanitized_kwargs)
        
    def error(self, msg: str, *args, **kwargs):
        """Log an error message, sanitizing any PHI."""
        sanitized_msg = self._phi_service.sanitize_string(str(msg))
        sanitized_args = self._sanitize_args(args)
        sanitized_kwargs = self._sanitize_kwargs(kwargs)
        self._logger.error(sanitized_msg, *sanitized_args, **sanitized_kwargs)
        
    def critical(self, msg: str, *args, **kwargs):
        """Log a critical message, sanitizing any PHI."""
        sanitized_msg = self._phi_service.sanitize_string(str(msg))
        sanitized_args = self._sanitize_args(args)
        sanitized_kwargs = self._sanitize_kwargs(kwargs)
        self._logger.critical(sanitized_msg, *sanitized_args, **sanitized_kwargs)
        
    def exception(self, msg: str, *args, **kwargs):
        """Log an exception message, sanitizing any PHI."""
        sanitized_msg = self._phi_service.sanitize_string(str(msg))
        sanitized_args = self._sanitize_args(args)
        # Don't sanitize exc_info or stack_info if present
        exc_info = kwargs.pop('exc_info', True)
        stack_info = kwargs.pop('stack_info', False)
        sanitized_kwargs = self._sanitize_kwargs(kwargs)
        sanitized_kwargs['exc_info'] = exc_info
        sanitized_kwargs['stack_info'] = stack_info
        self._logger.exception(sanitized_msg, *sanitized_args, **sanitized_kwargs)
        
    def log(self, level: int, msg: str, *args, **kwargs):
        """Log a message with the specified level, sanitizing any PHI."""
        sanitized_msg = self._phi_service.sanitize_string(str(msg))
        sanitized_args = self._sanitize_args(args)
        sanitized_kwargs = self._sanitize_kwargs(kwargs)
        self._logger.log(level, sanitized_msg, *sanitized_args, **sanitized_kwargs)
        
    def _sanitize_args(self, args: tuple) -> tuple:
        """Sanitize positional arguments."""
        sanitized_args = []
        for arg in args:
            if isinstance(arg, str):
                sanitized_args.append(self._phi_service.sanitize_string(arg))
            elif isinstance(arg, dict):
                sanitized_args.append(self._phi_service.sanitize_dict(arg))
            elif isinstance(arg, list):
                sanitized_args.append(self._phi_service.sanitize_list(arg))
            else:
                sanitized_args.append(arg)
        return tuple(sanitized_args)
    
    def _sanitize_kwargs(self, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize keyword arguments."""
        sanitized_kwargs = {}
        for key, value in kwargs.items():
            # Don't sanitize certain keys
            if key in {'exc_info', 'stack_info', 'stacklevel', 'extra'}:
                sanitized_kwargs[key] = value
                continue
                
            if isinstance(value, str):
                sanitized_kwargs[key] = self._phi_service.sanitize_string(value)
            elif isinstance(value, dict):
                sanitized_kwargs[key] = self._phi_service.sanitize_dict(value)
            elif isinstance(value, list):
                sanitized_kwargs[key] = self._phi_service.sanitize_list(value)
            else:
                sanitized_kwargs[key] = value
        return sanitized_kwargs

def get_sanitized_logger(name: str, 
                        phi_service: Optional[PHIService] = None,
                        log_level: int = logging.INFO) -> SanitizedLogger:
    """
    Get a sanitized logger instance.
    
    This is a convenience function for creating a sanitized logger.
    
    Args:
        name: Logger name (typically __name__)
        phi_service: Optional PHIService instance. If None, creates a new one.
        log_level: Logging level (defaults to INFO)
        
    Returns:
        A SanitizedLogger instance
    """
    return SanitizedLogger(name, phi_service, log_level)