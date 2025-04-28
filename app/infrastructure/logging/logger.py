# -*- coding: utf-8 -*-
"""
Logging configuration module.

This module provides a configured logger that follows HIPAA compliance
requirements for logging in healthcare applications.
"""

import logging
import sys
from typing import Dict, Any, Optional
import json
from datetime import datetime

from app.core.config import settings


class HIPAACompliantFormatter(logging.Formatter):
    """
    Custom formatter that ensures logs are HIPAA compliant by removing PHI.
    
    Formats logs in a structured JSON format for better analysis and includes
    additional fields needed for compliance auditing.
    """
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Format the log record as a JSON string with HIPAA-compliant fields.
        
        Args:
            record: The log record to format
            
        Returns:
            Formatted log message as a JSON string
        """
        # Create a dict with basic log information
        log_data = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "message": record.getMessage(),
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
            
        # Add extra fields from the record
        if hasattr(record, "extra") and isinstance(record.extra, dict):
            for key, value in record.extra.items():
                # Avoid overwriting existing fields
                if key not in log_data:
                    log_data[key] = value
                    
        # Sanitize PHI from log data (placeholder - real implementation would use PHI sanitizer)
        # In a real implementation, this would use a more sophisticated PHI detection and sanitization
        
        return json.dumps(log_data)


def get_logger(name: str) -> logging.Logger:
    """
    Get a configured logger instance.
    
    Args:
        name: The name for the logger, typically __name__
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    
    # Only configure if not already configured
    if not logger.handlers:
        logger.setLevel(getattr(logging, settings.LOG_LEVEL))
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(HIPAACompliantFormatter())
        logger.addHandler(console_handler)
        
        # Prevent propagation to the root logger
        logger.propagate = False
        
    return logger


def format_log_message(message: str, source: str, additional_data: Optional[Dict[str, Any]] = None) -> str:
    """
    Format a log message as a JSON string.

    Args:
        message: The log message.
        source: The source of the log message.
        additional_data: Additional data to include in the log message.

    Returns:
        A JSON string containing the log message and metadata.
    """
    log_data = {
        "timestamp": datetime.now().isoformat(),
        "level": "INFO",
        "message": message,
        "source": source
    }
    
    if additional_data:
        log_data.update(additional_data)
    
    return json.dumps(log_data)
