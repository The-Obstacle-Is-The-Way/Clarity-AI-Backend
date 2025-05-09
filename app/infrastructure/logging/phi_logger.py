"""
HIPAA-Compliant PHI Logger

This module provides specialized logging for handling Protected Health Information (PHI),
ensuring HIPAA compliance by automatically sanitizing sensitive data.
"""

import logging
import os
import sys
from typing import Any

# from app.config.settings import get_settings # Legacy import
from app.core.config.settings import get_settings # Corrected import

settings = get_settings() # Restore to original position

# Import directly from consolidated PHI sanitizer implementation
from app.infrastructure.security.phi import PHISafeLogger, get_sanitized_logger, PHISanitizer

from .audit_logger import AuditLogger # Restore to original position

class PHILogger:
    """
    HIPAA-compliant logger for safely handling PHI in log messages.

    Automatically sanitizes PHI from log messages and provides secure
    logging options for different levels of sensitivity.
    """

    def __init__(self, name: str = "novamind.phi", log_path: str | None = None):
        """
        Initialize the PHI logger with redaction and secure output.

        Args:
            name: Logger name
            log_path: Path to log file
        """
        self.settings = get_settings()
        # Use the sanitized logger directly
        self.logger = get_sanitized_logger(name)
        
        # Use getattr to safely get the log level with a default if not present
        log_level = getattr(self.settings, "LOG_LEVEL", "INFO")
        self.logger.setLevel(getattr(logging, log_level))

        # Ensure no logs with PHI go to the console
        self._setup_handlers(log_path)

    def _setup_handlers(self, log_path: str | None) -> None:
        """
        Set up secure logging handlers with PHI redaction.

        Args:
            log_path: Path to log file
        """
        # Clear any existing handlers
        if self.logger.handlers:
            self.logger.handlers.clear()

        # Create a basic formatter - PHISafeLogger handles PHI sanitization internally
        formatter = logging.Formatter(
            fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )

        # Add console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

        # Add file handler if path provided
        if log_path:
            # Ensure log directory exists
            log_dir = os.path.dirname(log_path)
            if not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)

            file_handler = logging.FileHandler(log_path)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

    def info(self, msg: str, *args, **kwargs) -> None:
        """
        Log an info message with PHI redaction.

        Args:
            msg: Log message
            args: Additional args for logger
            kwargs: Additional kwargs for logger
        """
        self.logger.info(msg, *args, **kwargs)

    def warning(self, msg: str, *args, **kwargs) -> None:
        """
        Log a warning message with PHI redaction.

        Args:
            msg: Log message
            args: Additional args for logger
            kwargs: Additional kwargs for logger
        """
        self.logger.warning(msg, *args, **kwargs)

    def error(self, msg: str, *args, **kwargs) -> None:
        """
        Log an error message with PHI redaction.

        Args:
            msg: Log message
            args: Additional args for logger
            kwargs: Additional kwargs for logger
        """
        self.logger.error(msg, *args, **kwargs)

    def critical(self, msg: str, *args, **kwargs) -> None:
        """
        Log a critical message with PHI redaction.

        Args:
            msg: Log message
            args: Additional args for logger
            kwargs: Additional kwargs for logger
        """
        self.logger.critical(msg, *args, **kwargs)

    def debug(self, msg: str, *args, **kwargs) -> None:
        """
        Log a debug message with PHI redaction.

        Args:
            msg: Log message
            args: Additional args for logger
            kwargs: Additional kwargs for logger
        """
        self.logger.debug(msg, *args, **kwargs)

    def exception(self, msg: str, *args, **kwargs) -> None:
        """
        Log an exception with PHI redaction.

        Args:
            msg: Log message
            args: Additional args for logger
            kwargs: Additional kwargs for logger
        """
        self.logger.exception(msg, *args, **kwargs)

    def log_access(
        self,
        user_id: str,
        username: str,
        role: str,
        resource_type: str,
        resource_id: str,
        action: str,
        phi_present: bool = False,
    ) -> None:
        """
        Log access to a resource, optionally marking it as containing PHI.

        Args:
            user_id: ID of user accessing the resource
            username: Username of the user
            role: Role of the user
            resource_type: Type of resource being accessed
            resource_id: ID of resource being accessed
            action: Type of access (e.g., "READ", "WRITE")
            phi_present: Whether PHI is present in the resource
        """
        # Construct a safe message without PHI
        message = (
            f"Access: {action} | "
            f"User: {username} ({role}) | "
            f"Resource: {resource_type} ID: {resource_id}"
        )

        # Add PHI flag if present
        if phi_present:
            message += " | PHI: YES"

        # Log at appropriate level
        if phi_present:
            # For access to PHI, log at INFO level minimum
            self.info(message)
        else:
            # For non-PHI access, log at DEBUG level
            self.debug(message)

    def log_phi_action(
        self,
        action_type: str,
        user_info: dict[str, Any],
        resource_info: dict[str, Any],
        details: str | None = None,
        success: bool = True,
    ) -> None:
        """
        Log an action involving PHI with extra security measures.

        Args:
            action_type: Type of action (e.g., "VIEW", "EXPORT", "PRINT")
            user_info: Information about the user performing the action
            resource_info: Information about the resource being accessed
            details: Additional details about the action
            success: Whether the action was successful
        """
        # Extract user information safely
        username = user_info.get("username", "unknown")
        role = user_info.get("role", "unknown")

        # Extract resource information safely
        resource_type = resource_info.get("type", "unknown")
        resource_id = resource_info.get("id", "unknown")

        # Construct a safe message without PHI
        status = "SUCCESS" if success else "FAILED"
        message = (
            f"PHI {action_type} {status} | "
            f"User: {username} ({role}) | "
            f"Resource: {resource_type} ID: {resource_id}"
        )

        # Add details if provided
        if details:
            message += f" | Details: {details}"

        # Log at appropriate level based on success
        if success:
            self.info(message)
        else:
            self.warning(message)


def get_phi_logger(
    name: str = "novamind.phi", log_path: str | None = None
) -> PHILogger:
    """
    Factory function to get a PHI logger instance.

    Args:
        name: Logger name
        log_path: Path to log file

    Returns:
        PHILogger: A PHI logger instance
    """
    return PHILogger(name=name, log_path=log_path)
