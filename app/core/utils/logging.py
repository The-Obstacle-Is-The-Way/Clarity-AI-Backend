"""
Logging Utility Module.

This module provides logging configuration and utilities for the application,
with special care for HIPAA compliance and PHI protection.
"""

import logging
import os
import sys
import traceback
from collections.abc import Callable
from datetime import datetime
from functools import wraps
from typing import Any, ParamSpec, TypeVar

from app.core.constants import LogLevel

# Type variables for function signatures
F = TypeVar("F", bound=Callable[..., Any])


class PHISanitizingFilter(logging.Filter):
    """Custom logging filter to sanitize PHI from log records."""

    def __init__(self, name: str = "PHISanitizer"):
        super().__init__(name)
        # Avoid circular import by not creating the anonymizer in __init__
        # Will be initialized in filter() method when first needed
        from typing import Any

        self.anonymizer: Any = None

    def filter(self, record: logging.LogRecord) -> bool:
        """Sanitize the log record message using DataAnonymizer."""
        # Lazy load the anonymizer when needed to avoid circular imports
        if self.anonymizer is None:
            # Import here to break circular dependency
            from app.core.utils.data_transformation import DataAnonymizer

            # Create anonymizer instance only when first needed
            self.anonymizer = DataAnonymizer()
            assert self.anonymizer is not None  # Help mypy understand this can't be None anymore

        # Ensure message is formatted correctly before sanitization
        original_message = record.getMessage()

        # Use the anonymizer's method to sanitize the text
        sanitized_message = self.anonymizer.anonymize_text(original_message)

        # Replace the original message attributes with the sanitized one
        # Need to update both msg and message for compatibility with different formatters
        record.msg = sanitized_message
        record.message = record.msg  # Update the 'message' attribute used by some formatters
        record.args = ()  # Clear args as they are now baked into the formatted msg

        return True  # Always process the record after potential sanitization


def get_logger(name: str) -> logging.Logger:
    """
    Get a configured logger instance for the specified name.

    This function creates and returns a logger with the specified name,
    configured according to the application's logging settings.
    HIPAA-compliant sanitization is automatically applied.

    Args:
        name: Logger name, typically __name__ of the calling module

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)

    # Only configure if it hasn't been done yet
    if not logger.handlers:
        # Get log level from environment or default to INFO
        log_level_str = os.getenv("LOG_LEVEL", "INFO").upper()
        log_level = getattr(logging, log_level_str, logging.INFO)

        # Set level
        logger.setLevel(log_level)

        # Create console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)

        # Create formatter
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s] - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        console_handler.setFormatter(formatter)

        # Add the PHI sanitizing filter
        console_handler.addFilter(PHISanitizingFilter())

        # Add handler to logger
        logger.addHandler(console_handler)

        # Prevent propagation to root logger to avoid duplicate logs
        logger.propagate = False

    return logger


# Define type variables for generic function signatures
T = TypeVar("T")
P = ParamSpec("P")


def log_execution_time(func=None, *, logger=None, level=LogLevel.DEBUG):
    """
    Decorator to log the execution time of a function.
    Can be used with or without arguments:

    @log_execution_time
    def my_func(): pass

    OR

    @log_execution_time(logger=my_logger, level=LogLevel.INFO)
    def my_func(): pass

    Args:
        func: Function to decorate
        logger: Logger to use, if None a new logger is created using function's module name
        level: Log level to use (will be converted to int)

    Returns:
        Decorated function or decorator function depending on usage
    """
    # Map LogLevel enum values to standard logging integers
    level_to_int = {
        LogLevel.DEBUG: logging.DEBUG,
        LogLevel.INFO: logging.INFO,
        LogLevel.WARNING: logging.WARNING,
        LogLevel.ERROR: logging.ERROR,
        LogLevel.CRITICAL: logging.CRITICAL,
    }

    def actual_decorator(fn):
        # Create specific logger for this function if not provided
        nonlocal logger, level
        log = logger or get_logger(fn.__module__)

        # Ensure level is converted to an int understood by stdlib logging
        if isinstance(level, LogLevel):
            log_level_int: int = level_to_int.get(level, logging.DEBUG)
        elif isinstance(level, str):
            log_level_int = int(getattr(logging, level.upper(), logging.DEBUG))
        else:  # already an int
            log_level_int = int(level)

        @wraps(fn)
        def wrapper(*args, **kwargs):
            start_time = datetime.now()

            try:
                # Execute the function
                result = fn(*args, **kwargs)

                # Calculate execution time
                end_time = datetime.now()
                duration_ms = (end_time - start_time).total_seconds() * 1000

                # Use the integer log level
                log.log(log_level_int, f"Function '{fn.__name__}' executed in {duration_ms:.2f} ms")

                return result
            except Exception as e:
                # Log exceptions with traceback
                end_time = datetime.now()
                duration_ms = (end_time - start_time).total_seconds() * 1000

                log.exception(f"Exception in '{fn.__name__}' after {duration_ms:.2f} ms: {e!s}")

                # Re-raise the exception
                raise

        return wrapper

    # Handle being called directly as @log_execution_time or with args
    if func is not None:
        return actual_decorator(func)
    else:
        return actual_decorator


def log_method_calls(
    logger: logging.Logger | None = None,
    level: LogLevel | int | str = LogLevel.DEBUG,
    log_args: bool = True,
    log_results: bool = True,
) -> Callable[[type], type]:
    """
    Class decorator to log method calls.

    Args:
        logger: Logger to use, if None a logger is created for each method
        level: Log level to use
        log_args: Whether to log method arguments
        log_results: Whether to log method return values

    Returns:
        Decorator function
    """
    # Normalize `level` to an integer understood by the stdlib `logging` module.
    # Order of checks matters for mypy: evaluate the *most specific* Enum branch
    # first, then strings, then fall back to ints.  This prevents the false
    # positive "unreachable" error triggered when `LogLevel` values are
    # considered a subtype of `int`.
    numeric_level: int
    if isinstance(level, LogLevel):
        # LogLevel enum values are already integers (10, 20, 30, etc.)
        numeric_level = level.value
    elif isinstance(level, str):
        # Resolve string names (e.g., "INFO") to their numeric constant; default INFO
        numeric_level = int(getattr(logging, level.upper(), logging.INFO))
    else:  # Already an int
        numeric_level = int(level)

    def decorator(cls: type) -> type:
        # Get class methods (excluding magic methods)
        for name, method in cls.__dict__.items():
            if callable(method) and not name.startswith("__"):
                setattr(
                    cls,
                    name,
                    _create_logged_method(method, logger, numeric_level, log_args, log_results),
                )
        return cls

    return decorator


def _create_logged_method(
    method: Callable,
    logger: logging.Logger | None,
    level: int,  # Already converted to int by the calling function
    log_args: bool,
    log_results: bool,
) -> Callable:
    """
    Create a logged version of a method.

    Args:
        method: Method to wrap with logging
        logger: Logger to use
        level: Log level to use
        log_args: Whether to log method arguments
        log_results: Whether to log method return values

    Returns:
        Wrapped method with logging
    """

    @wraps(method)
    def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
        # Get or create logger
        method_logger = logger
        if method_logger is None:
            method_logger = get_logger(f"{self.__class__.__module__}.{self.__class__.__name__}")

        # Build method call representation
        method_call = f"{self.__class__.__name__}.{method.__name__}"
        if log_args and (args or kwargs):
            args_str = ", ".join([str(arg) for arg in args])
            kwargs_str = ", ".join([f"{k}={v}" for k, v in kwargs.items()])
            args_kwargs = [s for s in [args_str, kwargs_str] if s]
            method_call += f"({', '.join(args_kwargs)})"

        # Log method entry - level is already an integer
        method_logger.log(level, f"Calling {method_call}")

        # Execute method
        try:
            result = method(self, *args, **kwargs)

            # Log successful completion - level is already an integer
            if log_results:
                method_logger.log(level, f"{method_call} returned: {result!s}")
            else:
                method_logger.log(level, f"{method_call} completed successfully")

            return result

        except Exception as e:
            # Log exception
            tb = traceback.format_exc()
            method_logger.error(f"Exception in {method_call}: {e!s}\n{tb}")
            raise  # Re-raise the exception

    return wrapper
