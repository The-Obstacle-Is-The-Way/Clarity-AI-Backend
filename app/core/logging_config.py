"""
Logging Configuration Module.

This module provides the central logging configuration dictionary for the application.
It follows best practices for logging in a HIPAA-compliant application, ensuring
no PHI is accidentally logged in plain text.
"""

import logging
import logging.config
import os
from pathlib import Path
from typing import Any

# Get log level from environment or default to INFO
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# Base configuration that can be extended for different environments
LOGGING_CONFIG_BASE: dict[str, Any] = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": "[%(asctime)s] [%(levelname)s] [%(name)s] - %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
        "detailed": {
            "format": "[%(asctime)s] [%(levelname)s] [%(name)s:%(lineno)d] - %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
    },
    "filters": {
        "phi_sanitizer": {
            "()": "app.core.utils.logging.PHISanitizingFilter",
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": LOG_LEVEL,
            "formatter": "standard",
            "filters": ["phi_sanitizer"],
            "stream": "ext://sys.stdout",
        },
        "file_handler": {
            "class": "logging.handlers.RotatingFileHandler",
            "level": LOG_LEVEL,
            "formatter": "detailed",
            "filters": ["phi_sanitizer"],
            "filename": str(Path(os.getenv("LOG_DIR", "logs")) / "app.log"),
            "maxBytes": 10485760,  # 10MB
            "backupCount": 10,
            "encoding": "utf8",
        },
        "error_file_handler": {
            "class": "logging.handlers.RotatingFileHandler",
            "level": "ERROR",
            "formatter": "detailed",
            "filters": ["phi_sanitizer"],
            "filename": str(Path(os.getenv("LOG_DIR", "logs")) / "error.log"),
            "maxBytes": 10485760,  # 10MB
            "backupCount": 10,
            "encoding": "utf8",
        },
    },
    "loggers": {
        "root": {
            "level": LOG_LEVEL,
            "handlers": ["console", "file_handler"],
            "propagate": False,
        },
        "app": {
            "level": LOG_LEVEL,
            "handlers": ["console", "file_handler"],
            "propagate": False,
        },
        "uvicorn": {
            "level": LOG_LEVEL,
            "handlers": ["console", "file_handler"],
            "propagate": False,
        },
        "sqlalchemy.engine": {
            "level": "WARNING",  # Set to INFO or DEBUG for SQL query logging
            "handlers": ["console", "file_handler"],
            "propagate": False,
        },
        "sqlalchemy": {
            "handlers": ["console"],
            "level": os.getenv("SQL_LOG_LEVEL", "WARNING"),
            "propagate": False,
        },
        "alembic": {
            "handlers": ["console"],
            "level": os.getenv("SQL_LOG_LEVEL", "WARNING"),
            "propagate": False,
        },
    },
}

# Create a concrete logging configuration by copying the base config
LOGGING_CONFIG = LOGGING_CONFIG_BASE.copy()

# Ensure logs directory exists
log_dir = Path.cwd() / "logs"
log_dir.mkdir(parents=True, exist_ok=True)


def setup_logging(config: dict[str, Any] | None = None) -> None:
    """
    Configure the logging system with the provided configuration or default.

    Args:
        config: Optional logging configuration dictionary to use instead of the default
    """
    if config is None:
        config = LOGGING_CONFIG

    # Create logs directory if it doesn't exist
    file_path = config["handlers"]["file_handler"]["filename"]
    log_dir = Path(file_path).parent
    log_dir.mkdir(parents=True, exist_ok=True)

    # Apply the configuration
    logging.config.dictConfig(config)

    logger = logging.getLogger(__name__)
    logger.debug("Logging configured successfully")
