"""
Logging Configuration Module.

This module provides the central logging configuration dictionary for the application.
It follows best practices for logging in a HIPAA-compliant application, ensuring
no PHI is accidentally logged in plain text.
"""

import os
from typing import Any

# Get log level from environment or default to INFO
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# Define a standard logging configuration dictionary
LOGGING_CONFIG: dict[str, Any] = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": "[%(asctime)s] [%(levelname)s] [%(name)s] - %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S"
        },
        "detailed": {
            "format": "[%(asctime)s] [%(levelname)s] [%(name)s:%(lineno)d] - %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S"
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
            "stream": "ext://sys.stdout"
        },
        "file_handler": {
            "class": "logging.handlers.RotatingFileHandler",
            "level": LOG_LEVEL,
            "formatter": "detailed",
            "filters": ["phi_sanitizer"],
            "filename": os.path.join(os.getenv("LOG_DIR", "logs"), "app.log"),
            "maxBytes": 10485760,  # 10MB
            "backupCount": 10,
            "encoding": "utf8"
        },
        "error_file_handler": {
            "class": "logging.handlers.RotatingFileHandler",
            "level": "ERROR",
            "formatter": "detailed",
            "filters": ["phi_sanitizer"],
            "filename": os.path.join(os.getenv("LOG_DIR", "logs"), "error.log"),
            "maxBytes": 10485760,  # 10MB
            "backupCount": 10,
            "encoding": "utf8"
        }
    },
    "loggers": {
        "": {  # Root logger
            "handlers": ["console"],
            "level": LOG_LEVEL,
        },
        "app": {
            "handlers": ["console"],
            "level": LOG_LEVEL,
            "propagate": False
        },
        "uvicorn": {
            "handlers": ["console"],
            "level": LOG_LEVEL,
            "propagate": False
        },
        "sqlalchemy": {
            "handlers": ["console"],
            "level": os.getenv("SQL_LOG_LEVEL", "WARNING"),
            "propagate": False
        },
        "alembic": {
            "handlers": ["console"],
            "level": os.getenv("SQL_LOG_LEVEL", "WARNING"),
            "propagate": False
        }
    }
}

# Only add file handlers if LOG_DIR is specified or logs directory exists
log_dir = os.getenv("LOG_DIR", "logs")
if not os.path.exists(log_dir):
    try:
        os.makedirs(log_dir, exist_ok=True)
        # Add file handlers to all loggers if we can create the log directory
        for logger_name in LOGGING_CONFIG["loggers"]:
            LOGGING_CONFIG["loggers"][logger_name]["handlers"].extend(["file_handler", "error_file_handler"])
    except OSError:
        # If we can't create log directory, just use console logging
        pass
