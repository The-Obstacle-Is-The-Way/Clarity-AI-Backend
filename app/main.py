"""
NOVAMIND FastAPI Application

This is the main application entry point for the NOVAMIND backend API.
It configures the FastAPI application, registers routes, middleware, and
event handlers.
"""

import logging
import logging.config

import uvicorn

# Monkey-patch httpx.AsyncClient to support 'app' parameter for FastAPI testing
# try:
#     import httpx
#     from httpx import ASGITransport
#     from httpx import AsyncClient as _AsyncClient
#     class AsyncClient(_AsyncClient):
#         def __init__(self, *args, app=None, **kwargs):
#             if app is not None:
#                 # Use ASGI transport for FastAPI app
#                 kwargs['transport'] = ASGITransport(app=app)
#             super().__init__(*args, **kwargs)
#             # Store reference to FastAPI app for fixture access
#             if app is not None:
#                 self.app = app
#     httpx.AsyncClient = AsyncClient
# except ImportError:
#     pass


# Use the new canonical config location
# Import Middleware and Services
# Import necessary types for middleware
# Remove direct imports of handlers/repos if not needed elsewhere in main
# from app.infrastructure.security.password.password_handler import PasswordHandler
# from app.domain.repositories.user_repository import UserRepository
# from unittest.mock import MagicMock
# Import settings and the factory function
from app.app_factory import create_application
from app.core.config.settings import get_settings
from app.core.logging_config import LOGGING_CONFIG

# Setup logging
logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger(__name__)

# settings = get_settings() # Legacy settings load

# Create application instance using the factory
# app = create_application(settings_override=settings) # Moved to if __name__ == "__main__"

if __name__ == "__main__":
    # This block runs only when the script is executed directly (e.g., by Uvicorn)
    # Load settings when running as main
    from app.core.config.settings import (
        get_settings as get_core_settings,
    )  # Ensure correct get_settings

    settings = get_core_settings()

    # Create application instance using the factory
    app = create_application(settings_override=settings)

    logger.info(
        f"Starting Uvicorn server. Host: {settings.SERVER_HOST}, Port: {settings.SERVER_PORT}, LogLevel: {settings.LOG_LEVEL.lower()}"
    )
    uvicorn.run(
        "app.main:app",  # Point to the app instance within this block
        host=settings.SERVER_HOST,
        port=settings.SERVER_PORT,
        log_level=settings.LOG_LEVEL.lower(),
        reload=settings.UVICORN_RELOAD,
        workers=settings.UVICORN_WORKERS,
    )
