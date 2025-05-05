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
try:
    import httpx
    from httpx import ASGITransport
    from httpx import AsyncClient as _AsyncClient
    class AsyncClient(_AsyncClient):
        def __init__(self, *args, app=None, **kwargs):
            if app is not None:
                # Use ASGI transport for FastAPI app
                kwargs['transport'] = ASGITransport(app=app)
            super().__init__(*args, **kwargs)
            # Store reference to FastAPI app for fixture access
            if app is not None:
                self.app = app
    httpx.AsyncClient = AsyncClient
except ImportError:
    pass


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

# Get settings instance
settings = get_settings()

# Create the FastAPI application instance using the factory
app = create_application(settings)


# --- Main Execution Block (for running with uvicorn directly) ---
if __name__ == "__main__":
    logger.info("Starting application using uvicorn...")
    uvicorn.run(
        "app.main:app", # Point to the app object in this file
        host=settings.SERVER_HOST,
        port=settings.SERVER_PORT,
        reload=settings.DEBUG, # Enable reload only if DEBUG is True
        log_level=settings.LOG_LEVEL.lower(),
        workers=settings.UVICORN_WORKERS if settings.ENVIRONMENT == "production" else 1,
    )