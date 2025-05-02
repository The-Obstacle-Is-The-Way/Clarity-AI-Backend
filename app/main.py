# -*- coding: utf-8 -*-
"""
NOVAMIND FastAPI Application

This is the main application entry point for the NOVAMIND backend API.
It configures the FastAPI application, registers routes, middleware, and
event handlers.
"""

import logging
import logging.config
import asyncio
from typing import Optional, Dict, Any
import os

# Monkey-patch httpx.AsyncClient to support 'app' parameter for FastAPI testing
try:
    import httpx
    from httpx import AsyncClient as _AsyncClient, ASGITransport
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

from fastapi import FastAPI, Depends, Request as FastapiRequest, status
from starlette.requests import Request as StarletteRequest
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

# Use the new canonical config location
from app.config.settings import get_settings
            
from app.infrastructure.persistence.sqlalchemy.config.database import get_db_instance, get_db_session
from app.presentation.api.routes import setup_routers 

# Import Middleware and Services
from app.presentation.middleware.authentication_middleware import AuthenticationMiddleware
from app.presentation.middleware.rate_limiting_middleware import setup_rate_limiting
from app.presentation.middleware.phi_middleware import PHIMiddleware  # PHI middleware (disabled in setup)

# Import necessary types for middleware
from starlette.responses import Response
from typing import Callable, Awaitable

# Import service provider functions needed for middleware instantiation
from app.presentation.dependencies.auth import get_authentication_service
from app.presentation.dependencies.auth import get_jwt_service

# Remove direct imports of handlers/repos if not needed elsewhere in main
# from app.infrastructure.security.password.password_handler import PasswordHandler
# from app.domain.repositories.user_repository import UserRepository
# from unittest.mock import MagicMock

# Import settings and the factory function
from app.app_factory import create_application
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