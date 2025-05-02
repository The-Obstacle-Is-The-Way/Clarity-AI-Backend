# -*- coding: utf-8 -*-
"""
NOVAMIND FastAPI Application

This is the main application entry point for the NOVAMIND backend API.
It configures the FastAPI application, registers routes, middleware, and
event handlers.
"""

import logging
from contextlib import asynccontextmanager
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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for FastAPI application.
    
    This handles application startup and shutdown events, including database initialization
    and connection cleanup.
    
    Args:
        app: FastAPI application instance
    """
    # Startup events
    logger.info("Starting NOVAMIND application")
    
    # Initialize AWS services
    from app.api.aws_init import initialize_aws_services
    logger.info("Initializing AWS services")
    initialize_aws_services()
    logger.info("AWS services initialized")
    
    # Initialize database
    db_instance = get_db_instance()
    # Ensure create_all is awaited if it's an async operation
    if hasattr(db_instance, 'create_all') and callable(getattr(db_instance, 'create_all')):
        # Temporarily comment out to isolate potential startup errors
        # await db_instance.create_all()
        logger.warning("Temporarily skipped db_instance.create_all() in lifespan for testing.")
        pass # Keep the if block valid
    
    # Yield control to the application
    logger.info("ASGI lifespan startup complete.")
    yield
    
    # Shutdown events
    logger.info("ASGI lifespan shutdown starting.")
    # Close database connections
    await db_instance.dispose()
    logger.info("ASGI lifespan shutdown complete.")


def create_application(dependency_overrides: Optional[Dict[Callable, Callable]] = None) -> FastAPI:
    """
    Create and configure the FastAPI application.
    
    Args:
        dependency_overrides: Optional dictionary to override dependencies.
    
    Returns:
        FastAPI: Configured FastAPI application
    """
    # Clear settings cache (e.g., to pick up TESTING flag) and get settings values
    try:
        get_settings.cache_clear()
    except Exception:
        pass
    settings = get_settings()
    project_name = settings.PROJECT_NAME
    app_description = getattr(settings, 'APP_DESCRIPTION', '')
    version = settings.VERSION
    
    app = FastAPI(
        title=project_name,
        description=app_description,
        version=version,
        lifespan=lifespan, # Use the defined lifespan manager
        dependency_overrides=dependency_overrides or {} # Apply overrides here
    )
    
    # --- Add Middleware (Order Matters!) ---
    
    # 1. CORS Middleware (Handles cross-origin requests first)
    origins = settings.BACKEND_CORS_ORIGINS
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=[str(origin) for origin in origins],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
    # 2. Error Handling Middleware (Outermost)
    # app.add_middleware(ErrorHandlingMiddleware)

    # 3. Security Headers
    # app.add_middleware(SecurityHeadersMiddleware)

    # 4. Authentication Middleware 
    # REMOVE the problematic container resolution block below
    # from app.infrastructure.di.container import container
    # try:
    #     from app.infrastructure.security.auth.authentication_service import AuthenticationService
    #     from app.core.interfaces.services.jwt_service import IJwtService
    #     logger.info("[create_application] Attempting to resolve services from container...")
    #     auth_service = container.resolve(AuthenticationService) 
    #     jwt_service = container.resolve(IJwtService)
    #     logger.info("[create_application] Successfully resolved services from container.")
    # except Exception as e:
    #     import traceback 
    #     logger.warning(f"[create_application] Could not resolve services from container. Exception Type: {type(e).__name__}, Message: {e}. Using direct instantiation.") 
    #     logger.warning(f"[create_application] Traceback:\n{traceback.format_exc()}")
    #     # Fallback logic removed...
    
    # AuthenticationMiddleware itself should handle its dependencies via FastAPI's Depends
    app.add_middleware(
        AuthenticationMiddleware,
        public_paths={
            "/openapi.json",
            "/docs",
            "/api/v1/auth/refresh",
            "/health",
        }
    )
    
    # 5. PHI Sanitization/Auditing Middleware (Processes after auth)
    # Disabled temporarily to ensure API request bodies are available for Pydantic parsing
    # add_phi_middleware(...) is omitted here

    # 6. Rate Limiting Middleware (Applies limits after auth & PHI handling)
    setup_rate_limiting(app)

    # 7. Security Headers Middleware (Adds headers to the final response using decorator style)
    @app.middleware("http")
    async def security_headers_middleware(
        request: FastapiRequest,
        call_next: Callable[[FastapiRequest], Awaitable[Response]]
    ) -> Response:
        """Add basic security headers to all responses."""
        logger.info(f"---> SecurityHeadersMiddleware: Executing for path: {request.url.path}") # DEBUG log
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        logger.info(f"---> SecurityHeadersMiddleware: Set X-Content-Type-Options header for path: {request.url.path}") # DEBUG log
        # Add other security headers here if needed, e.g.:
        # response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        # response.headers["X-Frame-Options"] = "DENY"
        return response
    
    # --- Setup Routers ---
    # Fetch the configured router instance from the setup function
    configured_api_router = setup_routers()
    
    api_prefix = settings.API_V1_STR
    if api_prefix.endswith('/'):
        api_prefix = api_prefix[:-1]
    
    # Include the configured router instance
    # Mount API router under versioned prefix
    app.include_router(configured_api_router, prefix=api_prefix)
    # Also mount API router at root for legacy/integration tests that expect unprefixed paths
    # app.include_router(configured_api_router) # Temporarily commented out to resolve potential conflicts
    
    # --- Static Files (Optional) ---
    static_dir = getattr(settings, 'STATIC_DIR', None)
    if static_dir:
        app.mount("/static", StaticFiles(directory=static_dir), name="static")
    
    # --- Add Custom Exception Handlers ---
    from fastapi.responses import JSONResponse
    import traceback

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: StarletteRequest, exc: Exception):
        # Log the full error internally
        logger.error(f"Unhandled exception caught for request {request.method} {request.url.path}: {exc}", exc_info=True)
        # Return a generic 500 response to the client
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            content={"detail": "Internal server error"}
        )

    return app

# Create the main FastAPI application instance using the factory function
# Always initialize the full application regardless of skip flag
app = create_application()

# Entry point for running the application directly (e.g., with `python app/main.py`)
# This is typically used for local development/debugging.
if __name__ == "__main__":
    import uvicorn
    logger.info("Starting application directly using uvicorn for development.")
    # Load settings to get host and port for uvicorn
    # Ensure settings are loaded correctly here for direct execution
    try:
        run_settings = get_settings()
        uvicorn.run(
            # Point uvicorn to the location of the factory function or the app instance
            # If using the factory pattern, it's often cleaner to point to the factory:
            "app.main:create_application", 
            # Or if you need the instance (ensure it's created only here):
            # app, 
            host=run_settings.HOST,
            port=run_settings.PORT,
            reload=run_settings.RELOAD, # Enable reload based on settings
            factory=True # Indicate that the import string points to a factory
        )
    except Exception as e:
        logger.critical(f"Failed to start uvicorn: {e}", exc_info=True)
        # Optionally, exit with an error code
        # import sys
        # sys.exit(1)