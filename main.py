# -*- coding: utf-8 -*-
"""
Clarity-AI FastAPI Application
=============================
Main entry point for the Clarity-AI psychiatric platform.
Implements HIPAA-compliant API with proper security measures.
"""

import os
import time
import traceback
from contextlib import asynccontextmanager
from typing import Callable, Dict, Any, List, Optional

import uvicorn
from fastapi import FastAPI, Request, Response, status, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.routing import APIRouter
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from app.core.config.settings import settings
from app.core.utils.logging import get_logger

# Updated imports to match new structure
from app.presentation.api.routes import api_router, setup_routers
from app.infrastructure.di.container import get_container
from app.domain.exceptions import (
    NovaBaseException,
    EntityNotFoundException,
    ValidationException,
    AuthenticationException,
    AuthorizationException,
)
from app.infrastructure.persistence.sqlalchemy.config.database import (
    get_db_instance,
    get_db_session,
)

# Ensure this import is correct and remove any old, direct router imports below
# from app.presentation.api.routes.analytics_endpoints import router as analytics_router

# Initialize logger using the utility function
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for FastAPI application.
    Handles startup and shutdown events.
    """
    # Startup
    logger.info(
        f"Starting Clarity-AI API {settings.APP_VERSION} in {settings.ENVIRONMENT} environment"
    )

    # Initialize dependency injection container
    get_container()

    # Load ML models and other resources
    logger.info("All services initialized successfully")

    yield

    # Shutdown
    logger.info("Shutting down Clarity-AI API")


# Create FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    description="HIPAA-compliant psychiatric platform with Digital Twin technology",
    version=settings.APP_VERSION,
    docs_url="/api/docs" if settings.DEBUG else None,
    redoc_url="/api/redoc" if settings.DEBUG else None,
    openapi_url="/api/openapi.json" if settings.DEBUG else None,
    lifespan=lifespan,
)


# Security middleware
@app.middleware("http")
async def security_headers_middleware(
    request: Request, call_next: Callable
) -> Response:
    """Add security headers to all responses."""
    response = await call_next(request)

    # HIPAA-compliant security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers[
        "Strict-Transport-Security"
    ] = "max-age=31536000; includeSubDomains"
    response.headers[
        "Content-Security-Policy"
    ] = "default-src 'self'; script-src 'self'; object-src 'none'"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

    return response


# Request logging middleware
@app.middleware("http")
async def log_requests_middleware(request: Request, call_next: Callable) -> Response:
    """Log all requests with timing information."""
    start_time = time.time()

    # Redact potential PHI from URL for security
    path = request.url.path
    if any(endpoint in path for endpoint in ["/patients", "/appointments", "/medical"]):
        path_parts = path.split("/")
        # Redact potential IDs
        path_parts = [
            part if not part.isdigit() and not len(part) > 10 else "[REDACTED]"
            for part in path_parts
        ]
        path = "/".join(path_parts)

    logger.info(f"Request started: {request.method} {path}")

    try:
        response = await call_next(request)
        process_time = time.time() - start_time
        logger.info(
            f"Request completed: {request.method} {path} - Status: {response.status_code} - Time: {process_time:.4f}s"
        )
        return response
    except Exception as e:
        process_time = time.time() - start_time
        logger.error(
            f"Request failed: {request.method} {path} - Error: {str(e)} - Time: {process_time:.4f}s"
        )
        raise


# Exception handlers
@app.exception_handler(NovaBaseException)
async def base_exception_handler(
    request: Request, exc: NovaBaseException
) -> JSONResponse:
    """Handle all Clarity-AI custom exceptions."""
    logger.warning(f"Application exception: {exc.__class__.__name__}: {str(exc)}")
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.__class__.__name__,
            "message": str(exc),
            "details": exc.details if hasattr(exc, "details") else None,
            "error_code": exc.error_code if hasattr(exc, "error_code") else None,
        },
    )


@app.exception_handler(EntityNotFoundException)
async def not_found_exception_handler(
    request: Request, exc: EntityNotFoundException
) -> JSONResponse:
    """Handle entity not found exceptions."""
    logger.warning(f"Entity not found: {str(exc)}")
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={
            "error": "EntityNotFound",
            "message": str(exc),
            "entity_type": exc.entity_type if hasattr(exc, "entity_type") else None,
            "entity_id": exc.entity_id if hasattr(exc, "entity_id") else None,
        },
    )


@app.exception_handler(ValidationException)
async def validation_exception_handler(
    request: Request, exc: ValidationException
) -> JSONResponse:
    """Handle validation exceptions."""
    logger.warning(f"Validation error: {str(exc)}")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "ValidationError",
            "message": str(exc),
            "field_errors": exc.field_errors if hasattr(exc, "field_errors") else None,
        },
    )


@app.exception_handler(AuthenticationException)
async def auth_exception_handler(
    request: Request, exc: AuthenticationException
) -> JSONResponse:
    """Handle authentication exceptions."""
    logger.warning(f"Authentication error: {str(exc)}")
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={
            "error": "AuthenticationError",
            "message": str(exc),
        },
    )


@app.exception_handler(AuthorizationException)
async def auth_exception_handler(
    request: Request, exc: AuthorizationException
) -> JSONResponse:
    """Handle authorization exceptions."""
    logger.warning(f"Authorization error: {str(exc)}")
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={
            "error": "AuthorizationError",
            "message": str(exc),
        },
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle all unhandled exceptions with HIPAA-compliant error messages."""
    error_id = str(int(time.time()))
    logger.error(f"Unhandled exception [{error_id}]: {str(exc)}")
    logger.error(traceback.format_exc())

    # In production, don't return detailed error information
    if settings.is_production():
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "ServerError",
                "message": "An unexpected error occurred",
                "error_id": error_id,
            },
        )
    else:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "ServerError",
                "message": str(exc),
                "error_id": error_id,
                "traceback": traceback.format_exc().split("\n"),
            },
        )


# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.api.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["*"],
    max_age=600,
)

# Add Trusted Host middleware for security
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.api.ALLOWED_HOSTS)

# Add session middleware
app.add_middleware(SessionMiddleware, secret_key=settings.security.JWT_SECRET_KEY)

# Add GZip middleware for compression
app.add_middleware(GZipMiddleware, minimum_size=1000)

# --- Setup and Include API Routers ---
# Call the setup function to dynamically load and include all routers
setup_routers()

# Include the main aggregated router with the configured prefix
# Ensure the prefix logic matches settings
api_prefix = settings.api.API_V1_PREFIX  # Assuming settings structure
if api_prefix.endswith("/"):  # Normalize prefix
    api_prefix = api_prefix[:-1]
app.include_router(api_router, prefix=api_prefix)
# --- End Router Setup ---


# Mount static files
app.mount("/static", StaticFiles(directory=str(settings.STATIC_DIR)), name="static")

# Web templates
templates = Jinja2Templates(directory=str(settings.TEMPLATES_DIR))


# Root route for health checks
@app.get("/", tags=["Health"])
async def root():
    """API root endpoint for health checks."""
    return {
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "healthy",
        "environment": settings.ENVIRONMENT,
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """Detailed health check endpoint for monitoring systems."""
    # Check critical services
    health_status = {
        "status": "healthy",
        "timestamp": time.time(),
        "version": settings.APP_VERSION,
        "services": {
            "api": "up",
            "database": "up",  # This should be checked properly in a real implementation
            "ml_services": "up",  # This should be checked properly in a real implementation
        },
    }

    return health_status


# Run application when executed directly
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.api.HOST,
        port=settings.api.PORT,
        reload=settings.DEBUG,
        log_level=settings.logging.LOG_LEVEL.lower(),
        ssl_keyfile=settings.security.SSL_KEY_PATH
        if settings.security.ENFORCE_HTTPS
        else None,
        ssl_certfile=settings.security.SSL_CERT_PATH
        if settings.security.ENFORCE_HTTPS
        else None,
    )
