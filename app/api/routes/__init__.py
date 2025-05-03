"""API routes package with route registration functions.

Provides utilities for dynamically registering API routes in the FastAPI application.
"""

from fastapi import APIRouter, FastAPI
from typing import List, Optional
import importlib
import logging
import os
import pkgutil


def setup_routers(app: FastAPI) -> None:
    """
    Setup all API routers from the routes module.
    
    This function dynamically discovers and registers all router modules in the API routes package.
    It ensures that all API endpoints defined in routing modules are properly mounted to the application.
    
    Args:
        app: FastAPI application instance to attach routers to
    """
    # Get the main API router
    api_router = APIRouter(prefix="/api")
    
    # Import and mount specific route modules
    from app.api.routes import auth
    api_router.include_router(auth.router, prefix="/auth", tags=["authentication"])
    
    # Try to import other router modules if available
    package_path = os.path.dirname(__file__)
    for _, module_name, is_pkg in pkgutil.iter_modules([package_path]):
        if not is_pkg and module_name not in ["__init__", "auth"]:
            try:
                module = importlib.import_module(f"app.api.routes.{module_name}")
                if hasattr(module, "router") and isinstance(module.router, APIRouter):
                    # Use the module name as the path prefix and tag
                    api_router.include_router(
                        module.router, 
                        prefix=f"/{module_name}", 
                        tags=[module_name]
                    )
            except ImportError:
                logging.warning(f"Could not import router module: {module_name}")
    
    # Add the main API router to the app
    app.include_router(api_router)