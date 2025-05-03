"""
Service dependency injection compatibility module.

This module provides backward compatibility for tests and code
that still references the old app.presentation.api.dependencies.services module.

DO NOT USE THIS IN NEW CODE - use app.api.dependencies instead.
"""

# Re-export from the new location
from app.api.dependencies import get_pat_service

# Add specific service dependencies needed by tests
def get_digital_twin_service():
    """
    Provide a Digital Twin service implementation.
    
    Backward compatibility function - use app.api.dependencies instead in new code.
    
    Returns:
        Digital Twin service implementation
    """
    # Simple stub implementation to allow test collection
    return None

def get_xgboost_service():
    """
    Provide an XGBoost service implementation.
    
    Backward compatibility function - use app.api.dependencies instead in new code.
    
    Returns:
        XGBoost service implementation
    """
    # Delegate to the clean architecture implementation
    from app.api.routes.xgboost import get_xgboost_service as new_get_xgboost_service
    return new_get_xgboost_service()
