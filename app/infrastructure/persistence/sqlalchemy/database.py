"""
This module is deprecated and will be removed in a future version.
Import Database classes from app.infrastructure.persistence.sqlalchemy.config.database instead.
"""

import warnings

warnings.warn(
    "This module is deprecated. Import database components from "
    "app.infrastructure.persistence.sqlalchemy.config.database instead.",
    DeprecationWarning,
    stacklevel=2
)

# Re-export the classes from config/database.py
from app.infrastructure.persistence.sqlalchemy.config.database import (
    Database, 
    get_db_instance, 
    get_db_session,
    DBSessionDep
)

# The Database and EnhancedDatabase classes were merged in config/database.py
# For backward compatibility, we'll continue to provide EnhancedDatabase as an alias
EnhancedDatabase = Database

# For backward compatibility with code that imports Base from here
from app.infrastructure.persistence.sqlalchemy.models.base import Base

# Also re-export the registry functions used by database.py
from app.infrastructure.persistence.sqlalchemy.registry import ensure_all_models_registered

__all__ = [
    "Database",
    "EnhancedDatabase",
    "Base",
    "get_db_instance",
    "get_db_session",
    "DBSessionDep",
    "ensure_all_models_registered"
]