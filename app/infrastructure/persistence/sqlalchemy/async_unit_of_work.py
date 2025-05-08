"""
This module is deprecated and will be removed in a future version.
Import AsyncSQLAlchemyUnitOfWork from app.infrastructure.persistence.sqlalchemy.unit_of_work.async_unit_of_work instead.
"""

import warnings

warnings.warn(
    "This module is deprecated. Import AsyncSQLAlchemyUnitOfWork from "
    "app.infrastructure.persistence.sqlalchemy.unit_of_work.async_unit_of_work instead.",
    DeprecationWarning,
    stacklevel=2
)

from app.infrastructure.persistence.sqlalchemy.unit_of_work.async_unit_of_work import AsyncSQLAlchemyUnitOfWork

__all__ = ["AsyncSQLAlchemyUnitOfWork"]
