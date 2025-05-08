"""
This module is deprecated and will be removed in a future version.
Import SQLAlchemyUnitOfWork from app.infrastructure.persistence.sqlalchemy.unit_of_work.unit_of_work instead.
"""

import warnings

warnings.warn(
    "This module is deprecated. Import SQLAlchemyUnitOfWork from "
    "app.infrastructure.persistence.sqlalchemy.unit_of_work.unit_of_work instead.",
    DeprecationWarning,
    stacklevel=2
)

from app.infrastructure.persistence.sqlalchemy.unit_of_work.unit_of_work import SQLAlchemyUnitOfWork, UnitOfWork

__all__ = ["SQLAlchemyUnitOfWork", "UnitOfWork"]