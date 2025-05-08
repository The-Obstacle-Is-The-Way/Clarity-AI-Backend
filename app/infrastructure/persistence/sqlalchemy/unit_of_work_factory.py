"""
This module is deprecated and will be removed in a future version.
Import UnitOfWorkFactory from app.infrastructure.persistence.sqlalchemy.unit_of_work.unit_of_work_factory instead.
"""

import warnings

warnings.warn(
    "This module is deprecated. Import UnitOfWorkFactory from "
    "app.infrastructure.persistence.sqlalchemy.unit_of_work.unit_of_work_factory instead.",
    DeprecationWarning,
    stacklevel=2
)

from app.infrastructure.persistence.sqlalchemy.unit_of_work.unit_of_work_factory import UnitOfWorkFactory

__all__ = ["UnitOfWorkFactory"]
