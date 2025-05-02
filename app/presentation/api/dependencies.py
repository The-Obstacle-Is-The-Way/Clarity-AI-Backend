"""
API dependency injection for Clarity AI Backend.

This module provides dependency injection functions for the API layer,
establishing a clean, testable architecture for the application through
proper dependency wiring that ensures HIPAA compliance and transaction safety.
"""

import logging
from collections.abc import AsyncGenerator
from typing import Annotated

from fastapi import Depends

from app.core.interfaces.unit_of_work import IUnitOfWork
from app.application.services.digital_twin_service import DigitalTwinService
from app.infrastructure.persistence.sqlalchemy.repositories.digital_twin_repository import SQLAlchemyDigitalTwinRepository
from app.core.dependencies.database import get_db_session
from app.infrastructure.persistence.sqlalchemy.unit_of_work_factory import UnitOfWorkFactory
from app.infrastructure.database.session import async_session_factory

logger = logging.getLogger(__name__)

# UnitOfWork factory instance
_unit_of_work_factory = UnitOfWorkFactory(
    session_factory=async_session_factory
)

async def get_unit_of_work() -> AsyncGenerator[IUnitOfWork, None]:
    """
    Get a Unit of Work instance for dependency injection.
    
    This dependency provides a transactional boundary for database operations,
    which is critical for maintaining data integrity in accordance with HIPAA.
    It ensures that all database operations within a request are atomic.
    
    Yields:
        An IUnitOfWork instance
    """
    unit_of_work = _unit_of_work_factory.create_unit_of_work()
    async with unit_of_work:
        yield unit_of_work

def get_digital_twin_repository(session: AsyncSession = Depends(get_db_session)) -> SQLAlchemyDigitalTwinRepository:
    """
    Get a digital twin repository instance.
    
    Args:
        session: Database session
        
    Returns:
        SQLAlchemyDigitalTwinRepository instance
    """
    return SQLAlchemyDigitalTwinRepository(session)

def get_digital_twin_service(repository: SQLAlchemyDigitalTwinRepository = Depends(get_digital_twin_repository)) -> DigitalTwinService:
    """
    Get a digital twin service instance.
    
    Args:
        repository: Digital twin repository
        
    Returns:
        DigitalTwinService instance
    """
    return DigitalTwinService(repository)

# Type aliases for common dependencies
UnitOfWorkDep = Annotated[IUnitOfWork, Depends(get_unit_of_work)]
DigitalTwinServiceDep = Annotated[DigitalTwinService, Depends(get_digital_twin_service)]