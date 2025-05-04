"""
Factory for creating Unit of Work instances.

This module provides a clean, dependency-injection friendly way to create
UnitOfWork instances with their proper repository dependencies.
"""

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.interfaces.unit_of_work import IUnitOfWork
from app.infrastructure.persistence.sqlalchemy.async_unit_of_work import AsyncSQLAlchemyUnitOfWork
from app.infrastructure.persistence.sqlalchemy.repositories.biometric_alert_repository import (
    SQLAlchemyBiometricAlertRepository,
)
from app.infrastructure.persistence.sqlalchemy.repositories.biometric_rule_repository import (
    SQLAlchemyBiometricRuleRepository,
)
from app.infrastructure.persistence.sqlalchemy.repositories.biometric_twin_repository import (
    SQLAlchemyBiometricTwinRepository,
)
from app.infrastructure.persistence.sqlalchemy.repositories.digital_twin_repository import (
    SQLAlchemyDigitalTwinRepository,
)
from app.infrastructure.persistence.sqlalchemy.repositories.patient_repository import (
    SQLAlchemyPatientRepository,
)
from app.infrastructure.persistence.sqlalchemy.repositories.user_repository import (
    SQLAlchemyUserRepository,
)


class UnitOfWorkFactory:
    """
    Factory for creating UnitOfWork instances with proper dependencies.
    
    This class manages the creation of UnitOfWork instances with the
    correct repository implementations, ensuring proper dependency injection.
    """
    
    def __init__(
        self, 
        session_factory: async_sessionmaker[AsyncSession],
        user_repository_class=SQLAlchemyUserRepository,
        patient_repository_class=SQLAlchemyPatientRepository,
        digital_twin_repository_class=SQLAlchemyDigitalTwinRepository,
        biometric_rule_repository_class=SQLAlchemyBiometricRuleRepository,
        biometric_alert_repository_class=SQLAlchemyBiometricAlertRepository,
        biometric_twin_repository_class=SQLAlchemyBiometricTwinRepository
    ):
        """
        Initialize the factory with repository class dependencies.
        
        Args:
            session_factory: Factory for creating database sessions
            user_repository_class: Class to use for user repositories
            patient_repository_class: Class to use for patient repositories
            digital_twin_repository_class: Class to use for digital twin repositories
            biometric_rule_repository_class: Class to use for biometric rule repositories
            biometric_alert_repository_class: Class to use for biometric alert repositories
            biometric_twin_repository_class: Class to use for biometric twin repositories
        """
        self.session_factory = session_factory
        self._user_repository_class = user_repository_class
        self._patient_repository_class = patient_repository_class
        self._digital_twin_repository_class = digital_twin_repository_class
        self._biometric_rule_repository_class = biometric_rule_repository_class
        self._biometric_alert_repository_class = biometric_alert_repository_class
        self._biometric_twin_repository_class = biometric_twin_repository_class
    
    def create_unit_of_work(self) -> IUnitOfWork:
        """
        Create a new UnitOfWork instance with proper repository dependencies.
        
        Returns:
            A fully configured UnitOfWork instance
        """
        return AsyncSQLAlchemyUnitOfWork(
            session_factory=self.session_factory,
            user_repository_cls=self._user_repository_class,
            patient_repository_cls=self._patient_repository_class,
            digital_twin_repository_cls=self._digital_twin_repository_class,
            biometric_rule_repository_cls=self._biometric_rule_repository_class,
            biometric_alert_repository_cls=self._biometric_alert_repository_class,
            biometric_twin_repository_cls=self._biometric_twin_repository_class
        )
