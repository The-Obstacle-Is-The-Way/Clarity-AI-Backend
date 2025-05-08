"""
HIPAA-compliant Async SQLAlchemy Unit of Work implementation.

This module provides a robust implementation of the Unit of Work pattern using AsyncIO and SQLAlchemy,
ensuring transactional integrity for PHI data operations according to HIPAA requirements.
"""

import logging
from typing import Any

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.interfaces.unit_of_work import IUnitOfWork
from app.core.interfaces.repositories.biometric_alert_repository import IBiometricAlertRepository
from app.core.interfaces.repositories.biometric_rule_repository import IBiometricRuleRepository
from app.core.interfaces.repositories.biometric_twin_repository import IBiometricTwinRepository
from app.core.interfaces.repositories.digital_twin_repository import IDigitalTwinRepository
from app.core.interfaces.repositories.patient_repository import IPatientRepository
from app.core.interfaces.repositories.user_repository_interface import IUserRepository
from app.domain.exceptions import RepositoryError

# Configure logger
logger = logging.getLogger(__name__)

class AsyncSQLAlchemyUnitOfWork(IUnitOfWork):
    """
    Async SQLAlchemy Unit of Work implementation that follows HIPAA guidelines.
    Manages session lifecycle and transaction boundaries for secure PHI data access.
    """

    def __init__(
        self, 
        session_factory: async_sessionmaker[AsyncSession],
        user_repository_cls: type[IUserRepository],
        patient_repository_cls: type[IPatientRepository],
        digital_twin_repository_cls: type[IDigitalTwinRepository],
        biometric_rule_repository_cls: type[IBiometricRuleRepository],
        biometric_alert_repository_cls: type[IBiometricAlertRepository],
        biometric_twin_repository_cls: type[IBiometricTwinRepository]
    ):
        """
        Initialize the Unit of Work with repository factories.

        Args:
            session_factory: Async SQLAlchemy session factory
            user_repository_cls: User repository class
            patient_repository_cls: Patient repository class 
            digital_twin_repository_cls: Digital twin repository class
            biometric_rule_repository_cls: Biometric rule repository class
            biometric_alert_repository_cls: Biometric alert repository class
            biometric_twin_repository_cls: Biometric twin repository class
        """
        self.session_factory = session_factory
        self._session: AsyncSession | None = None
        
        # Store repository classes
        self._user_repository_cls = user_repository_cls
        self._patient_repository_cls = patient_repository_cls
        self._digital_twin_repository_cls = digital_twin_repository_cls
        self._biometric_rule_repository_cls = biometric_rule_repository_cls
        self._biometric_alert_repository_cls = biometric_alert_repository_cls
        self._biometric_twin_repository_cls = biometric_twin_repository_cls
        
        # Repository instances - lazily initialized
        self._repositories: dict[str, Any] = {}
        
        # Transaction state
        self._transaction_started = False

    async def __aenter__(self) -> 'AsyncSQLAlchemyUnitOfWork':
        """
        Enter the async context manager, beginning a new transaction.
        
        Returns:
            The UnitOfWork instance for method chaining
        """
        self._session = self.session_factory()
        await self._session.begin()
        self._transaction_started = True
        logger.debug("Started async UoW context: Session created, transaction begun.")
        return self

    async def __aexit__(
        self, 
        exc_type: type[BaseException] | None, 
        exc_val: BaseException | None, 
        exc_tb: Any | None
    ) -> None:
        """
        Exit the async context manager, handling commit or rollback based on exceptions.
        
        Args:
            exc_type: The exception type if an exception was raised
            exc_val: The exception value if an exception was raised
            exc_tb: The traceback if an exception was raised
        """
        if self._session is None:
            logger.warning("Exiting UoW context with no active session.")
            return

        try:
            if exc_type:
                # Exception occurred, rollback the transaction
                logger.info(f"Rolling back transaction due to exception: {exc_val}")
                await self._session.rollback()
            else:
                # No exception, commit the transaction
                logger.debug("Committing transaction")
                await self._session.commit()
        except SQLAlchemyError as e:
            logger.error(f"Error during transaction cleanup: {e}")
            if self._session and self._transaction_started:
                await self._session.rollback()
            raise RepositoryError(f"Database error during transaction: {e!s}") from e
        finally:
            if self._session:
                await self._session.close()
                self._session = None
                self._transaction_started = False
            # Clear cached repository instances
            self._repositories = {}

    async def commit(self) -> None:
        """
        Commit all changes made within the transaction.
        
        This method persists all changes made through repositories within this
        unit of work to the underlying database or storage mechanism.
        
        Raises:
            RepositoryError: If no session is active
        """
        if self._session is None or not self._transaction_started:
            raise RepositoryError("No active transaction to commit.")
        
        try:
            await self._session.commit()
            # Start a new transaction for continued use within the context
            await self._session.begin()
        except SQLAlchemyError as e:
            logger.error(f"Error during commit: {e}")
            raise RepositoryError(f"Failed to commit transaction: {e!s}") from e

    async def rollback(self) -> None:
        """
        Rollback all changes made within the transaction.
        
        This method discards all changes made through repositories within this
        unit of work, leaving the database or storage mechanism unchanged.
        
        Raises:
            RepositoryError: If no session is active
        """
        if self._session is None or not self._transaction_started:
            raise RepositoryError("No active transaction to roll back.")
        
        try:
            await self._session.rollback()
            # Start a new transaction for continued use within the context
            await self._session.begin()
        except SQLAlchemyError as e:
            logger.error(f"Error during rollback: {e}")
            raise RepositoryError(f"Failed to roll back transaction: {e!s}") from e

    # Repository properties
    @property
    def users(self) -> IUserRepository:
        """Access to the user repository within this transaction."""
        if self._session is None:
            raise RepositoryError("No active session. Use 'async with unit_of_work:' context.")
        
        if "users" not in self._repositories:
            self._repositories["users"] = self._user_repository_cls(self._session)
        
        return self._repositories["users"]

    @property
    def patients(self) -> IPatientRepository:
        """Access to the patient repository within this transaction."""
        if self._session is None:
            raise RepositoryError("No active session. Use 'async with unit_of_work:' context.")
        
        if "patients" not in self._repositories:
            self._repositories["patients"] = self._patient_repository_cls(self._session)
        
        return self._repositories["patients"]

    @property
    def digital_twins(self) -> IDigitalTwinRepository:
        """Access to the digital twin repository within this transaction."""
        if self._session is None:
            raise RepositoryError("No active session. Use 'async with unit_of_work:' context.")
        
        if "digital_twins" not in self._repositories:
            self._repositories["digital_twins"] = self._digital_twin_repository_cls(self._session)
        
        return self._repositories["digital_twins"]

    @property
    def biometric_rules(self) -> IBiometricRuleRepository:
        """Access to the biometric rule repository within this transaction."""
        if self._session is None:
            raise RepositoryError("No active session. Use 'async with unit_of_work:' context.")
        
        if "biometric_rules" not in self._repositories:
            self._repositories["biometric_rules"] = self._biometric_rule_repository_cls(self._session)
        
        return self._repositories["biometric_rules"]

    @property
    def biometric_alerts(self) -> IBiometricAlertRepository:
        """Access to the biometric alert repository within this transaction."""
        if self._session is None:
            raise RepositoryError("No active session. Use 'async with unit_of_work:' context.")
        
        if "biometric_alerts" not in self._repositories:
            self._repositories["biometric_alerts"] = self._biometric_alert_repository_cls(self._session)
        
        return self._repositories["biometric_alerts"]

    @property
    def biometric_twins(self) -> IBiometricTwinRepository:
        """Access to the biometric twin repository within this transaction."""
        if self._session is None:
            raise RepositoryError("No active session. Use 'async with unit_of_work:' context.")
        
        if "biometric_twins" not in self._repositories:
            self._repositories["biometric_twins"] = self._biometric_twin_repository_cls(self._session)
        
        return self._repositories["biometric_twins"] 