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
from app.core.interfaces.repositories.biometric_alert_repository import (
    IBiometricAlertRepository,
)
from app.core.interfaces.repositories.biometric_rule_repository import (
    IBiometricRuleRepository,
)
from app.core.interfaces.repositories.biometric_twin_repository import (
    IBiometricTwinRepository,
)
from app.core.interfaces.repositories.digital_twin_repository import (
    IDigitalTwinRepository,
)
from app.core.interfaces.repositories.patient_repository import IPatientRepository
from app.core.interfaces.repositories.user_repository_interface import IUserRepository
from app.domain.exceptions import RepositoryError
from app.core.utils.logging import get_logger

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
        biometric_twin_repository_cls: type[IBiometricTwinRepository],
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
        self.logger = get_logger(__name__)
        self.logger.debug(
            f"UoW {id(self)}: __init__ called. Session factory: {session_factory}"
        )
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

    async def __aenter__(self) -> "AsyncSQLAlchemyUnitOfWork":
        """
        Enter the async context manager, beginning a new transaction.

        Returns:
            The UnitOfWork instance for method chaining
        """
        self.logger.debug(
            f"UoW {id(self)}: __aenter__ called. Current self._session: {id(self._session) if self._session else 'None'}"
        )
        self._session = self.session_factory()
        await self._session.begin()
        self._transaction_started = True
        self.logger.debug(
            "Started async UoW context: Session created, transaction begun."
        )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any | None,
    ) -> None:
        """
        Exit the async context manager, handling commit or rollback based on exceptions.

        Args:
            exc_type: The exception type if an exception was raised
            exc_val: The exception value if an exception was raised
            exc_tb: The traceback if an exception was raised
        """
        self.logger.debug(
            f"UoW {id(self)}: __aexit__ called. Session before exit: {id(self._session) if self._session else 'None'}. exc_type: {exc_type}"
        )
        if self._session is None:
            self.logger.warning(
                f"UoW {id(self)}: __aexit__ called but self._session is None. No rollback/commit/close action taken."
            )
            return

        try:
            if exc_type:
                # Exception occurred, rollback the transaction
                self.logger.info(
                    f"Rolling back transaction due to exception: {exc_val}"
                )
                await self._session.rollback()
            else:
                # No exception, commit the transaction
                self.logger.debug("Committing transaction")
                await self._session.commit()
        except SQLAlchemyError as e:
            self.logger.error(f"Error during transaction cleanup: {e}")
            if self._session and self._transaction_started:
                await self._session.rollback()
            raise RepositoryError(f"Database error during transaction: {e!s}") from e
        finally:
            if self._session:
                await self._session.close()
                self.logger.debug(
                    f"UoW {id(self)}: Session {id(self._session)} closed."
                )
            self._session = None
            self.logger.debug(
                f"UoW {id(self)}: self._session reset to None after __aexit__."
            )
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
        self.logger.debug(
            f"UoW {id(self)} users property: Accessing. Current self._session ID: {id(self._session) if self._session else 'None'}. Transaction started: {self._transaction_started}"
        )
        if self._session is None:
            self.logger.error(
                f"UoW {id(self)} users property: self._session is None. Raising RepositoryError."
            )
            raise RepositoryError(
                "No active session. Use 'async with unit_of_work:' context."
            )

        if "users" not in self._repositories:
            self.logger.debug(
                f"UoW {id(self)} users property: Creating new repository instance with session ID {id(self._session)}."
            )
            self._repositories["users"] = self._user_repository_cls(
                uow_session=self._session
            )
        else:
            self.logger.debug(
                f"UoW {id(self)} users property: Returning existing repository instance. Its uow_session ID: {id(self._repositories['users'].uow_session) if hasattr(self._repositories['users'], 'uow_session') and self._repositories['users'].uow_session else 'N/A or None'}"
            )

        return self._repositories["users"]

    @property
    def patients(self) -> IPatientRepository:
        """Access to the patient repository within this transaction."""
        self.logger.debug(
            f"UoW {id(self)} patients property: Accessing. Current self._session ID: {id(self._session) if self._session else 'None'}. Transaction started: {self._transaction_started}"
        )
        if self._session is None:
            self.logger.error(
                f"UoW {id(self)} patients property: self._session is None. Raising RepositoryError."
            )
            raise RepositoryError(
                "No active session. Use 'async with unit_of_work:' context."
            )

        if "patients" not in self._repositories:
            self.logger.debug(
                f"UoW {id(self)} patients property: Creating new repository instance with session ID {id(self._session)}."
            )
            self._repositories["patients"] = self._patient_repository_cls(
                uow_session=self._session
            )
        else:
            self.logger.debug(
                f"UoW {id(self)} patients property: Returning existing repository instance. Its uow_session ID: {id(self._repositories['patients'].uow_session) if hasattr(self._repositories['patients'], 'uow_session') and self._repositories['patients'].uow_session else 'N/A or None'}"
            )

        return self._repositories["patients"]

    @property
    def digital_twins(self) -> IDigitalTwinRepository:
        """Access to the digital twin repository within this transaction."""
        self.logger.debug(
            f"UoW {id(self)} digital_twins property: Accessing. Current self._session ID: {id(self._session) if self._session else 'None'}. Transaction started: {self._transaction_started}"
        )
        if self._session is None:
            self.logger.error(
                f"UoW {id(self)} digital_twins property: self._session is None. Raising RepositoryError."
            )
            raise RepositoryError(
                "No active session. Use 'async with unit_of_work:' context."
            )

        if "digital_twins" not in self._repositories:
            self.logger.debug(
                f"UoW {id(self)} digital_twins property: Creating new repository instance with session ID {id(self._session)}."
            )
            self._repositories["digital_twins"] = self._digital_twin_repository_cls(
                uow_session=self._session
            )
        else:
            self.logger.debug(
                f"UoW {id(self)} digital_twins property: Returning existing repository instance. Its uow_session ID: {id(self._repositories['digital_twins'].uow_session) if hasattr(self._repositories['digital_twins'], 'uow_session') and self._repositories['digital_twins'].uow_session else 'N/A or None'}"
            )

        return self._repositories["digital_twins"]

    @property
    def biometric_rules(self) -> IBiometricRuleRepository:
        """Access to the biometric rule repository within this transaction."""
        self.logger.debug(
            f"UoW {id(self)} biometric_rules property: Accessing. Current self._session ID: {id(self._session) if self._session else 'None'}. Transaction started: {self._transaction_started}"
        )
        if self._session is None:
            self.logger.error(
                f"UoW {id(self)} biometric_rules property: self._session is None. Raising RepositoryError."
            )
            raise RepositoryError(
                "No active session. Use 'async with unit_of_work:' context."
            )

        if "biometric_rules" not in self._repositories:
            self.logger.debug(
                f"UoW {id(self)} biometric_rules property: Creating new repository instance with session ID {id(self._session)}."
            )
            self._repositories["biometric_rules"] = self._biometric_rule_repository_cls(
                uow_session=self._session
            )
        else:
            self.logger.debug(
                f"UoW {id(self)} biometric_rules property: Returning existing repository instance. Its uow_session ID: {id(self._repositories['biometric_rules'].uow_session) if hasattr(self._repositories['biometric_rules'], 'uow_session') and self._repositories['biometric_rules'].uow_session else 'N/A or None'}"
            )

        return self._repositories["biometric_rules"]

    @property
    def biometric_alerts(self) -> IBiometricAlertRepository:
        """Access to the biometric alert repository within this transaction."""
        self.logger.debug(
            f"UoW {id(self)} biometric_alerts property: Accessing. Current self._session ID: {id(self._session) if self._session else 'None'}. Transaction started: {self._transaction_started}"
        )
        if self._session is None:
            self.logger.error(
                f"UoW {id(self)} biometric_alerts property: self._session is None. Raising RepositoryError."
            )
            raise RepositoryError(
                "No active session. Use 'async with unit_of_work:' context."
            )

        if "biometric_alerts" not in self._repositories:
            self.logger.debug(
                f"UoW {id(self)} biometric_alerts property: Creating new repository instance with session ID {id(self._session)}."
            )
            self._repositories[
                "biometric_alerts"
            ] = self._biometric_alert_repository_cls(uow_session=self._session)
        else:
            self.logger.debug(
                f"UoW {id(self)} biometric_alerts property: Returning existing repository instance. Its uow_session ID: {id(self._repositories['biometric_alerts'].uow_session) if hasattr(self._repositories['biometric_alerts'], 'uow_session') and self._repositories['biometric_alerts'].uow_session else 'N/A or None'}"
            )

        return self._repositories["biometric_alerts"]

    @property
    def biometric_twins(self) -> IBiometricTwinRepository:
        """Access to the biometric twin repository within this transaction."""
        self.logger.debug(
            f"UoW {id(self)} biometric_twins property: Accessing. Current self._session ID: {id(self._session) if self._session else 'None'}. Transaction started: {self._transaction_started}"
        )
        if self._session is None:
            self.logger.error(
                f"UoW {id(self)} biometric_twins property: self._session is None. Raising RepositoryError."
            )
            raise RepositoryError(
                "No active session. Use 'async with unit_of_work:' context."
            )

        if "biometric_twins" not in self._repositories:
            self.logger.debug(
                f"UoW {id(self)} biometric_twins property: Creating new repository instance with session ID {id(self._session)}."
            )
            self._repositories["biometric_twins"] = self._biometric_twin_repository_cls(
                uow_session=self._session
            )
        else:
            self.logger.debug(
                f"UoW {id(self)} biometric_twins property: Returning existing repository instance. Its uow_session ID: {id(self._repositories['biometric_twins'].uow_session) if hasattr(self._repositories['biometric_twins'], 'uow_session') and self._repositories['biometric_twins'].uow_session else 'N/A or None'}"
            )

        return self._repositories["biometric_twins"]
