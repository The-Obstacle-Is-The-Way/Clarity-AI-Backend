"""
Repository for HIPAA-compliant audit logs.

This repository handles database operations for audit logs, providing a clean 
abstraction over the persistence layer for the audit logging system.
"""

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import and_, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.core.interfaces.repositories.audit_log_repository_interface import (
    IAuditLogRepository,
)
from app.domain.entities.audit_log import AuditLog
from app.infrastructure.persistence.sqlalchemy.models.audit_log import (
    AuditLog as AuditLogModel,
)


class AuditLogRepository(IAuditLogRepository):
    """
    Repository for HIPAA-compliant audit logs, providing persistence operations.

    This implementation uses SQLAlchemy to store audit logs in a relational database.
    The repository follows the repository pattern to abstract persistence details.
    """

    def __init__(self, session: AsyncSession):
        """
        Initialize the audit log repository with a database session.

        Args:
            session: SQLAlchemy async session for database operations
        """
        self._session = session

    async def create(self, audit_log: AuditLog) -> str:
        """
        Create a new audit log entry in the database.

        Args:
            audit_log: Domain entity representing the audit log entry

        Returns:
            str: ID of the created audit log entry
        """
        # Convert domain entity to database model
        model = AuditLogModel(
            id=audit_log.id or uuid.uuid4(),
            timestamp=audit_log.timestamp or datetime.now(timezone.utc),
            event_type=audit_log.event_type,
            user_id=audit_log.actor_id,
            action=audit_log.action,
            resource_type=audit_log.resource_type,
            resource_id=audit_log.resource_id,
            ip_address=audit_log.ip_address,
            success=audit_log.success,
            details=audit_log.details,
        )

        # Add to session and commit
        self._session.add(model)
        await self._session.commit()

        return str(model.id)

    async def get_by_id(self, log_id: str) -> AuditLog | None:
        """
        Retrieve an audit log entry by its ID.

        Args:
            log_id: ID of the audit log entry

        Returns:
            Optional[AuditLog]: The audit log entry if found, None otherwise
        """
        query = select(AuditLogModel).where(AuditLogModel.id == log_id)
        result = await self._session.execute(query)
        model = result.scalars().first()

        if not model:
            return None

        # Convert database model to domain entity
        return AuditLog(
            id=str(model.id),
            timestamp=model.timestamp,
            event_type=model.event_type,
            actor_id=model.user_id,
            resource_type=model.resource_type,
            resource_id=model.resource_id,
            action=model.action,
            status="success" if model.success else "failure",
            ip_address=model.ip_address,
            details=model.details,
        )

    async def search(
        self,
        filters: dict[str, Any] | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditLog]:
        """
        Search for audit log entries based on filters.

        Args:
            filters: Filters to apply to the search
            start_time: Start time for time-range filtering
            end_time: End time for time-range filtering
            limit: Maximum number of results to return
            offset: Offset for pagination

        Returns:
            List[AuditLog]: List of matching audit log entries
        """
        filters = filters or {}
        query = select(AuditLogModel).order_by(desc(AuditLogModel.timestamp))

        # Apply filters
        filter_conditions = []

        if start_time:
            filter_conditions.append(AuditLogModel.timestamp >= start_time)

        if end_time:
            filter_conditions.append(AuditLogModel.timestamp <= end_time)

        if "event_type" in filters:
            filter_conditions.append(AuditLogModel.event_type == filters["event_type"])

        if "actor_id" in filters or "user_id" in filters:
            user_id = filters.get("actor_id") or filters.get("user_id")
            filter_conditions.append(AuditLogModel.user_id == user_id)

        if "resource_type" in filters:
            filter_conditions.append(AuditLogModel.resource_type == filters["resource_type"])

        if "resource_id" in filters:
            filter_conditions.append(AuditLogModel.resource_id == filters["resource_id"])

        if "action" in filters:
            filter_conditions.append(AuditLogModel.action == filters["action"])

        if "ip_address" in filters:
            filter_conditions.append(AuditLogModel.ip_address == filters["ip_address"])

        if "success" in filters:
            filter_conditions.append(AuditLogModel.success == filters["success"])

        # Apply all filters to the query
        if filter_conditions:
            query = query.where(and_(*filter_conditions))

        # Apply pagination
        query = query.limit(limit).offset(offset)

        # Execute the query
        result = await self._session.execute(query)
        models = result.scalars().all()

        # Convert models to domain entities
        return [
            AuditLog(
                id=str(model.id),
                timestamp=model.timestamp,
                event_type=model.event_type,
                actor_id=model.user_id,
                resource_type=model.resource_type,
                resource_id=model.resource_id,
                action=model.action,
                status="success" if model.success else "failure",
                ip_address=model.ip_address,
                details=model.details,
            )
            for model in models
        ]

    async def get_statistics(
        self, start_time: datetime | None = None, end_time: datetime | None = None
    ) -> dict[str, Any]:
        """
        Get statistics about audit logs for the specified time period.

        Args:
            start_time: Start time for time-range filtering
            end_time: End time for time-range filtering

        Returns:
            Dict[str, Any]: Statistics about audit logs
        """
        # Base query conditions
        conditions = []
        if start_time:
            conditions.append(AuditLogModel.timestamp >= start_time)
        if end_time:
            conditions.append(AuditLogModel.timestamp <= end_time)

        base_condition = and_(*conditions) if conditions else True

        # Count total logs
        total_query = select(func.count(AuditLogModel.id)).where(base_condition)
        total_result = await self._session.execute(total_query)
        total_logs = total_result.scalar() or 0

        # Count by event type
        event_type_query = (
            select(AuditLogModel.event_type, func.count(AuditLogModel.id))
            .where(base_condition)
            .group_by(AuditLogModel.event_type)
        )
        event_type_result = await self._session.execute(event_type_query)
        event_type_counts = {event_type: count for event_type, count in event_type_result.all()}

        # Count successful vs failed events
        success_query = (
            select(AuditLogModel.success, func.count(AuditLogModel.id))
            .where(base_condition)
            .group_by(AuditLogModel.success)
        )
        success_result = await self._session.execute(success_query)
        success_counts = {"success": 0, "failure": 0}
        for success, count in success_result.all():
            if success is True:
                success_counts["success"] = count
            elif success is False:
                success_counts["failure"] = count

        # Get most active users
        user_query = (
            select(AuditLogModel.user_id, func.count(AuditLogModel.id))
            .where(and_(AuditLogModel.user_id != None, base_condition))  # noqa: E711
            .group_by(AuditLogModel.user_id)
            .order_by(func.count(AuditLogModel.id).desc())
            .limit(10)
        )
        user_result = await self._session.execute(user_query)
        active_users = [(str(user_id), count) for user_id, count in user_result.all() if user_id]

        # Return compiled statistics
        return {
            "total_logs": total_logs,
            "logs_by_event_type": event_type_counts,
            "logs_by_outcome": success_counts,
            "most_active_users": active_users,
        }
