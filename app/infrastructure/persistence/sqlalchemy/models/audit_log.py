"""
SQLAlchemy model for Audit Logs.

This model stores audit trail information according to HIPAA requirements,
tracking access and modifications to sensitive data and system events.
"""

import uuid

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String
from sqlalchemy.sql import func

from app.infrastructure.persistence.sqlalchemy.types import GUID, JSONEncodedDict

# Assuming Base is correctly defined and imported from a central location like database.py
# If not, adjust the import path accordingly.
# from app.infrastructure.persistence.sqlalchemy.database import Base
# Trying relative import first, might need adjustment
from .base import Base


class AuditLog(Base):
    """
    Represents an entry in the system's audit log.

    Complies with HIPAA §164.312(b) - Audit controls.
    """

    __tablename__ = "audit_logs"

    id: Column = Column(GUID(), primary_key=True, default=uuid.uuid4)
    timestamp: Column = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
    # Types of events (phi_access, auth_event, system_change, etc.)
    event_type: Column = Column(String(100), nullable=False, index=True)

    # Link to user table (nullable for system events without a specific user context)
    user_id: Column = Column(GUID(), ForeignKey("users.id"), nullable=True, index=True)
    # TEMP: Comment out relationship until User model is implemented
    # user = relationship("User")

    # Source IP of the request
    ip_address: Column = Column(String(50), nullable=True)
    # Actions like 'login', 'view_record', 'update_settings', 'create_user'
    action: Column = Column(String(255), nullable=False)
    # Type of resource (patient, user, setting, etc.)
    resource_type: Column = Column(String(100), nullable=True)
    # ID of the resource (patient_id, user_id, etc.)
    resource_id: Column = Column(String(255), nullable=True, index=True)
    # Whether the action was successful
    success: Column = Column(Boolean, nullable=True)
    # Additional details as JSON
    details: Column = Column(JSONEncodedDict, nullable=True)

    def __repr__(self):
        return (
            f"<AuditLog(id={self.id}, timestamp='{self.timestamp}', "
            f"event_type='{self.event_type}', user_id='{self.user_id}', "
            f"action='{self.action}')>"
        )
