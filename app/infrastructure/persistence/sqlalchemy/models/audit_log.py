# -*- coding: utf-8 -*-
"""
SQLAlchemy model for Audit Logs.

This model stores audit trail information according to HIPAA requirements,
tracking access and modifications to sensitive data and system events.
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    String,
    Text,
    Integer
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.infrastructure.persistence.sqlalchemy.types import GUID

# Assuming Base is correctly defined and imported from a central location like database.py
# If not, adjust the import path accordingly.
# from app.infrastructure.persistence.sqlalchemy.database import Base 
# Trying relative import first, might need adjustment
from ..database import Base


class AuditLog(Base):
    """
    Represents an entry in the system's audit log.

    Complies with HIPAA §164.312(b) - Audit controls.
    """
    __tablename__ = "audit_logs"

    id = Column(GUID, primary_key=True, default=uuid.uuid4)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    event_type = Column(String(100), nullable=False, index=True)  # e.g., 'phi_access', 'auth_event', 'system_change'
    
    # Link to user table (nullable for system events without a specific user context)
    user_id = Column(GUID, ForeignKey('users.id'), nullable=True, index=True)
    # TEMP: Comment out relationship until User model is implemented
    # user = relationship("User") 

    ip_address = Column(String(50), nullable=True) # Source IP of the request
    action = Column(String(255), nullable=False) # e.g., 'login', 'view_record', 'update_settings', 'create_user'
    resource_type = Column(String(100), nullable=True) # e.g., 'patient', 'user', 'configuration', 'clinical_note'
    resource_id = Column(String(255), nullable=True, index=True) # ID of the specific resource affected
    success = Column(Boolean, nullable=True) # Was the action successful? Nullable if not applicable.
    
    # Store additional contextual details, ensuring PHI is not logged here directly
    # Use JSONB for flexibility and potential querying
    details = Column(JSONB, nullable=True) 

    def __repr__(self):
        return f"<AuditLog(id={self.id}, timestamp='{self.timestamp}', event_type='{self.event_type}', user_id='{self.user_id}', action='{self.action}')>" 