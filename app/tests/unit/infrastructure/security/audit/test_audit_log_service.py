"""
Unit tests for the audit logging service.

This module tests the audit logging service for HIPAA compliance and
proper functionality.
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List

import pytest
from fastapi import Request, Response
from unittest.mock import MagicMock, AsyncMock, patch

from app.application.services.audit_log_service import AuditLogService
from app.core.interfaces.services.audit_logger_interface import (
    IAuditLogger, AuditEventType, AuditSeverity
)
from app.domain.entities.audit_log import AuditLog
from app.infrastructure.security.audit.middleware import AuditLogMiddleware


# Test data
TEST_USER_ID = str(uuid.uuid4())
TEST_PATIENT_ID = str(uuid.uuid4())


class MockAuditLogRepository:
    """Mock repository for testing."""
    
    def __init__(self):
        self.logs = {}
        self._create = AsyncMock(return_value=str(uuid.uuid4()))
        self._get_by_id = AsyncMock(return_value=None)
        self._search = AsyncMock(return_value=[])
        self._get_statistics = AsyncMock(return_value={})
        self.create_audit_log = AsyncMock(return_value=str(uuid.uuid4()))
    
    async def create(self, audit_log: AuditLog) -> str:
        """Mock implementation of create."""
        return await self._create(audit_log)
    
    async def get_by_id(self, log_id: str):
        """Mock implementation of get_by_id."""
        return await self._get_by_id(log_id)
    
    async def search(self, **kwargs):
        """Mock implementation of search."""
        return await self._search(**kwargs)
    
    async def get_statistics(self, **kwargs):
        """Mock implementation of get_statistics."""
        return await self._get_statistics(**kwargs)


@pytest.fixture
def mock_repository():
    """Fixture for mock repository."""
    return MockAuditLogRepository()


@pytest.fixture
def audit_service(mock_repository):
    """Fixture for audit service."""
    return AuditLogService(mock_repository)


@pytest.mark.asyncio
class TestAuditLogService:
    """Test suite for the audit logging service."""
    
    async def test_log_event(self, audit_service, mock_repository):
        """Test logging an event."""
        mock_repository._create.reset_mock()
        
        log_id = await audit_service.log_event(
            event_type=AuditEventType.LOGIN,
            actor_id=TEST_USER_ID,
            action="login",
            status="success"
        )
        
        # Check that create was called
        mock_repository._create.assert_called_once()
        
        # Check that the log has the correct data
        audit_log = mock_repository._create.call_args[0][0]
        assert audit_log.event_type == AuditEventType.LOGIN
        assert audit_log.actor_id == TEST_USER_ID
        assert audit_log.action == "login"
        assert audit_log.status == "success"
    
    async def test_log_security_event(self, audit_service, mock_repository):
        """Test logging a security event."""
        mock_repository._create.reset_mock()
        
        log_id = await audit_service.log_security_event(
            description="Failed login attempt",
            actor_id=TEST_USER_ID,
            status="failure"
        )
        
        # Check that create was called
        mock_repository._create.assert_called_once()
        
        # Check that the log has the correct data
        audit_log = mock_repository._create.call_args[0][0]
        assert audit_log.event_type == AuditEventType.LOGIN_FAILED
        assert audit_log.actor_id == TEST_USER_ID
        assert "Failed login attempt" in str(audit_log.details)
    
    async def test_log_phi_access(self, audit_service, mock_repository):
        """Test logging PHI access."""
        mock_repository._create.reset_mock()
        
        log_id = await audit_service.log_phi_access(
            actor_id=TEST_USER_ID,
            patient_id=TEST_PATIENT_ID,
            resource_type="patient",
            action="view",
            status="success",
            phi_fields=["name", "dob"],
            reason="treatment"
        )
        
        # Check that create was called
        mock_repository._create.assert_called_once()
        
        # Check that the log has the correct data
        audit_log = mock_repository._create.call_args[0][0]
        assert audit_log.event_type == AuditEventType.PHI_ACCESSED
        assert audit_log.actor_id == TEST_USER_ID
        assert audit_log.resource_id == TEST_PATIENT_ID
        assert audit_log.resource_type == "patient"
        assert audit_log.action == "view"
        assert audit_log.status == "success"
        assert audit_log.details["reason"] == "treatment"
        assert "name" in audit_log.details["phi_fields"]
        assert "dob" in audit_log.details["phi_fields"]
    
    async def test_get_audit_trail(self, audit_service, mock_repository):
        """Test retrieving the audit trail."""
        # Create some test logs
        test_logs = [
            AuditLog(
                id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc),
                event_type=AuditEventType.PHI_ACCESSED,
                actor_id=TEST_USER_ID,
                resource_type="patient",
                resource_id=TEST_PATIENT_ID,
                action="view",
                status="success",
                details={"reason": "treatment"}
            ),
            AuditLog(
                id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc) - timedelta(hours=1),
                event_type=AuditEventType.LOGIN,
                actor_id=TEST_USER_ID,
                action="login",
                status="success"
            )
        ]
        
        # Mock the search method
        mock_repository._search.reset_mock()
        mock_repository._search.return_value = test_logs
        
        # Get the audit trail
        logs = await audit_service.get_audit_trail(
            filters={"actor_id": TEST_USER_ID},
            start_time=datetime.now(timezone.utc) - timedelta(days=1),
            end_time=datetime.now(timezone.utc)
        )
        
        # Check that search was called with the right parameters
        mock_repository._search.assert_called_once()
        
        # Check that the logs were returned
        assert len(logs) == 2
        assert logs[0]["event_type"] == AuditEventType.PHI_ACCESSED
        assert logs[1]["event_type"] == AuditEventType.LOGIN
    
    async def test_anomaly_detection(self, audit_service, mock_repository):
        """Test that anomalies are detected."""
        # Reset the service to clear any existing history
        audit_service._user_access_history = {}
        audit_service._suspicious_ips = set()
        
        # Set up test log with suspicious IP
        test_log = AuditLog(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            event_type=AuditEventType.PHI_ACCESSED,
            actor_id=TEST_USER_ID,
            resource_type="patient",
            resource_id=TEST_PATIENT_ID,
            action="view",
            ip_address="not_an_ip",  # Unusual IP that should trigger detection
            details={}
        )
        
        # Call the method to check for anomalies
        result = await audit_service._check_for_anomalies(TEST_USER_ID, test_log)
        
        # Verify result
        assert result is True
        
        # Verify the anomaly was detected by checking the logs or repository
        # Note: We can't use mock assertions because the real implementation is being used
        calls = mock_repository.create.call_args_list
        assert len(calls) >= 1, "Expected at least one call to create"
        
        # Look through the calls for the security event
        found_anomaly_log = False
        for call in calls:
            log = call[0][0]  # First arg of first call
            if log.event_type == AuditEventType.SECURITY_EVENT and 'geographic' in str(log.details):
                found_anomaly_log = True
                break
                
        assert found_anomaly_log, "Expected to find anomaly log with 'geographic' in details"


@pytest.mark.asyncio
class TestAuditLogMiddleware:
    """Test suite for the audit log middleware."""
    
    @pytest.fixture
    def mock_audit_logger(self):
        """Fixture for mock audit logger."""
        logger = MagicMock(spec=IAuditLogger)
        logger.log_phi_access = AsyncMock(return_value=str(uuid.uuid4()))
        return logger
    
    @pytest.fixture
    def middleware(self, mock_audit_logger):
        """Fixture for middleware."""
        app = MagicMock()
        app.state.disable_audit_middleware = False  # Explicitly enable for tests
        
        middleware = AuditLogMiddleware(
            app=app,
            audit_logger=mock_audit_logger,
            skip_paths=["/docs", "/redoc", "/openapi.json", "/api/health"]
        )
        
        # Override _is_audit_disabled to ensure audit logging is enabled for tests
        original_is_audit_disabled = middleware._is_audit_disabled
        middleware._is_audit_disabled = MagicMock(return_value=False)
        
        return middleware
    
    async def test_dispatch_phi_path(self, middleware, mock_audit_logger):
        """Test middleware dispatches for PHI paths."""
        # Mock request and response
        request = MagicMock(spec=Request)
        request.url.path = "/api/v1/patients/123"
        request.method = "GET"
        request.state.user = MagicMock(id=TEST_USER_ID)
        request.state.disable_audit_middleware = False  # Explicitly enable audit for this test
        request.app.state.disable_audit_middleware = False  # Explicitly enable audit at app level
        
        # Add app settings for environment detection
        from app.core.config.settings import Settings
        mock_settings = MagicMock(spec=Settings)
        mock_settings.ENVIRONMENT = "development"  # Not test environment
        request.state.settings = mock_settings
        request.app.state.settings = mock_settings
        
        # Mock call_next function
        response = MagicMock(spec=Response)
        response.status_code = 200
        call_next = AsyncMock(return_value=response)
        
        # Call middleware
        result = await middleware.dispatch(request, call_next)
        
        # Check that log_phi_access was called
        mock_audit_logger.log_phi_access.assert_called_once()
        
        # Check the arguments
        args, kwargs = mock_audit_logger.log_phi_access.call_args
        assert kwargs["actor_id"] == TEST_USER_ID
        assert kwargs["resource_type"] == "patient"
        assert kwargs["patient_id"] == "123"
        assert kwargs["action"] == "view"
        assert kwargs["status"] == "success"
        
        # Check that call_next was called and response was returned
        call_next.assert_called_once_with(request)
        assert result == response
    
    async def test_skip_non_phi_path(self, middleware, mock_audit_logger):
        """Test middleware skips non-PHI paths."""
        # Mock request and response
        request = MagicMock(spec=Request)
        request.url.path = "/docs"
        
        # Mock call_next function
        response = MagicMock(spec=Response)
        call_next = AsyncMock(return_value=response)
        
        # Call middleware
        result = await middleware.dispatch(request, call_next)
        
        # Check that log_phi_access was not called
        mock_audit_logger.log_phi_access.assert_not_called()
        
        # Check that call_next was called and response was returned
        call_next.assert_called_once_with(request)
        assert result == response
    
    async def test_extract_user_id(self, middleware):
        """Test extracting user ID from request."""
        # Create a mock request
        mock_request = MagicMock()
        mock_request.state.user = MagicMock()
        mock_request.state.user.id = "test-user-id"
        
        # Use the private method directly for testing
        user_id = await middleware._extract_user_id(mock_request)
        
        # Verify the user ID was extracted correctly
        assert user_id == "test-user-id" 