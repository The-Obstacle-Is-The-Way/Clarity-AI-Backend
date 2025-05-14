"""
Unit tests for the audit logging service.

This module tests the audit logging service for HIPAA compliance and
proper functionality.
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional

import pytest
from fastapi import Request, Response
from unittest.mock import MagicMock, AsyncMock, patch, call

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
        
        # Set up mocks
        original_log_event = audit_service.log_event
        mock_log_event = AsyncMock(return_value="mocked-security-event-id")
        audit_service.log_event = mock_log_event
        
        # Create a test request with the special IP that triggers anomaly detection
        test_request = MagicMock()
        test_request.client.host = "not_an_ip"  # Special value that triggers anomaly detection
        test_request.headers = {}
        
        # Create a spy to see if _check_for_anomalies is called
        original_check_anomalies = audit_service._check_for_anomalies
        check_anomalies_spy = AsyncMock(side_effect=original_check_anomalies)
        audit_service._check_for_anomalies = check_anomalies_spy
        
        # Call log_phi_access with the test request
        await audit_service.log_phi_access(
            actor_id=TEST_USER_ID,
            patient_id=TEST_PATIENT_ID,
            resource_type="patient",
            action="view",
            status="success",
            reason="treatment",
            request=test_request,
            phi_fields=["name", "dob"]
        )
        
        # Verify _check_for_anomalies was called
        assert check_anomalies_spy.called, "Anomaly detection check was not called"
        
        # The main test is that log_event should have been called with event_type=AuditEventType.SECURITY_EVENT
        # Find the security event call - there should be at least one call after the initial PHI log
        security_event_calls = [
            call for call in mock_log_event.call_args_list
            if call.kwargs.get("event_type") == AuditEventType.SECURITY_EVENT
        ]
        
        assert security_event_calls, "No security event was logged when an anomaly was detected"
        
        # Restore original methods
        audit_service.log_event = original_log_event
        audit_service._check_for_anomalies = original_check_anomalies


@pytest.mark.asyncio
class TestAuditLogMiddleware:
    """Test suite for the audit log middleware."""
    
    @pytest.fixture
    def mock_audit_logger(self):
        """Fixture for mock audit logger."""
        logger_mock = MagicMock(spec=IAuditLogger)
        logger_mock.log_phi_access = AsyncMock(return_value=str(uuid.uuid4()))
        return logger_mock
    
    @pytest.fixture
    def middleware(self, mock_audit_logger):
        """Fixture for middleware."""
        app = MagicMock()
        # Ensure app.state and necessary sub-attributes exist for middleware initialization and checks
        app.state = MagicMock()
        app.state.settings = MagicMock()
        app.state.settings.ENVIRONMENT = "not_test" # Default to not_test unless overridden by a specific test
        app.state.testing = False
        app.state.disable_audit_middleware = False

        return AuditLogMiddleware(
            app=app,
            audit_logger=mock_audit_logger,
            skip_paths=["/skip_this"] # Add a distinct skip_path for testing skip logic
        )

    def _prepare_request_mock(self, path: str, method: str, user_id: Optional[str] = TEST_USER_ID) -> MagicMock:
        request = MagicMock(spec=Request)
        request.url = MagicMock()
        request.url.path = path
        request.method = method
        request.headers = {"User-Agent": "TestAgent/1.0"}
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        
        # Mock app and app.state on the request object itself
        request.app = MagicMock()
        request.app.state = MagicMock()
        request.app.state.settings = MagicMock()
        request.app.state.settings.ENVIRONMENT = "not_test" 
        request.app.state.testing = False
        request.app.state.disable_audit_middleware = False
        
        request.state = MagicMock() # Ensure request.state exists
        if user_id:
            request.state.current_user = {"id": user_id, "username": f"user_{user_id}"}
        else:
            request.state.current_user = None
        return request

    @patch.object(AuditLogMiddleware, '_is_audit_disabled', new_callable=AsyncMock)
    async def test_dispatch_phi_path(self, mock_is_disabled_method: AsyncMock, middleware: AuditLogMiddleware, mock_audit_logger: MagicMock):
        """Test that PHI access is logged for PHI paths when audit is enabled."""
        mock_is_disabled_method.return_value = False # Ensure audit is NOT disabled

        request = self._prepare_request_mock(path="/api/v1/patients/123/phi", method="GET")
        call_next = AsyncMock(return_value=Response(status_code=200, content="Success"))

        response = await middleware.dispatch(request, call_next)
        
        assert response.status_code == 200
        call_next.assert_called_once_with(request)
        mock_audit_logger.log_phi_access.assert_called_once()
        
        args, kwargs = mock_audit_logger.log_phi_access.call_args
        assert kwargs["actor_id"] == TEST_USER_ID
        assert kwargs["resource_type"] == "patients"
        assert kwargs["resource_id"] == "123"
        assert kwargs["action"] == "view"
        assert kwargs["status"] == "success"
        assert kwargs["metadata"]["path"] == "/api/v1/patients/123/phi"
        assert kwargs["metadata"]["method"] == "GET"
        assert kwargs["ip_address"] == "127.0.0.1"

    @patch.object(AuditLogMiddleware, '_is_audit_disabled', new_callable=AsyncMock)
    async def test_audit_disabled_bypasses_logging(self, mock_is_disabled_method: AsyncMock, middleware: AuditLogMiddleware, mock_audit_logger: MagicMock):
        """Test that if audit is disabled, PHI path processing is skipped for logging."""
        mock_is_disabled_method.return_value = True # Simulate audit being disabled

        request = self._prepare_request_mock(path="/api/v1/patients/789/phi", method="GET")
        call_next = AsyncMock(return_value=Response(status_code=200, content="Disabled audit success"))

        response = await middleware.dispatch(request, call_next)

        assert response.status_code == 200
        call_next.assert_called_once_with(request)
        mock_audit_logger.log_phi_access.assert_not_called()
        mock_is_disabled_method.assert_called_once_with(request)


    @patch.object(AuditLogMiddleware, '_is_audit_disabled', new_callable=AsyncMock)
    async def test_skip_non_phi_path(self, mock_is_disabled_method: AsyncMock, middleware: AuditLogMiddleware, mock_audit_logger: MagicMock):
        """Test that non-PHI paths are skipped for logging, even if audit is enabled."""
        mock_is_disabled_method.return_value = False # Audit is enabled

        request = self._prepare_request_mock(path="/api/v1/health", method="GET")
        call_next = AsyncMock(return_value=Response(status_code=200, content="Health OK"))

        response = await middleware.dispatch(request, call_next)

        assert response.status_code == 200
        call_next.assert_called_once_with(request)
        mock_audit_logger.log_phi_access.assert_not_called()
        # _is_audit_disabled might still be called depending on implementation order,
        # but the key is no logging for non-PHI.

    @patch.object(AuditLogMiddleware, '_is_audit_disabled', new_callable=AsyncMock)
    async def test_skip_path_in_skip_list(self, mock_is_disabled_method: AsyncMock, middleware: AuditLogMiddleware, mock_audit_logger: MagicMock):
        """Test that paths in the explicit skip_paths list are skipped before PHI checks."""
        mock_is_disabled_method.return_value = False # Audit is enabled

        request = self._prepare_request_mock(path="/skip_this/subpath", method="GET")
        call_next = AsyncMock(return_value=Response(status_code=200, content="Skipped path success"))
        
        response = await middleware.dispatch(request, call_next)

        assert response.status_code == 200
        call_next.assert_called_once_with(request)
        mock_audit_logger.log_phi_access.assert_not_called()
        # _is_audit_disabled should not be called if path is skipped early
        mock_is_disabled_method.assert_not_called()


    @patch.object(AuditLogMiddleware, '_is_audit_disabled', new_callable=AsyncMock)
    async def test_logging_failure_does_not_break_request(self, mock_is_disabled_method: AsyncMock, middleware: AuditLogMiddleware, mock_audit_logger: MagicMock):
        """Test that if audit_logger.log_phi_access fails, the main request still completes."""
        mock_is_disabled_method.return_value = False # Audit is enabled

        request = self._prepare_request_mock(path="/api/v1/patients/logfail/phi", method="POST")
        call_next = AsyncMock(return_value=Response(status_code=201, content="Created"))

        mock_audit_logger.log_phi_access.side_effect = Exception("Simulated logging database error")

        response = await middleware.dispatch(request, call_next)

        assert response.status_code == 201 # Original request should succeed
        call_next.assert_called_once_with(request)
        mock_audit_logger.log_phi_access.assert_called_once() # Logger was attempted

    # ... (keep other tests like _extract_user_id, _extract_resource_info as they were, if they don't involve _is_audit_disabled directly)

    async def test_extract_user_id_success(self, middleware: AuditLogMiddleware):
        """Test extracting user ID from request.state.current_user."""
        request = self._prepare_request_mock(path="/any", method="GET", user_id="test_user_123")
        user_id = await middleware._extract_user_id(request)
        assert user_id == "test_user_123"

    async def test_extract_user_id_missing(self, middleware: AuditLogMiddleware):
        """Test extracting user ID when current_user is not on request.state."""
        request = self._prepare_request_mock(path="/any", method="GET", user_id=None)
        # Simulate current_user not being set
        del request.state.current_user
        user_id = await middleware._extract_user_id(request)
        assert user_id is None

    def test_extract_resource_info(self, middleware: AuditLogMiddleware):
        """Test extracting resource type and ID from path."""
        test_cases = [
            ("/api/v1/patients/patient123/phi", ("patients", "patient123")),
            ("/api/v1/medical-records/record456", ("medical-records", "record456")),
            ("/api/v1/users/user789", ("users", "user789")), # Assuming generic resource extraction
            ("/api/v1/patients/patient-uuid-val-with-dashes/resource", ("patients", "patient-uuid-val-with-dashes")),
            ("/api/v1/fixedpath", (None, None)), # No dynamic ID part
            ("/api/v1/patients/", ("patients", None)), # ID might be in payload for POST
        ]
        for path, expected in test_cases:
            resource_type, resource_id = middleware._extract_resource_info(path)
            assert resource_type == expected[0]
            assert resource_id == expected[1] 