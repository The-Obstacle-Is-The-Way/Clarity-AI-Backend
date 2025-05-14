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
import asyncio # Added for asyncio.TimeoutError in new tests

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
        # Default to a non-test environment for the fixture, tests can override request.app.state if needed
        app.state.settings.ENVIRONMENT = "production" 
        app.state.testing = False
        app.state.disable_audit_middleware = False

        return AuditLogMiddleware(
            app=app,
            audit_logger=mock_audit_logger,
            skip_paths=["/skip_this_path"] # Use a more specific skip_path for clarity
        )

    def _prepare_request_mock(self, path: str, method: str, user_id: Optional[str] = TEST_USER_ID, env: str = "production", testing_flag: bool = False, disable_audit_flag: bool = False) -> MagicMock:
        """Helper to create a comprehensively mocked Request object."""
        request = MagicMock(spec=Request)
        
        # Mock URL object and its path attribute
        request.url = MagicMock()
        request.url.path = path
        
        request.method = method
        request.headers = {"User-Agent": "TestAgent/1.0"}
        
        # Mock client object and its host attribute
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        
        # Mock app and app.state on the request object itself, as accessed by _is_audit_disabled
        request.app = MagicMock()
        request.app.state = MagicMock()
        request.app.state.settings = MagicMock()
        request.app.state.settings.ENVIRONMENT = env
        request.app.state.testing = testing_flag
        request.app.state.disable_audit_middleware = disable_audit_flag # For app-level disabling
        
        # Mock request.state and current_user for user extraction
        # AuditLogMiddleware._extract_user_id expects request.state.user
        request.state = MagicMock() 
        if user_id:
            # Simulate structure expected by _extract_user_id: request.state.user with an 'id' attribute
            user_details_mock = MagicMock(id=user_id) # Ensure 'id' attribute holds the direct string value
            # If AuditLogMiddleware._extract_user_id or other parts access more attributes of request.state.user,
            # they should be added here, e.g., user_details_mock.username = f"user_{user_id}"
            request.state.user = user_details_mock
        else:
            request.state.user = None # Correctly set to None if no user_id provided
        
        # For request-level disabling, if used by _is_audit_disabled
        request.state.disable_audit_middleware = False # Default to not disabled at request level

        return request

    @patch.object(AuditLogMiddleware, '_is_audit_disabled', new_callable=AsyncMock)
    async def test_dispatch_phi_path_logs_when_enabled(self, mock_is_disabled_method: AsyncMock, middleware: AuditLogMiddleware, mock_audit_logger: MagicMock):
        """Test that PHI access is logged for PHI paths when audit is enabled."""
        mock_is_disabled_method.return_value = False # Ensure audit is NOT disabled by the mock

        request = self._prepare_request_mock(path="/api/v1/patients/123/phi", method="GET")
        # Ensure the specific request mock doesn't accidentally disable audit via its own app.state properties
        request.app.state.settings.ENVIRONMENT = "production" # Explicitly non-test for this test
        request.app.state.testing = False
        request.app.state.disable_audit_middleware = False


        call_next_response = Response(status_code=200, content="Successful PHI access")
        call_next = AsyncMock(return_value=call_next_response)

        # Patch _extract_resource_info for predictable output in this unit test
        with patch.object(middleware, '_extract_resource_info', return_value=("patients", "123")) as mock_extract_resource:
            response = await middleware.dispatch(request, call_next)
        
        assert response == call_next_response
        call_next.assert_called_once_with(request)
        mock_extract_resource.assert_called_once_with("/api/v1/patients/123/phi")
        
        # Verify _is_audit_disabled was called (and returned False as per mock)
        # It's called twice in the current middleware.dispatch logic
        assert mock_is_disabled_method.call_count == 2
        mock_is_disabled_method.assert_has_calls([call(request), call(request)])
        
        mock_audit_logger.log_phi_access.assert_called_once()
        args, kwargs = mock_audit_logger.log_phi_access.call_args
        
        assert kwargs["actor_id"] == TEST_USER_ID
        assert kwargs["resource_type"] == "patients"
        assert kwargs["resource_id"] == "123"
        assert kwargs["patient_id"] == "123" # Assuming patient_id is derived from resource_id here
        assert kwargs["action"] == "view" # GET maps to view
        assert kwargs["status"] == "success" # Based on 200 OK from call_next
        assert kwargs["metadata"]["path"] == "/api/v1/patients/123/phi"
        assert kwargs["metadata"]["method"] == "GET"
        assert kwargs["ip_address"] == "127.0.0.1"
        assert "TestAgent/1.0" in kwargs["metadata"]["user_agent"]

    @patch.object(AuditLogMiddleware, '_is_audit_disabled', new_callable=AsyncMock)
    async def test_audit_disabled_bypasses_logging_for_phi_path(self, mock_is_disabled_method: AsyncMock, middleware: AuditLogMiddleware, mock_audit_logger: MagicMock):
        """Test that if audit is disabled (by mock), PHI path processing skips logging."""
        mock_is_disabled_method.return_value = True # Simulate _is_audit_disabled returning True

        request = self._prepare_request_mock(path="/api/v1/patients/789/phi", method="POST")
        call_next_response = Response(status_code=201, content="Created PHI entity")
        call_next = AsyncMock(return_value=call_next_response)

        response = await middleware.dispatch(request, call_next)

        assert response == call_next_response
        call_next.assert_called_once_with(request)
        mock_audit_logger.log_phi_access.assert_not_called()
        mock_is_disabled_method.assert_called_once_with(request) # Ensure our mock was the reason

    @patch.object(AuditLogMiddleware, '_is_audit_disabled', new_callable=AsyncMock)
    async def test_non_phi_path_skipped_even_if_audit_enabled(self, mock_is_disabled_method: AsyncMock, middleware: AuditLogMiddleware, mock_audit_logger: MagicMock):
        """Test non-PHI paths are skipped, even if _is_audit_disabled would allow logging."""
        mock_is_disabled_method.return_value = False # Audit is notionally enabled by this mock

        request = self._prepare_request_mock(path="/api/v1/health-check", method="GET")
         # Ensure the specific request mock doesn't accidentally disable audit via its own app.state properties
        request.app.state.settings.ENVIRONMENT = "production"
        request.app.state.testing = False
        request.app.state.disable_audit_middleware = False

        call_next_response = Response(status_code=200, content="Health OK")
        call_next = AsyncMock(return_value=call_next_response)

        response = await middleware.dispatch(request, call_next)

        assert response == call_next_response
        call_next.assert_called_once_with(request)
        mock_audit_logger.log_phi_access.assert_not_called()
        
        # _is_audit_disabled might be called before the PHI path check,
        # so we assert it was called. The crucial part is no logging for non-PHI.
        mock_is_disabled_method.assert_called_once_with(request)


    @patch.object(AuditLogMiddleware, '_is_audit_disabled', new_callable=AsyncMock)
    async def test_path_in_skip_list_is_skipped_early(self, mock_is_disabled_method: AsyncMock, middleware: AuditLogMiddleware, mock_audit_logger: MagicMock):
        """Test that paths in skip_paths list are skipped before _is_audit_disabled or PHI checks."""
        # mock_is_disabled_method is present due to decorator, but should not be called.
        # We don't set its return_value as it's irrelevant if code path is correct.

        request = self._prepare_request_mock(path="/skip_this_path/some/subresource", method="GET")
        call_next_response = Response(status_code=200, content="Skipped via skip_paths")
        call_next = AsyncMock(return_value=call_next_response)
        
        response = await middleware.dispatch(request, call_next)

        assert response == call_next_response
        call_next.assert_called_once_with(request)
        mock_audit_logger.log_phi_access.assert_not_called()
        mock_is_disabled_method.assert_not_called() # Crucial: skip_paths check should be first

    @patch.object(AuditLogMiddleware, '_is_audit_disabled', new_callable=AsyncMock)
    async def test_logging_failure_does_not_break_request_flow(self, mock_is_disabled_method: AsyncMock, middleware: AuditLogMiddleware, mock_audit_logger: MagicMock):
        """Test that if audit_logger.log_phi_access raises an exception, the main request still completes."""
        mock_is_disabled_method.return_value = False # Audit is enabled

        request = self._prepare_request_mock(path="/api/v1/patients/logfailure-case/phi", method="PUT")
        call_next_response = Response(status_code=202, content="Accepted")
        call_next = AsyncMock(return_value=call_next_response)

        # Simulate the logger itself failing
        mock_audit_logger.log_phi_access.side_effect = asyncio.TimeoutError("Simulated logging database timeout")

        with patch.object(middleware, '_extract_resource_info', return_value=("patients", "logfailure-case")):
            response = await middleware.dispatch(request, call_next)

        assert response == call_next_response # Original request should succeed despite logging error
        call_next.assert_called_once_with(request)
        mock_audit_logger.log_phi_access.assert_called_once() # Logger was attempted

    async def test_extract_user_id_from_valid_request_state(self, middleware: AuditLogMiddleware):
        """Test _extract_user_id successfully gets user ID from request.state.user.id."""
        user_id_val = str(uuid.uuid4())
        # _prepare_request_mock now correctly sets request.state.user with an object having an 'id' attribute
        request = self._prepare_request_mock(path="/any", method="GET", user_id=user_id_val)
        
        extracted_user_id = await middleware._extract_user_id(request)
        assert extracted_user_id == user_id_val

    async def test_extract_user_id_when_no_current_user(self, middleware: AuditLogMiddleware):
        """Test _extract_user_id returns None if request.state.user is None."""
        request = self._prepare_request_mock(path="/any", method="GET", user_id=None) # user_id=None sets request.state.user to None
        extracted_user_id = await middleware._extract_user_id(request)
        assert extracted_user_id is None

    async def test_extract_user_id_when_current_user_has_no_id(self, middleware: AuditLogMiddleware):
        """Test _extract_user_id returns None if request.state.user object lacks an 'id' attribute."""
        # _prepare_request_mock with user_id will create a mock with .id
        # To test this case, we need to manually create a mock without .id
        request = self._prepare_request_mock(path="/any", method="GET", user_id=None) # Start with no user
        user_without_id_mock = MagicMock()
        # del user_without_id_mock.id # Ensure 'id' is not present or getattr will create a new mock for it.
                                  # Instead, use spec to limit attributes
        user_without_id_mock = MagicMock(spec=[]) # An object with no attributes defined by spec
        request.state.user = user_without_id_mock
        
        extracted_user_id = await middleware._extract_user_id(request)
        assert extracted_user_id is None # getattr on user_without_id_mock for 'id' will return None (or raise if spec strict)
        
    async def test_extract_user_id_when_request_state_missing_user_attr(self, middleware: AuditLogMiddleware):
        """Test _extract_user_id returns None if request.state has no 'user' attribute."""
        request = self._prepare_request_mock(path="/any", method="GET", user_id=None) # Creates request.state
        # Explicitly delete the 'user' attribute from request.state
        if hasattr(request.state, "user"):
            delattr(request.state, "user") 
            
        extracted_user_id = await middleware._extract_user_id(request)
        assert extracted_user_id is None

    def test_extract_resource_info_various_paths(self, middleware: AuditLogMiddleware):
        """Test _extract_resource_info correctly parses various PHI-like and other paths."""
        # Note: The AuditLogMiddleware's default phi_url_patterns might influence this.
        # These tests assume the generic extraction logic based on typical REST patterns.
        test_cases = [
            ("/api/v1/patients/patient123/phi", ("patients", "patient123")),
            ("/api/v1/medical-records/record-abc-456", ("medical-records", "record-abc-456")),
            ("/api/v1/users/user789", ("users", "user789")),
            ("/api/v1/devices/dev_id_with_underscore/data", ("devices", "dev_id_with_underscore")),
            ("/api/v1/no_id_path", ("no_id_path", None)),
            ("/api/v1/patients/", ("patients", None)), # Common for POST to collection
            ("/api/v1/consultations/consult-guid-goes-here/notes/note-sub-id", ("consultations", "consult-guid-goes-here")),
        ]
        for path, expected in test_cases:
            resource_type, resource_id = middleware._extract_resource_info(path)
            assert resource_type == expected[0], f"Path: {path}"
            assert resource_id == expected[1], f"Path: {path}" 