#!/usr/bin/env python3
"""
HIPAA Audit Logging Security Tests

Tests the audit logging system for HIPAA compliance (§164.312(b) - Audit controls).
"""

import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List

import pytest
from fastapi import FastAPI, Request, Response, Depends
from fastapi.testclient import TestClient
from unittest.mock import MagicMock, AsyncMock, patch

from app.application.services.audit_log_service import AuditLogService
from app.core.interfaces.services.audit_logger_interface import (
    IAuditLogger, AuditEventType, AuditSeverity
)
from app.domain.entities.audit_log import AuditLog
from app.infrastructure.security.audit.middleware import AuditLogMiddleware
from app.presentation.api.dependencies.services import get_audit_logger
from app.infrastructure.persistence.repositories.audit_log_repository import AuditLogRepository


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
    
    async def create(self, audit_log: AuditLog) -> str:
        """Mock implementation of create."""
        log_id = await self._create(audit_log)
        self.logs[log_id] = audit_log
        return log_id
    
    async def get_by_id(self, log_id: str):
        """Mock implementation of get_by_id."""
        if log_id in self.logs:
            return self.logs[log_id]
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


@pytest.fixture
def app(audit_service):
    """Create test app with audit logging middleware."""
    app = FastAPI()
    
    # Override dependency
    app.dependency_overrides[get_audit_logger] = lambda: audit_service
    
    # Add middleware
    app.add_middleware(
        AuditLogMiddleware,
        audit_logger=audit_service,
        skip_paths=["/docs", "/redoc", "/openapi.json", "/health"]
    )
    
    # Add test routes
    @app.get("/patients/{patient_id}")
    async def get_patient(
        patient_id: str,
        audit_logger: IAuditLogger = Depends(get_audit_logger)
    ):
        # This route should trigger PHI access logging
        return {"id": patient_id, "name": "Test Patient"}
    
    @app.get("/health")
    async def health_check():
        # This route should not trigger PHI access logging
        return {"status": "ok"}
    
    return app


@pytest.fixture
def client(app):
    """Create test client."""
    return TestClient(app)


class TestAuditLoggingIntegration:
    """Integration tests for audit logging system."""

    def test_phi_access_logged(self, client, audit_service, mock_repository):
        """Test that PHI access is logged."""
        # Reset mock
        mock_repository._create.reset_mock()
        
        # Make request with auth
        client.headers = {"Authorization": f"Bearer token"}
        response = client.get(f"/patients/{TEST_PATIENT_ID}")
        
        # Check response
        assert response.status_code == 200
        
        # Check that create was called at least once
        assert mock_repository._create.call_count >= 1
        
        # Find the PHI access log
        phi_access_log = None
        for call in mock_repository._create.call_args_list:
            log = call[0][0]
            if (log.event_type == AuditEventType.PHI_ACCESSED and 
                log.resource_id == TEST_PATIENT_ID):
                phi_access_log = log
                break
        
        # Verify the log
        assert phi_access_log is not None
        assert phi_access_log.resource_type == "patient"
        assert phi_access_log.action == "view"
        assert phi_access_log.status == "success"
    
    def test_non_phi_path_not_logged(self, client, audit_service, mock_repository):
        """Test that non-PHI paths are not logged."""
        # Reset mock
        mock_repository._create.reset_mock()
        
        # Make request to non-PHI path
        response = client.get("/health")
        
        # Check response
        assert response.status_code == 200
        
        # Check that create was not called for PHI access
        phi_access_log = None
        for call in mock_repository._create.call_args_list:
            log = call[0][0]
            if log.event_type == AuditEventType.PHI_ACCESSED:
                phi_access_log = log
                break
        
        assert phi_access_log is None
    
    def test_failed_request_logged(self, client, audit_service, mock_repository):
        """Test that failed requests are logged."""
        # Reset mock
        mock_repository._create.reset_mock()
        
        # Make request to non-existent route
        response = client.get("/nonexistent")
        
        # Check response
        assert response.status_code == 404
        
        # Middleware should still log the attempt
        assert mock_repository._create.call_count >= 1


class TestAuditLogExport:
    """Tests for audit log export functionality."""
    
    @pytest.mark.asyncio
    async def test_export_audit_logs(self, audit_service, mock_repository):
        """Test exporting audit logs."""
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
        
        # Export logs
        with patch("aiofiles.open", new_callable=AsyncMock) as mock_open:
            # Mock file operations
            mock_file = AsyncMock()
            mock_open.return_value.__aenter__.return_value = mock_file
            
            # Call export
            file_path = await audit_service.export_audit_logs(
                format="csv",
                filters={"actor_id": TEST_USER_ID},
                start_time=datetime.now(timezone.utc) - timedelta(days=1),
                end_time=datetime.now(timezone.utc)
            )
            
            # Check that search was called with correct filters
            mock_repository._search.assert_called_once()
            
            # Check that file was written
            assert mock_file.write.call_count >= 1
            
            # Check content includes headers and data
            content = "".join([call[0][0] for call in mock_file.write.call_args_list])
            assert "timestamp" in content.lower()
            assert "event_type" in content.lower()
            assert "actor_id" in content.lower()
            assert "resource_id" in content.lower()
            assert TEST_USER_ID in content
            assert TEST_PATIENT_ID in content


class TestAuditAnomalyDetection:
    """Tests for audit anomaly detection functionality."""
    
    @pytest.mark.asyncio
    async def test_detect_anomalies(self, audit_service, mock_repository):
        """Test anomaly detection in audit logs."""
        # Reset service state
        audit_service._user_access_history = {}
        audit_service._suspicious_ips = set()
        
        # Reset mock repository
        mock_repository._create.reset_mock()
        
        # Create a series of access logs that trigger an anomaly
        # (too many accesses in a short time)
        for i in range(10):
            await audit_service.log_phi_access(
                actor_id=TEST_USER_ID,
                patient_id=str(uuid.uuid4()),  # Different patients
                resource_type="patient",
                action="view",
                status="success",
                phi_fields=["name", "dob"],
                reason="treatment",
                request_context={
                    "ip_address": "127.0.0.1",
                    "user_agent": "test-agent"
                }
            )
        
        # Check if anomaly was detected and logged
        security_event_logged = False
        for call in mock_repository._create.call_args_list:
            log = call[0][0]
            if (log.event_type == AuditEventType.SECURITY_EVENT and 
                "anomaly" in str(log.details).lower()):
                security_event_logged = True
                break
        
        assert security_event_logged
    
    @pytest.mark.asyncio
    async def test_geographic_anomaly(self, audit_service, mock_repository):
        """Test geographic location anomaly detection."""
        # Reset service state
        audit_service._user_access_history = {}
        audit_service._suspicious_ips = set()
        
        # Reset mock repository
        mock_repository._create.reset_mock()
        
        # First access from one location
        await audit_service.log_phi_access(
            actor_id=TEST_USER_ID,
            patient_id=TEST_PATIENT_ID,
            resource_type="patient",
            action="view",
            status="success",
            phi_fields=["name", "dob"],
            reason="treatment",
            request_context={
                "ip_address": "192.168.1.1",
                "geo_location": "New York, USA"
            }
        )
        
        # Second access from very different location soon after
        await audit_service.log_phi_access(
            actor_id=TEST_USER_ID,
            patient_id=TEST_PATIENT_ID,
            resource_type="patient",
            action="view",
            status="success",
            phi_fields=["name", "dob"],
            reason="treatment",
            request_context={
                "ip_address": "10.0.0.1",
                "geo_location": "Tokyo, Japan"
            }
        )
        
        # Check if geographic anomaly was detected
        geo_anomaly_logged = False
        for call in mock_repository._create.call_args_list:
            log = call[0][0]
            details_str = str(log.details).lower()
            if (log.event_type == AuditEventType.SECURITY_EVENT and 
                "location" in details_str and "anomaly" in details_str):
                geo_anomaly_logged = True
                break
        
        assert geo_anomaly_logged
