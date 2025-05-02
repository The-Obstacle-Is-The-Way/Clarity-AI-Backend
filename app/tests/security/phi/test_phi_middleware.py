"""
Tests for the PHI middleware components to validate HIPAA compliance.

These tests verify that the PHI middleware correctly sanitizes requests and responses
to prevent PHI exposure through API endpoints.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.infrastructure.security.phi import add_phi_middleware


class TestPHIMiddleware:
    """Test suite for the PHI middleware component."""
    
    @pytest.fixture
    def app(self):
        """Create a test FastAPI application."""
        app = FastAPI()
        
        @app.get("/test")
        def test_endpoint():
            return {"message": "No PHI here"}
            
        @app.get("/data-with-phi")
        def test_phi_endpoint():
            return {
                "patient": {
                    "name": "John Smith",
                    "ssn": "123-45-6789",
                    "contact": {
                        "email": "john.smith@example.com",
                        "phone": "(555) 123-4567"
                    }
                },
                "meta": {
                    "timestamp": "2023-01-01T12:00:00Z"
                }
            }
            
        @app.post("/process-phi")
        async def process_phi(request_data: dict):
            # Just echo back the data
            return request_data
            
        @app.get("/html-response")
        def html_response():
            from fastapi.responses import HTMLResponse
            return HTMLResponse(content="<html><body>No PHI here</body></html>")
            
        @app.get("/nested-phi")
        def nested_phi():
            return {
                "records": [
                    {
                        "id": 1,
                        "patient": {
                            "name": "Jane Doe",
                            "email": "jane.doe@example.com"
                        }
                    },
                    {
                        "id": 2,
                        "patient": {
                            "name": "Bob Johnson",
                            "ssn": "987-65-4321"
                        }
                    }
                ],
                "total": 2
            }
        
        return app
        
    @pytest.fixture
    def client(self, app):
        """Create a test client with PHI middleware."""
        # Add PHI middleware to the app
        add_phi_middleware(app)
        
        return TestClient(app)
        
    @pytest.fixture
    def audit_client(self, app):
        """Create a test client with PHI middleware in audit mode."""
        # Add PHI middleware to the app in audit mode
        add_phi_middleware(app, audit_mode=True)
        
        return TestClient(app)
        
    @pytest.fixture
    def whitelist_client(self, app):
        """Create a test client with PHI middleware and whitelist patterns."""
        # Add PHI middleware with whitelist patterns
        add_phi_middleware(
            app,
            whitelist_patterns={
                "/data-with-phi": ["John Smith"]  # Whitelist this name
            }
        )
        
        return TestClient(app)
        
    def test_sanitize_response_with_phi(self, client):
        """Test that PHI is sanitized in responses."""
        response = client.get("/data-with-phi")
        
        # Verify response
        assert response.status_code == 200
        data = response.json()
        
        # Verify PHI is sanitized
        patient = data["patient"]
        assert "John Smith" not in json.dumps(patient)
        assert "123-45-6789" not in json.dumps(patient)
        assert "john.smith@example.com" not in json.dumps(patient)
        assert "(555) 123-4567" not in json.dumps(patient)
        
        # Verify non-PHI is preserved
        assert "timestamp" in data["meta"]
        
        # Verify PHI is replaced with redaction markers
        assert any(("[REDACTED" in value if isinstance(value, str) else False) 
                   for value in patient.values())
                   
    def test_sanitize_request_with_phi(self, client):
        """Test that PHI is sanitized in request logging."""
        with patch('app.infrastructure.security.phi.middleware.logger') as mock_logger:
            # Send a request with PHI
            response = client.post(
                "/process-phi",
                json={
                    "patient": {
                        "name": "John Doe",
                        "ssn": "123-45-6789"
                    }
                },
                headers={"Content-Type": "application/json"}
            )
            
            # Verify response is sanitized
            assert response.status_code == 200
            data = response.json()
            assert "John Doe" not in json.dumps(data)
            assert "123-45-6789" not in json.dumps(data)
            
            # Verify logging occurred
            assert mock_logger.info.called or mock_logger.warning.called
            
    def test_whitelist_patterns(self, whitelist_client):
        """Test that whitelisted patterns are not sanitized."""
        response = whitelist_client.get("/data-with-phi")
        
        # Verify response
        assert response.status_code == 200
        data = response.json()
        
        # Verify whitelisted PHI is preserved
        assert "John Smith" in json.dumps(data)
        
        # Verify non-whitelisted PHI is still sanitized
        assert "123-45-6789" not in json.dumps(data)
        assert "john.smith@example.com" not in json.dumps(data)
        assert "(555) 123-4567" not in json.dumps(data)
        
    def test_audit_mode(self, audit_client):
        """Test that audit mode logs PHI but doesn't sanitize it."""
        with patch('app.infrastructure.security.phi.middleware.logger') as mock_logger:
            response = audit_client.get("/data-with-phi")
            
            # Verify response is not sanitized
            assert response.status_code == 200
            data = response.json()
            
            # Verify PHI is preserved
            assert "John Smith" in json.dumps(data)
            assert "123-45-6789" in json.dumps(data)
            
            # Verify logging occurred
            assert mock_logger.warning.called
            
    def test_sanitize_non_json_response(self, client):
        """Test that non-JSON responses are not modified."""
        response = client.get("/html-response")
        
        # Verify response
        assert response.status_code == 200
        assert response.text == "<html><body>No PHI here</body></html>"
        
    def test_sanitize_nested_json(self, client):
        """Test that PHI is sanitized in nested JSON structures."""
        response = client.get("/nested-phi")
        
        # Verify response
        assert response.status_code == 200
        data = response.json()
        
        # Verify PHI is sanitized in nested structures
        records_json = json.dumps(data["records"])
        assert "Jane Doe" not in records_json
        assert "Bob Johnson" not in records_json
        assert "987-65-4321" not in records_json
        assert "jane.doe@example.com" not in records_json
        
        # Verify structure is preserved
        assert len(data["records"]) == 2
        assert data["total"] == 2
        
    def test_add_phi_middleware(self):
        """Test that add_phi_middleware correctly adds middleware to the app."""
        app = FastAPI()
        
        # Mock the add_middleware method
        app.add_middleware = MagicMock()
        
        # Add PHI middleware
        add_phi_middleware(app)
        
        # Verify middleware was added
        app.add_middleware.assert_called_once()