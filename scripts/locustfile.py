"""
Locust Load Testing Configuration for Clarity-AI Backend
========================================================

This file defines load testing scenarios for the Clarity-AI Backend API.
Run with: make load-test or locust -f scripts/locustfile.py --host=http://localhost:8000
"""

from locust import HttpUser, task, between
import json
import random


class ClarityAIUser(HttpUser):
    """Simulates a user interacting with the Clarity-AI Backend API."""
    
    # Wait 1-3 seconds between requests to simulate real user behavior
    wait_time = between(1, 3)
    
    def on_start(self):
        """Called when a simulated user starts."""
        # Try to authenticate if auth endpoints exist
        self.token = None
        self.user_id = None
        
    @task(10)
    def health_check(self):
        """Test the health endpoint - most common request."""
        with self.client.get("/api/v1/health", catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Health check failed: {response.status_code}")
    
    @task(8)
    def api_docs(self):
        """Test OpenAPI documentation endpoint."""
        self.client.get("/docs")
    
    @task(6)
    def openapi_spec(self):
        """Test OpenAPI JSON specification."""
        self.client.get("/openapi.json")
    
    @task(5)
    def root_endpoint(self):
        """Test root API endpoint."""
        self.client.get("/")
    
    @task(3)
    def api_v1_root(self):
        """Test API v1 root endpoint."""
        self.client.get("/api/v1/")
    
    @task(2)
    def auth_endpoints(self):
        """Test authentication-related endpoints if they exist."""
        # Try common auth endpoints
        endpoints = [
            "/api/v1/auth/login",
            "/api/v1/auth/register", 
            "/api/v1/auth/me",
            "/api/v1/user/profile"
        ]
        
        endpoint = random.choice(endpoints)
        with self.client.get(endpoint, catch_response=True) as response:
            # These might return 404 or 401, which is expected
            if response.status_code in [200, 401, 404, 422]:
                response.success()
            else:
                response.failure(f"Unexpected status: {response.status_code}")
    
    @task(2)
    def ml_endpoints(self):
        """Test ML/AI endpoints if they exist."""
        endpoints = [
            "/api/v1/ml/predict",
            "/api/v1/ai/chat",
            "/api/v1/analysis/sentiment",
            "/api/v1/models/status"
        ]
        
        endpoint = random.choice(endpoints)
        with self.client.get(endpoint, catch_response=True) as response:
            # These might return 404, which is expected for non-existent endpoints
            if response.status_code in [200, 401, 404, 422]:
                response.success()
            else:
                response.failure(f"Unexpected status: {response.status_code}")
    
    @task(1)
    def post_requests(self):
        """Test POST requests with sample data."""
        endpoints_data = [
            ("/api/v1/auth/login", {"username": "test@example.com", "password": "testpass"}),
            ("/api/v1/ml/predict", {"text": "Sample text for analysis"}),
            ("/api/v1/feedback", {"rating": 5, "comment": "Great service!"})
        ]
        
        endpoint, data = random.choice(endpoints_data)
        
        with self.client.post(
            endpoint, 
            json=data,
            headers={"Content-Type": "application/json"},
            catch_response=True
        ) as response:
            # Accept various responses as successful for testing
            if response.status_code in [200, 201, 400, 401, 404, 422]:
                response.success()
            else:
                response.failure(f"Unexpected status: {response.status_code}")


class AdminUser(HttpUser):
    """Simulates an admin user with heavier usage patterns."""
    
    wait_time = between(0.5, 2)  # More aggressive timing
    weight = 1  # Less frequent than regular users
    
    @task(5)
    def admin_endpoints(self):
        """Test admin endpoints."""
        endpoints = [
            "/api/v1/admin/users",
            "/api/v1/admin/system/status",
            "/api/v1/admin/logs",
            "/api/v1/admin/metrics"
        ]
        
        endpoint = random.choice(endpoints)
        with self.client.get(endpoint, catch_response=True) as response:
            if response.status_code in [200, 401, 403, 404]:
                response.success()
            else:
                response.failure(f"Admin endpoint failed: {response.status_code}")
    
    @task(3)
    def bulk_operations(self):
        """Test bulk operations that might be admin-only."""
        data = {
            "operation": "bulk_update",
            "items": [{"id": i, "status": "active"} for i in range(10)]
        }
        
        with self.client.post(
            "/api/v1/admin/bulk",
            json=data,
            catch_response=True
        ) as response:
            if response.status_code in [200, 400, 401, 403, 404]:
                response.success()
            else:
                response.failure(f"Bulk operation failed: {response.status_code}")


class HighVolumeUser(HttpUser):
    """Simulates high-volume API usage for stress testing."""
    
    wait_time = between(0.1, 0.5)  # Very aggressive
    weight = 2  # Medium frequency
    
    @task
    def rapid_health_checks(self):
        """Rapid health check requests to test performance under load."""
        self.client.get("/api/v1/health")
    
    @task
    def concurrent_ml_requests(self):
        """Simulate concurrent ML processing requests."""
        data = {
            "text": f"Performance test request #{random.randint(1, 1000)}",
            "model": "default",
            "options": {"fast": True}
        }
        
        with self.client.post("/api/v1/ml/predict", json=data, catch_response=True) as response:
            if response.status_code in [200, 400, 404, 422, 429]:  # Include rate limiting
                response.success()
            else:
                response.failure(f"ML request failed: {response.status_code}")


# Performance Testing Configuration
class DatabaseStressUser(HttpUser):
    """Tests database-heavy operations."""
    
    wait_time = between(0.5, 1.5)
    weight = 1
    
    @task
    def database_operations(self):
        """Test endpoints that likely hit the database."""
        operations = [
            ("GET", "/api/v1/users/search?q=test"),
            ("GET", "/api/v1/analytics/dashboard"),
            ("GET", "/api/v1/reports/monthly"),
            ("POST", "/api/v1/data/export", {"format": "json"})
        ]
        
        method, endpoint = random.choice(operations[:3])  # Only GET for now
        
        with self.client.get(endpoint, catch_response=True) as response:
            if response.status_code in [200, 404, 401, 422]:
                response.success()
            else:
                response.failure(f"Database operation failed: {response.status_code}") 