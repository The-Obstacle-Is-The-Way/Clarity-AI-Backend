"""
Performance Benchmark Tests for Clarity-AI Backend
==================================================

These tests measure the performance of critical functions and endpoints.
Run with: make benchmark or pytest app/tests -k "benchmark" --benchmark-only
"""

import pytest
import asyncio
import time
import json
import uuid
from datetime import datetime
from unittest.mock import Mock, patch

# Import core functions to benchmark
from app.core.utils.logging import get_logger
from app.infrastructure.security.password import get_password_hash, verify_password


class TestCoreFunctionsBenchmarks:
    """Benchmark tests for core utility functions."""
    
    def test_logger_creation_benchmark(self, benchmark):
        """Benchmark logger creation performance."""
        def create_logger():
            return get_logger("test_logger")
        
        result = benchmark(create_logger)
        assert result is not None
    
    def test_password_hashing_benchmark(self, benchmark):
        """Benchmark password hashing performance."""
        password = "test_password_123!"
        
        def hash_password_test():
            return get_password_hash(password)
        
        result = benchmark(hash_password_test)
        assert result is not None
        assert len(result) > 50  # Hashed passwords should be substantial
    
    def test_password_verification_benchmark(self, benchmark):
        """Benchmark password verification performance."""
        password = "test_password_123!"
        hashed = get_password_hash(password)
        
        def verify_password_test():
            return verify_password(password, hashed)
        
        result = benchmark(verify_password_test)
        assert result is True
    
    def test_uuid_generation_benchmark(self, benchmark):
        """Benchmark UUID generation performance."""
        def generate_uuid_test():
            return str(uuid.uuid4())
        
        result = benchmark(generate_uuid_test)
        assert result is not None
        assert len(result) > 30  # UUIDs are long
    
    def test_datetime_conversion_benchmark(self, benchmark):
        """Benchmark datetime to string conversion."""
        dt = datetime.now()
        
        def datetime_conversion():
            return dt.isoformat()
        
        result = benchmark(datetime_conversion)
        assert result is not None
        assert isinstance(result, str)


class TestDataProcessingBenchmarks:
    """Benchmark tests for data processing operations."""
    
    def test_json_serialization_benchmark(self, benchmark):
        """Benchmark JSON serialization of complex data."""
        complex_data = {
            "users": [
                {
                    "id": i,
                    "name": f"User {i}",
                    "email": f"user{i}@example.com",
                    "metadata": {
                        "created": datetime.now().isoformat(),
                        "settings": {"theme": "dark", "notifications": True},
                        "scores": [j * 0.1 for j in range(100)]
                    }
                }
                for i in range(100)
            ]
        }
        
        def serialize_json():
            return json.dumps(complex_data)
        
        result = benchmark(serialize_json)
        assert len(result) > 1000
    
    def test_json_deserialization_benchmark(self, benchmark):
        """Benchmark JSON deserialization of complex data."""
        complex_data = {
            "items": [{"id": i, "value": f"item_{i}"} for i in range(1000)]
        }
        json_string = json.dumps(complex_data)
        
        def deserialize_json():
            return json.loads(json_string)
        
        result = benchmark(deserialize_json)
        assert len(result["items"]) == 1000
    
    def test_list_processing_benchmark(self, benchmark):
        """Benchmark list processing operations."""
        large_list = list(range(10000))
        
        def process_list():
            return [x * 2 for x in large_list if x % 2 == 0]
        
        result = benchmark(process_list)
        assert len(result) == 5000  # Half the numbers are even
    
    def test_dictionary_operations_benchmark(self, benchmark):
        """Benchmark dictionary operations."""
        def create_and_process_dict():
            data = {f"key_{i}": f"value_{i}" for i in range(1000)}
            # Simulate some processing
            processed = {}
            for k, v in data.items():
                if "5" in k:  # Filter condition
                    processed[k.upper()] = v.upper()
            return processed
        
        result = benchmark(create_and_process_dict)
        assert len(result) > 0


class TestAsyncBenchmarks:
    """Benchmark tests for asynchronous operations."""
    
    @pytest.mark.asyncio
    async def test_async_operation_benchmark(self, benchmark):
        """Benchmark async operation performance."""
        
        async def async_operation():
            # Simulate async work
            await asyncio.sleep(0.001)  # 1ms delay
            return {"status": "completed", "data": [i for i in range(100)]}
        
        def sync_wrapper():
            # Run async function in sync context for benchmarking
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(async_operation())
            finally:
                loop.close()
        
        result = benchmark(sync_wrapper)
        assert result["status"] == "completed"
        assert len(result["data"]) == 100
    
    @pytest.mark.asyncio  
    async def test_concurrent_tasks_benchmark(self, benchmark):
        """Benchmark concurrent task execution."""
        
        async def single_task(task_id: int):
            # Simulate async work
            await asyncio.sleep(0.001)
            return f"task_{task_id}_completed"
        
        async def run_concurrent_tasks():
            tasks = [single_task(i) for i in range(10)]
            return await asyncio.gather(*tasks)
        
        def sync_wrapper():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(run_concurrent_tasks())
            finally:
                loop.close()
        
        result = benchmark(sync_wrapper)
        assert len(result) == 10
        assert all("completed" in r for r in result)


class TestMockDatabaseBenchmarks:
    """Benchmark tests for simulated database operations."""
    
    def test_mock_database_query_benchmark(self, benchmark):
        """Benchmark simulated database query performance."""
        
        # Mock database data
        mock_users = [
            {"id": i, "name": f"User {i}", "active": i % 2 == 0}
            for i in range(1000)
        ]
        
        def query_active_users():
            # Simulate database query
            return [user for user in mock_users if user["active"]]
        
        result = benchmark(query_active_users)
        assert len(result) == 500  # Half are active
    
    def test_mock_database_insert_benchmark(self, benchmark):
        """Benchmark simulated database insert performance."""
        
        mock_db = []
        
        def insert_batch():
            nonlocal mock_db
            batch = [
                {"id": i, "timestamp": datetime.now().isoformat()}
                for i in range(100)
            ]
            mock_db.extend(batch)
            return len(batch)
        
        result = benchmark(insert_batch)
        assert result == 100
    
    def test_mock_complex_query_benchmark(self, benchmark):
        """Benchmark complex query simulation."""
        
        # Mock data with relationships
        users = [{"id": i, "department_id": i % 10} for i in range(1000)]
        departments = [{"id": i, "name": f"Dept {i}"} for i in range(10)]
        
        def complex_query():
            # Simulate JOIN-like operation
            result = []
            for user in users:
                if user["id"] % 5 == 0:  # Filter condition
                    dept = next(d for d in departments if d["id"] == user["department_id"])
                    result.append({
                        "user_id": user["id"],
                        "department_name": dept["name"]
                    })
            return result
        
        result = benchmark(complex_query)
        assert len(result) == 200  # Every 5th user


class TestSecurityBenchmarks:
    """Benchmark tests for security-related operations."""
    
    def test_multiple_password_hashing_benchmark(self, benchmark):
        """Benchmark hashing multiple passwords."""
        passwords = [f"password_{i}!" for i in range(10)]
        
        def hash_multiple_passwords():
            return [get_password_hash(pwd) for pwd in passwords]
        
        result = benchmark(hash_multiple_passwords)
        assert len(result) == 10
        assert all(len(h) > 50 for h in result)
    
    def test_token_generation_simulation_benchmark(self, benchmark):
        """Benchmark token generation simulation."""
        import secrets
        import string
        
        def generate_token():
            # Simulate JWT token generation
            alphabet = string.ascii_letters + string.digits
            return ''.join(secrets.choice(alphabet) for _ in range(64))
        
        result = benchmark(generate_token)
        assert len(result) == 64
        assert result.isalnum()


# Benchmark configuration and markers
pytestmark = [
    pytest.mark.benchmark,
    pytest.mark.performance
] 