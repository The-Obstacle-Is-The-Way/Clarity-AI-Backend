"""
Unit tests for Redis Cache Service.

Tests the Redis caching functionality with mock Redis to ensure proper
serialization, error handling, and TTL management.
"""

import json
import asyncio
from unittest.mock import AsyncMock, patch

import pytest
from app.tests.utils.asyncio_helpers import run_with_timeout

from app.infrastructure.cache.redis_cache import RedisCache


@pytest.fixture(scope="function")
def event_loop():
    """Create an instance of the default event loop for each test case."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    # The loop should be closed at the end of the test
    loop.close()


@pytest.fixture
def mock_redis_client():
    """Create a mock Redis client for testing."""
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=None)
    mock_client.setex = AsyncMock(return_value=True)
    mock_client.delete = AsyncMock(return_value=1)
    mock_client.exists = AsyncMock(return_value=1)
    mock_client.incrby = AsyncMock(return_value=1)
    mock_client.ttl = AsyncMock(return_value=300)
    return mock_client


@pytest.fixture
def redis_cache(mock_redis_client):
    """Create a RedisCache instance with a mock Redis client."""
    with patch("redis.asyncio.from_url", return_value=mock_redis_client):
        # The connection_url is mocked, so the actual URL doesn't matter here
        cache = RedisCache(connection_url="redis://mocked:6379/0")
        # Directly assign the mock client after initialization for testing
        cache.redis_client = mock_redis_client
        return cache


# Group tests within a class
class TestRedisCache:
    @pytest.mark.asyncio
    async def test_get_nonexistent_key(self, redis_cache, mock_redis_client):
        """Test getting a nonexistent key returns None."""
        mock_redis_client.get.return_value = None
        result = await redis_cache.get("nonexistent-key")
        assert result is None
        mock_redis_client.get.assert_called_once_with("nonexistent-key")

    @pytest.mark.asyncio
    async def test_get_existing_key(self, redis_cache, mock_redis_client):
        """Test getting an existing key returns deserialized data."""
        mock_data = {"test": "value", "nested": {"data": 123}}
        mock_redis_client.get.return_value = json.dumps(mock_data)

        result = await redis_cache.get("existing-key")

        assert result == mock_data
        mock_redis_client.get.assert_called_once_with("existing-key")

    @pytest.mark.asyncio
    async def test_get_invalid_json(self, redis_cache, mock_redis_client):
        """Test getting a key with invalid JSON returns None."""
        mock_redis_client.get.return_value = "invalid-json{"

        result = await redis_cache.get("invalid-key")

        assert result is None
        mock_redis_client.get.assert_called_once_with("invalid-key")

    @pytest.mark.asyncio
    async def test_set_simple_value(self, redis_cache, mock_redis_client):
        """Test setting a simple string value."""
        value = "simple-string-value"
        ttl = 60

        success = await redis_cache.set("test-key", value, ttl)

        assert success is True
        mock_redis_client.setex.assert_called_once()
        # Check JSON serialization occurred
        args = mock_redis_client.setex.call_args[0]
        assert args[0] == "test-key"
        assert args[1] == ttl
        # Deserialize to check value
        assert json.loads(args[2]) == value

    @pytest.mark.asyncio
    async def test_set_complex_value(self, redis_cache, mock_redis_client):
        """Test setting a complex dictionary value."""
        value = {"name": "test", "data": [1, 2, 3], "nested": {"x": "y"}}
        ttl = 300

        success = await redis_cache.set("complex-key", value, ttl)

        assert success is True
        mock_redis_client.setex.assert_called_once()
        args = mock_redis_client.setex.call_args[0]
        assert args[0] == "complex-key"
        assert args[1] == ttl
        # Deserialize to check value
        assert json.loads(args[2]) == value

    @pytest.mark.asyncio
    async def test_set_json_error(self, redis_cache, mock_redis_client):
        """Test setting a non-serializable value."""
        # Create a circular reference that can't be JSON serialized
        circular_ref = {"self_ref": None}
        circular_ref["self_ref"] = circular_ref

        with patch("json.dumps", side_effect=TypeError("Circular reference")):
            success = await redis_cache.set("error-key", circular_ref, 60)

        assert success is False
        mock_redis_client.setex.assert_not_called()

    @pytest.mark.asyncio
    async def test_set_redis_error(self, redis_cache, mock_redis_client):
        """Test setting a value when Redis raises an exception."""
        mock_redis_client.setex.side_effect = Exception("Redis connection error")

        success = await redis_cache.set("error-key", "value", 60)

        assert success is False
        mock_redis_client.setex.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_existing_key(self, redis_cache, mock_redis_client):
        """Test deleting an existing key."""
        mock_redis_client.delete.return_value = 1

        success = await redis_cache.delete_bool("existing-key")

        assert success is True
        mock_redis_client.delete.assert_called_once_with("existing-key")

    @pytest.mark.asyncio
    async def test_delete_nonexistent_key(self, redis_cache, mock_redis_client):
        """Test deleting a nonexistent key still returns success."""
        mock_redis_client.delete.return_value = 0

        success = await redis_cache.delete_bool("nonexistent-key")

        assert success is True  # We consider this a success since the key doesn't exist
        mock_redis_client.delete.assert_called_once_with("nonexistent-key")

    @pytest.mark.asyncio
    async def test_delete_redis_error(self, redis_cache, mock_redis_client):
        """Test deleting a key when Redis raises an exception."""
        mock_redis_client.delete.side_effect = Exception("Redis connection error")

        success = await redis_cache.delete_bool("error-key")

        assert success is False
        mock_redis_client.delete.assert_called_once_with("error-key")

    @pytest.mark.asyncio
    async def test_exists_true(self, redis_cache, mock_redis_client):
        """Test checking if a key exists when it does."""
        mock_redis_client.exists.return_value = 1

        exists = await redis_cache.exists("existing-key")

        assert exists is True
        mock_redis_client.exists.assert_called_once_with("existing-key")

    @pytest.mark.asyncio
    async def test_exists_false(self, redis_cache, mock_redis_client):
        """Test checking if a key exists when it doesn't."""
        mock_redis_client.exists.return_value = 0

        exists = await redis_cache.exists("nonexistent-key")

        assert exists is False
        mock_redis_client.exists.assert_called_once_with("nonexistent-key")

    @pytest.mark.asyncio
    async def test_exists_redis_error(self, redis_cache, mock_redis_client):
        """Test checking if a key exists when Redis raises an exception."""
        mock_redis_client.exists.side_effect = Exception("Redis connection error")

        exists = await redis_cache.exists("error-key")

        assert exists is False
        mock_redis_client.exists.assert_called_once_with("error-key")

    @pytest.mark.asyncio
    async def test_increment_success(self, redis_cache, mock_redis_client):
        """Test incrementing a counter."""
        mock_redis_client.incrby.return_value = 6

        new_value = await redis_cache.increment("counter-key", 5)

        assert new_value == 6
        mock_redis_client.incrby.assert_called_once_with("counter-key", 5)

    @pytest.mark.asyncio
    async def test_increment_redis_error(self, redis_cache, mock_redis_client):
        """Test incrementing a counter when Redis raises an exception."""
        mock_redis_client.incrby.side_effect = Exception("Redis connection error")

        new_value = await redis_cache.increment_with_none("error-key", 1)

        assert new_value is None
        mock_redis_client.incrby.assert_called_once_with("error-key", 1)

    @pytest.mark.asyncio
    async def test_get_ttl_success(self, redis_cache, mock_redis_client):
        """Test getting the TTL of a key."""
        mock_redis_client.ttl.return_value = 42

        ttl = await redis_cache.get_ttl("test-key")

        assert ttl == 42
        mock_redis_client.ttl.assert_called_once_with("test-key")

    @pytest.mark.asyncio
    async def test_get_ttl_nonexistent_key(self, redis_cache, mock_redis_client):
        """Test getting the TTL of a nonexistent key."""
        mock_redis_client.ttl.return_value = -2  # Redis returns -2 for nonexistent keys

        ttl = await redis_cache.get_ttl("nonexistent-key")

        assert ttl is None
        mock_redis_client.ttl.assert_called_once_with("nonexistent-key")

    @pytest.mark.asyncio
    async def test_get_ttl_persistent_key(self, redis_cache, mock_redis_client):
        """Test getting the TTL of a persistent key (no expiry)."""
        mock_redis_client.ttl.return_value = -1  # Redis returns -1 for persistent keys

        ttl = await redis_cache.get_ttl("persistent-key")

        assert ttl is None
        mock_redis_client.ttl.assert_called_once_with("persistent-key")

    @pytest.mark.asyncio
    async def test_get_ttl_redis_error(self, redis_cache, mock_redis_client):
        """Test getting the TTL when Redis raises an exception."""
        mock_redis_client.ttl.side_effect = Exception("Redis connection error")

        ttl = await redis_cache.get_ttl("error-key")

        assert ttl is None
        mock_redis_client.ttl.assert_called_once_with("error-key")


# These tests don't need the class structure or fixtures
def test_no_redis_available():
    """Test graceful degradation when Redis is not available."""
    with patch("redis.asyncio.from_url", side_effect=Exception("Connection error")):
        cache = RedisCache(
            connection_url="redis://unavailable:6379/0"
        )  # Use a different URL for clarity
        assert cache.redis_client is None


@pytest.mark.asyncio
async def test_methods_with_no_redis_client():
    """Test all methods gracefully handle when Redis client is not available."""
    # Simulate Redis not being available during initialization
    with patch("redis.asyncio.from_url", side_effect=Exception("Connection error")):
        cache = RedisCache(connection_url="redis://unavailable:6379/0")

    assert cache.redis_client is None  # Ensure client is None

    # Test all methods
    assert await cache.get("any-key") is None
    assert await cache.set("any-key", "value") is False
    assert (
        await cache.delete_bool("any-key") is False
    )  # Use delete_bool for boolean return
    assert await cache.exists("any-key") is False
    assert (
        await cache.increment_with_none("any-key") is None
    )  # Use increment_with_none for None return
    assert await cache.get_ttl("any-key") is None
