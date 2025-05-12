"""
Tests for Redis Cache Service.

This module contains tests for the Redis cache service implementation,
focusing on caching, rate limiting, and other Redis operations.
"""

import json
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from app.tests.utils.asyncio_helpers import run_with_timeout

from app.infrastructure.services.redis_cache_service import RedisCacheService


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
    client = AsyncMock()
    client.get = AsyncMock()
    client.set = AsyncMock(return_value=True)
    client.setex = AsyncMock(return_value=True)
    client.delete = AsyncMock(return_value=1)
    client.incrby = AsyncMock()
    client.expire = AsyncMock(return_value=True)
    client.hgetall = AsyncMock()
    client.hmset = AsyncMock(return_value=True)
    client.pipeline = MagicMock()

    # Setup pipeline mock
    pipeline_mock = AsyncMock()
    pipeline_mock.hmset = AsyncMock()
    pipeline_mock.expire = AsyncMock()
    pipeline_mock.execute = AsyncMock(return_value=[True])
    client.pipeline.return_value = pipeline_mock

    return client

@pytest.fixture
def redis_cache_service(mock_redis_client):
    """Create a Redis cache service with mocked dependencies for testing."""
    with patch("redis.asyncio.Redis.from_pool", return_value=mock_redis_client):
        with patch("redis.asyncio.connection.ConnectionPool"):
            service = RedisCacheService(
                host="localhost",
                port=6379,
                password="password",
                ssl=True,
                prefix="test:"
            )
            yield service


@pytest.mark.asyncio()
@pytest.mark.db_required()
@pytest.mark.asyncio
async def test_get_cache_hit(redis_cache_service, mock_redis_client):
    """Test retrieving a value from cache when the key exists."""
    # Arrange
    key = "test-key"
    expected_value = {"name": "test", "value": 123}
    mock_redis_client.get.return_value = json.dumps(expected_value)

    # Act
    result = await redis_cache_service.get(key)

    # Assert
    mock_redis_client.get.assert_called_once_with("test:test-key")
    assert result == expected_value

@pytest.mark.asyncio()
async def test_get_cache_miss(redis_cache_service, mock_redis_client):
    """Test retrieving a value from cache when the key doesn't exist."""
    # Arrange
    key = "missing-key"
    mock_redis_client.get.return_value = None

    # Act
    result = await redis_cache_service.get(key)

    # Assert
    mock_redis_client.get.assert_called_once_with("test:missing-key")
    assert result is None

@pytest.mark.asyncio()
async def test_set_with_ttl(redis_cache_service, mock_redis_client):
    """Test setting a value with TTL in cache."""
    # Arrange
    key = "ttl-key"
    value = {"data": "test-data"}
    ttl = 60

    # Act
    result = await redis_cache_service.set(key, value, ttl)

    # Assert
    mock_redis_client.setex.assert_called_once_with("test:ttl-key", ttl, json.dumps(value))
    assert result is True


@pytest.mark.asyncio()
async def test_delete_existing_key(redis_cache_service, mock_redis_client):
    """Test deleting an existing key from cache."""
    # Arrange
    key = "existing-key"
    mock_redis_client.delete.return_value = 1

    # Act
    result = await redis_cache_service.delete(key)

    # Assert
    mock_redis_client.delete.assert_called_once_with("test:existing-key")
    assert result is True

@pytest.mark.asyncio()
async def test_increment(redis_cache_service, mock_redis_client):
    """Test incrementing a counter."""
    # Arrange
    key = "counter-key"
    mock_redis_client.incrby.return_value = 5

    # Act
    result = await redis_cache_service.increment(key)

    # Assert
    mock_redis_client.incrby.assert_called_once_with("test:counter-key", 1)
    assert result == 5

@pytest.mark.asyncio()
async def test_expire(redis_cache_service, mock_redis_client):
    """Test setting expiration on a key."""
    # Arrange
    key = "expire-key"
    seconds = 3600

    # Act
    result = await redis_cache_service.expire(key, seconds)

    # Assert
    mock_redis_client.expire.assert_called_once_with("test:expire-key", seconds)
    assert result is True

@pytest.mark.asyncio()
async def test_get_hash(redis_cache_service, mock_redis_client):
    """Test getting a hash from cache."""
    # Arrange
    key = "hash-key"
    mock_redis_client.hgetall.return_value = {
        "field1": "value1",
        "field2": json.dumps({"nested": "value"}),
    }

    # Act
    result = await redis_cache_service.get_hash(key)

    # Assert
    mock_redis_client.hgetall.assert_called_once_with("test:hash-key")
    assert result["field1"] == "value1"
    assert result["field2"]["nested"] == "value"
