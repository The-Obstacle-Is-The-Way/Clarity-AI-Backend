"""
Example test file demonstrating the modern approach to asyncio testing.

This file shows how to use the pytest-asyncio decorator approach instead of
custom event loop fixtures. It also demonstrates proper test isolation.
"""

import asyncio

import pytest

from app.tests.utils.asyncio_helpers import run_with_timeout


# Modern approach: use the decorator with scope parameter
@pytest.mark.asyncio(scope="function")
async def test_async_addition():
    """Test a simple async function using modern approach."""

    # Define an async function
    async def add_numbers(a, b):
        await asyncio.sleep(0.1)  # Simulate some async work
        return a + b

    # Call the async function and assert
    result = await add_numbers(1, 2)
    assert result == 3


# Use helpers to manage timeouts
@pytest.mark.asyncio
async def test_with_timeout():
    """Test a function using timeout helper."""

    # Define an async function
    async def delayed_operation():
        await asyncio.sleep(0.2)
        return "completed"

    # Use the timeout helper
    result = await run_with_timeout(delayed_operation(), 1.0)
    assert result == "completed"


# Example of class-based tests
class TestAsyncOperations:
    """Test class for async operations."""

    @pytest.mark.asyncio
    async def test_async_map(self):
        """Test mapping a function over async results."""

        # Define an async function
        async def multiply(x):
            await asyncio.sleep(0.1)
            return x * 2

        # Map over a list of values
        values = [1, 2, 3, 4, 5]
        results = await asyncio.gather(*[multiply(x) for x in values])

        # Assert results
        assert results == [2, 4, 6, 8, 10]

    @pytest.mark.asyncio
    async def test_concurrent_tasks(self):
        """Test running multiple tasks concurrently."""
        # Create a list to track execution order
        execution_order = []

        async def task_a():
            await asyncio.sleep(0.2)
            execution_order.append("A")
            return "result A"

        async def task_b():
            await asyncio.sleep(0.1)
            execution_order.append("B")
            return "result B"

        # Run tasks concurrently
        result_a, result_b = await asyncio.gather(task_a(), task_b())

        # Assert correct results and execution order (B should finish before A)
        assert result_a == "result A"
        assert result_b == "result B"
        assert execution_order == ["B", "A"]
