"""Test file that uses the debug_with_timeout module to run the failing test with a timeout."""

import pytest
from .debug_with_timeout import run_test_with_timeout


# Make the test name unique so we can run it specifically
@pytest.mark.asyncio
async def test_internal_server_error_with_timeout(client_app_tuple_func_scoped):
    """Run the failing test with a timeout to diagnose the hanging issue."""
    await run_test_with_timeout(client_app_tuple_func_scoped)
