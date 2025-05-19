"""Debug test that directly copies the problematic test but adds a timeout."""

import asyncio
import logging
import sys
import traceback
from fastapi import status
from httpx import AsyncClient, ASGITransport, Response
import pytest

# Configure debug logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("debug_with_timeout")


async def run_test_with_timeout(client_app_tuple):
    """Run the exact test with timeout to identify where it hangs."""
    client, current_fastapi_app = client_app_tuple
    logger.debug("Starting the test with timeout...")

    # Add request ID to trace this specific request through middleware
    request_id = "debug-test-123"

    # Debug the app configuration
    logger.debug(f"App routes: {[route.path for route in current_fastapi_app.routes]}")
    logger.debug(f"App middleware: {current_fastapi_app.middleware_stack}")

    try:
        logger.debug("About to send request...")
        # Set a timeout for the entire test
        response = await asyncio.wait_for(
            client.get(
                "/test-api/test/runtime-error", headers={"X-Request-ID": request_id}
            ),
            timeout=8.0,
        )

        logger.debug(f"Got response: {response.status_code}")
        logger.debug(f"Response text: {response.text}")
        logger.debug(f"Response headers: {response.headers}")

        # Run the same assertions as the original test
        assert (
            response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        ), f"Expected 500, got {response.status_code}. Response: {response.text}"

        response_json = response.json()
        logger.debug(f"Response JSON: {response_json}")

        assert "detail" in response_json
        # HIPAA: Ensure generic error message, no PHI or sensitive details
        assert (
            response_json["detail"] == "An internal server error occurred."
        ), f"Expected generic error message, got: {response_json['detail']}"

        # Ensure the sensitive part of the original exception is not in the response
        assert (
            "This is a sensitive internal error detail that should be masked"
            not in response.text.lower()
        )
        assert "traceback" not in response.text.lower()

        logger.debug("Test completed successfully")
        return True

    except asyncio.TimeoutError:
        logger.error("TEST TIMED OUT - The request is hanging somewhere!")
        logger.error("This is likely caused by a middleware or error handling issue")
        return False
    except Exception as e:
        logger.error(f"Test failed with exception: {type(e).__name__}: {e}")
        logger.error(traceback.format_exc())
        return False


# This function can be imported and run from pytest
async def run_debug_test(client_app_tuple_func_scoped):
    """Function that can be called from pytest."""
    success = await run_test_with_timeout(client_app_tuple_func_scoped)
    # Force the test to pass or fail based on our success flag
    assert success, "Test failed or timed out"


if __name__ == "__main__":
    # This would need to be run with pytest, not directly
    logger.debug("This script should be run through pytest, not directly")
    logger.debug(
        "Use: python -m pytest app/tests/security/api/debug_with_timeout.py -v"
    )
