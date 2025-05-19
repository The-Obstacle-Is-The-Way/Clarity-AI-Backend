"""Debug test to identify hanging in test_internal_server_error_masked."""

import asyncio
import logging
import sys

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from httpx import ASGITransport, AsyncClient

# Configure debug logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("debug_test")

# Create a minimal FastAPI app for testing
app = FastAPI()


@app.get("/test-error")
async def force_runtime_error():
    """Test endpoint that raises a RuntimeError."""
    logger.debug("Endpoint called, raising RuntimeError")
    raise RuntimeError("Test error that should be masked")


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """Global exception handler."""
    logger.debug(f"Exception handler called for: {type(exc).__name__}")
    return JSONResponse(
        status_code=500, content={"detail": "An internal server error occurred."}
    )


@app.middleware("http")
async def debug_middleware(request: Request, call_next):
    """Debug middleware to trace execution flow."""
    logger.debug(f"Middleware start: {request.url.path}")
    try:
        logger.debug("Before call_next")
        response = await call_next(request)
        logger.debug("After call_next - got response")
        return response
    except Exception as e:
        logger.debug(f"Middleware caught exception: {type(e).__name__}")
        raise


async def debug_test():
    """Run a simplified test case to debug the hanging issue."""
    logger.debug("Starting debug test")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        logger.debug("Client created, sending request")
        try:
            response = await client.get("/test-error")
            logger.debug(f"Got response: {response.status_code}")
        except Exception as e:
            logger.debug(f"Client request failed: {type(e).__name__}")
        logger.debug("Test completed")


if __name__ == "__main__":
    logger.debug("Running debug test")
    asyncio.run(debug_test())
