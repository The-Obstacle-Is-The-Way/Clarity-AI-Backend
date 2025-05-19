"""Debug test focusing specifically on the hanging issue in test_internal_server_error_masked."""

import asyncio
import logging
import sys
import traceback
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from httpx import ASGITransport, AsyncClient
from starlette.middleware.base import BaseHTTPMiddleware

# Configure debug logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("debug_internal_error")


# Create a more complete app similar to the real test environment
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.debug("App startup")
    yield
    logger.debug("App shutdown")


app = FastAPI(lifespan=lifespan)


@app.get("/test-api/test/runtime-error")
async def force_runtime_error():
    """Endpoint that deliberately raises a RuntimeError, mimicking the test endpoint."""
    logger.debug("Runtime error endpoint called")
    raise RuntimeError(
        "This is a sensitive internal error detail that should be masked"
    )


# Add exception handler like in app_factory.py
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """Handler for all exceptions, returning a sanitized message."""
    logger.debug(f"Generic exception handler called for: {type(exc).__name__}")
    logger.debug(f"Exception details: {exc}")
    return JSONResponse(
        status_code=500, content={"detail": "An internal server error occurred."}
    )


# Request ID middleware
class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        logger.debug("RequestIdMiddleware - Start")
        try:
            response = await call_next(request)
            logger.debug("RequestIdMiddleware - After call_next")
            return response
        except Exception as e:
            logger.debug(f"RequestIdMiddleware - Exception: {type(e).__name__}")
            logger.debug(traceback.format_exc())
            raise


app.add_middleware(RequestIdMiddleware)


# Security Headers middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        logger.debug("SecurityHeadersMiddleware - Start")
        try:
            response = await call_next(request)
            logger.debug("SecurityHeadersMiddleware - After call_next")
            # Add headers that won't affect our test
            response.headers["X-Test"] = "Test"
            return response
        except Exception as e:
            logger.debug(f"SecurityHeadersMiddleware - Exception: {type(e).__name__}")
            logger.debug(traceback.format_exc())
            raise


app.add_middleware(SecurityHeadersMiddleware)


# Essential app state middleware (similar to app_factory.py)
@app.middleware("http")
async def set_essential_app_state_middleware(request: Request, call_next):
    logger.debug("Essential state middleware - Start")
    try:
        response = await call_next(request)
        logger.debug("Essential state middleware - After call_next")
        return response
    except Exception as e:
        logger.debug(f"Essential state middleware - Exception: {type(e).__name__}")
        logger.debug(traceback.format_exc())
        raise


async def run_test_with_timeout():
    """Run the test with a timeout to avoid infinite hanging."""
    logger.debug("Creating test client")
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        logger.debug("Sending request to trigger RuntimeError")
        try:
            # Set explicit timeout to avoid hanging
            response = await asyncio.wait_for(
                client.get("/test-api/test/runtime-error"), timeout=5.0
            )
            logger.debug(f"Response received: {response.status_code}")
            logger.debug(f"Response content: {response.text}")
        except asyncio.TimeoutError:
            logger.error("REQUEST TIMED OUT - Possible hanging detected!")
        except Exception as e:
            logger.debug(f"Exception during request: {type(e).__name__}")
            logger.debug(traceback.format_exc())

    logger.debug("Test completed")


if __name__ == "__main__":
    logger.debug("Starting debug test for internal server error masking")
    asyncio.run(run_test_with_timeout())
