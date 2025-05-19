import json
import logging
import time

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

# Define a strict allowlist of headers that are safe to log
# CRITICAL (HIPAA): Ensure no PHI-containing headers are added here.
SAFE_HEADERS_ALLOWLIST = {
    "accept",
    "accept-encoding",
    "accept-language",
    "user-agent",
    # Add other demonstrably safe headers here if necessary
}


class LoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for logging requests and responses in a HIPAA-compliant manner."""

    def __init__(self, app: ASGIApp, logger: logging.Logger | None = None) -> None:
        super().__init__(app)
        self.logger = logger or logging.getLogger(__name__)

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        """Log request start and finish details."""
        start_time = time.time()

        # Try to get request_id set by RequestIdMiddleware
        try:
            # Use attribute access, which is standard for Starlette state
            request_id = request.state.request_id
        except (
            AttributeError
        ):  # Handle case where RequestIdMiddleware might not have run
            request_id = "N/A"  # Fallback if not set

        # Extract safe headers
        safe_headers = {
            k: v
            for k, v in request.headers.items()
            if k.lower() in SAFE_HEADERS_ALLOWLIST
        }

        response = None
        try:
            response = await call_next(request)
            process_time = (time.time() - start_time) * 1000  # Convert to ms
            status_code = response.status_code
            log_level = logging.INFO  # Default level for successful responses

            # Log request finish details
            # CRITICAL (HIPAA): Do not log response body or sensitive headers.
            log_details_success = {
                "message": "Request finished",
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "client_ip": self._get_client_ip(request),
                "headers": safe_headers,
                "status_code": status_code,
                "duration_ms": round(process_time, 2),
            }
            self.logger.log(log_level, json.dumps(log_details_success))

        except Exception as e:
            # Log exceptions before re-raising
            process_time = (time.time() - start_time) * 1000  # Convert to ms
            status_code = 500  # Assume internal server error for unhandled exceptions
            log_level = logging.ERROR
            log_details_error = {
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "client_ip": self._get_client_ip(request),
                "headers": safe_headers,
                "duration_ms": round(process_time, 2),
                "error": e,
            }
            self.logger.error(
                f"Request failed: {request.method} {request.url.path} {request_id} "
                f"| Duration: {log_details_error['duration_ms']:.2f}ms | Error: {e}",
                exc_info=True,  # Include traceback information
                extra=log_details_error,
            )
            raise  # Re-raise the exception to be handled by FastAPI/Starlette

        return response

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP, handling potential None value."""
        if request.client:
            return request.client.host
        return "N/A"
