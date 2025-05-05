import uuid
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

class RequestIdMiddleware(BaseHTTPMiddleware):
    """
    Middleware to ensure each request has a unique ID (x-request-id).

    - If a valid UUID is provided in the 'X-Request-ID' header, it's used.
    - Otherwise, a new UUIDv4 is generated.
    - The request ID is stored in request.state.request_id
    - The request ID is added to the response headers.
    """
    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        request_id = request.headers.get("x-request-id")

        try:
            # Validate if the provided ID is a valid UUID
            if request_id:
                uuid.UUID(request_id)
            else:
                # Generate a new UUID if header is missing
                request_id = str(uuid.uuid4())
        except (ValueError, TypeError):
            # Generate a new UUID if the provided ID is invalid
            request_id = str(uuid.uuid4())

        # Store the request ID in the request state
        request.state.request_id = request_id

        # Proceed with the request/response cycle
        response = await call_next(request)

        # Add the request ID to the response headers
        response.headers["x-request-id"] = request_id

        return response
