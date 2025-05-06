import uuid
from unittest.mock import patch

import pytest
from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import Receive, Scope, Send

from app.presentation.middleware.request_id import RequestIdMiddleware


async def dummy_app(scope: Scope, receive: Receive, send: Send) -> None:
    """A minimal ASGI app for testing middleware."""
    response = Response("Hello, world!", media_type="text/plain")
    await response(scope, receive, send)


async def dummy_call_next(request: Request) -> Response:
    """A minimal call_next function for testing middleware."""
    # Simulate accessing request state if needed by downstream handlers
    _ = request.state.request_id
    return Response("Call next response", status_code=200)


@pytest.mark.asyncio
async def test_request_id_middleware_generates_id():
    """Test that middleware generates an ID if none is provided."""
    with patch("uuid.uuid4") as mock_uuid4:
        fixed_test_uuid = "123e4567-e89b-12d3-a456-426614174000"  # A fixed, known UUID string
        mock_uuid4.return_value = fixed_test_uuid

        middleware = RequestIdMiddleware(app=dummy_app)
        scope = {"type": "http", "method": "GET", "headers": []}
        request = Request(scope)

        response = await middleware.dispatch(request, dummy_call_next)

        assert request.state.request_id == fixed_test_uuid
        assert response.headers["X-Request-ID"] == fixed_test_uuid
        mock_uuid4.assert_called_once()


@pytest.mark.asyncio
async def test_request_id_middleware_uses_valid_incoming_id():
    """Test that middleware uses a valid incoming X-Request-ID."""
    incoming_id = str(uuid.uuid4())
    headers = Headers({"X-Request-ID": incoming_id})
    scope = {"type": "http", "method": "GET", "headers": headers.raw}
    request = Request(scope)

    middleware = RequestIdMiddleware(app=dummy_app)
    response = await middleware.dispatch(request, dummy_call_next)

    assert request.state.request_id == incoming_id
    assert response.headers["X-Request-ID"] == incoming_id


@pytest.mark.asyncio
async def test_request_id_middleware_generates_id_for_invalid_incoming_id():
    """Test that middleware generates an ID if the incoming one is invalid."""
    with patch("uuid.uuid4") as mock_uuid4_local:
        fixed_test_uuid = "789e0123-e45b-67c8-d901-234567890123"  # A different fixed, known UUID string
        mock_uuid4_local.return_value = fixed_test_uuid

        invalid_incoming_id = "not-a-valid-uuid"
        headers = Headers({"X-Request-ID": invalid_incoming_id})
        scope = {"type": "http", "method": "GET", "headers": headers.raw}
        request = Request(scope)

        middleware = RequestIdMiddleware(app=dummy_app)
        response = await middleware.dispatch(request, dummy_call_next)

        mock_uuid4_local.assert_called_once()
        assert request.state.request_id == fixed_test_uuid
        assert response.headers["X-Request-ID"] == fixed_test_uuid
