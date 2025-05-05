import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.routing import Route
from starlette.testclient import TestClient
from starlette.types import Receive, Scope, Send, ASGIApp

from app.presentation.middleware.request_id import RequestIdMiddleware

# --- Test Setup ---

# A simple endpoint for testing middleware
async def dummy_endpoint(request: Request) -> PlainTextResponse:
    # Access state if needed for assertion later (not strictly needed for these tests)
    request_id = getattr(request.state, "request_id", None)
    return PlainTextResponse(f"OK - ID: {request_id}")

# Middleware to clear state before RequestIdMiddleware runs (for specific tests)
async def clear_request_state(request: Request, call_next: callable) -> Response:
    if hasattr(request.state, "_state"): # Clear Starlette's internal state dict
        request.state._state = {}
    return await call_next(request)

@pytest.fixture
def test_app() -> Starlette:
    """Fixture to create a Starlette app with RequestIdMiddleware."""
    routes = [
        Route("/test", endpoint=dummy_endpoint)
    ]
    middleware = [
        Middleware(RequestIdMiddleware) # Add the middleware
    ]
    app = Starlette(routes=routes, middleware=middleware)
    return app

@pytest.fixture
def client(test_app: Starlette) -> TestClient:
    """Fixture to create a TestClient for the app."""
    return TestClient(test_app)

# --- Unit Tests ---

def test_new_request_id_generated(client: TestClient) -> None:
    """Test that a new request ID is generated if none is provided."""
    response = client.get("/test")
    assert response.status_code == 200
    assert "x-request-id" in response.headers
    try:
        uuid.UUID(response.headers["x-request-id"])
    except ValueError:
        pytest.fail("X-Request-ID is not a valid UUID")
    # Check response body includes the generated ID
    assert f"ID: {response.headers['x-request-id']}" in response.text

def test_existing_valid_request_id_used(client: TestClient) -> None:
    """Test that a valid existing request ID is used."""
    existing_id = str(uuid.uuid4())
    headers = {"X-Request-ID": existing_id}
    response = client.get("/test", headers=headers)
    assert response.status_code == 200
    assert response.headers["x-request-id"] == existing_id
    assert f"ID: {existing_id}" in response.text

def test_invalid_request_id_regenerated(client: TestClient) -> None:
    """Test that an invalid request ID results in a new one being generated."""
    invalid_id = "not-a-uuid"
    headers = {"X-Request-ID": invalid_id}
    response = client.get("/test", headers=headers)
    assert response.status_code == 200
    assert "x-request-id" in response.headers
    new_id = response.headers["x-request-id"]
    assert new_id != invalid_id # Ensure a new ID was generated
    try:
        uuid.UUID(new_id)
    except ValueError:
        pytest.fail("Generated X-Request-ID is not a valid UUID")
    assert f"ID: {new_id}" in response.text

@pytest.mark.asyncio
async def test_dispatch_stores_state_and_sets_header() -> None:
    """Test dispatch directly, checking state and header setting."""
    # Mock the call_next function
    mock_call_next = AsyncMock()
    mock_response = Response("mock response", status_code=200)
    mock_call_next.return_value = mock_response

    # Create a mock Request
    scope: Scope = {
        "type": "http",
        "headers": [],
        "method": "GET",
        "path": "/test",
        "state": {}, # Ensure state starts empty
    }
    async def mock_receive() -> dict:
        return {}
    async def mock_send(message: dict) -> None:
        pass
    receive: Receive = mock_receive
    send: Send = mock_send
    request = Request(scope, receive, send)

    # Instantiate the middleware
    middleware = RequestIdMiddleware(app=MagicMock(spec=ASGIApp)) # app isn't used in this dispatch logic

    # Call dispatch
    response = await middleware.dispatch(request, mock_call_next)

    # Assertions
    mock_call_next.assert_awaited_once_with(request)
    assert hasattr(request.state, "request_id")
    request_id = request.state.request_id
    assert isinstance(request_id, str)
    try:
        uuid.UUID(request_id)
        assert request_id is not None # Added assertion
    except (ValueError, TypeError): # Added TypeError
        pytest.fail("request.state.request_id is not a valid UUID string")

    assert response is mock_response
    assert "x-request-id" in response.headers
    assert response.headers["x-request-id"] == request_id
