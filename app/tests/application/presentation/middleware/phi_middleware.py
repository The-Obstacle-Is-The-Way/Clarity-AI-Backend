"""
PHI Middleware for FastAPI.

This middleware intercepts API requests and responses to sanitize any potential
Protected Health Information (PHI) before it's logged or returned to clients,
ensuring HIPAA compliance at the API layer.
"""

import json
import re
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

# Import infrastructure PHI components
from app.infrastructure.security.phi import PHIService, get_sanitized_logger

# Use PHI-sanitized logger
logger = get_sanitized_logger(__name__)


class PHIMiddleware(BaseHTTPMiddleware):
    """
    HIPAA-compliant middleware that sanitizes PHI in requests and responses.

    This middleware sits between the client and the application to ensure no PHI
    is accidentally leaked through the API layer.
    """

    def __init__(
        self,
        app: ASGIApp,
        phi_service: PHIService | None = None,
        redaction_text: str = "[REDACTED {phi_type}]",
        exclude_paths: list[str] | None = None,
        whitelist_patterns: dict[str, list[str]] | None = None,
        audit_mode: bool = False,
    ):
        """
        Initialize the PHI middleware.

        Args:
            app: The ASGI application
            phi_service: Custom PHI service to use
            redaction_text: Text to use when redacting PHI (can use {phi_type})
            exclude_paths: List of path prefixes to exclude from PHI scanning
            whitelist_patterns: Dict mapping paths to patterns that are allowed
            audit_mode: If True, only log potential PHI without redacting
        """
        super().__init__(app)
        self.phi_service = phi_service or PHIService()
        self.redaction_text = redaction_text
        self.exclude_paths = set(exclude_paths or [])
        self.whitelist_patterns = whitelist_patterns or {}
        self.audit_mode = audit_mode

        # Precompile whitelist patterns for faster matching
        self.compiled_patterns = {}
        for path, patterns in self.whitelist_patterns.items():
            self.compiled_patterns[path] = [re.compile(re.escape(p)) for p in patterns]

        # Default excluded paths
        self.default_exclude_paths = [
            "/docs",
            "/redoc",
            "/openapi.json",
            "/health",
            "/metrics",
            "/static",
        ]

        # Add default exclusions
        for path in self.default_exclude_paths:
            self.exclude_paths.add(path)

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """
        Process the request and response.

        Args:
            request: The incoming request
            call_next: Function to call the next middleware/route handler

        Returns:
            The processed response
        """
        # Check if the path should be excluded from PHI scanning
        if self._should_exclude_path(request.url.path):
            return await call_next(request)

        # Create a copy of the request with sanitized content for logging
        # but preserve the original request for processing
        await self._create_sanitized_request_copy(request)

        # Call the next middleware/route handler with original request
        response = await call_next(request)

        # Sanitize the response before returning it
        sanitized_response = await self._sanitize_response(response, request.url.path)

        return sanitized_response

    def _should_exclude_path(self, path: str) -> bool:
        """
        Check if a path should be excluded from PHI sanitization.

        Args:
            path: The request path

        Returns:
            True if the path should be excluded, False otherwise
        """
        return any(path.startswith(excluded) for excluded in self.exclude_paths)

    def _get_whitelists_for_path(self, path: str) -> list[re.Pattern]:
        """
        Get the compiled whitelist patterns for a path.

        Args:
            path: The request path

        Returns:
            List of compiled regex patterns
        """
        patterns = []
        for prefix, pattern_list in self.compiled_patterns.items():
            if path.startswith(prefix):
                patterns.extend(pattern_list)
        return patterns

    def _preprocess_response_for_whitelist(self, data: Any, path: str) -> Any:
        """
        Preprocess data to protect whitelisted content before sanitization.

        Args:
            data: The data to preprocess
            path: The request path

        Returns:
            Preprocessed data with whitelist markers
        """
        # Get whitelist patterns for this path
        whitelist_patterns = self._get_whitelists_for_path(path)
        if not whitelist_patterns:
            return data

        if isinstance(data, str):
            # Add special marker around whitelisted content
            for pattern in whitelist_patterns:
                # Replace with a special marker that won't be touched by PHI sanitization
                data = pattern.sub(lambda m: f"__WHITELIST__{m.group(0)}__WHITELIST__", data)
        elif isinstance(data, dict):
            for key, value in data.items():
                data[key] = self._preprocess_response_for_whitelist(value, path)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                data[i] = self._preprocess_response_for_whitelist(item, path)
        return data

    def _restore_whitelisted_content(self, data: Any) -> Any:
        """
        Restore whitelisted content after sanitization.

        Args:
            data: Data that was sanitized

        Returns:
            Data with whitelisted content restored
        """
        if isinstance(data, str):
            # Remove the special markers and restore original content
            return re.sub(r"__WHITELIST__(.*?)__WHITELIST__", r"\1", data)
        elif isinstance(data, dict):
            for key, value in data.items():
                data[key] = self._restore_whitelisted_content(value)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                data[i] = self._restore_whitelisted_content(item)
        return data

    async def _create_sanitized_request_copy(self, request: Request) -> None:
        """
        Create a sanitized copy of the request for logging purposes.
        Does not modify the original request.

        Args:
            request: The original request
        """
        try:
            # Only process JSON requests
            content_type = request.headers.get("content-type", "")
            if "application/json" not in content_type.lower():
                return

            # Get the request body
            body = await request.body()
            if not body:
                return

            # Parse the request body
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                # Not valid JSON
                return

            # Check if the body contains PHI
            contains_phi = self._check_for_phi_in_data(data, request.url.path)

            if contains_phi:
                if self.audit_mode:
                    # Only log in audit mode
                    logger.warning("PHI detected in request to %s (audit mode)", request.url.path)
                else:
                    # Preprocess to protect whitelisted content
                    preprocessed_data = self._preprocess_response_for_whitelist(
                        data, request.url.path
                    )

                    # Create sanitized copy for logging
                    sanitized_data = self.phi_service.sanitize_dict(preprocessed_data)

                    # Restore whitelisted content
                    sanitized_data = self._restore_whitelisted_content(sanitized_data)

                    # Store sanitized data in request state for logging
                    request.state.sanitized_body = sanitized_data

                    logger.info("Sanitized PHI in request to %s for logging", request.url.path)

        except Exception as e:
            logger.error("Error processing request to %s: %s", request.url.path, str(e))

    async def _sanitize_response(self, response: Response, path: str) -> Response:
        """
        Sanitize a response to remove PHI.

        Args:
            response: The original response
            path: The request path

        Returns:
            Sanitized response
        """
        # Skip non-JSON responses
        content_type = response.headers.get("content-type", "")
        if not content_type or "application/json" not in content_type.lower():
            return response

        # Get the response body
        response_body = b""

        # Process the response body
        try:
            # Handle different response types
            if isinstance(response, Response):
                # Regular response
                if hasattr(response, "body"):
                    response_body = response.body
                elif hasattr(response, "body_iterator"):
                    # Streaming response, consume it
                    async for chunk in response.body_iterator:
                        response_body += chunk
                else:
                    # Can't get the body, return unchanged
                    return response

            # Skip empty responses
            if not response_body:
                return response

            # Parse the response body as JSON
            try:
                body_json = json.loads(response_body)
            except json.JSONDecodeError:
                # Not valid JSON, return unchanged
                return response

            # Check if the body contains PHI
            contains_phi = self._check_for_phi_in_data(body_json, path)

            if contains_phi:
                if self.audit_mode:
                    # Only log in audit mode
                    logger.warning("PHI detected in response from %s (audit mode)", path)
                    # Return unchanged response in audit mode
                    return response
                else:
                    # Preprocess to protect whitelisted content
                    preprocessed_data = self._preprocess_response_for_whitelist(body_json, path)

                    # Sanitize the response body
                    sanitized_body = self.phi_service.sanitize_dict(preprocessed_data)

                    # Restore whitelisted content
                    sanitized_body = self._restore_whitelisted_content(sanitized_body)

                    # Create a new response with the sanitized body
                    sanitized_response = JSONResponse(
                        content=sanitized_body,
                        status_code=response.status_code,
                        headers=dict(response.headers),
                    )

                    logger.info("Sanitized PHI in response from %s", path)

                    return sanitized_response
            else:
                # No PHI detected, return unchanged
                return response

        except Exception as e:
            logger.error("Error sanitizing response from %s: %s", path, str(e))
            # Return the original response on error
            return response

    def _check_for_phi_in_data(self, data: Any, path: str) -> bool:
        """
        Check if data contains PHI.

        Args:
            data: The data to check
            path: The request path (for whitelist checking)

        Returns:
            True if data contains PHI, False otherwise
        """
        # Handle different data types
        if isinstance(data, str):
            # Check if the string contains PHI
            # Skip whitelist check here as we'll handle it during sanitization
            return self.phi_service.contains_phi(data)
        elif isinstance(data, dict):
            # Check if any value in the dictionary contains PHI
            for key, value in data.items():
                if self._check_for_phi_in_data(value, path):
                    return True
        elif isinstance(data, (list, tuple)):
            # Check if any item in the list contains PHI
            for item in data:
                if self._check_for_phi_in_data(item, path):
                    return True

        # No PHI detected
        return False


def add_phi_middleware(
    app: FastAPI,
    exclude_paths: list[str] | None = None,
    whitelist_patterns: dict[str, list[str]] | None = None,
    audit_mode: bool = False,
) -> None:
    """
    Adds the PHIMiddleware to the FastAPI application.

    Args:
        app: The FastAPI application instance.
        exclude_paths: List of path prefixes to exclude from PHI scanning.
        whitelist_patterns: Dict mapping paths to patterns that are allowed.
        audit_mode: If True, only log potential PHI without redacting.
    """
    # Create PHI service
    phi_service = PHIService()

    # Create middleware
    middleware = PHIMiddleware(
        app=app,
        phi_service=phi_service,
        exclude_paths=exclude_paths,
        whitelist_patterns=whitelist_patterns,
        audit_mode=audit_mode,
    )

    # Add middleware to app
    app.add_middleware(BaseHTTPMiddleware, dispatch=middleware.dispatch)

    # Log middleware addition
    logger.info("PHI middleware added to FastAPI application (audit_mode=%s)", audit_mode)
