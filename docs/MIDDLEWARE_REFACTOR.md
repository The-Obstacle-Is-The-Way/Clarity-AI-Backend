# Middleware Refactoring Plan: Clarity AI Backend

**Version:** 1.0
**Date:** 2025-05-05

## 1. Overview

This document outlines the plan to refactor the middleware layer of the Clarity AI Backend application. The primary goal is to improve the architecture, maintainability, testability, and security of the middleware components, aligning them with Clean Architecture principles, SOLID/DRY practices, and HIPAA requirements.

## 2. Goals

*   **Architectural Alignment:** Consolidate all custom middleware implementations into the `app/presentation/middleware` layer.
*   **Clean Architecture Compliance:** Ensure middleware interacts with other layers (Application, Infrastructure) *only* through interfaces defined in the Core layer (`app/core/interfaces`).
*   **Dependency Injection (DI):** Implement proper DI for middleware dependencies (services, configurations) injected during application startup.
*   **SOLID/DRY Principles:** Ensure each middleware adheres to the Single Responsibility Principle and avoid code duplication.
*   **Testability:** Improve unit and integration test coverage for all middleware components, enabling reliable testing with mocked dependencies.
*   **Maintainability & Clarity:** Reduce complexity by removing shims, standardizing implementation patterns, and improving code organization.
*   **HIPAA Compliance & Security:** Strengthen security posture by ensuring compliant logging (no PHI), robust authentication/authorization, effective rate limiting, and strict CORS configuration.
*   **Resolve Existing Issues:** Fix current test failures related to middleware signature mismatches and address missing middleware implementations.

## 3. Non-Goals

*   Implementing entirely new, unrelated middleware features.
*   Large-scale refactoring of other application layers beyond what's necessary for middleware integration and DI.
*   Changing the core business logic within services called by middleware.

## 4. Scope

The following middleware components are in scope for this refactoring effort:

1.  **`RequestIdMiddleware`**: Implement and integrate.
2.  **`LoggingMiddleware`**: Implement and integrate (HIPAA compliant).
3.  **`RateLimitingMiddleware`**: Move, refactor, configure DI, fix tests.
4.  **`AuthenticationMiddleware`**: Move, refactor (separate AuthN/AuthZ), configure DI, fix tests.
5.  **`CORSMiddleware`**: Review and ensure secure, environment-driven configuration.

Related tasks include:
*   Defining necessary core interfaces (`IRateLimiterService`, `IJwtService`, `IUserService`).
*   Updating application factory (`app/app_factory.py`) for middleware registration and DI setup.
*   Updating or creating unit and integration tests for middleware.
*   Defining configuration models (`RateLimitConfig`).
*   Updating imports across the codebase.

## 5. Current State & Issues (Summary)

*   **Inconsistent Locations:** Middleware exists in `core`, `infrastructure`, and `presentation`.
*   **Missing Implementations:** `RequestIdMiddleware`, `LoggingMiddleware` are missing.
*   **Test Failures:** `RateLimitingMiddleware`, `AuthenticationMiddleware` tests fail due to signature mismatches, likely caused by architectural inconsistencies or outdated test setups.
*   **Architectural Violations:** `AuthenticationMiddleware` in `infrastructure`, `RateLimitingMiddleware` split between `core` and `presentation`, potential lack of DI.
*   **Shims:** `RateLimitingMiddleware` uses a confusing shim.
*   **Potential SRP Violations:** `AuthenticationMiddleware` might be handling both AuthN and AuthZ.
*   **Configuration Concerns:** CORS needs security review; Rate limiting config location unclear.

*(See previous analysis sections for detailed breakdown if needed)*

## 6. Proposed Refactoring Strategy & Detailed Steps

**Core Principles:**
*   **Location:** All custom middleware -> `app/presentation/middleware/`
*   **Base Class:** Use `starlette.middleware.base.BaseHTTPMiddleware` for custom middleware requiring state or complex logic.
*   **DI:** Inject application-lifetime dependencies (services like `IJwtService`, configurations) via `__init__` during instantiation in `app_factory.py`. Access request-specific data via `request.state`.
*   **State:** Use `request.state` to pass data between middleware and from middleware to endpoints (e.g., `request.state.request_id`, `request.state.user`).
*   **Error Handling:** Use standard FastAPI `HTTPException` for middleware-related errors (e.g., 401 Unauthorized, 403 Forbidden, 429 Too Many Requests).
*   **Configuration:** Load middleware settings (CORS origins, rate limits) from application settings/environment variables, not hardcoded.
*   **Order:** Register middleware in `app_factory.py` using `app.add_middleware()` in a specific, logical order.

**Detailed Steps:**

1.  **Prepare Environment:**
    *   Ensure necessary core interfaces exist: `app/core/interfaces/security/jwt_service_interface.py:IJwtService`, `app/core/interfaces/repositories/user_repository_interface.py:IUserRepository` (Update: Use `IUserRepository` instead of `IUserService` directly if middleware only needs lookup), `app/core/interfaces/services/rate_limiter_service_interface.py:IRateLimiterService`.
    *   Ensure concrete implementations exist (e.g., `JwtService`, `UserRepository`, `RedisRateLimiterService`) in the appropriate layers (`infrastructure` or `application`).
    *   Define configuration models if not present (e.g., `app/presentation/config/rate_limiting.py:RateLimitConfig`).

2.  **Implement `RequestIdMiddleware` (`Iteration 1`)**
    *   Create `app/presentation/middleware/request_id.py`.
    *   Implement `RequestIdMiddleware(BaseHTTPMiddleware)`:
        *   In `dispatch`, check for `X-Request-ID` header. If present and valid (e.g., UUID format), use it. Otherwise, generate a `uuid.uuid4()$.
        *   Store the ID in `request.state.request_id = generated_or_incoming_id`.
        *   Call `response = await call_next(request)`.
        *   Add the ID to the response header: `response.headers['X-Request-ID'] = request.state.request_id`.
    *   Write unit tests mocking `uuid` and checking `request.state` and response headers.

3.  **Implement `LoggingMiddleware` (`Iteration 1`)**
    *   Create `app/presentation/middleware/logging.py`.
    *   Implement `LoggingMiddleware(BaseHTTPMiddleware)`:
        *   Inject standard Python `logging.Logger` via `__init__` (configured in `app_factory`).
        *   In `dispatch`:
            *   Record `start_time = time.time()`.
            *   Log basic request info *before* `call_next`: Method, Path, Client IP (`request.client.host`), `request_id` (from `request.state`). **Use JSON format.** Define a strict allowlist of safe headers to log (e.g., `User-Agent`, `Accept`). **ABSOLUTELY NO OTHER HEADERS, QUERY PARAMS, OR BODY.**
            *   `response = await call_next(request)`.
            *   Calculate `process_time = time.time() - start_time`.
            *   Log response info *after* `call_next`: Status Code, Process Time, `request_id`. **NO RESPONSE BODY/HEADERS.**
    *   Write unit tests mocking the logger and `time`, verifying log messages and exclusion of sensitive data.

4.  **Refactor `RateLimitingMiddleware` (`Iteration 2`)**
    *   Move implementation from `app/core/security/rate_limiting/middleware.py` to `app/presentation/middleware/rate_limiting.py`.
    *   Delete the shim `app/presentation/middleware/rate_limiting_middleware.py`.
    *   Refactor `RateLimitingMiddleware(BaseHTTPMiddleware)`:
        *   Modify `__init__` to accept injected `rate_limiter_service: IRateLimiterService` and `config: RateLimitConfig`.
        *   In `dispatch`:
            *   Determine the key for rate limiting (e.g., `request.client.host` or `request.state.user.id` if AuthN runs first).
            *   Call `await self.rate_limiter_service.is_limit_exceeded(key, self.config)`.
            *   If exceeded, raise `HTTPException(status_code=429, detail="Too Many Requests")`.
            *   Otherwise, `response = await call_next(request)`.
    *   Move `RateLimitConfig` definition to `app/presentation/config/rate_limiting.py` (or `app/core/config/`).
    *   Update imports.
    *   Fix unit tests (`app/tests/unit/presentation/middleware/test_rate_limiting_middleware.py`): Update instantiation, mock `IRateLimiterService`.

5.  **Refactor `AuthenticationMiddleware` (`Iteration 3`)**
    *   Identify current location (likely `app/infrastructure/security/middleware.py`) and move to `app/presentation/middleware/authentication.py`.
    *   Refactor `AuthenticationMiddleware(BaseHTTPMiddleware)`:
        *   Modify `__init__` to accept injected `jwt_service: IJwtService` and `user_repo: IUserRepository`.
        *   Define a simple Pydantic model for the user context (e.g., `AuthenticatedUser(id: UUID, roles: List[str])`) to be stored in state.
        *   In `dispatch`:
            *   Extract token from `Authorization: Bearer <token>` header.
            *   If no token and route is public (requires mechanism to check route metadata or path patterns), `return await call_next(request)`.
            *   If token present: Use `jwt_service` to validate/decode. Handle exceptions (InvalidToken, ExpiredSignature) -> `HTTPException(401)`.
            *   Use `user_repo` to fetch user by ID from token payload. Handle UserNotFound -> `HTTPException(401)`.
            *   Populate `request.state.user = AuthenticatedUser(...)`.
            *   `response = await call_next(request)`.
    *   Update imports.
    *   Fix unit tests (`app/tests/unit/presentation/middleware/test_auth_middleware_unit.py`): Update instantiation, mock `IJwtService` and `IUserRepository`.
    *   **Note:** Authorization (role checks) should be handled by FastAPI dependencies in specific endpoints, checking `request.state.user.roles`.

6.  **Update Application Factory (`app_factory.py`) (`Iteration 1, 2, 3`)**
    *   Remove commented-out/old middleware imports/registrations.
    *   Import middleware from `app.presentation.middleware`.
    *   Instantiate dependencies (services, configurations, logger).
    *   Register middleware using `app.add_middleware()` in the correct order:
        1.  `CORSMiddleware` (Needs careful configuration review - Step 7)
        2.  `RequestIdMiddleware`
        3.  `LoggingMiddleware` (Inject configured logger)
        4.  `RateLimitingMiddleware` (Inject `IRateLimiterService` impl and `RateLimitConfig` instance)
        5.  `AuthenticationMiddleware` (Inject `IJwtService` impl and `IUserRepository` impl)

7.  **Review `CORSMiddleware` Configuration (`Iteration 4`)**
    *   Locate `app.add_middleware(CORSMiddleware, ...)` in `app_factory.py`.
    *   Ensure `allow_origins` is a *specific list* loaded from settings, NOT `["*"]` if `allow_credentials=True`.
    *   Ensure `allow_credentials`, `allow_methods`, `allow_headers` are configured securely based on frontend requirements and loaded from settings.

8.  **Update Global Imports & Tests (`Iteration 4`)**
    *   Search codebase (`grep`) for any remaining imports pointing to old middleware locations and update them.
    *   Write/update *integration tests* that verify the *combined* effect of middleware (e.g., request ID appears in logs, rate limit blocks after N requests, authenticated user accessible in endpoint, CORS headers are correct).
    *   Run the *entire* test suite.

## 7. Testing Strategy

*   **Unit Tests:** Each middleware MUST have dedicated unit tests in `app/tests/unit/presentation/middleware/`. These tests should mock all external dependencies (services, config, time, uuid) injected via `__init__` or used globally. Focus on testing the middleware's logic in isolation.
*   **Integration Tests:** Tests in `app/tests/integration/` should verify the end-to-end flow through the middleware chain for representative endpoints (public, authenticated, rate-limited). Use `TestClient` and verify response headers, status codes, and expected side effects (like logs, if feasible to capture/assert). Overriding dependencies (like `IRateLimiterService`) might be needed here too.

## 8. HIPAA / Security Considerations

*   **Logging:** Strict adherence to **NO PHI** in logs (request/response bodies, sensitive headers, query params) is mandatory. Log only essential, non-sensitive metadata.
*   **Authentication:** Robust token validation and secure user lookup are critical. Ensure proper error handling for invalid/expired tokens.
*   **Authorization:** While not *in* the AuthN middleware, ensure subsequent authorization checks (endpoint dependencies) correctly use the user context established by the middleware.
*   **CORS:** Configuration must be strict, allowing only known frontend origins, methods, and headers. Load from secure configuration sources.
*   **Rate Limiting:** Protects against DoS and resource exhaustion.

## 9. Rollback Plan (Simplified)

*   Use Git branches for each iteration.
*   If an iteration introduces critical issues not easily fixed, revert the branch merge and reassess the specific step.
*   Ensure tests pass thoroughly before merging each iteration branch.

## 10. Success Criteria

*   All custom middleware resides in `app/presentation/middleware`.
*   Middleware uses `BaseHTTPMiddleware` where appropriate and follows consistent patterns.
*   DI is correctly implemented for middleware dependencies.
*   `RequestIdMiddleware` and `LoggingMiddleware` are implemented and functional.
*   `RateLimitingMiddleware` and `AuthenticationMiddleware` are refactored, relocated, and functional.
*   All previous middleware-related test failures are resolved.
*   New unit and integration tests for middleware pass.
*   The full application test suite passes after refactoring.
*   CORS configuration is verified as secure and loaded from settings.
*   Code review confirms adherence to Clean Architecture, SOLID/DRY, and HIPAA logging constraints.

## 11. To-Do Checklist

**Iteration 1: Request ID & Logging Middleware**

* [x] Create `app/presentation/middleware/request_id.py`.
* [x] Implement `RequestIdMiddleware` logic (generate/use ID, set state, set header).
* [x] Create `app/tests/unit/presentation/middleware/test_request_id_middleware.py`.
* [x] Write/fix unit tests for `RequestIdMiddleware`.
* [x] Create `app/presentation/middleware/logging.py`.
* [x] Implement `LoggingMiddleware` logic (inject logger, log request/response safely, handle errors, use request ID).
* [x] Create `app/tests/unit/presentation/middleware/test_logging.py`.
* [x] Write/fix unit tests for `LoggingMiddleware`.
* [x] Update `app_factory.py` to register `RequestIdMiddleware`.
* [x] Update `app_factory.py` to register `LoggingMiddleware` (injecting logger).

**Iteration 2: Rate Limiting Middleware**

* [x] Define `IRateLimiter` interface in `app/core/interfaces/services/rate_limiting/rate_limiter_interface.py`.
* [x] Implement `InMemoryRateLimiter` in `app/infrastructure/security/rate_limiting/in_memory_limiter.py`.
* [x] Define `RateLimitConfig` in `app/core/interfaces/services/rate_limiting/rate_limiter_interface.py`.
* [x] Move `RateLimitingMiddleware` implementation to `app/presentation/middleware/rate_limiting.py`.
* [x] Create dependency provider in `app/infrastructure/security/rate_limiting/providers.py`.
* [x] Refactor `RateLimitingMiddleware` to use `IRateLimiter` interface via dependency injection.
* [x] Update `app_factory.py` to instantiate and inject the rate limiter implementation.
* [x] Update/fix unit tests in `app/tests/unit/presentation/middleware/test_rate_limiting_middleware.py` to mock the interface and use the new structure.

**Iteration 3: Authentication Middleware**

* [ ] Define `IJwtService` interface in `app/core/interfaces/security/`.
* [ ] Ensure `JwtService` exists in `infrastructure` and implements the interface.
* [ ] Ensure `IUserRepository` interface exists and is used.
* [ ] Ensure `UserRepository` implementation exists.
* [ ] Move `AuthenticationMiddleware` to `app/presentation/middleware/authentication.py`.
* [ ] Define `AuthenticatedUser` Pydantic model for `request.state`.
* [ ] Refactor `AuthenticationMiddleware` to use injected `IJwtService` and `IUserRepository`, setting `request.state.user`.
* [ ] Update `app_factory.py` to instantiate and inject `IJwtService` and `IUserRepository` implementations into `AuthenticationMiddleware` registration.
* [ ] Update/fix unit tests in `app/tests/unit/presentation/middleware/test_auth_middleware_unit.py` (or similar path) to mock interfaces.

**Iteration 4: CORS & Final Integration**

* [ ] Review `CORSMiddleware` registration in `app_factory.py` for secure configuration (origins, credentials, methods, headers) loaded from settings.
* [ ] Perform codebase search (`grep`) for any remaining old middleware imports and update them.
* [ ] Write/update integration tests covering the combined middleware flow (request ID, logging, rate limiting, authentication, CORS headers).
* [ ] Run the *entire* test suite and fix any remaining failures.

**Final Review**

* [ ] Final Code Review: Verify all goals and success criteria are met.
