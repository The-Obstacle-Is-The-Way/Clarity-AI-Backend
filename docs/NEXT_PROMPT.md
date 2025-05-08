# Next Prompt: Implement Logging Middleware

## Changes Summary

We've successfully completed the Authentication Middleware refactoring:

1. **Moved Authentication Middleware to Presentation Layer**:
   - Created Pydantic models for authenticated users
   - Implemented proper dependency injection for JWT service and user repository
   - Fixed tests to use mocked interfaces

2. **JWT Service Refactoring**:
   - Fixed async/sync method alignment between interface and implementation
   - Removed duplicate interface definitions
   - Enhanced token payload validation

3. **CORS Configuration**:
   - Updated to use environment-driven settings for enhanced security
   - Added more detailed logging

4. **Integration Testing**:
   - Created tests for middleware chain interaction
   - Added tests for request ID propagation

## Next Critical Focus: Logging Middleware

The next most critical area to address is implementing the `LoggingMiddleware` that is currently disabled in the app factory. This is a HIPAA compliance requirement and will provide essential auditing capabilities.

## Architectural Guidelines

- Place middleware in `app/presentation/middleware/`
- Follow Clean Architecture principles with proper separation of concerns
- Implement dependency injection for services 
- Use `request.state` to pass data between middleware components
- Ensure HIPAA compliance with NO PHI in logs
- Write comprehensive unit tests

## Specific Tasks

1. Implement `LoggingMiddleware` with:
   - HIPAA-compliant logging (no PHI, query params, or sensitive headers)
   - Request/response timing
   - Request ID correlation
   - Structured JSON log format
   - Proper error handling

2. Create unit tests for `LoggingMiddleware`

3. Update app factory to enable `LoggingMiddleware`

4. Verify integration with other middleware components

## HIPAA Security Requirements

- Log only non-PHI metadata (method, path, status code, timing)
- Use allowlist approach for headers (only log safe headers like User-Agent)
- NEVER log request/response bodies, query parameters, or authorization headers
- Implement request ID correlation for audit traceability
- Ensure proper error handling to avoid leaking sensitive data in errors

## Testing Strategy

- Create unit tests mocking logger, request, response
- Verify correct formatting and content of log messages
- Test that PHI is never logged under any circumstance
- Verify request ID correlation works correctly
- Ensure performance impact is minimal 