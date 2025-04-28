# Novamind Backend

The Novamind Backend is a HIPAA-compliant, robust psychiatry and mental health digital twin platform designed according to clean architecture principles.

## Architecture Overview

The backend follows a clean, layered architecture based on SOLID principles:

### Domain Layer

The core of the application, containing:
- **Entities**: Business objects representing core concepts 
- **Interfaces**: Abstractions that define contracts for other layers
- **Exceptions**: Domain-specific exception hierarchy for proper error handling
- **Value Objects**: Immutable objects representing domain concepts without identity

### Application Layer

Orchestrates the domain layer and applies use cases:
- **Services**: Application-specific services that orchestrate domain operations
- **DTOs**: Data Transfer Objects for clean API boundaries
- **Use Cases**: Implementation of specific use cases (e.g., authentication flows)
- **Assemblers/Mappers**: Convert between domain entities and DTOs

### Infrastructure Layer

Implements interfaces defined in the domain layer:
- **Persistence**: Database access, repositories, and ORM implementations
- **Security**: Authentication, authorization, encryption, and token management
- **External Services**: Integrations with third-party services
- **Logging**: Comprehensive audit and application logging

### API Layer

Exposes the application to the outside world:
- **Controllers**: FastAPI route handlers
- **Middleware**: Cross-cutting concerns (authentication, logging)
- **Request/Response Models**: Pydantic models for API validation
- **Documentation**: OpenAPI schema and documentation

## Security Implementation

### Authentication & Authorization

- **JWT-based authentication**: Secure token generation, validation, and management
- **Token blacklisting**: Support for token revocation and session management
- **Role-based access control**: Granular permission system for resources
- **Session timeouts**: Automatic session expiration for security

### HIPAA Compliance

- **PHI Protection**: Sanitization of protected health information in logs and errors
- **Audit Logging**: Comprehensive logging of all security events
- **Encryption**: Data encryption at rest and in transit
- **Error Handling**: Secure error handling that prevents leaking sensitive information

## Getting Started

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Configure environment variables:
   ```
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. Run database migrations:
   ```
   alembic upgrade head
   ```

4. Start the development server:
   ```
   uvicorn app.main:app --reload
   ```

## Development Guidelines

1. Follow the SOLID principles and clean architecture
2. Maintain clear boundaries between architectural layers
3. Write comprehensive tests for all components
4. Use dependency injection for testability
5. Document all public interfaces and APIs
6. Maintain HIPAA compliance in all code
7. Ensure proper error handling throughout the application 