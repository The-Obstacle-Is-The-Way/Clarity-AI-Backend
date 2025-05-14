# Clarity AI Backend

The Clarity AI Backend is a HIPAA-compliant, revolutionary psychiatric digital twin platform designed according to clean architecture principles. It transforms fragmented clinical data into integrated predictive models that evolve in real-time with patient data.

## Architecture Overview

The backend follows a clean, layered architecture based on Robert C. Martin's principles:

### Domain Layer

The core of the application, containing:
- **Entities**: Business objects representing core psychiatric concepts 
- **Value Objects**: Immutable objects with domain logic
- **Domain Services**: Pure business logic with no external dependencies
- **Repository Interfaces**: Data access abstractions defined at the domain level
- **Domain Exceptions**: Business rule violations and domain-specific errors

### Application Layer

Orchestrates the domain layer and implements use cases:
- **Use Cases**: Implementation of specific user stories and workflows
- **Application Services**: Orchestration services that coordinate domain objects
- **DTOs**: Data Transfer Objects for clean API boundaries
- **Assemblers/Mappers**: Convert between domain entities and DTOs

### Infrastructure Layer

Implements interfaces defined in the domain layer:
- **Repositories**: Database access implementations using SQLAlchemy
- **ORM Models**: Database mappings with field-level encryption for PHI
- **External Services**: Integrations with ML models and third-party services
- **Security**: Authentication, authorization, encryption, and token management
- **Logging**: HIPAA-compliant audit and application logging

### Presentation Layer

Exposes the application via FastAPI:
- **API Routes**: FastAPI route handlers implementing RESTful endpoints
- **Schemas**: Pydantic models for request/response validation
- **Middleware**: Cross-cutting concerns (auth, PHI protection)
- **Dependencies**: FastAPI dependency injection providers
- **Error Handlers**: Global error processing with PHI protection

## Security Implementation

### Authentication & Authorization

- **JWT-based authentication**: Secure token generation, validation, and management
- **Token blacklisting**: Support for token revocation and session management
- **Role-based access control**: Granular permission system for resources
- **Session timeouts**: Automatic session expiration for HIPAA compliance

### HIPAA Compliance

- **PHI Protection**: Middleware sanitization of protected health information
- **Field-level Encryption**: Sensitive PHI encrypted at rest in the database
- **Comprehensive Audit Logging**: Logging of all PHI access with user context
- **Secure Error Handling**: Prevents leaking sensitive information in errors
- **TLS Encryption**: All data encrypted in transit

## AI/ML Components

The platform integrates multiple AI/ML technologies:

- **MentaLLaMA**: Specialized language model for psychiatric analysis
- **PAT (Pretrained Actigraphy Transformer)**: Analyzes movement patterns for psychiatric insights
- **XGBoost Ensemble**: Predictive modeling for treatment response and outcomes
- **Digital Twin Integration**: Creates comprehensive patient digital twins

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
3. Always implement proper HIPAA protections for PHI
4. Write comprehensive tests for all components
5. Use dependency injection for testability
6. Document all public interfaces and APIs
7. Ensure consistent error handling throughout the application 