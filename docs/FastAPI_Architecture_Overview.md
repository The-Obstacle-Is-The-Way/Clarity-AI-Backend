# Clarity AI Backend: FastAPI Architecture Overview

## System Architecture

The Clarity AI Backend is a digital twin platform for psychiatric care that employs a modern, clean architecture using FastAPI. This document provides a high-level overview of the system architecture and serves as a starting point for understanding the codebase.

## Architectural Diagram

```
┌────────────────────────────────────────────────────────────────────┐
│                         HTTP/HTTPS Requests                        │
└───────────────────────────────────┬────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────┐
│                        FastAPI Application                         │
│  ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐   │
│  │    Middleware   │   │    Routers      │   │    Exception    │   │
│  │      Chain      │   │      &          │   │    Handlers     │   │
│  │                 │   │   Endpoints     │   │                 │   │
│  └────────┬────────┘   └────────┬────────┘   └────────┬────────┘   │
└───────────┼─────────────────────┼─────────────────────┼────────────┘
            │                     │                     │            
┌───────────▼─────────────────────▼─────────────────────▼────────────┐
│                       Dependency Injection                         │
└───────────┬─────────────────────┬─────────────────────┬────────────┘
            │                     │                     │            
┌───────────▼─────────┐ ┌─────────▼─────────┐ ┌─────────▼────────────┐ 
│    Application      │ │      Domain       │ │   Infrastructure     │ 
│      Layer          │ │      Layer        │ │       Layer          │ 
│                     │ │                   │ │                      │ 
│  - Use Cases        │ │  - Entities       │ │  - Repositories      │ 
│  - DTOs             │ │  - Value Objects  │ │  - External Services │ 
│  - Services         │ │  - Repositories   │ │  - Security          │ 
│                     │ │    Interfaces     │ │  - Persistence       │ 
└─────────────────────┘ └───────────────────┘ └──────────────────────┘ 
            │                     │                     │            
            └─────────────────────▼─────────────────────┘            
                                  │                                  
                     ┌────────────▼────────────┐                     
                     │      Database           │                     
                     │ (SQLAlchemy/PostgreSQL) │                     
                     └─────────────────────────┘                     
```

## Core Architectural Components

### 1. Clean Architecture

The codebase follows Clean Architecture principles with distinct layers:

- **Domain Layer**: The core business logic, entities, and business rules
- **Application Layer**: Orchestration of domain entities, use cases, and application-specific logic
- **Infrastructure Layer**: External interfaces, database access, and third-party services
- **Presentation Layer**: FastAPI endpoints, request handling, and responses

This architecture ensures that business rules and logic remain independent of external frameworks and can be tested in isolation.

### 2. Domain-Driven Design (DDD)

The system employs DDD concepts:

- **Entities**: Core business objects with identity and lifecycle (patients, digital twins)
- **Value Objects**: Immutable objects without identity (risk scores, metrics)
- **Aggregates**: Clusters of entities and value objects treated as a unit
- **Repositories**: Abstractions for data access
- **Services**: Domain operations that don't naturally fit in entities
- **Factories**: Creation of complex domain objects

### 3. Key Technology Stack

- **FastAPI**: Modern, high-performance web framework for building APIs
- **Pydantic**: Data validation and settings management
- **SQLAlchemy**: ORM and SQL toolkit
- **Alembic**: Database migrations
- **JWT**: Authentication and authorization
- **Redis**: Caching and rate limiting
- **Pytest**: Testing framework

## Technical Capabilities

### 1. API Capabilities

- **RESTful Endpoints**: Standard HTTP methods with appropriate status codes
- **OpenAPI Documentation**: Auto-generated API documentation
- **Versioning**: Path-based versioning (e.g., `/api/v1/`)
- **Rate Limiting**: Protection against abuse
- **Pagination**: For resource collections
- **Filtering & Sorting**: For flexible data access

### 2. Security Features

- **Authentication**: JWT-based with refresh tokens
- **Authorization**: Role-based access control
- **Input Validation**: Pydantic models for all endpoints
- **Output Sanitization**: PHI removal from responses
- **Rate Limiting**: Brute force protection
- **Audit Logging**: Comprehensive tracking of system access
- **Error Handling**: Secure error responses

### 3. HIPAA Compliance

The architecture is designed with HIPAA compliance as a primary requirement:

- **PHI Protection**: Encryption at rest and in transit
- **Access Controls**: Role-based authorization
- **Audit Trails**: Detailed logging of PHI access
- **Data Segregation**: Proper isolation of patient data
- **Secure Error Handling**: No PHI in error messages
- **Session Management**: Automatic timeouts

## Core Domain Modules

The Clarity AI Backend supports these primary domains:

1. **Authentication** (`/api/v1/auth/`): User authentication and authorization
2. **Patients** (`/api/v1/patients/`): Patient management and records
3. **Digital Twins** (`/api/v1/digital-twins/`): Digital twin models for patients
4. **Biometrics** (`/api/v1/biometrics/`): Biometric data collection and analysis
5. **ML Models** (`/api/v1/xgboost/`, `/api/v1/mentallama/`): Machine learning predictions
6. **Analytics** (`/api/v1/analytics/`): Data analysis and reporting

## Development Workflow

### 1. Application Initialization

The application uses a factory pattern (`app_factory.py`) that:

1. Initializes settings based on environment
2. Sets up database connections
3. Configures middleware
4. Registers routes
5. Sets up exception handlers

### 2. Request Flow

When a request arrives:

1. **Middleware Chain**: Processes each request through multiple middleware layers
2. **Authentication**: Validates credentials and sets user context
3. **Routing**: Dispatches to appropriate endpoint
4. **Validation**: Validates input data with Pydantic
5. **Business Logic**: Executes domain and application logic
6. **Response**: Returns validated, sanitized response

### 3. Dependency Injection

Services are injected using FastAPI's dependency injection system, with provider functions registered in the container.

## Documentation Resources

For deeper understanding, refer to:

- [FastAPI Implementation Guide](./FastAPI_Implementation.md): Detailed implementation strategies
- [FastAPI Testing Guide](./FastAPI_Testing_Guide.md): Testing approaches and patterns
- [API Documentation](../app/openapi.json): Auto-generated OpenAPI schema

## Getting Started

New developers should start by:

1. Understanding the layered architecture and module separation
2. Exploring the API through the OpenAPI documentation
3. Following domain-specific code paths to understand implementation
4. Reviewing test cases for behavior examples 