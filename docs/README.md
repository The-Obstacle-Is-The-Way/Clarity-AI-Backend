# Clarity AI Backend Documentation

This directory contains comprehensive documentation for the Clarity AI Backend, a revolutionary HIPAA-compliant psychiatric digital twin platform that transforms fragmented clinical data into integrated predictive models.

## Documentation Structure

The documentation is organized by architectural layers and categories, following clean architecture principles.

### Core Architecture Documentation

1. [**Clean Architecture Principles**](./Clean_Architecture_Principles.md) - Implementation of clean architecture in the platform
2. [**Project Structure Overview**](./Project_Structure_Overview.md) - Directory organization and rationale
3. [**Dependency Injection Guide**](./Dependency_Injection_Guide.md) - DI patterns and implementation
4. [**Design Patterns Guide**](./Design_Patterns_Guide.md) - GOF/SOLID patterns used in the codebase
5. [**Error Handling Strategy**](./Error_Handling_Strategy.md) - Domain-driven exception handling

### Domain Layer Documentation

1. [**Domain Models & Entities**](./Domain_Models_Entities.md) - Core business entities and models
2. [**Value Objects Guide**](./Value_Objects_Guide.md) - Immutable value objects
3. [**Domain Service Interfaces**](./Domain_Service_Interfaces.md) - Core domain service abstractions
4. [**Token Blacklist Repository Interface**](./Token_Blacklist_Repository_Interface.md) - Repository interface standard

### Application Layer Documentation

1. [**Use Case Implementation**](./Use_Case_Implementation.md) - Business workflow implementation
2. [**DTOs & Data Mapping**](./DTOs_And_Data_Mapping.md) - Data transfer objects and mappers
3. [**Application Services**](./Application_Services.md) - Application service orchestration

### Infrastructure Layer Documentation

1. [**Database Access Guide**](./Database_Access_Guide.md) - HIPAA-compliant persistence implementation
2. [**Redis Service Interface**](./Redis_Service_Interface.md) - Caching and rate limiting
3. [**External Services Integration**](./External_Services_Integration.md) - Third-party integrations
4. [**Password Handler Interface**](./Password_Handler_Interface.md) - Security services
5. [**Audit Logger Interface**](./Audit_Logger_Interface.md) - HIPAA-compliant audit logging

### Presentation Layer Documentation

1. [**API Security**](./API_Security.md) - Authentication, authorization, and middleware
2. [**API Versioning Strategy**](./API_Versioning_Strategy.md) - API evolution approach
3. [**Schema Validation**](./Schema_Validation.md) - Request/response validation with Pydantic
4. [**Authentication System**](./Authentication_System.md) - Authentication flow and security
5. [**Rate Limiting Middleware**](./Rate_Limiting_Middleware.md) - API rate limiting
6. [**Request ID Middleware**](./Request_ID_Middleware.md) - Request tracking

### Domain-Specific Implementation Documentation

1. [**Patient API Routes**](./Patient_API_Routes.md) - Patient management endpoints
2. [**Digital Twin API Routes**](./Digital_Twin_API_Routes.md) - Digital twin API implementation
3. [**Biometric Alert Rules API**](./Biometric_Alert_Rules_API.md) - Alert rules configuration
4. [**ML Integration Architecture**](./ML_Integration_Architecture.md) - ML system architecture
5. [**PAT Service**](./PAT_Service.md) - Pretrained Actigraphy Transformer service
6. [**Actigraphy System**](./Actigraphy_System.md) - Actigraphy data processing

### FastAPI Implementation Documentation

1. [**FastAPI Architecture Overview**](./FastAPI_Architecture_Overview.md) - High-level FastAPI implementation
2. [**FastAPI Implementation Guide**](./FastAPI_Implementation.md) - Detailed implementation patterns
3. [**FastAPI Endpoint Development**](./FastAPI_Endpoint_Development.md) - Creating new endpoints
4. [**FastAPI HIPAA Compliance**](./FastAPI_HIPAA_Compliance.md) - HIPAA compliance implementation
5. [**FastAPI Testing Guide**](./FastAPI_Testing_Guide.md) - Testing approaches

### Status and Roadmap Documentation

1. [**Documentation Checklist**](./Documentation_Checklist.md) - Status of all documentation files
2. [**Next Prompt**](./Next_Prompt.md) - Implementation roadmap for next stages

## HIPAA Compliance Documentation

The documentation includes comprehensive coverage of HIPAA compliance requirements:

1. **PHI Protection**: Details on field-level encryption and data protection
2. **Authentication & Authorization**: Secure access control mechanisms
3. **Audit Logging**: Comprehensive logging of all PHI access
4. **Error Handling**: Preventing PHI leakage in error responses
5. **API Security**: Securing endpoints and data transmission

## Getting Started

New developers should follow this reading order:

1. Start with the [Project Structure Overview](./Project_Structure_Overview.md) to understand the codebase organization
2. Review the [Clean Architecture Principles](./Clean_Architecture_Principles.md) to understand the architectural approach
3. Examine the [FastAPI Architecture Overview](./FastAPI_Architecture_Overview.md) for web framework implementation
4. Study the [Database Access Guide](./Database_Access_Guide.md) for data persistence patterns
5. Understand the [API Security](./API_Security.md) and [FastAPI HIPAA Compliance](./FastAPI_HIPAA_Compliance.md) for security requirements

## API Reference

The REST API documentation is available at `/docs` when running the application locally. This interactive Swagger UI provides detailed information about all available endpoints, request/response schemas, and authentication requirements.

## Documentation Maintenance

These documents reflect the current implementation of the Clarity AI Backend. When making significant changes to the codebase, please ensure that the corresponding documentation is updated accordingly. The [Documentation Checklist](./Documentation_Checklist.md) helps track documentation status and alignment with the code. 