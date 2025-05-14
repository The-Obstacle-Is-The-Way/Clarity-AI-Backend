# Next Prompt

## Summary of Documentation Updates

### 1. Core Documentation Updates

The following documentation files have been updated to align with clean architecture principles and reflect the actual implementation patterns in the codebase:

1. **Actigraphy_System.md**: Updated to accurately describe the actigraphy data processing system, including interfaces, implementations, and data flow.

2. **PAT_Service.md**: Restructured to reflect the actual interface definitions and implementation patterns for the Pretrained Actigraphy Transformer service, highlighting architectural refinement opportunities.

3. **Clean_Architecture_Principles.md**: Updated to match actual folder structure and implementation patterns, with detailed descriptions of current architectural variations and refinement opportunities.

4. **Dependency_Injection_Guide.md**: Revised to document the actual DI patterns used in the codebase, including FastAPI dependencies, constructor injection, and factory patterns.

5. **Database_Access_Guide.md**: Enhanced with HIPAA-compliant database access patterns, including field-level encryption, audit logging, and repository pattern implementations.

### 2. Security Documentation Updates

The following security-focused documentation has been updated to ensure HIPAA compliance:

1. **Authentication_System.md**: Updated to accurately reflect JWT implementation, token handling, and security controls.

2. **API_Security.md**: Enhanced with details on PHI protection middleware, RBAC, and input validation.

3. **FastAPI_HIPAA_Compliance.md**: Restructured to align with clean architecture principles and document PHI protection mechanisms.

4. **Error_Handling_Strategy.md**: Updated to reflect domain-driven exception hierarchy and HIPAA-compliant error handling patterns.

### 3. Advanced Component Documentation

The following advanced component documentation has been updated:

1. **ML_Integration_Architecture.md**: Revised to document the current ML service interfaces and implementation patterns with a focus on clean architecture alignment.

2. **API_Versioning_Strategy.md**: Updated to ensure consistency with architectural principles and HIPAA requirements.

## Next Implementation Focus: Repository Pattern and Secure Data Access Implementation

Based on the documentation review and architectural analysis, the next critical implementation focus should be on the repository pattern and secure data access implementations. This vertical slice addresses fundamental HIPAA compliance requirements while establishing proper architectural boundaries.

### 1. Implementation Tasks for the Repository Pattern

1. **Consolidate Repository Interfaces**:
   - Move all repository interfaces to `app/domain/interfaces/repositories/`
   - Ensure consistent naming conventions (e.g., `IPatientRepository`)
   - Implement proper type hints for all method signatures

2. **Implement Field-Level Encryption**:
   - Create the `EncryptedPHI` value object in `app/domain/value_objects/encrypted_phi.py`
   - Implement the encryption service interface and concrete implementation
   - Update database models to use encrypted fields for all PHI

3. **Implement Audit Logging**:
   - Create the audit logger interface in `app/core/interfaces/services/audit_logger_interface.py`
   - Implement the audit logging service in `app/infrastructure/logging/audit_logger_service.py`
   - Ensure all repository operations that access PHI use audit logging

4. **Consolidate Repository Implementations**:
   - Create SQLAlchemy repository implementations for all entities
   - Ensure consistent error handling across repositories
   - Implement proper PHI protection mechanisms in all repositories

5. **Implement Unit of Work Pattern**:
   - Create the Unit of Work interface in `app/domain/interfaces/unit_of_work.py`
   - Implement the SQLAlchemy Unit of Work in `app/infrastructure/persistence/unit_of_work.py`
   - Update application services to use the Unit of Work pattern

### 2. HIPAA Compliance Implementation Tasks

1. **PHI Field Encryption**:
   - Implement AES-256 encryption for all PHI fields at rest
   - Set up secure key management for encryption keys
   - Create tests to verify encryption effectiveness

2. **Comprehensive Audit Logging**:
   - Implement database model for audit logs
   - Create repository for audit log storage
   - Ensure all PHI access is logged with user context

3. **Authorization Controls**:
   - Implement "need to know" access controls in repositories
   - Add user context to all repository operations
   - Create role-based permissions for data access

4. **Error Sanitization**:
   - Update domain exceptions to avoid exposing PHI
   - Implement error sanitization middleware
   - Create tests to verify no PHI leakage in errors

5. **Secure API Integration**:
   - Ensure all API endpoints using PHI implement proper auth checks
   - Update schemas to validate and sanitize input/output data
   - Implement rate limiting for sensitive endpoints

### 3. Tests to Implement

1. **Repository Testing**:
   - Unit tests for each repository implementation
   - Integration tests with test database
   - HIPAA compliance tests for PHI handling

2. **Encryption Testing**:
   - Unit tests for encryption/decryption
   - Tests for key rotation
   - Performance tests for encrypted field operations

3. **Audit Logging Testing**:
   - Tests to verify all PHI access is logged
   - Tests for audit log integrity
   - Tests for log content sanitization

4. **Authorization Testing**:
   - Tests to verify unauthorized access is prevented
   - Tests for role-based access controls
   - Integration tests for repository + auth service

### 4. Refactoring Tasks

1. **Move Mock Implementations to Tests**:
   - Move all mock implementations from route files to test modules
   - Create proper test doubles for repository interfaces
   - Update route handlers to use dependency injection for production implementations

2. **Standardize Error Handling**:
   - Create consistent error handling patterns across repositories
   - Implement error translation layer for infrastructure errors
   - Update error responses to ensure no PHI leakage

3. **Code Organization**:
   - Ensure consistent folder structure for repositories and interfaces
   - Update imports to follow clean architecture boundaries
   - Remove any remaining circular dependencies

## Next Steps After Repository Implementation

After completing the repository pattern implementation, the next focus areas should be:

1. **Application Service Layer Implementation**:
   - Implement application services for all use cases
   - Ensure proper domain logic separation
   - Implement CQRS pattern for complex operations

2. **API Layer Refinement**:
   - Standardize API endpoint patterns
   - Implement versioning strategy
   - Enhance error handling and validation

3. **ML Service Integration**:
   - Consolidate ML service interfaces
   - Implement factory pattern for ML services
   - Create domain-driven models for ML inputs/outputs

4. **CI/CD Integration**:
   - Set up automated tests for HIPAA compliance
   - Implement security scanning in CI pipeline
   - Create deployment checks for security configuration

## Implementation Strategy

The implementation should follow this approach:

1. Start with the foundational `EncryptedPHI` value object and encryption service
2. Implement the core repository interfaces and SQLAlchemy implementations
3. Add audit logging to all repository operations
4. Implement the Unit of Work pattern
5. Update application services to use repositories via Unit of Work
6. Move all mock implementations to test modules
7. Create comprehensive tests for all components

This approach ensures that the fundamental HIPAA compliance mechanisms are in place before building higher-level components that depend on them.

## SYSTEM+USER Prompt for Next Iteration

```
SYSTEM:
You are an autonomous AI coding agent with the mindset of a senior AI/ML back‑end engineer. Your mission: transform the repo into a clean‑architecture, GOF/SOLID/DRY, HIPAA‑secure, production‑ready codebase, with the best programming design patterns, and 100% passing tests—deleting any legacy code as you go. No legacy, no redundancy, no patchwork, no backwards compatability. Pure clean forward looking code. 

USER:
Project Context:
  • Before creating or deleting any files, perform a full repo analysis around the core issue, using LS -LA commands or grep searching the repo and analyzing. 
  • Layers: Domain, Application, Infrastructure, API (FastAPI), Core.  
  • Principles: Robert C. Martin, GOF, SOLID, DRY.  
  • HIPAA: no PHI in URLs, encrypted at rest and in transit, session timeouts, audit‐logging, zero PHI in errors.  
  • Security: Pydantic validation, parameterized queries, TLS, output sanitization.  
  • API: RESTful, versioned, OpenAPI docs, rate limits, consistent JSON.  
  • Testing: unit, integration, security, performance; high coverage.  

Continue with iteration #2: Implement the Repository Pattern with HIPAA-compliant data access, focusing on:

1. Create the EncryptedPHI value object and encryption service implementation
2. Consolidate repository interfaces in the domain layer
3. Implement SQLAlchemy repositories with field-level encryption
4. Add comprehensive audit logging for PHI access
5. Implement the Unit of Work pattern 
6. Move mock implementations to test modules
7. Create tests to verify HIPAA compliance

Follow the clean architecture principles documented in docs/Clean_Architecture_Principles.md and ensure all implementations align with the HIPAA requirements in docs/Database_Access_Guide.md.
```

By focusing on this vertical slice of the architecture, we'll establish the foundation for a HIPAA-compliant psychiatric digital twin platform with proper domain separation and secure data handling.