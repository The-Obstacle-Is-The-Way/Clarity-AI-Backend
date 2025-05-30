# Architecture Documentation

This section contains documentation on the architecture of the Clarity-AI Backend system. It follows clean architecture principles with clear separation of concerns.

## Contents

- [Architecture Overview](./overview.md) - High-level overview of the system architecture
- [Clean Architecture Diagram](./clean_architecture_diagram.md) - Visual representation of the clean architecture layers
- [Domain Model](./domain_model.md) - Core domain entities and relationships
- [ML Integration](./ml_integration.md) - Integration with machine learning services

## Clean Architecture

The Clarity-AI Backend follows a clean architecture pattern with four main layers:

1. **Domain Layer** - Core business entities and logic
2. **Application Layer** - Use cases and application services
3. **Infrastructure Layer** - External service implementations
4. **Presentation Layer** - API endpoints and controllers

Each layer has a specific responsibility, and dependencies only point inward (from outer layers to inner layers).

## Key Architectural Principles

- **Dependency Inversion** - High-level modules do not depend on low-level modules
- **Separation of Concerns** - Each component has a single responsibility
- **Interface Segregation** - Clients only depend on interfaces they use
- **Domain-Driven Design** - Software design centered around the domain model
- **HIPAA Compliance** - Architecture designed with security and privacy at its core

## HIPAA Compliance Measures

The architecture incorporates several key measures to ensure HIPAA compliance:

- **Data Encryption** - PHI is encrypted both in transit and at rest
- **Access Control** - Role-based access control with proper authentication
- **Audit Logging** - Comprehensive logging of all access to PHI
- **Data Isolation** - Clear boundaries between PHI and non-PHI data
- **Secure Communication** - TLS for all API communication

## Machine Learning Integration

The architecture includes integration with multiple machine learning services:

- **MentaLLaMA** - HIPAA-compliant psychiatric analysis service
- **XGBoost Models** - For predictive analytics
- **Psychiatric Analysis Tool (PAT)** - Specialized analysis toolkit

## Further Reading

For more detailed information about specific components, refer to:

- [Project Structure](../development/project_structure.md)
- [API Documentation](../api/README.md)
- [HIPAA Compliance](../compliance/hipaa_compliance.md)