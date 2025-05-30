# Clean Architecture Diagram

The Clarity-AI Backend implements Clean Architecture, which separates concerns into concentric layers. Each layer has a specific responsibility and dependency flows only inward.

```mermaid
graph TD
    subgraph "Clean Architecture"
        A["Presentation Layer<br>(API, Web UI)"] --> B["Application Layer<br>(Use Cases, DTOs)"]
        B --> C["Domain Layer<br>(Entities, Business Logic)"]
        A --> D["Infrastructure Layer<br>(External Services, Persistence)"]
        B --> D
        D -.-> C
        
        style A fill:#d4f0f0,stroke:#333,stroke-width:2px
        style B fill:#d4e6f0,stroke:#333,stroke-width:2px
        style C fill:#e0d4f0,stroke:#333,stroke-width:2px
        style D fill:#f0e4d4,stroke:#333,stroke-width:2px
    end
```

## Layer Responsibilities

### Domain Layer (Core)

The innermost layer contains:

- **Entities**: Business objects with methods and properties
- **Value Objects**: Immutable objects defined by their attributes
- **Domain Services**: Domain logic that doesn't belong to a specific entity
- **Domain Interfaces**: Abstractions required by domain logic
- **Domain Events**: Events representing state changes in domain objects

### Application Layer

The application layer contains:

- **Use Cases**: Application-specific business rules
- **DTOs**: Data Transfer Objects for input/output
- **Application Services**: Orchestration of domain objects
- **Application Interfaces**: Abstractions for external dependencies

### Infrastructure Layer

The infrastructure layer contains:

- **Repositories**: Data access implementations
- **External Services**: Integration with external systems
- **ORM Mappings**: Database mappings
- **Authentication**: Security implementations
- **Logging**: Logging implementations
- **Cache**: Caching implementations

### Presentation Layer

The presentation layer contains:

- **API Controllers/Endpoints**: HTTP request handlers
- **API Models**: Request/response models
- **Middleware**: HTTP pipeline components
- **Validation**: Input validation
- **Documentation**: API documentation

## Dependency Flow

```mermaid
graph LR
    A["Presentation<br>Layer"] --> B["Application<br>Layer"]
    B --> C["Domain<br>Layer"]
    D["Infrastructure<br>Layer"] --> B
    D -.-> C
    
    style A fill:#d4f0f0,stroke:#333,stroke-width:2px
    style B fill:#d4e6f0,stroke:#333,stroke-width:2px
    style C fill:#e0d4f0,stroke:#333,stroke-width:2px
    style D fill:#f0e4d4,stroke:#333,stroke-width:2px
```

The dependency rule states that source code dependencies should only point inward. This means:

- Domain layer has no dependencies on other layers
- Application layer depends only on the domain layer
- Presentation layer depends on application and domain layers
- Infrastructure layer depends on application and domain layers

## HIPAA Compliance Considerations

```mermaid
graph TD
    subgraph "HIPAA Compliance"
        A["Access Control<br>(JWT Authentication)"] --> B["PHI Handling<br>(Domain Entities)"]
        C["Audit Logging<br>(Infrastructure)"] --> B
        D["Data Encryption<br>(Infrastructure)"] --> B
        E["Secure API<br>(Presentation)"] --> B
        
        style A fill:#f0d4d4,stroke:#333,stroke-width:2px
        style B fill:#e0d4f0,stroke:#333,stroke-width:2px
        style C fill:#d4e6f0,stroke:#333,stroke-width:2px
        style D fill:#d4f0d4,stroke:#333,stroke-width:2px
        style E fill:#f0f0d4,stroke:#333,stroke-width:2px
    end
```

HIPAA compliance is integrated across all layers:

- **Domain Layer**: Defines PHI entities and security rules
- **Application Layer**: Enforces business rules for PHI access
- **Infrastructure Layer**: Implements encryption, audit logging
- **Presentation Layer**: Secure API endpoints, authentication

## Machine Learning Integration

```mermaid
graph TD
    subgraph "ML Architecture"
        A["ML API Endpoints<br>(Presentation)"] --> B["ML Use Cases<br>(Application)"]
        B --> C["ML Domain Services<br>(Domain)"]
        D["ML Service Implementations<br>(Infrastructure)"] --> B
        
        style A fill:#d4f0f0,stroke:#333,stroke-width:2px
        style B fill:#d4e6f0,stroke:#333,stroke-width:2px
        style C fill:#e0d4f0,stroke:#333,stroke-width:2px
        style D fill:#f0e4d4,stroke:#333,stroke-width:2px
    end
```

Machine learning components follow the same architectural principles:

- **Domain Layer**: ML core entities and service interfaces
- **Application Layer**: ML use cases and orchestration
- **Infrastructure Layer**: Specific ML model implementations
- **Presentation Layer**: ML-related API endpoints