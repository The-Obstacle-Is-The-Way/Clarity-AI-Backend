# Novamind Digital Twin Platform Tools

This directory contains tools for development, maintenance, and refactoring of the Novamind Digital Twin Platform codebase.

## Refactoring Tools

### Code Structure Refactoring (`refactor_code_structure.py`)

This script refactors the codebase to follow clean architecture principles by:

1. Eliminating legacy code paths (especially `/refactored/` paths) 
2. Moving files to their canonical locations
3. Creating a proper directory structure according to clean architecture
4. Updating import statements to reflect the new structure
5. Removing empty directories

#### Usage

To see what changes would be made without actually making them:

```bash
python refactor_code_structure.py --dry-run
```

To execute the refactoring:

```bash
python refactor_code_structure.py
```

#### Clean Architecture Structure

The script reorganizes the codebase according to the following structure:

```
backend/
├── app/
│   ├── domain/                   # Domain layer - pure business logic
│   │   ├── entities/             # Business entities and aggregates
│   │   │   ├── auth/             # Authentication and authorization entities
│   │   │   ├── digital_twin/     # Digital twin domain entities
│   │   │   └── patient/          # Patient domain entities
│   │   ├── exceptions/           # Domain-specific exceptions
│   │   ├── events/               # Domain events
│   │   ├── value_objects/        # Value objects used across entities
│   │   └── repositories/         # Repository interfaces (contracts)
│   ├── application/              # Application layer - use cases and services
│   │   ├── interfaces/           # Service interfaces
│   │   └── use_cases/            # Application-specific use cases
│   ├── infrastructure/           # Infrastructure layer - external services
│   │   ├── repositories/         # Repository implementations
│   │   │   └── mongodb/          # MongoDB implementations
│   │   ├── services/             # External service implementations
│   │   │   └── trinity_stack/    # Trinity stack AI services
│   │   └── security/             # Security implementations
│   ├── api/                      # API layer - FastAPI endpoints
│   │   └── v1/                   # API version 1
│   │       ├── endpoints/        # API endpoints grouped by domain
│   │       └── schemas/          # Pydantic schemas for request/response
│   └── core/                     # Cross-cutting concerns
└── tests/                        # Test suite
    ├── unit/                     # Unit tests
    ├── integration/              # Integration tests
    └── e2e/                      # End-to-end tests
```

#### Post-Refactoring Steps

After running the script:

1. Run the test suite to verify all functionality works correctly
2. Resolve any import errors that may have been missed by the script
3. Review the refactored structure for any adjustments needed
4. Run integration tests to verify the application works end-to-end
5. Update documentation to reflect the new structure

#### Implementation Details

The refactoring script:

- Identifies files in `/refactored/` paths
- Determines the appropriate destination based on file type and content
- Moves files to their new locations, preserving metadata
- Creates necessary directories and `__init__.py` files
- Updates import statements throughout the codebase
- Cleans up empty directories

## Maintenance Tools

Additional tools for maintaining the codebase are located in:

- `tools/maintenance/`: Code quality and maintenance scripts
- `tools/security/`: Security scanning and analysis tools

## Best Practices

When writing new code:

1. Follow the established clean architecture
2. Put files in the correct layers based on their responsibility
3. No backward compatibility shims or adapters
4. Ensure proper separation of concerns
5. Write tests that verify the functionality works correctly