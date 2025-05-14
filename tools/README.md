# Clarity Digital Twin Platform Tools

This directory contains tools for development, maintenance, and security of the Clarity Digital Twin Platform codebase.

## Directory Structure

- `tools/maintenance/` - Code quality and maintenance tools
- `tools/security/` - Security scanning and PHI audit tools
- `tools/refactor/` - Code refactoring and structure tools

## Refactoring Tools

### Code Structure Refactoring (`refactor_code_structure.py`)

This tool refactors the codebase to follow clean architecture principles by organizing the codebase according to:

- Domain layer - Business entities and logic
- Application layer - Use cases and service interfaces
- Infrastructure layer - External services and repository implementations
- API layer - FastAPI endpoints and schemas
- Core - Cross-cutting concerns

```bash
# Preview changes without applying
python tools/refactor_code_structure.py --dry-run

# Execute refactoring
python tools/refactor_code_structure.py
```

## Security Tools

### PHI Auditing (`security/phi_auditor_complete.py`)

Scans the codebase for potential PHI leakage in logs and error messages to ensure HIPAA compliance.

```bash
# Run a comprehensive PHI audit
python tools/security/phi_auditor_complete.py

# Fix issues automatically
python tools/security/complete_phi_audit_fixer.py
```

## Maintenance Tools

Tools for maintaining the codebase including:

- Configuration templates for testing
- Code quality checks
- Type verification

## Clean Architecture Implementation

All tools in this repository follow these principles:

1. Separation of concerns between tools
2. Proper error handling and logging
3. Strong typing with Pydantic models
4. HIPAA compliance enforcement
5. Consistent naming conventions

When using or contributing to these tools, please follow the established clean architecture principles found in the main codebase.

## Best Practices

When writing new tools:

1. Follow the established directory structure
2. Use type hints consistently
3. Add comprehensive error handling
4. Include proper documentation
5. Write tests to verify functionality