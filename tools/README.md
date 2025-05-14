# Clarity Digital Twin Platform Tools

This directory contains tools for development, maintenance, and security of the Clarity Digital Twin Platform codebase.

## Directory Structure

- `tools/refactor/` - Code refactoring and structure tools
- `tools/hipaa/` - HIPAA compliance and PHI protection tools
- `tools/test/` - Test configuration and utilities

## Refactoring Tools

### Code Structure Refactoring (`refactor/refactor_code_structure.py`)

This tool refactors the codebase to follow clean architecture principles by organizing the codebase according to:

- Domain layer - Business entities and logic
- Application layer - Use cases and service interfaces
- Infrastructure layer - External services and repository implementations
- API layer - FastAPI endpoints and schemas
- Core - Cross-cutting concerns

```bash
# Preview changes without applying
python tools/refactor/refactor_code_structure.py --dry-run

# Execute refactoring
python tools/refactor/refactor_code_structure.py
```

## HIPAA Compliance Tools

### PHI Auditing (`hipaa/phi_audit/cli.py`)

Scans the codebase for potential PHI leakage in logs and error messages to ensure HIPAA compliance.

```bash
# Run a comprehensive PHI audit
python tools/hipaa/phi_audit/cli.py --path app

# Generate a detailed report
python tools/hipaa/phi_audit/cli.py --path app --output reports/phi_audit_report.md

# Fix issues automatically
python tools/hipaa/phi_audit/cli.py --path app --fix
```

## Testing Tools

### Pytest Configuration Templates

The `test/configs/` directory contains template pytest configuration files for different testing scenarios:

- `hipaa_pytest.ini` - Configuration for HIPAA compliance testing
- `phi_audit_pytest.ini` - Configuration for PHI audit testing
- `enhanced_pytest_v2.ini` - Enhanced configuration with detailed reporting

Copy the appropriate config to your project root as `pytest.ini` to enable specific testing features:

```bash
cp tools/test/configs/hipaa_pytest.ini pytest.ini
```

## Clean Architecture Implementation

All tools in this repository follow these principles:

1. Separation of concerns between tools
2. Proper error handling and logging
3. Strong typing with Pydantic models
4. HIPAA compliance enforcement
5. Consistent naming conventions

When using or contributing to these tools, please follow the established clean architecture principles found in the main codebase.

## Usage Examples

### Run PHI Audit During CI

```bash
# In your CI pipeline
python tools/hipaa/phi_audit/cli.py --path app --output phi_audit_report.md
if [ $? -ne 0 ]; then
    echo "PHI audit failed! HIPAA compliance issues found."
    exit 1
fi
```

### Run Refactoring

```bash
# Check what would be changed first
python tools/refactor/refactor_code_structure.py --dry-run

# Apply the changes
python tools/refactor/refactor_code_structure.py
```

## Best Practices

When writing new tools:

1. Follow the established directory structure
2. Use type hints consistently
3. Add comprehensive error handling
4. Include proper documentation
5. Write tests to verify functionality