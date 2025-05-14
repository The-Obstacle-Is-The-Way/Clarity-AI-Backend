# Clarity AI Backend Scripts

This directory contains utility scripts for the Clarity AI Backend project. These scripts are designed to help with development, testing, HIPAA compliance verification, and CI/CD processes.

## Testing Scripts

### `run_tests.py`

A comprehensive test runner that executes tests in dependency order.

```bash
# Run all tests in order (standalone → venv → integration)
./scripts/run_tests.py

# Run only standalone tests
./scripts/run_tests.py --skip-venv --skip-integration

# Run specific test files
./scripts/run_tests.py app/tests/standalone/test_enhanced_log_sanitizer.py

# Continue running tests even if previous stages fail
./scripts/run_tests.py --continue-on-failure

# Show commands without executing them
./scripts/run_tests.py --dry-run
```

### `ci_test_runner.sh`

A shell script designed for CI/CD environments that runs all tests and generates reports.

```bash
# Run standalone and venv tests
./scripts/ci_test_runner.sh

# Run all tests including integration tests
WITH_INTEGRATION=true ./scripts/ci_test_runner.sh

# Continue even if tests fail
CONTINUE_ON_FAILURE=true ./scripts/ci_test_runner.sh
```

## HIPAA Compliance Scripts

### `hipaa_phi_audit.py` 

Scans the codebase for potential PHI leakage in logs and error messages.

```bash
# Run a comprehensive PHI audit
./scripts/hipaa_phi_audit.py

# Generate a detailed report
./scripts/hipaa_phi_audit.py --output-report reports/phi_audit_report.md

# Check specific directories only
./scripts/hipaa_phi_audit.py --directories app/presentation app/infrastructure
```

### `check_log_sanitization.py`

Verifies that all logging statements properly use the log sanitizer.

```bash
# Check all logging statements in the codebase
./scripts/check_log_sanitization.py

# Fix issues automatically where possible
./scripts/check_log_sanitization.py --auto-fix
```

## Utility Scripts

### `fix_pat_mock.py`

Applies fixes to the PAT mock service to address test failures.

```bash
./scripts/fix_pat_mock.py
```

### `create_test_classification.py`

Generates a comprehensive report about test organization and dependencies.

```bash
# Generate markdown report (default)
./scripts/create_test_classification.py

# Generate JSON report
./scripts/create_test_classification.py --format json

# Specify output file name
./scripts/create_test_classification.py --output my-test-report
```

## Directory Structure

The scripts follow these conventions:

- Testing scripts are prefixed with `test_` or contain `test` in their name
- CI/CD scripts are prefixed with `ci_`
- HIPAA compliance scripts are prefixed with `hipaa_` or contain `phi` in their name
- Utility scripts focus on a specific functionality

## Contributing

When adding new scripts:

1. Follow the naming conventions
2. Add proper documentation
3. Make scripts executable (`chmod +x script_name.py`)
4. Update this README with usage instructions

## Running Scripts

Most Python scripts can be run directly if they have the executable bit set:

```bash
./scripts/script_name.py
```

Or they can be run with the Python interpreter:

```bash
python scripts/script_name.py
```

Shell scripts should be run with:

```bash
./scripts/script_name.sh
```

## Troubleshooting

If you encounter permission issues with scripts:

```bash
# Make script executable
chmod +x scripts/script_name.py
```

If a script fails with import errors, ensure you're running from the project root:

```bash
cd /path/to/Clarity-AI-Backend
./scripts/script_name.py
```
