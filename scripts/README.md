# Clarity AI Backend Scripts

This directory contains utility scripts for the Clarity AI Backend project. These scripts are organized to help with development, testing, deployment, and maintenance of the platform while ensuring HIPAA compliance.

## Directory Structure

- `scripts/core/` - Core scripts for running the application and tests
- `scripts/db/` - Database management and migration scripts
- `scripts/deploy/` - Deployment automation scripts
- `scripts/test/` - Test runners and utilities
- `scripts/utils/` - General utility scripts

## Core Scripts

### Docker and Environment Scripts

- `core/docker_entrypoint.py` - Entrypoint for Docker containers
- `core/docker_test_runner.py` - Runs tests in Docker environment
- `core/redis_validator.py` - Validates Redis configuration

## Test Scripts

- `test/run_all_tests.py` - Comprehensive test runner
- `test/run_tests_by_level.py` - Runs tests organized by level (unit, integration, etc.)
- `run_tests.sh` - Shell script to run tests in the correct order

## Database Scripts

- `db/fix_db_driver.py` - Utilities for database driver management

## Deployment Scripts

- `deploy/deploy_and_test.sh` - Automated deployment and testing

## Utility Scripts

- `utils/datetime_transformer.py` - Datetime transformation utilities
- `verify_types.py` - Validates type hints across the codebase

## Usage Examples

### Running All Tests

```bash
# Run all tests in order
./scripts/run_tests.sh

# Run tests with specific options
./scripts/test/run_all_tests.py --skip-integration
```

### Deployment

```bash
# Deploy and run automated tests
./scripts/deploy/deploy_and_test.sh
```

## Contributing

When adding new scripts:

1. Place scripts in the appropriate directory based on functionality
2. Follow clean code principles and add proper type hints
3. Include documentation within the script
4. Make scripts executable (`chmod +x script_name.py`)
5. Update this README with usage instructions if necessary

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
