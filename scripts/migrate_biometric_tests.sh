#!/bin/bash

# Example script to demonstrate a complete migration of a biometric processor test
# This serves as a template for other migrations

set -e  # Exit on error

# Configuration
STANDALONE_FILE="app/tests/standalone/core/test_standalone_biometric_processor.py"
TARGET_FILE="app/tests/unit/core/test_biometric_processor.py"

# Check if the migration script exists
if [ ! -f "scripts/migrate_standalone_tests.sh" ]; then
    echo "Error: Migration script not found"
    echo "Run this script from the project root directory"
    exit 1
fi

# Ensure the scripts are executable
chmod +x scripts/migrate_standalone_tests.sh

echo "=== Running Biometric Processor Test Migration Example ==="
echo 

# Step 1: Analyze the test
echo "Step 1: Analyzing test file ${STANDALONE_FILE}..."
./scripts/migrate_standalone_tests.sh

# Step 2: Generate a template
echo 
echo "Step 2: Creating migration template..."
echo 
./scripts/migrate_standalone_tests.sh --create-template "${STANDALONE_FILE}"

# Step 3: Run the original standalone test to verify coverage
echo 
echo "Step 3: Running original standalone test to get baseline coverage..."
echo 
python -m pytest "${STANDALONE_FILE}" -v

# Step 4: Run the migrated test to verify migration worked
echo 
echo "Step 4: Running migrated test to verify migration worked..."
echo 
python -m pytest "${TARGET_FILE}" -v

echo 
echo "=== Migration Summary ==="
echo "Original test: ${STANDALONE_FILE}"
echo "Migrated test: ${TARGET_FILE}"
echo 
echo "To continue with other tests, use the migration script:"
echo "./scripts/migrate_standalone_tests.sh --create-template PATH_TO_STANDALONE_TEST"
echo 
echo "For further details, check the migration documentation:"
echo "docs/testing/standalone_test_migration_guide.md"
echo "docs/testing/test_migration_status.md" 