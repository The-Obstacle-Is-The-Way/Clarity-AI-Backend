#!/bin/bash

# Standalone Test Migration Script
# This script automates the process of migrating standalone tests to proper unit tests

set -e  # Exit on error

# Configuration
STANDALONE_DIR="app/tests/standalone"
UNIT_DIR="app/tests/unit"
INTEGRATION_DIR="app/tests/integration"
MIGRATION_LOG="test_migration_log.csv"

# Create directory if it doesn't exist
mkdir -p "$(dirname "$MIGRATION_LOG")"

# Create or clear the migration log
echo "Source,Destination,Status,Notes" > $MIGRATION_LOG

# Function to categorize a test based on its content
categorize_test() {
    local source_path=$1
    local test_content=$(cat "$source_path")
    
    # Check if it contains duplicate implementations
    if grep -q "Self-contained test" "$source_path" || grep -q "standalone" "$source_path"; then
        echo "needs_migration"
    elif grep -q "import pytest" "$source_path" && ! grep -q "from app." "$source_path"; then
        echo "needs_migration"
    elif grep -q "from app." "$source_path"; then
        echo "ready_for_copy"
    else
        echo "needs_analysis"
    fi
}

# Create a function to identify the proper destination for a standalone test
get_destination_path() {
    local source_path=$1
    local filename=$(basename "$source_path")
    local dirname=$(dirname "$source_path")
    
    # Extract component from directory path
    local component="${dirname#$STANDALONE_DIR/}"
    
    # Handle different naming patterns
    if [[ "$filename" == test_standalone_* ]]; then
        # Extract the main component name by removing the prefix
        local base_name="${filename#test_standalone_}"
        echo "$UNIT_DIR/$component/test_$base_name"
    else
        # For other tests, just copy the name but ensure proper directory
        echo "$UNIT_DIR/$component/$filename"
    fi
}

# Function to create a migration template
create_template() {
    local source_path=$1
    local dest_path=$(get_destination_path "$source_path")
    
    # Ensure the directory exists
    mkdir -p "$(dirname "$dest_path")"
    
    # Read source file
    local source_content=$(cat "$source_path")
    
    # Generate template with migration comments
    cat > "$dest_path" << EOF
"""
Migrated from standalone test: $source_path

This test has been migrated to use the actual implementation
instead of a self-contained duplicate implementation.
"""

import pytest
from unittest.mock import MagicMock, patch

# TODO: Replace standalone imports with actual implementation imports
# Original imports:
$(grep "^import\|^from" "$source_path")

# TODO: Replace with actual implementation imports
# from app.domain... import ...
# from app.core... import ...

# Original test code (needs migration):
$(cat "$source_path" | sed 's/^/# /')

# Migrated test code:
# TODO: Implement properly migrated tests below

def test_migrated_placeholder():
    """Placeholder test to be replaced with migrated tests."""
    assert True
EOF
    
    echo "Created migration template at $dest_path"
    echo "Please edit this file to implement the migrated tests"
}

# Main functionality
if [[ "$1" == "--create-template" ]]; then
    if [[ -z "$2" ]]; then
        echo "Error: No source file specified"
        echo "Usage: $0 --create-template path/to/standalone/test.py"
        exit 1
    fi
    
    source_path="$2"
    if [[ ! -f "$source_path" ]]; then
        echo "Error: Source file does not exist: $source_path"
        exit 1
    fi
    
    create_template "$source_path"
    exit 0
fi

# Analyze all standalone tests
echo "=== Standalone Test Migration Tool ==="
echo
echo "Analyzing standalone tests..."
echo

# Find all standalone test files
standalone_tests=$(find "$STANDALONE_DIR" -name "*.py" -type f | grep -v "__pycache__" | grep -v "__init__")
test_count=$(echo "$standalone_tests" | wc -l)
echo "Found $test_count standalone test files to analyze"
echo

# Categorize each test
needs_migration=0
ready_for_copy=0
needs_analysis=0

for test_file in $standalone_tests; do
    dest_path=$(get_destination_path "$test_file")
    category=$(categorize_test "$test_file")
    
    echo "$test_file -> $dest_path [$category]"
    
    # Update counts
    if [[ "$category" == "needs_migration" ]]; then
        needs_migration=$((needs_migration + 1))
    elif [[ "$category" == "ready_for_copy" ]]; then
        ready_for_copy=$((ready_for_copy + 1))
    elif [[ "$category" == "needs_analysis" ]]; then
        needs_analysis=$((needs_analysis + 1))
    fi
    
    # Add to migration log
    echo "$test_file,$dest_path,$category," >> $MIGRATION_LOG
done

echo
echo "Migration Analysis Summary:"
echo "  - Needs migration: $needs_migration"
echo "  - Ready for copy: $ready_for_copy"
echo "  - Needs analysis: $needs_analysis"
echo "  - Total: $test_count"
echo
echo "Migration analysis complete. See $MIGRATION_LOG for details."
echo
echo "Next steps:"
echo "1. Review the migration log to identify high-priority tests to migrate"
echo "2. For each test to migrate:"
echo "   a. Create a template: $0 --create-template path/to/standalone/test.py"
echo "   b. Update the template to use actual implementations"
echo "   c. Run the tests to ensure they pass"
echo "3. Once all tests are migrated, the standalone directory can be removed" 