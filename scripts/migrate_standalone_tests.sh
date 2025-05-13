#!/bin/bash

# Standalone Test Migration Script
# This script automates the process of migrating standalone tests to proper unit tests

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========== STANDALONE TEST MIGRATION UTILITY ==========${NC}"
echo -e "${YELLOW}This script helps analyze and migrate standalone tests to proper unit tests${NC}"

# Configuration
STANDALONE_DIR="app/tests/standalone"
UNIT_DIR="app/tests/unit"
INTEGRATION_DIR="app/tests/integration"
MIGRATION_LOG="test_migration_log.csv"

# Create directory if it doesn't exist
mkdir -p "$(dirname "$MIGRATION_LOG")"
mkdir -p "migration_analysis"

# Create or clear the migration log
echo "Source,Destination,Status,Notes" > $MIGRATION_LOG

# Get total count of standalone tests
TOTAL_TESTS=$(find ${STANDALONE_DIR} -name "test_*.py" | wc -l)
echo -e "${BLUE}Found ${TOTAL_TESTS} standalone test files to analyze${NC}"

# Function to determine the destination path for a standalone test
get_destination_path() {
    source_file=$1
    rel_path=${source_file#${STANDALONE_DIR}/}
    
    # Determine target directory based on file path
    if [[ "$rel_path" == *"/api/"* ]]; then
        if grep -q "integration" "$source_file"; then
            echo "${INTEGRATION_DIR}/${rel_path}"
        else
            echo "${UNIT_DIR}/${rel_path}"
        fi
    elif [[ "$rel_path" == *"/e2e/"* ]]; then
        echo "${INTEGRATION_DIR}/${rel_path#e2e/}"
    else
        echo "${UNIT_DIR}/${rel_path}"
    fi
}

# Function to categorize a test file
categorize_test() {
    file=$1
    
    # Check if there's a corresponding unit test already
    dest_path=$(get_destination_path "$file")
    if [ -f "$dest_path" ]; then
        echo "duplicate"
        return
    fi
    
    # Count imports from main codebase vs. standalone code
    main_imports=$(grep -E "from app\." "$file" | grep -v "from app.tests" | wc -l)
    standalone_imports=$(grep -E "from app.tests.standalone" "$file" | wc -l)
    
    if [ $standalone_imports -gt 5 ]; then
        echo "needs_migration"
    elif [ $main_imports -gt 5 ]; then
        echo "ready_for_copy"
    else
        echo "needs_analysis"
    fi
}

# Function to categorize a test file for analysis
analyze_test() {
    file=$1
    filename=$(basename $file)
    module_path=${file#${STANDALONE_DIR}/}
    
    # Check if there's already a unit test for the same functionality
    unit_test_path=${UNIT_DIR}/${module_path}
    
    if [ -f "$unit_test_path" ]; then
        echo -e "${YELLOW}[DUPLICATE] ${file} has a corresponding unit test at ${unit_test_path}${NC}"
        echo "${file}" >> migration_analysis/duplicate_tests.txt
    else
        # Check for imports from the main codebase
        imports=$(grep -E "from app\." ${file} | grep -v "from app.tests" | wc -l)
        
        if [ $imports -gt 5 ]; then
            echo -e "${GREEN}[VALUABLE] ${file} has ${imports} imports from main codebase - good candidate for migration${NC}"
            echo "${file}" >> migration_analysis/valuable_tests.txt
        else
            standalone_imports=$(grep -E "from app.tests.standalone" ${file} | wc -l)
            if [ $standalone_imports -gt 3 ]; then
                echo -e "${RED}[PROBLEMATIC] ${file} heavily depends on other standalone code (${standalone_imports} imports)${NC}"
                echo "${file}" >> migration_analysis/problematic_tests.txt
            else
                echo -e "${BLUE}[CANDIDATE] ${file} needs review for migration${NC}"
                echo "${file}" >> migration_analysis/candidate_tests.txt
            fi
        fi
    fi
}

# Create template for migration
create_template() {
    source_file=$1
    dest_path=$(get_destination_path "$source_file")
    dest_dir=$(dirname "$dest_path")
    
    # Create target directory
    mkdir -p "$dest_dir"
    
    echo "Creating migration template: $dest_path"
    
    # Create header with migration info
    cat > "$dest_path" << EOF
"""
Migrated test from standalone test to proper unit test.
Original file: $source_file

This test uses the actual implementations from the main codebase.
Migration date: $(date)
"""

# Migrated imports from original file
# (Replace standalone imports with actual implementations)
$(grep -v "from app.tests.standalone" "$source_file" | grep -v "import app.tests.standalone")

# TODO: Update the test to use actual implementations instead of standalone duplicates

EOF
    
    echo "Migration template created at $dest_path"
    echo "Edit the template to update imports and test implementations."
}

# Reset analysis files
rm -f migration_analysis/duplicate_tests.txt
rm -f migration_analysis/valuable_tests.txt
rm -f migration_analysis/problematic_tests.txt
rm -f migration_analysis/candidate_tests.txt

touch migration_analysis/duplicate_tests.txt
touch migration_analysis/valuable_tests.txt
touch migration_analysis/problematic_tests.txt
touch migration_analysis/candidate_tests.txt

# Analyze all test files
echo -e "${BLUE}Analyzing standalone tests...${NC}"
for file in $(find ${STANDALONE_DIR} -name "test_*.py"); do
    analyze_test $file
done

# Generate counts
DUPLICATE_COUNT=$(wc -l < migration_analysis/duplicate_tests.txt 2>/dev/null || echo 0)
VALUABLE_COUNT=$(wc -l < migration_analysis/valuable_tests.txt 2>/dev/null || echo 0)
PROBLEMATIC_COUNT=$(wc -l < migration_analysis/problematic_tests.txt 2>/dev/null || echo 0)
CANDIDATE_COUNT=$(wc -l < migration_analysis/candidate_tests.txt 2>/dev/null || echo 0)

echo -e "\n${BLUE}======== ANALYSIS RESULTS ========${NC}"
echo -e "${GREEN}Valuable tests: ${VALUABLE_COUNT}${NC}"
echo -e "${RED}Problematic tests: ${PROBLEMATIC_COUNT}${NC}"
echo -e "${YELLOW}Duplicate tests: ${DUPLICATE_COUNT}${NC}"
echo -e "${BLUE}Candidate tests: ${CANDIDATE_COUNT}${NC}"

# Generate migration template for one of the valuable tests as an example
if [ $VALUABLE_COUNT -gt 0 ]; then
    EXAMPLE_TEST=$(head -n 1 migration_analysis/valuable_tests.txt)
    TEST_NAME=$(basename $EXAMPLE_TEST .py)
    TARGET_DIR="${UNIT_DIR}/$(dirname ${EXAMPLE_TEST#${STANDALONE_DIR}/})"
    MIGRATION_TEMPLATE="${TARGET_DIR}/${TEST_NAME}_migrated.py"
    
    mkdir -p "$TARGET_DIR"
    
    echo -e "\n${GREEN}Generating migration template for ${EXAMPLE_TEST}${NC}"
    echo "\"\"\"
Migrated from standalone test to proper unit test.
Original file: ${EXAMPLE_TEST}

This test uses the actual implementations from the main codebase.
Migration date: $(date)
\"\"\"

# Import the actual implementations being tested
$(grep -E "from app\." ${EXAMPLE_TEST} | grep -v "from app.tests")

# Test fixtures go here
# ...

# Migrated test classes go here
# ...

# Run with pytest -vx ${MIGRATION_TEMPLATE}
" > ${MIGRATION_TEMPLATE}

    echo -e "${GREEN}Migration template created at ${MIGRATION_TEMPLATE}${NC}"
    echo -e "${BLUE}Edit the template to include proper test cases using the actual implementation.${NC}"
fi

echo -e "\n${BLUE}========== MIGRATION GUIDE ==========${NC}"
echo -e "${GREEN}1. Prioritize migrating valuable tests first${NC}"
echo -e "${GREEN}2. Delete duplicate tests as they're already covered${NC}"
echo -e "${GREEN}3. Review problematic tests - they may need significant rework${NC}"
echo -e "${GREEN}4. Candidate tests should be evaluated individually${NC}"
echo -e "\n${YELLOW}Use 'scripts/migrate_biometric_tests.sh' for an example of a complete migration${NC}"

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

# If we get here, it's the main analysis mode
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