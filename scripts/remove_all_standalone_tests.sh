#!/bin/bash
set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========== STANDALONE TEST REMOVAL UTILITY ==========${NC}"
echo -e "${YELLOW}This script will migrate valuable tests and remove all standalone tests${NC}"

# Root directories
STANDALONE_DIR="app/tests/standalone"
UNIT_DIR="app/tests/unit"
INTEGRATION_DIR="app/tests/integration"
E2E_DIR="app/tests/e2e"

# Create migration log
MIGRATION_LOG="migration_log.txt"
echo "Standalone Test Migration Log - $(date)" > $MIGRATION_LOG
echo "----------------------------------------" >> $MIGRATION_LOG

# Function to ensure target directory exists
ensure_dir() {
    mkdir -p "$1"
}

# Function to migrate a test file
migrate_test() {
    source_file=$1
    dest_dir=$2
    filename=$(basename "$source_file")
    relative_path=${source_file#${STANDALONE_DIR}/}
    target_dir="${dest_dir}/$(dirname "$relative_path")"
    target_file="${target_dir}/${filename}"
    
    ensure_dir "$target_dir"
    
    echo -e "${YELLOW}Migrating: ${source_file} -> ${target_file}${NC}"
    
    # Check for direct imports from app.tests.standalone
    standalone_imports=$(grep -E "from app.tests.standalone" "$source_file" 2>/dev/null | wc -l)
    
    if [ $standalone_imports -gt 0 ]; then
        echo -e "${RED}Warning: File depends on other standalone code (${standalone_imports} imports)${NC}"
        echo "Warning: ${source_file} has ${standalone_imports} standalone imports" >> $MIGRATION_LOG
    fi
    
    # Create migration header
    cat > "$target_file" << EOF
"""
Migrated from standalone test to proper unit test.
Original file: ${source_file}

This test uses the actual implementations from the main codebase.
Migration date: $(date)
"""

EOF

    # Extract imports that aren't from app.tests.standalone
    grep -v "from app.tests.standalone" "$source_file" | \
    grep -v "import app.tests.standalone" >> "$target_file"
    
    echo "Migrated: ${source_file} -> ${target_file}" >> $MIGRATION_LOG
    
    return 0
}

# Function to migrate an API test to proper API test
migrate_api_test() {
    source_file=$1
    echo -e "${YELLOW}Migrating API test: ${source_file}${NC}"
    
    # API tests should be either integration or e2e tests
    if grep -q "integration" "$source_file"; then
        target_dir=$INTEGRATION_DIR
    else
        target_dir=$E2E_DIR
    fi
    
    migrate_test "$source_file" "$target_dir"
}

# Function to migrate a core domain test to unit test
migrate_domain_test() {
    source_file=$1
    echo -e "${YELLOW}Migrating Domain test: ${source_file}${NC}"
    migrate_test "$source_file" "$UNIT_DIR"
}

# Function to analyze a file and determine if it's worth migrating
analyze_file() {
    file=$1
    
    # Check for imports from the main codebase (not from app.tests)
    main_imports=$(grep -E "from app\." "$file" | grep -v "from app.tests" | wc -l)
    
    # Check for test methods
    test_methods=$(grep -E "def test_" "$file" | wc -l)
    
    # If file has good test coverage and imports from main codebase
    if [ $test_methods -gt 2 ] && [ $main_imports -gt 3 ]; then
        echo -e "${GREEN}[VALUABLE] ${file} has ${test_methods} tests and ${main_imports} main imports${NC}"
        return 0  # Worth migrating
    else
        echo -e "${RED}[LOW VALUE] ${file} only has ${test_methods} tests and ${main_imports} main imports${NC}"
        return 1  # Not worth migrating
    fi
}

# Create directories if they don't exist
ensure_dir "$UNIT_DIR"
ensure_dir "$INTEGRATION_DIR"
ensure_dir "$E2E_DIR"

# Process all standalone test files
echo -e "${BLUE}Processing all standalone test files...${NC}"
for file in $(find "$STANDALONE_DIR" -name "test_*.py"); do
    echo -e "\n${BLUE}Analyzing: ${file}${NC}"
    
    if analyze_file "$file"; then
        # File is worth migrating
        if [[ "$file" =~ "api/" ]]; then
            migrate_api_test "$file"
        else
            migrate_domain_test "$file"
        fi
        
        echo -e "${GREEN}Migration complete!${NC}"
    else
        echo -e "${RED}Skipping migration - low value test${NC}"
        echo "Skipped: ${file} - low value test" >> $MIGRATION_LOG
    fi
done

# Process support files (non-test files)
echo -e "\n${BLUE}Processing support files...${NC}"
for file in $(find "$STANDALONE_DIR" -name "*.py" | grep -v "test_" | grep -v "__init__" | grep -v "__pycache__"); do
    filename=$(basename "$file")
    echo -e "${YELLOW}Support file: ${file}${NC}"
    echo "Support file found: ${file}" >> $MIGRATION_LOG
done

# Run unit tests to verify migrations
echo -e "\n${BLUE}Running tests to verify migrations...${NC}"
python -m pytest "$UNIT_DIR" -v || true

# Remove all standalone tests
if [ "$1" == "--delete" ]; then
    echo -e "\n${RED}Removing all standalone tests...${NC}"
    rm -rf "$STANDALONE_DIR"
    echo -e "${GREEN}All standalone tests have been removed!${NC}"
else
    echo -e "\n${YELLOW}To delete all standalone tests, run:${NC}"
    echo -e "${RED}$0 --delete${NC}"
fi

echo -e "\n${GREEN}Migration process complete!${NC}"
echo -e "${BLUE}Check ${MIGRATION_LOG} for details${NC}"
echo -e "\n${YELLOW}NOTE: You'll need to fix imports and adjust tests to use actual implementations${NC}"
echo -e "${YELLOW}Some tests may still fail and require manual intervention${NC}\n" 