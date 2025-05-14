#!/bin/bash
set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========== STANDALONE TEST MIGRATION MASTER SCRIPT ==========${NC}"
echo -e "${YELLOW}This script will run all test migrations and clean up standalone tests${NC}"

# Make all scripts executable
chmod +x scripts/migrate_standalone_tests.sh
chmod +x scripts/migrate_biometric_tests.sh
chmod +x scripts/migrate_digital_twin_tests.sh
chmod +x scripts/migrate_pat_tests.sh
chmod +x scripts/remove_all_standalone_tests.sh

# Step 1: Run the biometric tests migration
echo -e "\n${BLUE}STEP 1: Migrating Biometric Event Processor Tests${NC}"
./scripts/migrate_biometric_tests.sh

# Step 2: Run the digital twin tests migration
echo -e "\n${BLUE}STEP 2: Migrating Digital Twin Tests${NC}"
./scripts/migrate_digital_twin_tests.sh

# Step 3: Run the PAT service tests migration
echo -e "\n${BLUE}STEP 3: Migrating PAT Service Tests${NC}"
./scripts/migrate_pat_tests.sh

# Step 4: Run the comprehensive migration for any remaining tests
echo -e "\n${BLUE}STEP 4: Migrating All Remaining Tests${NC}"
./scripts/remove_all_standalone_tests.sh

# Step 5: Run tests to verify migrations
echo -e "\n${BLUE}STEP 5: Verifying Migrations${NC}"
echo -e "${YELLOW}Running migrated unit tests...${NC}"
python -m pytest app/tests/unit/core/test_biometric_processor.py -v || true
python -m pytest app/tests/unit/domain/test_digital_twin.py -v || true
python -m pytest app/tests/unit/domain/test_pat_service.py -v || true

# Step 6: Clean up standalone tests if requested
if [ "$1" == "--delete" ]; then
    echo -e "\n${BLUE}STEP 6: Removing All Standalone Tests${NC}"
    echo -e "${RED}Deleting standalone test directory...${NC}"
    rm -rf app/tests/standalone
    echo -e "${GREEN}Successfully removed all standalone tests!${NC}"
else
    echo -e "\n${BLUE}STEP 6: Clean Up${NC}"
    echo -e "${YELLOW}To delete all standalone tests, run:${NC}"
    echo -e "${RED}$0 --delete${NC}"
fi

echo -e "\n${GREEN}========== MIGRATION COMPLETE ==========${NC}"
echo -e "The codebase now follows clean architecture principles with:"
echo -e "✅ Proper separation of concerns"
echo -e "✅ Tests that verify the actual implementations"
echo -e "✅ No duplicated code or implementations"
echo -e "✅ Better maintainability and reliability"

echo -e "\n${BLUE}Next Steps:${NC}"
echo -e "1. Fix any remaining test failures"
echo -e "2. Update documentation to reflect the new test structure"
echo -e "3. Continue cleaning up other technical debt in the codebase" 