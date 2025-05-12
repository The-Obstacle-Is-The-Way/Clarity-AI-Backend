#!/bin/bash
# run_asyncio_migration.sh - Script to migrate and test asyncio changes

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}===== Asyncio Test Migration Helper =====${NC}"
echo

# Step 1: Run the migration script in dry-run mode
echo -e "${YELLOW}Step 1: Analyzing files for migration (dry run)...${NC}"
python scripts/migrate_to_modern_asyncio.py --dry-run
echo

# Step 2: Run the example test to verify the approach
echo -e "${YELLOW}Step 2: Running example tests to verify modern approach...${NC}"
python -m pytest app/tests/unit/examples/test_modern_asyncio.py -v
echo

# Step 3: Ask user if they want to proceed with migration
echo -e "${YELLOW}Do you want to proceed with the migration? (y/n)${NC}"
read -r answer
if [[ "$answer" != "y" && "$answer" != "Y" ]]; then
    echo -e "${RED}Migration aborted.${NC}"
    exit 0
fi

# Step 4: Run the migration script for real
echo -e "${YELLOW}Step 4: Migrating files to modern asyncio approach...${NC}"
python scripts/migrate_to_modern_asyncio.py
echo

# Step 5: Run specific test directories to verify
echo -e "${YELLOW}Step 5: Running tests to verify migration...${NC}"
echo -e "${YELLOW}Testing infrastructure layer...${NC}"
python -m pytest app/tests/unit/infrastructure/cache/ -v

echo
echo -e "${YELLOW}Testing core layer...${NC}"
python -m pytest app/tests/unit/core/ -v

echo
echo -e "${YELLOW}Testing presentation layer...${NC}"
python -m pytest app/tests/unit/presentation/api/dependencies/ -v

echo -e "${GREEN}Migration complete! Please review the changes and fix any remaining issues.${NC}"
echo -e "${YELLOW}You may want to run the full test suite to verify all tests are passing:${NC}"
echo -e "python -m pytest" 