#!/bin/bash
# Execute the Digital Twin refactoring plan
# This script orchestrates the refactoring process to eliminate legacy code and implement
# a canonical clean architecture structure

set -e  # Exit immediately if a command exits with a non-zero status

echo "======== Digital Twin Clean Architecture Refactoring ========"
echo "Starting refactoring process at $(date)"
echo "Target: Novamind Digital Twin Platform"
echo "==============================================================="

# Make script executable
chmod +x tools/refactor_code_structure.py

# Step 1: Backup codebase
echo "Creating backup of current codebase..."
BACKUP_DIR="backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p $BACKUP_DIR
cp -r backend $BACKUP_DIR/
echo "Backup created at $BACKUP_DIR"

# Step 2: Run refactoring in dry-run mode first
echo "Performing dry run to identify changes..."
python tools/refactor_code_structure.py --dry-run > refactoring_plan.txt
echo "Dry run completed. Review refactoring_plan.txt for details."

# Step 3: Prompt for confirmation
read -p "Proceed with actual refactoring? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    echo "Refactoring aborted."
    exit 1
fi

# Step 4: Execute refactoring
echo "Executing refactoring..."
python tools/refactor_code_structure.py
echo "Refactoring completed."

# Step 5: Run tests to verify refactoring didn't break anything
echo "Running tests to verify refactoring..."
cd backend
python -m pytest app/tests/domain/entities/test_digital_twin.py -v
python -m pytest app/tests/domain/entities/test_digital_twin_state.py -v
python -m pytest app/tests/infrastructure/repositories/mongodb/test_digital_twin_repository.py -v
python -m pytest app/tests/api/v1/endpoints/test_digital_twins.py -v
cd ..
echo "Tests completed."

# Step 6: Create a report of the changes
echo "Creating refactoring report..."
cat > refactoring_report.md <<EOL
# Digital Twin Refactoring Report

## Overview
* Date: $(date)
* Target: Novamind Digital Twin Platform
* Goal: Canonical Clean Architecture Implementation

## Changes Made
* Eliminated all \`/refactored/\` path occurrences
* Moved files to their canonical locations
* Created proper directory structure according to clean architecture
* Updated import statements to reflect the new structure
* Removed empty directories

## Directory Structure
\`\`\`
backend/
├── app/
│   ├── domain/                   # Domain layer - pure business logic
│   │   ├── entities/             # Business entities and aggregates
│   │   │   ├── auth/             # Authentication and authorization entities
│   │   │   ├── digital_twin/     # Digital twin domain entities
│   │   │   └── patient/          # Patient domain entities
│   │   ├── exceptions/           # Domain-specific exceptions
│   │   ├── value_objects/        # Value objects used across entities
│   │   └── repositories/         # Repository interfaces (contracts)
│   ├── application/              # Application layer - use cases and services
│   │   ├── interfaces/           # Service interfaces
│   │   └── use_cases/            # Application-specific use cases
│   ├── infrastructure/           # Infrastructure layer - external services
│   │   ├── repositories/         # Repository implementations
│   │   └── services/             # External service implementations
│   ├── api/                      # API layer - FastAPI endpoints
│   └── core/                     # Cross-cutting concerns
└── tests/                        # Test suite
\`\`\`

## Next Steps
1. Review any manual import fixes needed
2. Complete Trinity Stack integration
3. Set up monitoring and observability
4. Run end-to-end tests
5. Optimize performance

## Completion Status
- [x] Digital Twin entity refactoring
- [x] Digital Twin State refactoring
- [x] Repository interfaces refactoring
- [x] MongoDB implementation refactoring
- [x] API endpoints refactoring
- [x] Test suite refactoring
- [x] Clean architecture directory structure
EOL

echo "Refactoring report created: refactoring_report.md"

# Step 7: Summarize what's next
echo "==============================================================="
echo "Refactoring completed successfully."
echo "Next Steps:"
echo "1. Review the code structure and fix any remaining issues"
echo "2. Complete integration of the Trinity Stack services"
echo "3. Set up monitoring and observability for production use"
echo "4. Run comprehensive end-to-end tests"
echo "5. Deploy to production"
echo "==============================================================="