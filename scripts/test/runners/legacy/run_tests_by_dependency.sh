#!/bin/bash
# run_tests_by_dependency.sh
#
# This script runs tests based on their dependency level:
# - Level 1: Standalone tests (no external dependencies)
# - Level 2: VENV-only tests (require Python packages but no external services)
# - Level 3: DB-required tests (require database or other external services)
#
# Usage:
#   ./scripts/run_tests_by_dependency.sh [options]
#
# Options:
#   --help, -h              Show this help message
#   --level, -l LEVEL       Run tests at specific level (1, 2, 3, or all)
#   --update-markers, -u    Update test files with dependency markers
#   --ci-mode, -c           Run in CI mode (generate reports)
#   --verbose, -v           Enable verbose output
#   --failfast, -f          Stop on first test failure
#   --skip-categorization   Skip the categorization step (faster if markers exist)

set -e

# Colors for terminal output
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Initialize variables
LEVEL="all"
UPDATE_MARKERS=false
CI_MODE=false
VERBOSE=""
FAIL_FAST=""
SKIP_CATEGORIZATION=false

# Directory paths
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TESTS_DIR="${BASE_DIR}/app/tests"
CATEGORIZER="${BASE_DIR}/app/scripts/test_categorizer.py"
REPORTS_DIR="${BASE_DIR}/test-results"

# Process command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --help|-h)
      echo "Usage: ./scripts/run_tests_by_dependency.sh [options]"
      echo ""
      echo "Options:"
      echo "  --help, -h              Show this help message"
      echo "  --level, -l LEVEL       Run tests at specific level (1, 2, 3, or all)"
      echo "  --update-markers, -u    Update test files with dependency markers"
      echo "  --ci-mode, -c           Run in CI mode (generate reports)"
      echo "  --verbose, -v           Enable verbose output"
      echo "  --failfast, -f          Stop on first test failure"
      echo "  --skip-categorization   Skip the categorization step (faster if markers exist)"
      exit 0
      ;;
    --level|-l)
      LEVEL="$2"
      shift 2
      ;;
    --update-markers|-u)
      UPDATE_MARKERS=true
      shift
      ;;
    --ci-mode|-c)
      CI_MODE=true
      shift
      ;;
    --verbose|-v)
      VERBOSE="-v"
      shift
      ;;
    --failfast|-f)
      FAIL_FAST="--exitfirst"
      shift
      ;;
    --skip-categorization)
      SKIP_CATEGORIZATION=true
      shift
      ;;
    *)
      echo -e "${RED}Error: Unknown option: $1${NC}"
      exit 1
      ;;
  esac
done

# Validate level
if [[ ! "$LEVEL" =~ ^(1|2|3|all)$ ]]; then
  echo -e "${RED}Error: Invalid level. Must be 1, 2, 3, or all.${NC}"
  exit 1
fi

# Check if categorizer script exists
if [ ! -f "$CATEGORIZER" ]; then
  echo -e "${RED}Error: Categorizer script not found at $CATEGORIZER${NC}"
  exit 1
fi

# Create reports directory if in CI mode
if [ "$CI_MODE" = true ]; then
  mkdir -p "$REPORTS_DIR"
fi

# Function to run tests at a specific level
run_tests_at_level() {
  local level_num=$1
  local marker=$2
  local level_name=$3
  
  echo -e "\n${BLUE}=====================================================${NC}"
  echo -e "${BLUE}Running ${level_name} tests (Level ${level_num})${NC}"
  echo -e "${BLUE}=====================================================${NC}"
  
  # Set up test command
  local test_cmd="python -m pytest -m $marker $VERBOSE $FAIL_FAST"
  
  # Add JUnit report output if in CI mode
  if [ "$CI_MODE" = true ]; then
    test_cmd="$test_cmd --junitxml=${REPORTS_DIR}/${marker}-results.xml"
  fi
  
  # Run the tests
  echo -e "${YELLOW}Command: $test_cmd ${TESTS_DIR}${NC}\n"
  
  # Run the test command
  if $test_cmd "${TESTS_DIR}"; then
    echo -e "\n${GREEN}✓ All ${level_name} tests passed!${NC}"
    return 0
  else
    echo -e "\n${RED}✗ ${level_name} tests failed!${NC}"
    return 1
  fi
}

# Function to report overall status
report_status() {
  local status=$1
  if [ $status -eq 0 ]; then
    echo -e "\n${GREEN}✓ All requested tests passed!${NC}"
  else
    echo -e "\n${RED}✗ Some tests failed. Please check the output above.${NC}"
  fi
}

# Categorize tests if needed
if [ "$SKIP_CATEGORIZATION" = false ]; then
  echo -e "${BLUE}Categorizing tests...${NC}"
  
  # Run categorizer with update flag if requested
  if [ "$UPDATE_MARKERS" = true ]; then
    python "$CATEGORIZER" --base-dir "$BASE_DIR" --tests-dir "app/tests" --update
  else
    python "$CATEGORIZER" --base-dir "$BASE_DIR" --tests-dir "app/tests"
  fi
fi

# Track overall test status
OVERALL_STATUS=0

# Run tests based on requested level
case $LEVEL in
  1|all)
    run_tests_at_level 1 "standalone" "Standalone"
    LEVEL_1_STATUS=$?
    OVERALL_STATUS=$((OVERALL_STATUS + LEVEL_1_STATUS))
    
    # Break if level 1 failed and failfast is enabled
    if [ "$LEVEL" = "1" ]; then
      report_status $LEVEL_1_STATUS
      exit $LEVEL_1_STATUS
    fi
    
    # If failfast is enabled and level 1 failed, exit
    if [ -n "$FAIL_FAST" ] && [ $LEVEL_1_STATUS -ne 0 ]; then
      report_status $LEVEL_1_STATUS
      exit $LEVEL_1_STATUS
    fi
    ;;
esac

case $LEVEL in
  2|all)
    run_tests_at_level 2 "venv_only" "VENV-only"
    LEVEL_2_STATUS=$?
    OVERALL_STATUS=$((OVERALL_STATUS + LEVEL_2_STATUS))
    
    # Break if level 2 failed and failfast is enabled
    if [ "$LEVEL" = "2" ]; then
      report_status $LEVEL_2_STATUS
      exit $LEVEL_2_STATUS
    fi
    
    # If failfast is enabled and level 2 failed, exit
    if [ -n "$FAIL_FAST" ] && [ $LEVEL_2_STATUS -ne 0 ]; then
      report_status $OVERALL_STATUS
      exit $OVERALL_STATUS
    fi
    ;;
esac

case $LEVEL in
  3|all)
    run_tests_at_level 3 "db_required" "DB-required"
    LEVEL_3_STATUS=$?
    OVERALL_STATUS=$((OVERALL_STATUS + LEVEL_3_STATUS))
    
    if [ "$LEVEL" = "3" ]; then
      report_status $LEVEL_3_STATUS
      exit $LEVEL_3_STATUS
    fi
    ;;
esac

# Report overall status
report_status $OVERALL_STATUS
exit $OVERALL_STATUS