#!/bin/bash
# Run all tests in the correct order, fixing issues as needed

set -e  # Exit on any error

# ANSI color codes
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BOLD='\033[1m'
RESET='\033[0m'

# Display header
echo -e "${BOLD}${BLUE}===============================================${RESET}"
echo -e "${BOLD}${BLUE}      Novamind Backend Complete Test Suite    ${RESET}"
echo -e "${BOLD}${BLUE}===============================================${RESET}"
echo

# Move to the base directory
cd "$(dirname "$0")/.."
BASE_DIR="$(pwd)"

# Function to display section headers
section() {
  echo -e "\n${BOLD}${YELLOW}$1${RESET}"
  echo -e "${BOLD}${YELLOW}$(printf '=%.0s' $(seq 1 ${#1}))${RESET}\n"
}

# Function to run a command and check its result
run_command() {
  echo -e "${BOLD}Running:${RESET} $1"
  start_time=$(date +%s)
  
  eval "$1"
  result=$?
  
  end_time=$(date +%s)
  duration=$((end_time - start_time))
  
  if [ $result -eq 0 ]; then
    echo -e "${GREEN}Success!${RESET} (${duration}s)"
    return 0
  else
    echo -e "${RED}Failed!${RESET} (${duration}s)"
    return 1
  fi
}

# Function to run tests with a specific type
run_tests() {
  local test_type=$1
  local should_continue=$2
  
  section "Running $test_type Tests"
  
  if ! run_command "python scripts/run_tests.py --$test_type"; then
    echo -e "\n${RED}${BOLD}$test_type tests failed!${RESET}"
    if [ "$should_continue" = "false" ]; then
      echo -e "${YELLOW}Stopping the test suite as requested.${RESET}"
      exit 1
    fi
    echo -e "${YELLOW}Continuing with next test level as requested.${RESET}"
  fi
}

# Step 1: Apply our test fixes
section "Applying Test Fixes"

# Create the required test directories if they don't exist
mkdir -p app/tests/standalone app/tests/venv app/tests/integration

# Step 2: Generate a report of test classifications
section "Classifying Tests"
run_command "python scripts/classify_tests.py --report"

# Step 3: Run standalone tests
run_tests "standalone" true

# Step 4: Run VENV tests (if requested and if standalone tests pass)
if [ "$1" = "--with-venv" ] || [ "$1" = "--all" ]; then
  run_tests "venv" true
fi

# Step 5: Run integration tests (if requested and if previous tests pass)
if [ "$1" = "--with-integration" ] || [ "$1" = "--all" ]; then
  run_tests "integration" true
fi

section "Test Suite Completed"
echo -e "${GREEN}${BOLD}All requested tests have been run.${RESET}"
echo 
echo "Use the following arguments to control test execution:"
echo "  --with-venv        Run standalone and VENV tests"
echo "  --with-integration Run standalone and integration tests"
echo "  --all              Run all tests (standalone, VENV, and integration)"
echo "  --coverage         Add coverage reporting (can be combined with other flags)"

exit 0