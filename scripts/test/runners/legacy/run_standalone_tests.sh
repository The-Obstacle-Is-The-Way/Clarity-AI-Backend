#!/bin/bash
# run_standalone_tests.sh
#
# This script runs only standalone tests with no external dependencies
# Useful for quick feedback during development and CI/CD pipelines

set -e

# Colors for terminal output
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Base directory
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORTS_DIR="${BASE_DIR}/test-results"
COVERAGE_DIR="${BASE_DIR}/coverage_html"

# Create reports directory
mkdir -p "${REPORTS_DIR}"

# Default options
VERBOSE=""
FAILFAST=""
GENERATE_COVERAGE=true

print_usage() {
  echo "Usage: $0 [options]"
  echo ""
  echo "Options:"
  echo "  --help, -h              Show this help message"
  echo "  --verbose, -v           Enable verbose test output"
  echo "  --failfast, -f          Stop on first test failure"
  echo "  --no-coverage           Skip coverage reporting"
  echo "  --test-path=PATH        Run tests in specific path (default: app/tests/standalone/)"
  echo ""
  echo "Example:"
  echo "  $0 -v --test-path=app/tests/standalone/test_provider.py"
}

# Parse command line arguments
TEST_PATH="app/tests/standalone/"

while [[ $# -gt 0 ]]; do
  case $1 in
    --help|-h)
      print_usage
      exit 0
      ;;
    --verbose|-v)
      VERBOSE="-v"
      shift
      ;;
    --failfast|-f)
      FAILFAST="--exitfirst"
      shift
      ;;
    --no-coverage)
      GENERATE_COVERAGE=false
      shift
      ;;
    --test-path=*)
      TEST_PATH="${1#*=}"
      shift
      ;;
    *)
      echo -e "${RED}Error: Unknown option: $1${NC}"
      print_usage
      exit 1
      ;;
  esac
done

# Function to print section header
print_header() {
  echo -e "\n${BLUE}============================================================${NC}"
  echo -e "${BLUE}$1${NC}"
  echo -e "${BLUE}============================================================${NC}"
}

# Run the standalone tests
run_standalone_tests() {
  print_header "Running Standalone Tests: ${TEST_PATH}"
  
  # Build the pytest command
  local pytest_cmd="python -m pytest"
  
  # Add marker for standalone tests
  pytest_cmd="$pytest_cmd -m standalone"
  
  # Add coverage if enabled
  if [[ "$GENERATE_COVERAGE" == "true" ]]; then
    pytest_cmd="$pytest_cmd --cov=app --cov-report=term --cov-report=html:${COVERAGE_DIR}/standalone"
  fi
  
  # Add verbose mode if requested
  if [[ -n "$VERBOSE" ]]; then
    pytest_cmd="$pytest_cmd $VERBOSE"
  fi
  
  # Add failfast if requested
  if [[ -n "$FAILFAST" ]]; then
    pytest_cmd="$pytest_cmd $FAILFAST"
  fi
  
  # Add the test path
  pytest_cmd="$pytest_cmd ${TEST_PATH}"
  
  # Add JUnit XML output for CI integration
  pytest_cmd="$pytest_cmd --junitxml=${REPORTS_DIR}/standalone-results.xml"
  
  # Show the command that will be executed
  echo -e "${YELLOW}Command: ${pytest_cmd}${NC}\n"
  
  # Run the tests
  if eval "$pytest_cmd"; then
    echo -e "\n${GREEN}✓ All standalone tests passed!${NC}"
    return 0
  else
    echo -e "\n${RED}✗ Standalone tests failed!${NC}"
    return 1
  fi
}

# Run from the correct directory
(
  cd "$BASE_DIR"
  run_standalone_tests
  exit $?
)

# Exit with the exit code from the subshell
exit $?