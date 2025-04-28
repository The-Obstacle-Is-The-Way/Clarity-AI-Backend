#!/bin/bash
# run_test_pipeline.sh
#
# This script runs a complete test pipeline, executing tests in optimal dependency order:
# 1. Standalone tests (no dependencies) for fastest failure detection
# 2. VENV tests (Python package dependencies only)
# 3. DB tests (database and other external dependencies)
#
# The script provides comprehensive reporting and can be used in CI/CD pipelines.

set -e

# Colors for terminal output
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Base directory
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${BASE_DIR}/.." && pwd)"
REPORTS_DIR="${BASE_DIR}/test-results"
COVERAGE_DIR="${BASE_DIR}/coverage_html"

# Create reports directory
mkdir -p "${REPORTS_DIR}"

# Parse command line arguments
SKIP_STANDALONE=false
SKIP_VENV=false
SKIP_DB=false
UPDATE_MARKERS=false
VERBOSE=""
CI_MODE=false
FAILFAST=""
MARKERS_ONLY=false
NO_COVERAGE=false

print_usage() {
  echo "Usage: $0 [options]"
  echo ""
  echo "Options:"
  echo "  --help, -h                Show this help message"
  echo "  --skip-standalone         Skip standalone tests"
  echo "  --skip-venv               Skip venv-only tests"
  echo "  --skip-db                 Skip database tests"
  echo "  --update-markers, -u      Update test markers based on automatic detection"
  echo "  --verbose, -v             Enable verbose test output"
  echo "  --ci-mode, -c             Run in CI mode (generate detailed reports)"
  echo "  --failfast, -f            Stop on first test failure"
  echo "  --markers-only, -m        Only use markers, not directory structure"
  echo "  --no-coverage             Skip coverage reporting"
  echo ""
  echo "Example:"
  echo "  $0 --skip-db -v           Run only standalone and venv tests with verbose output"
}

while [[ $# -gt 0 ]]; do
  case $1 in
    --help|-h)
      print_usage
      exit 0
      ;;
    --skip-standalone)
      SKIP_STANDALONE=true
      shift
      ;;
    --skip-venv)
      SKIP_VENV=true
      shift
      ;;
    --skip-db)
      SKIP_DB=true
      shift
      ;;
    --update-markers|-u)
      UPDATE_MARKERS=true
      shift
      ;;
    --verbose|-v)
      VERBOSE="-v"
      shift
      ;;
    --ci-mode|-c)
      CI_MODE=true
      shift
      ;;
    --failfast|-f)
      FAILFAST="--exitfirst"
      shift
      ;;
    --markers-only|-m)
      MARKERS_ONLY=true
      shift
      ;;
    --no-coverage)
      NO_COVERAGE=true
      shift
      ;;
    *)
      echo -e "${RED}Error: Unknown option: $1${NC}"
      print_usage
      exit 1
      ;;
  esac
done

# Function to print a section header
print_header() {
  echo -e "\n${BLUE}============================================================${NC}"
  echo -e "${BLUE}$1${NC}"
  echo -e "${BLUE}============================================================${NC}"
}

# Function to run tests at a specific dependency level
run_test_level() {
  local level_name=$1
  local marker=$2
  local report_prefix=$3
  local additional_args=$4
  
  print_header "Running ${level_name} Tests"
  
  # Skip if requested
  if [[ "$level_name" == "Standalone" && "$SKIP_STANDALONE" == "true" ]]; then
    echo -e "${YELLOW}Skipping ${level_name} tests as requested${NC}"
    return 0
  fi
  if [[ "$level_name" == "VENV-only" && "$SKIP_VENV" == "true" ]]; then
    echo -e "${YELLOW}Skipping ${level_name} tests as requested${NC}"
    return 0
  fi
  if [[ "$level_name" == "DB-required" && "$SKIP_DB" == "true" ]]; then
    echo -e "${YELLOW}Skipping ${level_name} tests as requested${NC}"
    return 0
  fi
  
  # Build the pytest command
  local pytest_cmd="python -m pytest"
  
  # Add marker filtering
  if [[ -n "$marker" ]]; then
    pytest_cmd="$pytest_cmd -m $marker"
  fi
  
  # Add coverage if not disabled
  if [[ "$NO_COVERAGE" != "true" ]]; then
    pytest_cmd="$pytest_cmd --cov=app --cov-report=term --cov-report=html:${COVERAGE_DIR}/${marker}"
  fi
  
  # Add verbose mode if requested
  if [[ -n "$VERBOSE" ]]; then
    pytest_cmd="$pytest_cmd $VERBOSE"
  fi
  
  # Add failfast if requested
  if [[ -n "$FAILFAST" ]]; then
    pytest_cmd="$pytest_cmd $FAILFAST"
  fi
  
  # Add CI mode reports if requested
  if [[ "$CI_MODE" == "true" ]]; then
    pytest_cmd="$pytest_cmd --junitxml=${REPORTS_DIR}/${report_prefix}-results.xml"
  fi
  
  # Add any additional args
  if [[ -n "$additional_args" ]]; then
    pytest_cmd="$pytest_cmd $additional_args"
  fi
  
  # Determine test paths based on strategy
  if [[ "$MARKERS_ONLY" == "true" ]]; then
    pytest_cmd="$pytest_cmd app/tests/"
  else
    # Use directory structure as a fallback along with markers
    case "$level_name" in
      "Standalone")
        pytest_cmd="$pytest_cmd app/tests/standalone/"
        ;;
      "VENV-only")
        pytest_cmd="$pytest_cmd app/tests/venv_only/ app/tests/unit/"
        ;;
      "DB-required")
        pytest_cmd="$pytest_cmd app/tests/integration/ app/tests/e2e/ app/tests/db_required/"
        ;;
    esac
  fi
  
  # Show the command that will be executed
  echo -e "${YELLOW}Command: ${pytest_cmd}${NC}\n"
  
  # Run the tests
  if eval "$pytest_cmd"; then
    echo -e "\n${GREEN}✓ All ${level_name} tests passed!${NC}"
    return 0
  else
    echo -e "\n${RED}✗ ${level_name} tests failed!${NC}"
    return 1
  fi
}

# Update markers if requested
if [[ "$UPDATE_MARKERS" == "true" ]]; then
  print_header "Updating Test Markers"
  
  if [[ -f "${BASE_DIR}/app/scripts/test_categorizer.py" ]]; then
    python "${BASE_DIR}/app/scripts/test_categorizer.py" --base-dir "$BASE_DIR" --tests-dir "app/tests" --update
  else
    echo -e "${RED}Error: Test categorizer script not found at ${BASE_DIR}/app/scripts/test_categorizer.py${NC}"
    exit 1
  fi
fi

# Track test results
STANDALONE_RESULT=0
VENV_RESULT=0
DB_RESULT=0

# Run tests in dependency order
(
  cd "$BASE_DIR"
  
  # Standalone tests (fastest, no dependencies)
  run_test_level "Standalone" "standalone" "standalone" 
  STANDALONE_RESULT=$?
  
  # If standalone tests fail and failfast is enabled, exit
  if [[ "$STANDALONE_RESULT" -ne 0 && -n "$FAILFAST" ]]; then
    exit $STANDALONE_RESULT
  fi
  
  # VENV-only tests (require Python packages but no external services)
  run_test_level "VENV-only" "venv_only" "venv" 
  VENV_RESULT=$?
  
  # If VENV tests fail and failfast is enabled, exit
  if [[ "$VENV_RESULT" -ne 0 && -n "$FAILFAST" ]]; then
    exit $((STANDALONE_RESULT + VENV_RESULT))
  fi
  
  # DB-required tests (require database or other external services)
  run_test_level "DB-required" "db_required" "db" 
  DB_RESULT=$?
  
  # Calculate overall result
  OVERALL_RESULT=$((STANDALONE_RESULT + VENV_RESULT + DB_RESULT))
  
  # Generate combined coverage report if running all tests
  if [[ "$NO_COVERAGE" != "true" && "$SKIP_STANDALONE" != "true" && "$SKIP_VENV" != "true" && "$SKIP_DB" != "true" ]]; then
    print_header "Generating Combined Coverage Report"
    python -m coverage combine
    python -m coverage html -d "${COVERAGE_DIR}/combined"
    python -m coverage report
  fi
  
  # Final summary
  print_header "Test Pipeline Results"
  if [[ "$SKIP_STANDALONE" != "true" ]]; then
    if [[ "$STANDALONE_RESULT" -eq 0 ]]; then
      echo -e "${GREEN}✓ Standalone tests: PASSED${NC}"
    else
      echo -e "${RED}✗ Standalone tests: FAILED${NC}"
    fi
  else
    echo -e "${YELLOW}! Standalone tests: SKIPPED${NC}"
  fi
  
  if [[ "$SKIP_VENV" != "true" ]]; then
    if [[ "$VENV_RESULT" -eq 0 ]]; then
      echo -e "${GREEN}✓ VENV-only tests: PASSED${NC}"
    else
      echo -e "${RED}✗ VENV-only tests: FAILED${NC}"
    fi
  else
    echo -e "${YELLOW}! VENV-only tests: SKIPPED${NC}"
  fi
  
  if [[ "$SKIP_DB" != "true" ]]; then
    if [[ "$DB_RESULT" -eq 0 ]]; then
      echo -e "${GREEN}✓ DB-required tests: PASSED${NC}"
    else
      echo -e "${RED}✗ DB-required tests: FAILED${NC}"
    fi
  else
    echo -e "${YELLOW}! DB-required tests: SKIPPED${NC}"
  fi
  
  echo ""
  if [[ "$OVERALL_RESULT" -eq 0 ]]; then
    echo -e "${GREEN}✓ Overall test pipeline: PASSED${NC}"
  else
    echo -e "${RED}✗ Overall test pipeline: FAILED${NC}"
  fi
  
  exit $OVERALL_RESULT
)

# Exit with the exit code from the subshell
exit $?