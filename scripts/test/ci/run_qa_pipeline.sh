#!/bin/bash
# run_qa_pipeline.sh
#
# This script runs a complete quality assurance pipeline:
# 1. Lint code with Ruff
# 2. Run standalone tests (no dependencies)
# 3. Run VENV tests (Python package dependencies only)
# 4. Run DB tests (database and other external dependencies)
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
REPORTS_DIR="${BASE_DIR}/test-results"
COVERAGE_DIR="${BASE_DIR}/coverage_html"

# Create reports directory
mkdir -p "${REPORTS_DIR}"

# Parse command line arguments
SKIP_LINT=false
SKIP_STANDALONE=false
SKIP_VENV=false
SKIP_DB=false
VERBOSE=""
CI_MODE=false
FAILFAST=""
FIX_ISSUES=false

print_usage() {
  echo "Usage: $0 [options]"
  echo ""
  echo "Options:"
  echo "  --help, -h                Show this help message"
  echo "  --skip-lint               Skip code linting"
  echo "  --skip-standalone         Skip standalone tests"
  echo "  --skip-venv               Skip venv-only tests"
  echo "  --skip-db                 Skip database tests"
  echo "  --fix-issues, -f          Fix linting issues and attempt to fix failing tests"
  echo "  --verbose, -v             Enable verbose output"
  echo "  --ci-mode, -c             Run in CI mode (generate detailed reports)"
  echo "  --failfast                Stop on first test failure"
  echo ""
  echo "Example:"
  echo "  $0 --skip-db -v           Run only linting, standalone and venv tests with verbose output"
}

while [[ $# -gt 0 ]]; do
  case $1 in
    --help|-h)
      print_usage
      exit 0
      ;;
    --skip-lint)
      SKIP_LINT=true
      shift
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
    --verbose|-v)
      VERBOSE="-v"
      shift
      ;;
    --ci-mode|-c)
      CI_MODE=true
      shift
      ;;
    --failfast)
      FAILFAST="--exitfirst"
      shift
      ;;
    --fix-issues|-f)
      FIX_ISSUES=true
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

# Track results
LINT_RESULT=0
STANDALONE_RESULT=0
VENV_RESULT=0
DB_RESULT=0

# Run linting if not skipped
if [[ "$SKIP_LINT" != "true" ]]; then
  print_header "Running Code Linting"
  
  lint_cmd="python -m scripts.lint_tests"
  if [[ "$FIX_ISSUES" == "true" ]]; then
    lint_cmd="$lint_cmd --fix"
  fi
  
  if [[ "$VERBOSE" == "-v" ]]; then
    lint_cmd="$lint_cmd --verbose"
  fi
  
  if [[ "$CI_MODE" == "true" ]]; then
    lint_cmd="$lint_cmd --ci"
  fi
  
  echo -e "${YELLOW}Command: ${lint_cmd}${NC}\n"
  
  if (cd "$BASE_DIR" && eval "$lint_cmd"); then
    echo -e "\n${GREEN}✓ Linting passed!${NC}"
    LINT_RESULT=0
  else
    echo -e "\n${RED}✗ Linting failed!${NC}"
    LINT_RESULT=1
    
    if [[ "$FAILFAST" == "--exitfirst" && "$LINT_RESULT" -ne 0 ]]; then
      exit $LINT_RESULT
    fi
  fi
fi

# Run the test pipeline script with appropriate flags
if [[ "$SKIP_STANDALONE" == "true" ]]; then
  test_args="--skip-standalone"
else
  test_args=""
fi

if [[ "$SKIP_VENV" == "true" ]]; then
  test_args="$test_args --skip-venv"
fi

if [[ "$SKIP_DB" == "true" ]]; then
  test_args="$test_args --skip-db"
fi

if [[ "$VERBOSE" == "-v" ]]; then
  test_args="$test_args --verbose"
fi

if [[ "$CI_MODE" == "true" ]]; then
  test_args="$test_args --ci-mode"
fi

if [[ "$FAILFAST" == "--exitfirst" ]]; then
  test_args="$test_args --failfast"
fi

# Run the main test pipeline if any test level is enabled
if [[ "$SKIP_STANDALONE" != "true" || "$SKIP_VENV" != "true" || "$SKIP_DB" != "true" ]]; then
  print_header "Running Test Pipeline"
  
  test_cmd="${BASE_DIR}/scripts/run_test_pipeline.sh $test_args"
  echo -e "${YELLOW}Command: ${test_cmd}${NC}\n"
  
  if eval "$test_cmd"; then
    TEST_RESULT=0
  else
    TEST_RESULT=$?
    if [[ "$TEST_RESULT" -eq 0 ]]; then
      TEST_RESULT=1  # Ensure non-zero if failed
    fi
  fi
else
  TEST_RESULT=0
fi

# Final summary
print_header "Quality Assurance Pipeline Results"

if [[ "$SKIP_LINT" != "true" ]]; then
  if [[ "$LINT_RESULT" -eq 0 ]]; then
    echo -e "${GREEN}✓ Code linting: PASSED${NC}"
  else
    echo -e "${RED}✗ Code linting: FAILED${NC}"
  fi
else
  echo -e "${YELLOW}! Code linting: SKIPPED${NC}"
fi

OVERALL_RESULT=$((LINT_RESULT + TEST_RESULT))

echo ""
if [[ "$OVERALL_RESULT" -eq 0 ]]; then
  echo -e "${GREEN}✓ Overall QA pipeline: PASSED${NC}"
else
  echo -e "${RED}✗ Overall QA pipeline: FAILED${NC}"
fi

exit $OVERALL_RESULT