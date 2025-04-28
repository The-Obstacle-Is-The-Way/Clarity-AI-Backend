#!/bin/bash
# Novamind Digital Twin Test Suite Runner
#
# This script runs the Novamind Digital Twin test suite in dependency order:
# 1. Standalone tests (no dependencies)
# 2. VENV-only tests (require Python packages but no external services)
# 3. DB-required tests (require database connections)
#
# Usage:
#   ./run_test_suite.sh [options]
#
# Options:
#   --stage <stage>: Run only a specific stage (standalone, venv, db, all)
#   --junit: Generate JUnit XML reports for CI systems
#   --coverage: Generate code coverage reports
#   --lint: Run linting checks before tests
#   --fix: Fix linting issues automatically
#   --docker: Run tests using Docker containers
#   --help: Display this help message

set -e  # Exit on error

# Default options
STAGE="all"
JUNIT=false
COVERAGE=false
LINT=false
FIX=false
DOCKER=false
VERBOSE=false

# Terminal colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Parse arguments
while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    --stage)
      STAGE="$2"
      shift
      shift
      ;;
    --junit)
      JUNIT=true
      shift
      ;;
    --coverage)
      COVERAGE=true
      shift
      ;;
    --lint)
      LINT=true
      shift
      ;;
    --fix)
      FIX=true
      shift
      ;;
    --docker)
      DOCKER=true
      shift
      ;;
    --verbose)
      VERBOSE=true
      shift
      ;;
    --help)
      echo "Novamind Digital Twin Test Suite Runner"
      echo ""
      echo "Usage:"
      echo "  ./run_test_suite.sh [options]"
      echo ""
      echo "Options:"
      echo "  --stage <stage>: Run only a specific stage (standalone, venv, db, all)"
      echo "  --junit: Generate JUnit XML reports for CI systems"
      echo "  --coverage: Generate code coverage reports"
      echo "  --lint: Run linting checks before tests"
      echo "  --fix: Fix linting issues automatically"
      echo "  --docker: Run tests using Docker containers"
      echo "  --verbose: Show more detailed output"
      echo "  --help: Display this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Validate stage option
if [[ ! "$STAGE" =~ ^(standalone|venv|db|all)$ ]]; then
  echo -e "${RED}ERROR: Invalid stage '$STAGE'. Must be one of: standalone, venv, db, all${NC}"
  exit 1
fi

# Ensure we're in the backend directory
cd "$(dirname "$0")/.." || exit 1
ROOT_DIR=$(pwd)

echo -e "${BLUE}=== Novamind Digital Twin Test Suite Runner ===${NC}"
echo -e "${BLUE}Running in: ${ROOT_DIR}${NC}"
echo -e "${BLUE}Configuration:${NC}"
echo -e "${BLUE}- Stage: ${STAGE}${NC}"
echo -e "${BLUE}- JUnit Reports: ${JUNIT}${NC}"
echo -e "${BLUE}- Coverage Reports: ${COVERAGE}${NC}"
echo -e "${BLUE}- Linting: ${LINT}${NC}"
echo -e "${BLUE}- Auto-fix: ${FIX}${NC}"
echo -e "${BLUE}- Docker: ${DOCKER}${NC}"

# Create results directory if it doesn't exist
mkdir -p test-results

# Run linting if requested
if [[ "$LINT" == "true" ]]; then
  echo -e "\n${YELLOW}=== Running Linting Checks ===${NC}"
  
  if [[ "$FIX" == "true" ]]; then
    echo -e "${YELLOW}Running black with auto-fix...${NC}"
    python -m black app
    
    echo -e "${YELLOW}Running isort with auto-fix...${NC}"
    python -m isort app
  else
    echo -e "${YELLOW}Running black check...${NC}"
    python -m black --check app

    echo -e "${YELLOW}Running isort check...${NC}"
    python -m isort --check-only app
  fi
  
  echo -e "${YELLOW}Running flake8...${NC}"
  python -m flake8 app
  
  echo -e "${YELLOW}Running mypy...${NC}"
  python -m mypy app
  
  echo -e "${GREEN}Linting completed${NC}"
fi

# Function to run tests
run_tests() {
  local stage=$1
  local marker=""
  local report_name=""
  
  case $stage in
    standalone)
      marker="standalone"
      report_name="standalone-results"
      ;;
    venv)
      marker="venv_only"
      report_name="venv-results"
      ;;
    db)
      marker="db_required"
      report_name="db-results"
      ;;
    *)
      echo -e "${RED}Invalid stage: $stage${NC}"
      return 1
      ;;
  esac
  
  echo -e "\n${YELLOW}=== Running $stage Tests ===${NC}"
  
  # Build pytest command
  local cmd="python -m pytest -m $marker -v"
  
  # Add JUnit option if requested
  if [[ "$JUNIT" == "true" ]]; then
    cmd+=" --junitxml=test-results/${report_name}.xml"
  fi
  
  # Add coverage options if requested
  if [[ "$COVERAGE" == "true" ]]; then
    cmd+=" --cov=app --cov-report=term --cov-report=html:coverage_html/${stage}"
  fi
  
  if [[ "$VERBOSE" == "true" ]]; then
    cmd+=" -v"
  fi
  
  # Execute the command
  echo -e "${YELLOW}Running: $cmd${NC}"
  if ! eval "$cmd"; then
    echo -e "${RED}$stage tests failed${NC}"
    return 1
  fi
  
  echo -e "${GREEN}$stage tests passed${NC}"
  return 0
}

# Function to run tests with Docker
run_docker_tests() {
  local stage=$1
  
  echo -e "\n${YELLOW}=== Running $stage Tests in Docker ===${NC}"
  
  # Build docker-compose command
  local cmd="docker-compose -f docker-compose.test.yml run --rm test-runner python -m pytest -m $stage -v"
  
  # Add JUnit option if requested
  if [[ "$JUNIT" == "true" ]]; then
    cmd+=" --junitxml=/app/test-results/${stage}-results.xml"
  fi
  
  # Add coverage options if requested
  if [[ "$COVERAGE" == "true" ]]; then
    cmd+=" --cov=app --cov-report=term --cov-report=html:/app/coverage_html/${stage}"
  fi
  
  if [[ "$VERBOSE" == "true" ]]; then
    cmd+=" -v"
  fi
  
  # Execute the command
  echo -e "${YELLOW}Running: $cmd${NC}"
  if ! eval "$cmd"; then
    echo -e "${RED}$stage tests failed${NC}"
    return 1
  fi
  
  echo -e "${GREEN}$stage tests passed${NC}"
  return 0
}

# Run tests based on the selected stage and mode
if [[ "$DOCKER" == "true" ]]; then
  # Start Docker containers if needed for DB tests
  if [[ "$STAGE" == "db" || "$STAGE" == "all" ]]; then
    echo -e "\n${YELLOW}=== Starting Docker Services ===${NC}"
    docker-compose -f docker-compose.test.yml up -d postgres redis
    
    # Give services time to start
    echo -e "${YELLOW}Waiting for services to start...${NC}"
    sleep 5
  fi
  
  # Run selected tests in Docker
  case $STAGE in
    standalone)
      run_docker_tests "standalone"
      ;;
    venv)
      run_docker_tests "venv_only"
      ;;
    db)
      run_docker_tests "db_required"
      ;;
    all)
      run_docker_tests "standalone" && run_docker_tests "venv_only" && run_docker_tests "db_required"
      ;;
  esac
  
  # Stop Docker containers if they were started
  if [[ "$STAGE" == "db" || "$STAGE" == "all" ]]; then
    echo -e "\n${YELLOW}=== Stopping Docker Services ===${NC}"
    docker-compose -f docker-compose.test.yml down
  fi
else
  # Run selected tests locally
  case $STAGE in
    standalone)
      run_tests "standalone"
      ;;
    venv)
      run_tests "venv"
      ;;
    db)
      run_tests "db"
      ;;
    all)
      run_tests "standalone" && run_tests "venv" && run_tests "db"
      ;;
  esac
fi

echo -e "\n${GREEN}=== Test Suite Execution Complete ===${NC}"

if [[ "$COVERAGE" == "true" ]]; then
  echo -e "${GREEN}Coverage reports available in coverage_html/${NC}"
fi

if [[ "$JUNIT" == "true" ]]; then
  echo -e "${GREEN}JUnit reports available in test-results/${NC}"
fi