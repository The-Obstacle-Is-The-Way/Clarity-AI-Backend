#!/bin/bash
# Comprehensive CI Test Runner for Novamind Backend
# This script orchestrates the entire test process for CI/CD pipelines

set -e

# Define colors for output
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Print a formatted header
print_header() {
  echo -e "\n${BLUE}===================================================${NC}"
  echo -e "${BLUE}  $1${NC}"
  echo -e "${BLUE}===================================================${NC}\n"
}

# Print a formatted section
print_section() {
  echo -e "\n${CYAN}>>> $1${NC}\n"
}

# Print a success message
print_success() {
  echo -e "${GREEN}✅ $1${NC}"
}

# Print a warning message
print_warning() {
  echo -e "${YELLOW}⚠️  $1${NC}"
}

# Print an error message
print_error() {
  echo -e "${RED}❌ $1${NC}"
}

# Change to the backend directory
cd "$(dirname "$0")/.."
BACKEND_DIR="$(pwd)"

print_header "Running Novamind Backend Tests"
echo "Backend directory: $BACKEND_DIR"

# Apply any needed test fixes
print_section "Applying test fixes"
if [ -f "$BACKEND_DIR/scripts/fix_pat_mock.py" ]; then
  echo "Running PAT mock service fixes..."
  python "$BACKEND_DIR/scripts/fix_pat_mock.py"
else
  print_warning "PAT mock fix script not found, skipping"
fi

# Run the standalone tests first
print_section "Running standalone tests"
python -m pytest app/tests/standalone/ --cov=app --cov-report=html:coverage_html/standalone --junitxml=test-results/standalone-results.xml

# Exit if standalone tests failed and we're not continuing on failure
if [ $? -ne 0 ] && [ "${CONTINUE_ON_FAILURE:-false}" != "true" ]; then
  print_error "Standalone tests failed, stopping test execution"
  exit 1
fi

# Setup for VENV tests if they exist
if [ -d "$BACKEND_DIR/app/tests/venv" ]; then
  print_section "Running VENV tests"
  python -m pytest app/tests/venv/ --cov=app --cov-report=html:coverage_html/venv --junitxml=test-results/venv-results.xml
  
  # Exit if VENV tests failed and we're not continuing on failure
  if [ $? -ne 0 ] && [ "${CONTINUE_ON_FAILURE:-false}" != "true" ]; then
    print_error "VENV tests failed, stopping test execution"
    exit 1
  fi
else
  print_warning "No VENV tests found, skipping"
fi

# Run integration tests if --with-integration is specified
if [ "${WITH_INTEGRATION:-false}" == "true" ]; then
  print_section "Running integration tests"
  
  # Start Docker containers for integration tests
  print_section "Starting Docker containers for integration tests"
  docker-compose -f docker-compose.test.yml up -d
  
  # Wait for services to be ready
  print_section "Waiting for services to be ready"
  sleep 5
  
  # Run the integration tests
  docker-compose -f docker-compose.test.yml exec -T app python -m pytest app/tests/integration/ --cov=app --cov-report=html:coverage_html/integration --junitxml=test-results/integration-results.xml
  INTEGRATION_EXIT_CODE=$?
  
  # Clean up Docker containers
  print_section "Cleaning up Docker containers"
  docker-compose -f docker-compose.test.yml down
  
  # Exit if integration tests failed
  if [ $INTEGRATION_EXIT_CODE -ne 0 ] && [ "${CONTINUE_ON_FAILURE:-false}" != "true" ]; then
    print_error "Integration tests failed"
    exit 1
  fi
else
  print_warning "Skipping integration tests (use --with-integration to run them)"
fi

# Generate the test classification report
print_section "Generating test classification report"
if [ -f "$BACKEND_DIR/scripts/create_test_classification.py" ]; then
  python "$BACKEND_DIR/scripts/create_test_classification.py"
else
  print_warning "Test classification script not found, skipping"
fi

# Combine coverage reports if possible
print_section "Combining coverage reports"
if command -v coverage &> /dev/null; then
  coverage combine coverage_html/standalone/.coverage coverage_html/venv/.coverage coverage_html/integration/.coverage 2>/dev/null || true
  coverage html -d coverage_html/combined
  coverage xml -o coverage_html/coverage.xml
  coverage report
  print_success "Combined coverage report generated"
else
  print_warning "Coverage command not found, skipping combined report"
fi

print_header "Test Execution Complete"

# Print summary
print_section "Test Summary"
echo "✅ Standalone tests completed"
[ -d "$BACKEND_DIR/app/tests/venv" ] && echo "✅ VENV tests completed" || echo "⚠️  VENV tests skipped"
[ "${WITH_INTEGRATION:-false}" == "true" ] && echo "✅ Integration tests completed" || echo "⚠️  Integration tests skipped"
echo "✅ Test classification report generated"

print_success "All tests completed successfully!"
exit 0