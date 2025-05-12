#!/bin/bash
# Clarity AI Backend Test Runner
# This script provides a unified interface for running tests with different configurations

set -e

# Default values
TEST_TYPE="all"
VERBOSITY="-v"
COVERAGE=false
FILTER=""
FAILFAST=false
TEST_PATTERN=""

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print usage
function show_help {
    echo -e "${BLUE}Clarity AI Backend Test Runner${NC}"
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -t, --type TYPE       Test type to run (unit|integration|e2e|security|all) [default: all]"
    echo "  -v, --verbose         Enable verbose output"
    echo "  -q, --quiet           Minimal output"
    echo "  -c, --coverage        Generate coverage report"
    echo "  -f, --filter FILTER   Filter tests by substring match"
    echo "  -p, --pattern PATTERN Filter tests by pytest pattern (e.g., 'test_*')"
    echo "  -x, --failfast        Stop on first failure"
    echo "  -h, --help            Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --type unit                     # Run all unit tests"
    echo "  $0 --type integration --coverage   # Run integration tests with coverage report"
    echo "  $0 --filter patient                # Run tests with 'patient' in their name"
    echo "  $0 --pattern test_database*        # Run tests matching the pattern 'test_database*'"
    echo ""
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -t|--type)
            TEST_TYPE="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSITY="-vv"
            shift
            ;;
        -q|--quiet)
            VERBOSITY=""
            shift
            ;;
        -c|--coverage)
            COVERAGE=true
            shift
            ;;
        -f|--filter)
            FILTER="$2"
            shift 2
            ;;
        -p|--pattern)
            TEST_PATTERN="$2"
            shift 2
            ;;
        -x|--failfast)
            FAILFAST=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $key${NC}"
            show_help
            exit 1
            ;;
    esac
done

# Convert the test type to a pytest path filter
case $TEST_TYPE in
    "unit")
        TEST_PATH="app/tests/unit/"
        ;;
    "integration")
        TEST_PATH="app/tests/integration/"
        ;;
    "e2e")
        TEST_PATH="app/tests/e2e/"
        ;;
    "security")
        TEST_PATH="app/tests/security/"
        ;;
    "all")
        TEST_PATH="app/tests/"
        ;;
    *)
        echo -e "${RED}Invalid test type: $TEST_TYPE${NC}"
        show_help
        exit 1
        ;;
esac

# Build the pytest command
PYTEST_CMD="python -m pytest"

# Add verbosity
if [[ -n "$VERBOSITY" ]]; then
    PYTEST_CMD="$PYTEST_CMD $VERBOSITY"
fi

# Add test path
PYTEST_CMD="$PYTEST_CMD $TEST_PATH"

# Add filter if specified
if [[ -n "$FILTER" ]]; then
    PYTEST_CMD="$PYTEST_CMD -k \"$FILTER\""
fi

# Add pattern if specified
if [[ -n "$TEST_PATTERN" ]]; then
    PYTEST_CMD="$PYTEST_CMD -k \"$TEST_PATTERN\""
fi

# Add failfast if enabled
if [[ "$FAILFAST" = true ]]; then
    PYTEST_CMD="$PYTEST_CMD -x"
fi

# Add coverage if enabled
if [[ "$COVERAGE" = true ]]; then
    PYTEST_CMD="$PYTEST_CMD --cov=app --cov-report=term --cov-report=html"
fi

# Print the command
echo -e "${CYAN}Running command:${NC} $PYTEST_CMD"

# Run the tests
echo -e "${GREEN}Starting $TEST_TYPE tests...${NC}"
eval $PYTEST_CMD

# Process the result
if [[ $? -eq 0 ]]; then
    echo -e "${GREEN}All tests passed!${NC}"
    
    # If coverage report was generated, show the path
    if [[ "$COVERAGE" = true ]]; then
        echo -e "${BLUE}Coverage report generated at htmlcov/index.html${NC}"
    fi
else
    echo -e "${RED}Some tests failed.${NC}"
    exit 1
fi

exit 0 