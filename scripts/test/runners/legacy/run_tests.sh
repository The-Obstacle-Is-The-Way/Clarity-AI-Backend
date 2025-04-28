#!/bin/bash
# Unified Test Runner for Novamind Digital Twin Backend
# This script provides a user-friendly interface to the dependency-based
# test runner, allowing easy execution of tests by dependency level.

set -e  # Exit on error

# Colors for terminal output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Banner function
function print_banner() {
    echo -e "${BLUE}=================================================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}=================================================================${NC}"
    echo ""
}

# Set the base directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"

# Set default options
VERBOSE=false
COVERAGE=false
REPORT=false
JUNIT=false
SKIP_INSTALL=false
CATEGORY="all"
TEST_PATH=""

# Define usage function
function show_usage() {
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  all               Run all tests in dependency order"
    echo "  standalone        Run standalone tests (no dependencies)"
    echo "  venv              Run venv-only tests (require packages but no external services)"
    echo "  db                Run database-required tests"
    echo "  report            Generate test report without running tests"
    echo "  help              Show this help message"
    echo ""
    echo "Options:"
    echo "  --verbose, -v     Show detailed output"
    echo "  --coverage, -c    Generate coverage report"
    echo "  --report, -r      Generate detailed test report"
    echo "  --junit, -j       Generate JUnit XML reports"
    echo "  --skip-install    Skip dependency installation"
    echo "  --path PATH       Path to specific test file or directory"
    echo ""
    echo "Examples:"
    echo "  $0 all            Run all tests in dependency order"
    echo "  $0 standalone     Run standalone tests"
    echo "  $0 venv -c        Run venv tests with coverage"
    echo "  $0 db -v          Run database tests with verbose output"
    echo "  $0 all -c -r -j   Run all tests with coverage, report, and JUnit output"
    echo ""
}

# Parse command argument
if [ $# -lt 1 ]; then
    show_usage
    exit 1
fi

COMMAND=$1
shift

case $COMMAND in
    all|standalone|venv|db|report)
        # Map command to category
        case $COMMAND in
            all)
                CATEGORY="all"
                ;;
            standalone)
                CATEGORY="standalone"
                ;;
            venv)
                CATEGORY="venv_only"
                ;;
            db)
                CATEGORY="db_required"
                ;;
            report)
                REPORT=true
                CATEGORY="all"
                ;;
        esac
        ;;
    help)
        show_usage
        exit 0
        ;;
    *)
        echo -e "${RED}Error: Unknown command '$COMMAND'${NC}"
        show_usage
        exit 1
        ;;
esac

# Parse options
while [[ $# -gt 0 ]]; do
    case $1 in
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --coverage|-c)
            COVERAGE=true
            shift
            ;;
        --report|-r)
            REPORT=true
            shift
            ;;
        --junit|-j)
            JUNIT=true
            shift
            ;;
        --skip-install)
            SKIP_INSTALL=true
            shift
            ;;
        --path)
            if [[ $# -gt 1 ]]; then
                TEST_PATH=$2
                shift 2
            else
                echo -e "${RED}Error: --path requires a value${NC}"
                exit 1
            fi
            ;;
        *)
            echo -e "${RED}Error: Unknown option '$1'${NC}"
            show_usage
            exit 1
            ;;
    esac
done

# Print header
print_banner "NOVAMIND DIGITAL TWIN BACKEND TEST RUNNER"
echo -e "Working directory: ${YELLOW}$BASE_DIR${NC}"
echo -e "Selected category: ${YELLOW}$CATEGORY${NC}"
if [ ! -z "$TEST_PATH" ]; then
    echo -e "Test path: ${YELLOW}$TEST_PATH${NC}"
fi
echo ""

# Install dependencies if not skipped
if [ "$SKIP_INSTALL" = false ]; then
    if [ -f "$BASE_DIR/requirements-test.txt" ]; then
        echo -e "${CYAN}Installing test dependencies...${NC}"
        pip install -r "$BASE_DIR/requirements-test.txt"
        echo ""
    fi
fi

# Ensure Python path is set correctly
export PYTHONPATH=$BASE_DIR:$PYTHONPATH

# Build the command
CMD="python $SCRIPT_DIR/run_dependency_tests.py --category $CATEGORY"

# Add options
if [ "$VERBOSE" = true ]; then
    CMD="$CMD --verbose"
fi

if [ "$COVERAGE" = true ]; then
    CMD="$CMD --coverage"
fi

if [ "$REPORT" = true ]; then
    CMD="$CMD --report"
fi

if [ "$JUNIT" = true ]; then
    CMD="$CMD --junit"
fi

if [ ! -z "$TEST_PATH" ]; then
    CMD="$CMD $TEST_PATH"
fi

# Print command
echo -e "${CYAN}Running command: ${NC}$CMD"
echo ""

# Run the command
eval $CMD

# Print summary
SUCCESS=$?
if [ $SUCCESS -eq 0 ]; then
    print_banner "TESTS COMPLETED SUCCESSFULLY"
    echo -e "${GREEN}All tests completed successfully!${NC}"
else
    print_banner "TESTS FAILED"
    echo -e "${RED}Some tests failed. See above for details.${NC}"
fi

echo ""
echo -e "${BLUE}For more options, run: $0 help${NC}"
echo ""

exit $SUCCESS