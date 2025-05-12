#!/bin/bash
# run_tests.sh - Main script for running various test utilities

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

function print_usage() {
    echo "Usage: $0 [command]"
    echo
    echo "Commands:"
    echo "  migration      - Run the asyncio test migration helper"
    echo "  asyncio        - Run asyncio tests"
    echo "  comprehensive  - Run comprehensive tests across all layers"
    echo "  all            - Run all test suites"
    echo "  help           - Show this help message"
    echo
    echo "Examples:"
    echo "  $0 asyncio"
    echo "  $0 all"
}

function run_migration() {
    echo -e "${BLUE}Running asyncio test migration...${NC}"
    ./scripts/test_utils/run_asyncio_migration.sh
}

function run_asyncio_tests() {
    echo -e "${BLUE}Running asyncio tests...${NC}"
    ./scripts/test_utils/run_asyncio_tests.sh
}

function run_comprehensive() {
    echo -e "${BLUE}Running comprehensive tests...${NC}"
    ./scripts/test_utils/run_comprehensive_tests.sh
}

function run_all() {
    run_asyncio_tests
    echo
    run_comprehensive
}

# Main entry point
if [ $# -eq 0 ]; then
    print_usage
    exit 0
fi

case "$1" in
    migration)
        run_migration
        ;;
    asyncio)
        run_asyncio_tests
        ;;
    comprehensive)
        run_comprehensive
        ;;
    all)
        run_all
        ;;
    help)
        print_usage
        ;;
    *)
        echo -e "${RED}Unknown command: $1${NC}"
        print_usage
        exit 1
        ;;
esac 