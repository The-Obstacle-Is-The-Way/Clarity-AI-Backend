#!/bin/bash
# Test Runner Script for Novamind Backend
# This script provides an easy way to run tests at different dependency levels

set -e

# Default values
LEVEL="all"
COVERAGE=false
VERBOSE=false
JIT_REPORT=""
SKIP_FAILED=false
EXTRA_ARGS=""

# Root directory
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

show_help() {
    echo "Novamind Backend Test Runner"
    echo "Usage: $0 [options]"
    echo 
    echo "Options:"
    echo "  -l, --level LEVEL     Test level to run: standalone, venv_only, db_required, or all (default: all)"
    echo "  -c, --coverage        Enable coverage reporting"
    echo "  -v, --verbose         Enable verbose output"
    echo "  -j, --junit PATH      Generate JUnit XML reports in the specified directory"
    echo "  -s, --skip-failed     Continue to next level even if the previous level fails"
    echo "  -e, --extra ARGS      Additional arguments to pass to pytest (quote the string)"
    echo "  -a, --analyze         Only analyze test dependencies, don't run tests"
    echo "  -m, --mark            Analyze and add markers to tests based on dependencies"
    echo "  -h, --help            Show this help message"
    echo
    echo "Examples:"
    echo "  $0 -l standalone                  # Run only standalone tests"
    echo "  $0 -l all -c -v                   # Run all tests with coverage and verbose output"
    echo "  $0 -l venv_only -j test-reports   # Run venv_only tests with JUnit reports"
    echo "  $0 -a                             # Only analyze test dependencies"
    echo "  $0 -m                             # Add dependency markers to tests"
    echo
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -l|--level)
            LEVEL="$2"
            shift 2
            ;;
        -c|--coverage)
            COVERAGE=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -j|--junit)
            JUNIT_REPORT="$2"
            shift 2
            ;;
        -s|--skip-failed)
            SKIP_FAILED=true
            shift
            ;;
        -e|--extra)
            EXTRA_ARGS="$2"
            shift 2
            ;;
        -a|--analyze)
            echo "Analyzing test dependencies..."
            python "$ROOT_DIR/scripts/classify_tests.py" --mode analyze
            exit $?
            ;;
        -m|--mark)
            echo "Adding dependency markers to tests..."
            python "$ROOT_DIR/scripts/classify_tests.py" --mode mark
            exit $?
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Error: Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Validate level
if [[ "$LEVEL" != "standalone" && "$LEVEL" != "venv_only" && "$LEVEL" != "db_required" && "$LEVEL" != "all" ]]; then
    echo "Error: Invalid test level: $LEVEL"
    echo "Valid levels are: standalone, venv_only, db_required, all"
    exit 1
fi

# Build command arguments
ARGS=""

if [ "$LEVEL" != "all" ]; then
    ARGS="--levels $LEVEL"
else 
    ARGS="--levels all"
fi

if [ "$COVERAGE" = true ]; then
    ARGS="$ARGS --coverage"
fi

if [ "$VERBOSE" = true ]; then
    ARGS="$ARGS --verbose"
fi

if [ -n "$JUNIT_REPORT" ]; then
    ARGS="$ARGS --junit $JUNIT_REPORT"
fi

if [ "$SKIP_FAILED" = true ]; then
    ARGS="$ARGS --skip-failed"
fi

if [ -n "$EXTRA_ARGS" ]; then
    ARGS="$ARGS --extra-args \"$EXTRA_ARGS\""
fi

# Run the tests
eval "python \"$ROOT_DIR/scripts/run_dependency_tests.py\" $ARGS"