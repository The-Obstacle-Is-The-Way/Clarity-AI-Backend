#!/bin/bash
# Script to lint documentation for prose style issues using Vale

# Check if Vale is installed
if ! command -v vale &> /dev/null; then
    echo "Error: Vale is not installed"
    echo "Install instructions: https://vale.sh/docs/vale-cli/installation/"
    exit 1
fi

# Default to checking all markdown files if no arguments provided
if [ $# -eq 0 ]; then
    echo "Linting all markdown files in the docs directory..."
    vale --config=.vale.ini docs/
else
    # Lint specific files or directories
    echo "Linting specified files/directories..."
    vale --config=.vale.ini "$@"
fi