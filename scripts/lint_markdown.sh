#!/bin/bash
# Script to lint markdown files in the repository

# Check if markdownlint-cli is installed
if ! command -v markdownlint &> /dev/null; then
    echo "Error: markdownlint-cli is not installed"
    echo "Install it with: npm install -g markdownlint-cli"
    exit 1
fi

# Default to checking all markdown files if no arguments provided
if [ $# -eq 0 ]; then
    echo "Linting all markdown files in the repository..."
    markdownlint "**/*.md" --ignore node_modules
else
    # Lint specific files or directories
    echo "Linting specified markdown files..."
    markdownlint "$@"
fi