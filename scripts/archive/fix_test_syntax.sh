#!/bin/bash
# ============================================================================
# Test Syntax Fixer Script
# 
# This script runs the test syntax fixer tools and verifies the results
# Usage: ./scripts/test/fix_test_syntax.sh [--verify-only]
# ============================================================================

set -e

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Set the root directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
TEST_DIR="$PROJECT_ROOT/app/tests"

# Print header
print_header() {
  echo -e "\n${BLUE}===========================================================================${NC}"
  echo -e "${BLUE}$1${NC}"
  echo -e "${BLUE}===========================================================================${NC}\n"
}

# Print section header
print_section() {
  echo -e "\n${YELLOW}==== $1 ====${NC}\n"
}

# Verify test files for syntax errors
verify_test_files() {
  print_section "Verifying Test Files"
  
  # Find files with syntax errors
  echo "Checking for syntax errors in test files..."
  
  error_files=()
  error_count=0
  
  while IFS= read -r file; do
    if ! python -m py_compile "$file" 2>/dev/null; then
      error_files+=("$file")
      ((error_count++))
      echo -e "${RED}✗ Syntax error in:${NC} $(basename "$file")"
    fi
  done < <(find "$TEST_DIR" -name "*.py" -type f)
  
  # Show summary
  if [ $error_count -eq 0 ]; then
    echo -e "\n${GREEN}✓ All test files have valid syntax!${NC}"
    return 0
  else
    echo -e "\n${RED}Found $error_count files with syntax errors${NC}"
    
    # List the problematic files
    print_section "Files With Syntax Errors"
    for file in "${error_files[@]}"; do
      rel_path=$(realpath --relative-to="$PROJECT_ROOT" "$file")
      echo -e "${RED}✗ $rel_path${NC}"
      # Get specific error (first 2 lines only)
      python -m py_compile "$file" 2>&1 | head -n 2 | sed 's/^/    /'
    done
    
    return 1
  fi
}

# Run the syntax fixer
run_syntax_fixer() {
  print_section "Running Syntax Fixer"
  
  echo "Executing master syntax fix script..."
  python "$SCRIPT_DIR/run_syntax_fix.py"
  
  # Check if it succeeded
  if [ $? -eq 0 ]; then
    echo -e "\n${GREEN}✓ Syntax fixer completed successfully${NC}"
  else
    echo -e "\n${YELLOW}! Syntax fixer completed with warnings${NC}"
  fi
}

# Main function
main() {
  print_header "Test Syntax Fixer"
  
  # Check if we should only verify
  if [ "$1" == "--verify-only" ]; then
    verify_test_files
    exit $?
  fi
  
  # First verify to see what needs fixing
  echo "Initial verification..."
  initial_errors=$(find "$TEST_DIR" -name "*.py" -type f -exec python -m py_compile {} \; 2>&1 | grep -c "SyntaxError" || true)
  
  if [ "$initial_errors" -eq 0 ]; then
    echo -e "${GREEN}✓ No syntax errors found. Nothing to fix!${NC}"
    exit 0
  else
    echo -e "${YELLOW}! Found $initial_errors files with syntax errors${NC}"
  fi
  
  # Run the fixer
  run_syntax_fixer
  
  # Verify the results
  echo -e "\nVerifying results..."
  verify_test_files
  
  # Check if we fixed everything
  final_status=$?
  if [ $final_status -eq 0 ]; then
    print_header "All syntax errors have been fixed!"
    exit 0
  else
    print_header "Some files still need manual fixes. See above for details."
    exit 1
  fi
}

# Execute main function with all arguments
main "$@"