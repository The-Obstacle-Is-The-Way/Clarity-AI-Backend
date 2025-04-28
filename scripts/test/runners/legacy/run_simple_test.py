#!/usr/bin/env python3
"""
Simple test runner for Novamind Digital Twin Backend

This script runs a single test file to verify the test infrastructure works.
It's useful for debugging test issues without the complexity of the full test suite.
"""

import os
import sys
import pytest
from pathlib import Path

def main():
    """Run a simple test to verify the test infrastructure."""
    # Get the project root
    project_root = Path(__file__).resolve().parent.parent
    
    # Set up environment
    os.environ["PYTHONPATH"] = str(project_root)
    os.environ["TESTING"] = "1"
    
    # Create a minimal test file
    test_file = project_root / "app" / "tests" / "standalone" / "test_simple.py"
    
    with open(test_file, "w") as f:
        f.write("""
import pytest

@pytest.mark.standalone
def test_simple_addition():
    assert 1 + 1 == 2
""")
    
    print(f"Created test file: {test_file}")
    
    # Run the test
    print("Running test...")
    result = pytest.main(["-v", str(test_file)])
    
    # Clean up
    os.remove(test_file)
    
    return result

if __name__ == "__main__":
    sys.exit(main())