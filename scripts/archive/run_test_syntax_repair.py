#!/usr/bin/env python3
"""
NovaMind Digital Twin Backend - Test Suite Syntax Repair Tool

This script orchestrates a comprehensive repair process for test suite syntax issues.
It executes various syntax fixers in the proper sequence to address common problems in test files.

Usage:
  python run_test_syntax_repair.py [--file FILE_PATH] [--verbose] [--dry-run]
"""

import os
import sys
import time
import argparse
import importlib.util
import logging
import subprocess
from typing import List, Dict, Optional, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join(os.path.dirname(__file__), "test_repair.log"))
    ]
)
logger = logging.getLogger(__name__)

# Root directories
SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPTS_DIR, "../.."))
TESTS_DIR = os.path.join(PROJECT_ROOT, "app/tests")
SYNTAX_DIR = os.path.join(SCRIPTS_DIR, "syntax")

# Repair steps and their corresponding scripts
REPAIR_STEPS = [
    {
        "name": "Basic Syntax Repairs",
        "script": os.path.join(SYNTAX_DIR, "fix_test_syntax.py"),
        "description": "Fixing basic Python syntax errors (indentation, parentheses, colons)"
    },
    {
        "name": "Test Pattern Repairs",
        "script": os.path.join(SYNTAX_DIR, "fix_test_patterns.py"),
        "description": "Fixing test-specific patterns (patch calls, fixtures, assertions)"
    }
]


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Run comprehensive test syntax repairs")
    parser.add_argument("--file", help="Path to a specific file to repair")
    parser.add_argument("--dir", default=TESTS_DIR, help="Directory containing test files to repair")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--dry-run", action="store_true", help="Show changes without applying them")
    parser.add_argument("--steps", help="Comma-separated list of step numbers to run (e.g., '1,3')")
    return parser.parse_args()


def find_test_files(base_dir: str) -> List[str]:
    """Find all Python test files in the given directory."""
    test_files = []
    for root, _, files in os.walk(base_dir):
        for file in files:
            if file.endswith('.py') and ('test_' in file or file.startswith('test')):
                test_files.append(os.path.join(root, file))
    return test_files


def check_syntax_errors(files: List[str]) -> Dict[str, Tuple[int, int, str]]:
    """Check which files have syntax errors."""
    files_with_errors = {}
    
    for file_path in files:
        try:
            # Try to compile the file
            with open(file_path, 'r', encoding='utf-8') as f:
                source = f.read()
            compile(source, file_path, 'exec')
        except SyntaxError as e:
            files_with_errors[file_path] = (e.lineno, e.offset, str(e))
        except Exception as e:
            # For other exceptions, just note there was an error
            files_with_errors[file_path] = (0, 0, str(e))
    
    return files_with_errors


def run_repair_step(step: Dict, args: argparse.Namespace) -> bool:
    """Run a single repair step."""
    logger.info(f"\n=== Running {step['name']} ===")
    logger.info(f"Description: {step['description']}")
    
    cmd = [sys.executable, step['script']]
    
    if args.file:
        cmd.extend(["--file", args.file])
    elif args.dir:
        cmd.extend(["--dir", args.dir])
    
    if args.verbose:
        cmd.append("--verbose")
    
    if args.dry_run:
        cmd.append("--dry-run")
    
    logger.info(f"Executing: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        logger.info(result.stdout)
        if result.stderr:
            logger.warning(result.stderr)
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        logger.error(f"Step failed with code {e.returncode}")
        logger.error(e.stderr)
        return False
    except Exception as e:
        logger.error(f"Error executing step: {e}")
        return False


def main():
    """Main function for coordinating test repair steps."""
    start_time = time.time()
    args = parse_args()
    
    # Print header
    logger.info("=" * 80)
    logger.info("NovaMind Digital Twin Backend - Test Suite Syntax Repair Tool")
    logger.info("=" * 80)
    
    # Determine which steps to run
    steps_to_run = []
    if args.steps:
        try:
            step_indices = [int(i) - 1 for i in args.steps.split(',')]
            for idx in step_indices:
                if 0 <= idx < len(REPAIR_STEPS):
                    steps_to_run.append(REPAIR_STEPS[idx])
                else:
                    logger.warning(f"Invalid step index: {idx + 1}")
        except ValueError:
            logger.error(f"Invalid step specification: {args.steps}")
            return 1
    else:
        steps_to_run = REPAIR_STEPS
    
    # Get all test files
    if args.file:
        if not os.path.exists(args.file):
            logger.error(f"File not found: {args.file}")
            return 1
        files = [args.file]
    else:
        logger.info(f"Finding test files in {args.dir}")
        files = find_test_files(args.dir)
        logger.info(f"Found {len(files)} test files")
    
    # Check for syntax errors before repairs
    files_with_errors = check_syntax_errors(files)
    logger.info(f"Found {len(files_with_errors)} files with syntax errors before repairs")
    
    # Run each repair step
    successful_steps = 0
    for step in steps_to_run:
        if run_repair_step(step, args):
            successful_steps += 1
        else:
            logger.warning(f"Step '{step['name']}' did not complete successfully")
    
    # Check for syntax errors after repairs
    files_with_errors_after = check_syntax_errors(files)
    fixed_count = len(files_with_errors) - len(files_with_errors_after)
    
    # Print summary
    elapsed_time = time.time() - start_time
    logger.info("\n" + "=" * 80)
    logger.info("Repair Summary:")
    logger.info(f"- Total files checked: {len(files)}")
    logger.info(f"- Files with syntax errors before: {len(files_with_errors)}")
    logger.info(f"- Files with syntax errors after: {len(files_with_errors_after)}")
    logger.info(f"- Files fixed: {fixed_count}")
    logger.info(f"- Steps completed successfully: {successful_steps}/{len(steps_to_run)}")
    logger.info(f"- Total time: {elapsed_time:.2f} seconds")
    logger.info("=" * 80)
    
    if len(files_with_errors_after) > 0:
        logger.info("\nFiles still needing manual fixes:")
        for file_path, (lineno, offset, msg) in files_with_errors_after.items():
            # Display relative path for readability
            rel_path = os.path.relpath(file_path, PROJECT_ROOT)
            logger.info(f"  {rel_path} (line {lineno}, col {offset}: {msg})")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())