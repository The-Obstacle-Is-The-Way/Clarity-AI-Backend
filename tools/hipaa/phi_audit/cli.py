#!/usr/bin/env python3
"""
PHI Audit Command Line Interface

This module provides a command-line interface for running PHI audits on the codebase.
"""

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import List, Optional, Dict, Any

# Configure logging with no PHI
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("phi_audit")


def setup_parser() -> argparse.ArgumentParser:
    """Set up command line argument parser."""
    parser = argparse.ArgumentParser(
        description="HIPAA PHI Audit Tool - Scan codebase for potential PHI leakage",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "--path", type=str, default="app", help="Path to scan for PHI leakage"
    )

    parser.add_argument(
        "--output",
        type=str,
        default="phi_audit_report.md",
        help="Output file for the audit report",
    )

    parser.add_argument(
        "--fix", action="store_true", help="Automatically fix common PHI leakage issues"
    )

    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )

    parser.add_argument(
        "--exclude",
        type=str,
        nargs="+",
        default=["__pycache__", ".git", ".venv", "venv", "env", "build", "dist"],
        help="Directories to exclude from scanning",
    )

    return parser


def run_audit(args: argparse.Namespace) -> int:
    """
    Run the PHI audit with the specified arguments.

    Args:
        args: Command line arguments

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    try:
        if args.verbose:
            logger.setLevel(logging.DEBUG)

        logger.info(f"Starting PHI audit on path: {args.path}")
        logger.info(f"Excluding directories: {', '.join(args.exclude)}")

        # Import auditor here to avoid circular imports
        try:
            from tools.hipaa.phi_audit.phi_auditor_complete import run_phi_audit

            result = run_phi_audit(
                path=args.path,
                output_file=args.output,
                exclude_dirs=args.exclude,
                verbose=args.verbose,
            )

            if args.fix and result.issues_found:
                logger.info(
                    "Issues found. Attempting to automatically fix common problems..."
                )
                from tools.hipaa.phi_audit.complete_phi_audit_fixer import (
                    fix_phi_issues,
                )

                fix_result = fix_phi_issues(
                    issues=result.issues, path=args.path, verbose=args.verbose
                )

                logger.info(
                    f"Fixed {fix_result.fixed_count} of {result.issues_found} issues"
                )

                # Re-run audit to verify fixes
                logger.info("Re-running audit to verify fixes...")
                result = run_phi_audit(
                    path=args.path,
                    output_file=args.output,
                    exclude_dirs=args.exclude,
                    verbose=args.verbose,
                )

            if result.issues_found > 0:
                logger.warning(
                    f"Found {result.issues_found} potential PHI leakage issues"
                )
                logger.info(f"See detailed report at: {args.output}")
                return 1
            else:
                logger.info("No PHI leakage issues found")
                return 0

        except ImportError as e:
            logger.error(f"Failed to import PHI audit modules: {str(e)}")
            return 2

    except Exception as e:
        # Sanitize exception message to avoid PHI leakage
        logger.error(f"Error during PHI audit: {type(e).__name__}")
        if args.verbose:
            # In verbose mode, show more details but still sanitize
            logger.error(f"Details: {str(e).replace('(', '[').replace(')', ']')}")
        return 3


def main() -> int:
    """Main entry point for PHI audit CLI."""
    parser = setup_parser()
    args = parser.parse_args()
    return run_audit(args)


if __name__ == "__main__":
    sys.exit(main())
