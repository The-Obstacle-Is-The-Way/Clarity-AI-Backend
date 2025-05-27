#!/usr/bin/env python3
"""
Script to systematically fix linting issues in the Clarity-AI-Backend codebase.

This script provides tools to:
1. Scan the codebase for linting issues
2. Fix specific categories of issues
3. Report progress and remaining issues

It follows a phased approach to ensure high-quality fixes while maintaining
code functionality and HIPAA compliance.
"""

import argparse
import json
import subprocess
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, Any, Tuple


class FixPhase(str, Enum):
    """Phases for fixing linting issues."""

    IMPORTS = "imports"
    FORMATTING = "formatting"
    SECURITY = "security"
    EXCEPTIONS = "exceptions"
    UNUSED = "unused"
    TYPES = "types"
    ALL = "all"


# Configure paths
PROJECT_ROOT = Path(__file__).parent.parent.absolute()
APP_DIR = PROJECT_ROOT / "app"


def get_issue_counts(output: str) -> Dict[str, int]:
    """Extract issue counts from ruff output."""
    counts: Dict[str, int] = {}
    for line in output.split("\n"):
        parts = line.strip().split()
        if len(parts) >= 2 and parts[0].isdigit() and len(parts[1]) == 5 and parts[1][4] == " ":
            code = parts[1][:4]
            count = int(parts[0])
            counts[code] = count
    return counts


def run_command(cmd: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
    """Run a command and return returncode, stdout, stderr."""
    if cwd is None:
        cwd = PROJECT_ROOT

    result = subprocess.run(cmd, cwd=str(cwd), text=True, capture_output=True)
    return result.returncode, result.stdout, result.stderr


def run_ruff_check(
    select: str | None = None, fix: bool = False, path: str | None = None, show_fixes: bool = True
) -> tuple[int, str]:
    """Run ruff check with specified options."""
    cmd = ["python", "-m", "ruff", "check"]

    if select:
        cmd.extend(["--select", select])

    if fix:
        cmd.append("--fix")
        if show_fixes:
            cmd.append("--show-fixes")

    if path:
        cmd.append(path)
    else:
        cmd.append("app")

    returncode, stdout, stderr = run_command(cmd)
    return returncode, stdout + stderr


def run_black(check: bool = False, path: str | None = None) -> tuple[int, str]:
    """Run black formatter."""
    cmd = ["python", "-m", "black"]

    if check:
        cmd.append("--check")

    if path:
        cmd.append(path)
    else:
        cmd.append("app")

    returncode, stdout, stderr = run_command(cmd)
    return returncode, stdout + stderr


def run_isort(check: bool = False, path: str | None = None) -> tuple[int, str]:
    """Run isort to fix import ordering."""
    cmd = ["python", "-m", "isort"]

    if check:
        cmd.append("--check-only")

    if path:
        cmd.append(path)
    else:
        cmd.append("app")

    returncode, stdout, stderr = run_command(cmd)
    return returncode, stdout + stderr


def fix_import_issues(path: str | None = None) -> None:
    """Fix import-related issues."""
    print("Fixing import issues...")
    _, output = run_isort(path=path)
    print(f"isort output:\n{output}")

    # Fix import statements with ruff
    _, output = run_ruff_check(select="I", fix=True, path=path)
    print(f"Ruff import fixes:\n{output}")


def fix_formatting_issues(path: str | None = None) -> None:
    """Fix formatting issues with black."""
    print("Fixing formatting issues...")
    _, output = run_black(path=path)
    print(f"Black output:\n{output}")


def fix_security_issues(path: str | None = None) -> None:
    """Fix security-related issues."""
    print("Fixing security issues...")
    _, output = run_ruff_check(select="S", fix=True, path=path)
    print(f"Security fixes:\n{output}")


def fix_exception_issues(path: str | None = None) -> None:
    """Fix exception handling issues."""
    print("Fixing exception issues...")
    _, output = run_ruff_check(select="B904", fix=True, path=path)
    print(f"Exception handling fixes:\n{output}")


def fix_unused_code(path: str | None = None) -> None:
    """Fix unused imports and variables."""
    print("Fixing unused code...")
    _, output = run_ruff_check(select="F401,F841", fix=True, path=path)
    print(f"Unused code fixes:\n{output}")


def fix_type_annotations(path: str | None = None) -> None:
    """Fix type annotation issues."""
    print("Fixing type annotation issues...")
    # This uses the --unsafe-fixes option because type annotation fixes are considered unsafe
    cmd = ["python", "-m", "ruff", "check", "--select", "ANN", "--fix", "--unsafe-fixes"]

    if path:
        cmd.append(path)
    else:
        cmd.append("app")

    returncode, stdout, stderr = run_command(cmd)
    print(f"Type annotation fixes:\n{stdout + stderr}")


def generate_report() -> None:
    """Generate a detailed report of the current linting status."""
    print("Generating linting report...")
    report: Dict[str, Any] = {
        "timestamp": datetime.now().isoformat(),
        "ruff": {},
        "black": {},
        "isort": {},
    }

    # Run ruff with statistics
    cmd = ["python", "-m", "ruff", "check", "app", "--statistics"]
    returncode, stdout, stderr = run_command(cmd)
    report["ruff"]["returncode"] = returncode
    report["ruff"]["stats"] = get_issue_counts(stdout + stderr)

    # Run black in check mode
    returncode, output = run_black(check=True)
    report["black"]["returncode"] = returncode
    report["black"]["would_change"] = (
        output.count("would reformat") if "would reformat" in output else 0
    )

    # Run isort in check mode
    returncode, output = run_isort(check=True)
    report["isort"]["returncode"] = returncode
    report["isort"]["would_change"] = output.count("ERROR:") if "ERROR:" in output else 0

    # Save report to file
    report_path = PROJECT_ROOT / "lint_report.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"Lint report saved to {report_path}")

    # Print summary
    print("\nLinting Summary:")
    print(f"Ruff issues: {sum(report['ruff']['stats'].values())}")
    print(f"Black formatting issues: {report['black']['would_change']}")
    print(f"isort import ordering issues: {report['isort']['would_change']}")


def main() -> None:
    """Main function to orchestrate linting fixes."""
    parser = argparse.ArgumentParser(description="Fix linting issues in the codebase.")
    parser.add_argument(
        "--phase",
        type=str,
        choices=[p.value for p in FixPhase],
        default=FixPhase.ALL.value,
        help="Fix phase to run (default: all)",
    )
    parser.add_argument(
        "--path", type=str, help="Specific path to fix (default: entire app directory)"
    )
    parser.add_argument("--report", action="store_true", help="Generate a report of linting issues")
    args = parser.parse_args()

    if args.report:
        generate_report()
        return

    if args.phase == FixPhase.ALL.value:
        # Order matters here!
        fix_import_issues(args.path)
        fix_formatting_issues(args.path)
        fix_security_issues(args.path)
        fix_exception_issues(args.path)
        fix_unused_code(args.path)
        fix_type_annotations(args.path)
    elif args.phase == FixPhase.IMPORTS.value:
        fix_import_issues(args.path)
    elif args.phase == FixPhase.FORMATTING.value:
        fix_formatting_issues(args.path)
    elif args.phase == FixPhase.SECURITY.value:
        fix_security_issues(args.path)
    elif args.phase == FixPhase.EXCEPTIONS.value:
        fix_exception_issues(args.path)
    elif args.phase == FixPhase.UNUSED.value:
        fix_unused_code(args.path)
    elif args.phase == FixPhase.TYPES.value:
        fix_type_annotations(args.path)

    # Generate final report after fixes
    generate_report()


if __name__ == "__main__":
    main()
