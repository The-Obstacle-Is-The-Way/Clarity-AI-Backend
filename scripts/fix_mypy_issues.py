#!/usr/bin/env python3
"""
Script to systematically fix mypy typing issues in the Clarity-AI-Backend codebase.

This script provides tools to:
1. Scan the codebase for typing issues
2. Generate missing type annotations
3. Fix common typing errors
4. Report progress and remaining issues
"""

import argparse
import json
import re
import subprocess
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# Configure paths
PROJECT_ROOT = Path(__file__).parent.parent.absolute()
APP_DIR = PROJECT_ROOT / "app"


def run_command(cmd: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
    """Run a command and return returncode, stdout, stderr."""
    if cwd is None:
        cwd = PROJECT_ROOT

    result = subprocess.run(cmd, cwd=str(cwd), text=True, capture_output=True)
    return result.returncode, result.stdout, result.stderr


def run_mypy(path: str | None = None) -> tuple[int, str]:
    """Run mypy type checker with specified options."""
    cmd = ["python", "-m", "mypy"]

    if path:
        cmd.append(path)
    else:
        cmd.append("app")

    returncode, stdout, stderr = run_command(cmd)
    return returncode, stdout + stderr


def parse_mypy_output(output: str) -> dict[str, list[dict]]:
    """Parse mypy output and group errors by file."""
    errors_by_file = defaultdict(list)

    for line in output.split("\n"):
        if not line or ":" not in line:
            continue

        # Typical format: file.py:line: error: message
        parts = line.split(":", 3)
        if len(parts) < 4:
            continue

        file_path = parts[0]
        try:
            line_num = int(parts[1])
            error_type = parts[2].strip()
            message = parts[3].strip()

            errors_by_file[file_path].append(
                {"line": line_num, "type": error_type, "message": message}
            )
        except (ValueError, IndexError):
            continue

    return dict(errors_by_file)


def analyze_typing_issues(issues: dict[str, list[dict]]) -> dict:
    """Analyze typing issues to identify patterns and frequencies."""
    analysis = {
        "total_files": len(issues),
        "total_issues": sum(len(file_issues) for file_issues in issues.values()),
        "issue_types": defaultdict(int),
        "files_by_issue_count": [],
        "common_patterns": defaultdict(int),
    }

    # Count issue types
    for file_path, file_issues in issues.items():
        for issue in file_issues:
            # Extract error category from message
            message = issue["message"]
            analysis["issue_types"][message] += 1

            # Look for common patterns
            if "has no attribute" in message:
                analysis["common_patterns"]["missing_attribute"] += 1
            elif "is not subscriptable" in message:
                analysis["common_patterns"]["not_subscriptable"] += 1
            elif "has incompatible type" in message:
                analysis["common_patterns"]["incompatible_type"] += 1
            elif "has no return type specified" in message:
                analysis["common_patterns"]["missing_return_type"] += 1
            elif "parameter has no annotation" in message:
                analysis["common_patterns"]["missing_param_type"] += 1

    # Sort files by issue count
    analysis["files_by_issue_count"] = sorted(
        [(file_path, len(issues)) for file_path, issues in issues.items()],
        key=lambda x: x[1],
        reverse=True,
    )

    # Convert defaultdicts to regular dicts for JSON serialization
    analysis["issue_types"] = dict(analysis["issue_types"])
    analysis["common_patterns"] = dict(analysis["common_patterns"])

    return analysis


def generate_typing_report(output: str) -> None:
    """Generate a detailed report of typing issues."""
    print("Generating typing report...")
    issues = parse_mypy_output(output)
    analysis = analyze_typing_issues(issues)

    report = {"timestamp": datetime.now().isoformat(), "mypy_issues": issues, "analysis": analysis}

    # Save report to file
    report_path = PROJECT_ROOT / "typing_report.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"Typing report saved to {report_path}")

    # Print summary
    print("\nTyping Issues Summary:")
    print(f"Total files with issues: {analysis['total_files']}")
    print(f"Total typing issues: {analysis['total_issues']}")
    print("\nCommon patterns:")
    for pattern, count in analysis["common_patterns"].items():
        print(f"  {pattern}: {count}")

    print("\nTop files by issue count:")
    for file_path, count in analysis["files_by_issue_count"][:10]:  # Show top 10
        print(f"  {file_path}: {count}")


def fix_return_types(file_path: str, issues: list[dict]) -> None:
    """Add missing return type annotations."""
    print(f"Adding return types to {file_path}...")

    # Read the file
    with open(file_path) as f:
        lines = f.readlines()

    # Track modified lines to avoid duplicate modifications
    modified_lines = set()

    for issue in issues:
        if "has no return type specified" not in issue["message"]:
            continue

        line_num = issue["line"] - 1  # 0-indexed
        if line_num in modified_lines or line_num >= len(lines):
            continue

        line = lines[line_num]

        # Simple heuristic: add -> Any to function definitions
        if re.search(r"def\s+\w+\s*\([^)]*\)\s*:", line):
            modified_line = re.sub(r"(def\s+\w+\s*\([^)]*\))\s*:", r"\1 -> Any:", line)
            lines[line_num] = modified_line
            modified_lines.add(line_num)

    # Write back the modified file if changes were made
    if modified_lines:
        # Insert import for Any if needed
        if "from typing import Any" not in "".join(lines[:20]):
            # Find typing imports
            import_inserted = False
            for i, line in enumerate(lines[:20]):
                if re.search(r"from\s+typing\s+import", line):
                    # Add Any to existing typing import
                    if "Any" not in line:
                        lines[i] = line.rstrip()
                        if line.rstrip().endswith(","):
                            lines[i] += " Any,\n"
                        else:
                            lines[i] = re.sub(r"import\s+(.+)$", r"import \1, Any", lines[i]) + "\n"
                    import_inserted = True
                    break

            # If no typing import found, add one
            if not import_inserted:
                # Find the right position after other imports
                for i, line in enumerate(lines[:20]):
                    if (
                        line.strip()
                        and not line.strip().startswith("import")
                        and not line.strip().startswith("from")
                    ):
                        lines.insert(i, "from typing import Any\n\n")
                        break

        with open(file_path, "w") as f:
            f.writelines(lines)


def fix_parameter_types(file_path: str, issues: list[dict]) -> None:
    """Add missing parameter type annotations."""
    print(f"Adding parameter types to {file_path}...")

    # Read the file
    with open(file_path) as f:
        lines = f.readlines()

    # Track modified lines to avoid duplicate modifications
    modified_lines = set()

    for issue in issues:
        if "parameter has no annotation" not in issue["message"]:
            continue

        line_num = issue["line"] - 1  # 0-indexed
        if line_num in modified_lines or line_num >= len(lines):
            continue

        line = lines[line_num]

        # Extract parameter name from message
        match = re.search(r"'(\w+)' parameter has no annotation", issue["message"])
        if not match:
            continue

        param_name = match.group(1)

        # Simple heuristic: add ': Any' to the parameter
        pattern = rf"(\b{param_name}\b)(?!\s*:)"
        if re.search(pattern, line):
            modified_line = re.sub(pattern, r"\1: Any", line)
            lines[line_num] = modified_line
            modified_lines.add(line_num)

    # Write back the modified file if changes were made
    if modified_lines:
        # Insert import for Any if needed
        if "from typing import Any" not in "".join(lines[:20]) and "Any" not in "".join(lines[:20]):
            # Find typing imports
            import_inserted = False
            for i, line in enumerate(lines[:20]):
                if re.search(r"from\s+typing\s+import", line):
                    # Add Any to existing typing import
                    lines[i] = line.rstrip()
                    if line.rstrip().endswith(","):
                        lines[i] += " Any,\n"
                    else:
                        lines[i] = re.sub(r"import\s+(.+)$", r"import \1, Any", lines[i]) + "\n"
                    import_inserted = True
                    break

            # If no typing import found, add one
            if not import_inserted:
                # Find the right position after other imports
                for i, line in enumerate(lines[:20]):
                    if (
                        line.strip()
                        and not line.strip().startswith("import")
                        and not line.strip().startswith("from")
                    ):
                        lines.insert(i, "from typing import Any\n\n")
                        break

        with open(file_path, "w") as f:
            f.writelines(lines)


def main():
    """Main function to orchestrate typing fixes."""
    parser = argparse.ArgumentParser(description="Fix typing issues in the codebase.")
    parser.add_argument(
        "--path", type=str, help="Specific path to fix (default: entire app directory)"
    )
    parser.add_argument(
        "--report-only", action="store_true", help="Generate a report without fixing issues"
    )
    parser.add_argument(
        "--fix-returns", action="store_true", help="Fix missing return type annotations"
    )
    parser.add_argument(
        "--fix-params", action="store_true", help="Fix missing parameter type annotations"
    )
    parser.add_argument("--fix-all", action="store_true", help="Fix all supported typing issues")
    args = parser.parse_args()

    # Run mypy and get issues
    returncode, output = run_mypy(args.path)

    if args.report_only or (not args.fix_returns and not args.fix_params and not args.fix_all):
        # Just generate a report if requested or if no specific fixes selected
        generate_typing_report(output)
        return

    issues = parse_mypy_output(output)

    # Apply selected fixes
    for file_path, file_issues in issues.items():
        if args.fix_returns or args.fix_all:
            fix_return_types(file_path, file_issues)

        if args.fix_params or args.fix_all:
            fix_parameter_types(file_path, file_issues)

    # Run mypy again to check results
    returncode, output = run_mypy(args.path)
    generate_typing_report(output)


if __name__ == "__main__":
    main()
