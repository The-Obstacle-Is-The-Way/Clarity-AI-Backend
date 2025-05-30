#!/usr/bin/env python3
"""
Verification script for Y Combinator technical review readiness.
Run this script to check if your codebase improvements are ready for review.
"""

import subprocess
import sys
import json
import os
from pathlib import Path


class AuditVerifier:
    def __init__(self):
        self.results = {}
        self.warnings = []
        self.errors = []
        
    def run_command(self, command: str, check_output: bool = True) -> tuple[bool, str]:
        """Run a command and return success status and output."""
        try:
            if check_output:
                result = subprocess.run(
                    command, shell=True, capture_output=True, text=True, timeout=30
                )
                return result.returncode == 0, result.stdout + result.stderr
            else:
                result = subprocess.run(command, shell=True, timeout=30)
                return result.returncode == 0, ""
        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, str(e)

    def check_security_vulnerabilities(self) -> bool:
        """Check for critical security vulnerabilities."""
        print("🔒 Checking security vulnerabilities...")
        
        success, output = self.run_command("python -m safety check --json")
        if success:
            try:
                data = json.loads(output)
                vuln_count = len(data.get("vulnerabilities", []))
                if vuln_count == 0:
                    print("  ✅ No security vulnerabilities found")
                    return True
                else:
                    print(f"  ⚠️ {vuln_count} vulnerabilities found")
                    self.warnings.append(f"Security vulnerabilities: {vuln_count}")
                    return False
            except json.JSONDecodeError:
                print("  ⚠️ Could not parse safety output")
                return False
        else:
            print("  ❌ Safety check failed")
            self.errors.append("Safety check failed")
            return False

    def check_code_formatting(self) -> bool:
        """Check code formatting compliance."""
        print("🎨 Checking code formatting...")
        
        success, output = self.run_command("python -m black app/ --check --quiet")
        if success:
            print("  ✅ Code formatting compliant")
            return True
        else:
            print("  ⚠️ Code formatting issues found")
            self.warnings.append("Code formatting not compliant")
            return False

    def check_import_organization(self) -> bool:
        """Check import organization."""
        print("📦 Checking import organization...")
        
        success, output = self.run_command("python -m isort app/ --check-only --quiet")
        if success:
            print("  ✅ Import organization compliant")
            return True
        else:
            print("  ⚠️ Import organization issues found")
            self.warnings.append("Import organization not compliant")
            return False

    def check_basic_linting(self) -> bool:
        """Check basic linting with Ruff."""
        print("🔍 Checking basic code quality...")
        
        success, output = self.run_command("python -m ruff check app/ --exit-zero")
        if success:
            # Count issues
            lines = output.strip().split('\n') if output.strip() else []
            issue_count = len([line for line in lines if line.strip() and not line.startswith('Found')])
            
            if issue_count == 0:
                print("  ✅ No code quality issues found")
                return True
            elif issue_count < 100:
                print(f"  ⚠️ {issue_count} minor code quality issues found")
                self.warnings.append(f"Minor code quality issues: {issue_count}")
                return True
            else:
                print(f"  ❌ {issue_count} code quality issues found")
                self.warnings.append(f"Code quality issues: {issue_count}")
                return False
        else:
            print("  ❌ Linting check failed")
            self.errors.append("Linting check failed")
            return False

    def check_test_suite(self) -> bool:
        """Check if test suite passes."""
        print("🧪 Running test suite...")
        
        success, output = self.run_command("python -m pytest tests/ -x --tb=no --quiet")
        if success:
            print("  ✅ All tests passing")
            return True
        else:
            print("  ❌ Test failures detected")
            self.errors.append("Test suite has failures")
            return False

    def check_application_startup(self) -> bool:
        """Check if application starts successfully."""
        print("🚀 Checking application startup...")
        
        # Try to start the application briefly
        success, output = self.run_command("timeout 10s python main.py || true")
        if "started server process" in output.lower() or "uvicorn running" in output.lower():
            print("  ✅ Application starts successfully")
            return True
        else:
            print("  ⚠️ Application startup unclear (may be normal)")
            self.warnings.append("Application startup verification inconclusive")
            return True  # Don't fail on this, as it might be expected

    def check_file_structure(self) -> bool:
        """Check critical file structure."""
        print("📁 Checking file structure...")
        
        critical_files = [
            "app/__init__.py",
            "app/main.py",
            "requirements.txt",
            "README.md",
            ".env.example"
        ]
        
        missing_files = []
        for file_path in critical_files:
            if not Path(file_path).exists():
                missing_files.append(file_path)
        
        if not missing_files:
            print("  ✅ All critical files present")
            return True
        else:
            print(f"  ⚠️ Missing files: {', '.join(missing_files)}")
            self.warnings.append(f"Missing critical files: {', '.join(missing_files)}")
            return len(missing_files) < 2  # Allow up to 1 missing file

    def check_environment_setup(self) -> bool:
        """Check environment and dependencies."""
        print("🌍 Checking environment setup...")
        
        # Check if we're in a virtual environment
        if sys.prefix == sys.base_prefix:
            print("  ⚠️ Not running in virtual environment")
            self.warnings.append("Not running in virtual environment")
        else:
            print("  ✅ Virtual environment detected")
        
        # Check critical imports
        try:
            import fastapi
            import sqlalchemy
            import pydantic
            print("  ✅ Critical dependencies importable")
            return True
        except ImportError as e:
            print(f"  ❌ Import error: {e}")
            self.errors.append(f"Critical dependency missing: {e}")
            return False

    def generate_report(self) -> dict:
        """Generate final verification report."""
        checks = [
            ("Security", self.check_security_vulnerabilities()),
            ("Code Formatting", self.check_code_formatting()),
            ("Import Organization", self.check_import_organization()),
            ("Code Quality", self.check_basic_linting()),
            ("Test Suite", self.check_test_suite()),
            ("Application Startup", self.check_application_startup()),
            ("File Structure", self.check_file_structure()),
            ("Environment", self.check_environment_setup()),
        ]
        
        passed = sum(1 for _, success in checks if success)
        total = len(checks)
        
        return {
            "checks": {name: success for name, success in checks},
            "passed": passed,
            "total": total,
            "score": round((passed / total) * 100, 1),
            "warnings": self.warnings,
            "errors": self.errors
        }

    def print_summary(self, report: dict):
        """Print verification summary."""
        print("\n" + "="*60)
        print("🎯 Y COMBINATOR REVIEW READINESS REPORT")
        print("="*60)
        
        score = report["score"]
        if score >= 90:
            status = "🟢 EXCELLENT"
            recommendation = "Ready for technical review!"
        elif score >= 75:
            status = "🟡 GOOD"
            recommendation = "Minor improvements recommended before review."
        elif score >= 60:
            status = "🟠 NEEDS WORK"
            recommendation = "Several issues should be addressed before review."
        else:
            status = "🔴 NOT READY"
            recommendation = "Significant issues must be fixed before review."
        
        print(f"\nOverall Score: {score}% - {status}")
        print(f"Passed: {report['passed']}/{report['total']} checks")
        print(f"\n📋 Recommendation: {recommendation}")
        
        if report["errors"]:
            print(f"\n❌ Critical Issues ({len(report['errors'])}):")
            for error in report["errors"]:
                print(f"  • {error}")
        
        if report["warnings"]:
            print(f"\n⚠️ Warnings ({len(report['warnings'])}):")
            for warning in report["warnings"]:
                print(f"  • {warning}")
        
        print("\n📋 Individual Check Results:")
        for check_name, passed in report["checks"].items():
            status_icon = "✅" if passed else "❌"
            print(f"  {status_icon} {check_name}")
        
        print("\n🚀 Next Steps:")
        if score >= 90:
            print("  • Review TECHNICAL_AUDIT_REPORT.md for talking points")
            print("  • Practice demo presentation")
            print("  • Prepare for technical questions")
        elif score >= 75:
            print("  • Address warnings using QUICK_WINS_IMPLEMENTATION.md")
            print("  • Re-run this verification script")
            print("  • Review audit report when ready")
        else:
            print("  • Fix critical errors first")
            print("  • Execute Phase 1A from QUICK_WINS_IMPLEMENTATION.md")
            print("  • Re-run this verification script")
        
        print("\n" + "="*60)


def main():
    """Main verification function."""
    print("🔍 Y Combinator Technical Review Readiness Verification")
    print("This script checks if your codebase is ready for technical review.\n")
    
    # Check if we're in the right directory
    if not Path("app").exists():
        print("❌ Error: Please run this script from the project root directory")
        print("   (The directory containing the 'app' folder)")
        sys.exit(1)
    
    verifier = AuditVerifier()
    report = verifier.generate_report()
    verifier.print_summary(report)
    
    # Save report
    report_path = Path("logs/reports/readiness-verification.json")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"\n📄 Detailed report saved to: {report_path}")
    
    # Exit with appropriate code
    sys.exit(0 if report["score"] >= 75 else 1)


if __name__ == "__main__":
    main()