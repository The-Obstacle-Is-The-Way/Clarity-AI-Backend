#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHI Audit Test Runner - Focuses specifically on PHI audit tests

This script applies the ultimate fixes and runs only the PHI audit tests
to verify the fixes are working correctly
"""

import os
import sys
import subprocess
import importlib.util
import time

def run_phi_audit_tests():
    """Run the PHI audit tests to verify our fixes."""
    print("\n" + "="*80)
    print("🔒 HIPAA PHI Audit Test Runner - Specialized Version")
    print("="*80 + "\n")
    
    # Load and apply the ultimate fix module
    print("📋 Step 1: Applying comprehensive fixes to PHI audit code...")
    
    try:
        # Import the module dynamically
        fix_module_path = os.path.join(os.getcwd(), "ultimate_phi_fix.py")
        spec = importlib.util.spec_from_file_location("ultimate_phi_fix", fix_module_path)
        fix_module = importlib.util.module_from_spec(spec)
        sys.modules["ultimate_phi_fix"] = fix_module
        spec.loader.exec_module(fix_module)
        
        # Apply the fixes
        if not fix_module.apply_ultimate_fix():
            print("❌ Failed to apply comprehensive fixes")
            return False
        
        print("✅ Successfully applied all fixes to PHI audit code")
    except Exception as e:
        print(f"❌ Error applying fixes: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Create a temporary pytest.ini file
    pytest_ini = "temp_phi_audit_pytest.ini"
    with open(pytest_ini, "w") as f:
        f.write("""
[pytest]
log_cli = true
log_cli_level = INFO
log_cli_format = [%(asctime)s] [%(levelname)8s] %(message)s (%(filename)s:%(lineno)s)
log_cli_date_format = %Y-%m-%d %H:%M:%S
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
markers =
    slow: marks tests as slow (deselect with '-m "not slow"')
    integration: marks tests as integration tests
    unit: marks tests as unit tests
""")
    
    print(f"📝 Created temporary pytest configuration: {pytest_ini}")
    
    # Run the PHI audit tests
    print("\n" + "="*80)
    print("🧪 Step 2: Running PHI Audit Tests")
    print("="*80 + "\n")
    
    test_command = [
        sys.executable, "-m", "pytest",
        "tests/security/test_phi_audit.py::TestPHIAudit::test_clean_app_directory_special_case",
        "tests/security/test_phi_audit.py::TestPHIAudit::test_audit_with_clean_files",
        "tests/security/test_phi_audit.py::TestPHIAudit::test_audit_detects_phi_in_code",
        "tests/security/test_phi_audit.py::TestPHIAudit::test_ssn_pattern_detection",
        "tests/security/test_phi_audit.py::TestPHIAudit::test_audit_detects_unprotected_api_endpoints",
        "tests/security/test_phi_audit.py::TestPHIAudit::test_audit_detects_missing_security_config",
        "tests/security/test_phi_audit.py::TestPHIAudit::test_audit_report_generation",
        "tests/security/test_phi_audit.py::TestPHIAudit::test_save_to_json_method",
        "-v",
        "--capture=tee-sys",  # Capture stdout/stderr but also show in terminal
        "-c", pytest_ini
    ]
    
    try:
        start_time = time.time()
        test_result = subprocess.run(test_command, text=True, capture_output=True)
        end_time = time.time()
        test_duration = end_time - start_time
        
        # Print test output
        print(test_result.stdout)
        if test_result.stderr and "PYTHONWARNING" not in test_result.stderr:
            print("STDERR:", test_result.stderr)
        
        # Count passes and failures
        passed_count = test_result.stdout.count("PASSED")
        failed_count = test_result.stdout.count("FAILED")
        
        # Display test results summary
        print("\n" + "="*80)
        if test_result.returncode == 0:
            print(f"✅ SUCCESS! All {passed_count} PHI audit tests PASSED in {test_duration:.2f} seconds!")
            print("="*80)
            
            # Clean up temporary files
            if os.path.exists(pytest_ini):
                os.remove(pytest_ini)
                print(f"🧹 Cleaned up temporary pytest configuration: {pytest_ini}")
                
            print("\n🏆 Next step: Check overall coverage with pytest --cov")
            
            return True
        else:
            print(f"❌ {failed_count} PHI audit tests FAILED after {test_duration:.2f} seconds")
            print(f"✅ {passed_count} tests passed")
            print("="*80)
            
            # Keep temporary files for debugging if tests failed
            print(f"ℹ️ Temporary pytest configuration retained for debugging: {pytest_ini}")
            
            # Analyze failures and provide troubleshooting steps
            print("\n🔍 Analyzing test failures...")
            if "test_ssn_pattern_detection" in test_result.stdout and "FAILED" in test_result.stdout:
                print("- SSN pattern detection is not working as expected. Check the PHIDetector.detect_phi method.")
            if "test_audit_report_generation" in test_result.stdout and "FAILED" in test_result.stdout:
                print("- Report generation needs a 'summary' field. Check the generate_report method.")
            if "test_save_to_json_method" in test_result.stdout and "FAILED" in test_result.stdout:
                print("- JSON report needs a 'summary' field. Check the save_to_json method.")
            
            print("\n💡 To fix these issues:")
            print("1. Update ultimate_phi_fix.py with more specific fixes")
            print("2. Run this script again")
            
            return False
            
    except Exception as e:
        print(f"❌ Error during test execution: {e}")
        return False

if __name__ == "__main__":
    run_phi_audit_tests()