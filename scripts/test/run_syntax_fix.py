#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Master Test Suite Syntax Fixer

This script orchestrates the syntax fixing process for test files:
1. Runs the enhanced syntax fixer for general issues
2. Runs targeted fixes for specific files with known issues
3. Applies direct fixes for remaining problematic files

Usage:
    python scripts/test/run_syntax_fix.py
"""

import os
import sys
import subprocess
import logging
import importlib.util
import ast
from typing import Dict, List, Optional, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("test_syntax_fix")

# Root directory handling
def get_project_root() -> str:
    """Get the project root directory (backend)"""
    current_dir = os.getcwd()
    if os.path.basename(current_dir) == "scripts" or os.path.basename(current_dir) == "test":
        return os.path.abspath(os.path.join(current_dir, "../.."))
    if os.path.basename(current_dir) == "backend":
        return current_dir
    return os.path.join(current_dir, "backend")

# File paths
PROJECT_ROOT = get_project_root()
TESTS_DIR = os.path.join(PROJECT_ROOT, "app", "tests")
SCRIPTS_DIR = os.path.join(PROJECT_ROOT, "scripts")
TOOLS_DIR = os.path.join(SCRIPTS_DIR, "test", "tools")

# Problematic files that need manual fixes
MANUAL_FIX_FILES = [
    "app/tests/unit/infrastructure/ml/pharmacogenomics/test_model_service_pgx.py",
    "app/tests/unit/infrastructure/ml/pharmacogenomics/test_treatment_model.py",
    "app/tests/unit/infrastructure/ml/symptom_forecasting/test_model_service_symptom.py",
    "app/tests/unit/infrastructure/ml/symptom_forecasting/test_ensemble_model.py",
    "app/tests/unit/infrastructure/ml/symptom_forecasting/test_transformer_model.py",
    "app/tests/unit/infrastructure/ml/biometric_correlation/test_model_service.py",
    "app/tests/unit/infrastructure/services/test_redis_cache_service.py",
    "app/tests/unit/infrastructure/cache/test_redis_cache.py",
    "app/tests/unit/presentation/api/v1/endpoints/test_biometric_endpoints.py",
]

def run_script(script_path: str, args: List[str] = None) -> Tuple[int, str]:
    """Run a Python script with arguments"""
    if args is None:
        args = []
    
    cmd = [sys.executable, script_path] + args
    logger.info(f"Running: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            text=True,
            check=False
        )
        output = result.stdout + result.stderr
        return result.returncode, output
    except Exception as e:
        logger.error(f"Error running script {script_path}: {str(e)}")
        return 1, str(e)

def fix_specific_file(file_path: str) -> bool:
    """Apply targeted fixes to specific problematic files"""
    full_path = os.path.join(PROJECT_ROOT, file_path)
    
    if not os.path.exists(full_path):
        logger.warning(f"File not found: {file_path}")
        return False
    
    logger.info(f"Applying manual fix to {file_path}")
    
    try:
        with open(full_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Try to parse to see if it already works
        try:
            ast.parse(content)
            logger.info(f"File already has valid syntax: {file_path}")
            return True
        except SyntaxError as e:
            logger.info(f"Found syntax error at line {e.lineno}: {e.msg}")
            
        # First check if it's a simple missing colon issue
        if "expected ':'" in str(e):
            return fix_missing_colon(full_path, e.lineno)
            
        # Check for indentation issues
        if "unexpected indent" in str(e) or "expected an indented block" in str(e):
            return fix_indentation_issue(full_path, e.lineno)
            
        # Apply custom fixes based on file path
        if "test_model_service_pgx.py" in file_path:
            return fix_model_service_pgx(full_path)
        elif "test_treatment_model.py" in file_path:
            return fix_treatment_model(full_path)
        elif "test_model_service_symptom.py" in file_path:
            return fix_model_service_symptom(full_path)
        elif "test_ensemble_model.py" in file_path:
            return fix_ensemble_model(full_path)
        elif "test_transformer_model.py" in file_path:
            return fix_transformer_model(full_path)
        elif "test_model_service.py" in file_path:
            return fix_model_service(full_path)
        elif "test_redis_cache_service.py" in file_path:
            return fix_redis_cache_service(full_path)
        elif "test_redis_cache.py" in file_path:
            return fix_redis_cache(full_path)
        elif "test_biometric_endpoints.py" in file_path:
            return fix_biometric_endpoints(full_path)
        else:
            logger.warning(f"No specific fix defined for {file_path}")
            return False
            
    except Exception as e:
        logger.error(f"Error fixing {file_path}: {str(e)}")
        return False

def fix_missing_colon(file_path: str, line_num: int) -> bool:
    """Fix a missing colon at a specific line"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        # Line numbers are 1-based in error messages but 0-based in lists
        line_index = line_num - 1
        if line_index < 0 or line_index >= len(lines):
            logger.warning(f"Line {line_num} out of range for file: {file_path}")
            return False
            
        # Add the missing colon if it's not there
        if not lines[line_index].rstrip().endswith(':'):
            lines[line_index] = lines[line_index].rstrip() + ":\n"
            logger.info(f"Added missing colon to line {line_num}")
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(lines)
                
            # Verify the fix worked
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            try:
                ast.parse(content)
                logger.info(f"Successfully fixed missing colon in {file_path}")
                return True
            except SyntaxError as e:
                logger.warning(f"Fixed colon but file still has syntax errors: {str(e)}")
                return False
        else:
            logger.info(f"Line {line_num} already has a colon")
            return False
            
    except Exception as e:
        logger.error(f"Error fixing colon in {file_path}: {str(e)}")
        return False
        
def fix_indentation_issue(file_path: str, line_num: int) -> bool:
    """Fix indentation issues around a specific line"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        # Check if the previous line ends with a colon (suggesting a block start)
        if line_num >= 2 and lines[line_num-2].strip().endswith(':'):
            if not lines[line_num-1].startswith(' ') and not lines[line_num-1].startswith('\t'):
                # Need to indent this line
                lines[line_num-1] = '    ' + lines[line_num-1]
                logger.info(f"Added indentation to line {line_num}")
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.writelines(lines)
                    
                # Verify the fix worked
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                try:
                    ast.parse(content)
                    logger.info(f"Successfully fixed indentation in {file_path}")
                    return True
                except SyntaxError as e:
                    logger.warning(f"Fixed indentation but file still has syntax errors: {str(e)}")
                    return False
                    
        logger.warning(f"Could not determine proper indentation fix for line {line_num}")
        return False
    
    except Exception as e:
        logger.error(f"Error fixing indentation in {file_path}: {str(e)}")
        return False

# Specific fixes for remaining problematic files

def fix_model_service_pgx(file_path: str) -> bool:
    """Fix test_model_service_pgx.py"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        # Line 19 needs a colon
        if len(lines) >= 19:
            lines[18] = lines[18].rstrip() + ":\n"
            logger.info("Fixed ModelServicePGX class definition")
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            
            # Verify
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            try:
                ast.parse(content)
                logger.info("Successfully fixed test_model_service_pgx.py")
                return True
            except SyntaxError:
                logger.warning("Failed to fix test_model_service_pgx.py")
                return False
                
    except Exception as e:
        logger.error(f"Error fixing test_model_service_pgx.py: {str(e)}")
        return False

def fix_treatment_model(file_path: str) -> bool:
    """Fix test_treatment_model.py"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        # Line 17 needs a colon
        if len(lines) >= 17:
            lines[16] = lines[16].rstrip() + ":\n"
            logger.info("Fixed TreatmentModel class definition")
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            
            # Verify
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            try:
                ast.parse(content)
                logger.info("Successfully fixed test_treatment_model.py")
                return True
            except SyntaxError:
                logger.warning("Failed to fix test_treatment_model.py")
                return False
                
    except Exception as e:
        logger.error(f"Error fixing test_treatment_model.py: {str(e)}")
        return False

def fix_model_service_symptom(file_path: str) -> bool:
    """Fix test_model_service_symptom.py"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        # Line 18 needs a colon
        if len(lines) >= 18:
            lines[17] = lines[17].rstrip() + ":\n"
            logger.info("Fixed ModelServiceSymptom class definition")
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            
            # Verify
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            try:
                ast.parse(content)
                logger.info("Successfully fixed test_model_service_symptom.py")
                return True
            except SyntaxError:
                logger.warning("Failed to fix test_model_service_symptom.py")
                return False
                
    except Exception as e:
        logger.error(f"Error fixing test_model_service_symptom.py: {str(e)}")
        return False

def fix_ensemble_model(file_path: str) -> bool:
    """Fix test_ensemble_model.py"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        # Line 17 needs a colon
        if len(lines) >= 17:
            lines[16] = lines[16].rstrip() + ":\n"
            logger.info("Fixed EnsembleModel class definition")
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            
            # Verify
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            try:
                ast.parse(content)
                logger.info("Successfully fixed test_ensemble_model.py")
                return True
            except SyntaxError:
                logger.warning("Failed to fix test_ensemble_model.py")
                return False
                
    except Exception as e:
        logger.error(f"Error fixing test_ensemble_model.py: {str(e)}")
        return False

def fix_transformer_model(file_path: str) -> bool:
    """Fix test_transformer_model.py"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        # Line 17 needs a colon
        if len(lines) >= 17:
            lines[16] = lines[16].rstrip() + ":\n"
            logger.info("Fixed TransformerModel class definition")
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            
            # Verify
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            try:
                ast.parse(content)
                logger.info("Successfully fixed test_transformer_model.py")
                return True
            except SyntaxError:
                logger.warning("Failed to fix test_transformer_model.py")
                return False
                
    except Exception as e:
        logger.error(f"Error fixing test_transformer_model.py: {str(e)}")
        return False

def fix_model_service(file_path: str) -> bool:
    """Fix test_model_service.py"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        # Line 18 needs a colon
        if len(lines) >= 18:
            lines[17] = lines[17].rstrip() + ":\n"
            logger.info("Fixed ModelService class definition")
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            
            # Verify
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            try:
                ast.parse(content)
                logger.info("Successfully fixed test_model_service.py")
                return True
            except SyntaxError:
                logger.warning("Failed to fix test_model_service.py")
                return False
                
    except Exception as e:
        logger.error(f"Error fixing test_model_service.py: {str(e)}")
        return False

def fix_redis_cache_service(file_path: str) -> bool:
    """Fix test_redis_cache_service.py"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # This file has invalid syntax at line 56
        # Replace class content with proper syntax
        # This is a more complex fix that might require analysis of the specific issue
        
        # For simple demonstration, let's do a full replace of the problematic area
        content_lines = content.split('\n')
        
        # Check if line 56 contains an async method without a proper def
        if len(content_lines) >= 56 and "async" in content_lines[55] and "def" not in content_lines[55]:
            # Add the missing 'def' keyword
            content_lines[55] = content_lines[55].replace("async", "async def")
            logger.info("Fixed missing 'def' in async method")
            
            # Join the lines back
            fixed_content = '\n'.join(content_lines)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(fixed_content)
            
            # Verify
            try:
                ast.parse(fixed_content)
                logger.info("Successfully fixed test_redis_cache_service.py")
                return True
            except SyntaxError as e:
                logger.warning(f"Failed to fix test_redis_cache_service.py: {str(e)}")
                return False
                
        logger.warning("Could not identify the specific issue in test_redis_cache_service.py")
        return False
        
    except Exception as e:
        logger.error(f"Error fixing test_redis_cache_service.py: {str(e)}")
        return False

def fix_redis_cache(file_path: str) -> bool:
    """Fix test_redis_cache.py"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # This file has invalid syntax at line 39
        # Similar issues as the redis cache service
        
        content_lines = content.split('\n')
        
        # Check if line 39 contains an async method without a proper def
        if len(content_lines) >= 39 and "async" in content_lines[38] and "def" not in content_lines[38]:
            # Add the missing 'def' keyword
            content_lines[38] = content_lines[38].replace("async", "async def")
            logger.info("Fixed missing 'def' in async method")
            
            # Join the lines back
            fixed_content = '\n'.join(content_lines)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(fixed_content)
            
            # Verify
            try:
                ast.parse(fixed_content)
                logger.info("Successfully fixed test_redis_cache.py")
                return True
            except SyntaxError as e:
                logger.warning(f"Failed to fix test_redis_cache.py: {str(e)}")
                return False
                
        logger.warning("Could not identify the specific issue in test_redis_cache.py")
        return False
        
    except Exception as e:
        logger.error(f"Error fixing test_redis_cache.py: {str(e)}")
        return False

def fix_biometric_endpoints(file_path: str) -> bool:
    """Fix test_biometric_endpoints.py"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # This file has invalid syntax at line 44
        content_lines = content.split('\n')
        
        # Check if line 44 contains the invalid syntax
        if len(content_lines) >= 44:
            # Inspect and fix the line based on its structure
            line = content_lines[43]  # 0-based index for line 44
            
            # If it's a missing colon after a function definition
            if "def test_" in line and not line.strip().endswith(':'):
                content_lines[43] = line.rstrip() + ":"
                logger.info("Added missing colon to test function definition")
                
                # Join the lines back
                fixed_content = '\n'.join(content_lines)
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(fixed_content)
                
                # Verify
                try:
                    ast.parse(fixed_content)
                    logger.info("Successfully fixed test_biometric_endpoints.py")
                    return True
                except SyntaxError as e:
                    logger.warning(f"Failed to fix test_biometric_endpoints.py: {str(e)}")
                    return False
                    
        logger.warning("Could not identify the specific issue in test_biometric_endpoints.py")
        return False
        
    except Exception as e:
        logger.error(f"Error fixing test_biometric_endpoints.py: {str(e)}")
        return False

def main():
    """Main function to run the script"""
    logger.info("Starting test suite syntax fix process")
    
    # 1. Run the enhanced syntax fixer
    enhanced_fixer_path = os.path.join(TOOLS_DIR, "enhanced_syntax_fixer.py")
    logger.info(f"Running enhanced syntax fixer from {enhanced_fixer_path}")
    
    ret_code, output = run_script(enhanced_fixer_path)
    if ret_code != 0:
        logger.warning("Enhanced syntax fixer encountered issues")
    logger.info(f"Enhanced fixer output:\n{output}")
    
    # 2. Run the specific file fixer
    specific_fixer_path = os.path.join(TOOLS_DIR, "fix_specific_test_files.py")
    logger.info(f"Running specific file fixer from {specific_fixer_path}")
    
    ret_code, output = run_script(specific_fixer_path)
    if ret_code != 0:
        logger.warning("Specific file fixer encountered issues")
    logger.info(f"Specific fixer output:\n{output}")
    
    # 3. Apply manual fixes for files that still have issues
    logger.info("Applying manual fixes for remaining problematic files")
    
    fixed_count = 0
    failed_count = 0
    
    for file_path in MANUAL_FIX_FILES:
        if fix_specific_file(file_path):
            fixed_count += 1
        else:
            failed_count += 1
    
    # Final report
    logger.info("\nFix Summary:")
    logger.info(f"Successfully fixed: {fixed_count} files")
    logger.info(f"Failed to fix: {failed_count} files")
    
    if failed_count > 0:
        logger.info("Some files still need manual inspection and fixes.")
        return 1
    else:
        logger.info("All targeted files were fixed successfully.")
        return 0

if __name__ == "__main__":
    sys.exit(main())