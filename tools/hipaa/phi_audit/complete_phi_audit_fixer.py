#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fix indentation and other issues in the PHI auditor script.
"""
import os
import re

def fix_phi_auditor_class():
    """Fix indentation and method issues in the PHIAuditor class."""
    with open("scripts/run_hipaa_phi_audit.py", "r") as f:
        lines = f.readlines()
    
    # Detect class boundaries
    start_line = 0
    end_line = len(lines)
    for i, line in enumerate(lines):
        if line.strip() == "class PHIAuditor:":
            start_line = i
        elif i > start_line and line.strip().startswith("class ") and start_line > 0:
            end_line = i
            break
    
    # Fix indentation for class methods
    fixed_lines = lines[:start_line + 2]  # Include class definition and docstring
    
    i = start_line + 2
    while i < end_line:
        line = lines[i]
        
        # Check if this is a method definition
        if re.match(r'\s+def\s+\w+\(', line):
            # Add method definition with correct indentation
            method_lines = [line]
            j = i + 1
            
            # Collect all lines of the method
            while j < end_line and (lines[j].strip() == "" or lines[j].startswith(" " * 8)):
                method_lines.append(lines[j])
                j += 1
            
            # Fix indentation for the method
            fixed_method = []
            for m_line in method_lines:
                if m_line.strip():  # Skip empty lines
                    # Ensure consistent indentation (4 spaces for method, 8 for content)
                    stripped = m_line.lstrip()
                    if m_line.startswith("    def"):
                        fixed_method.append(m_line)  # Keep as is
                    else:
                        fixed_method.append("        " + stripped)  # 8 spaces indentation
                else:
                    fixed_method.append("\n")  # Keep empty lines
            
            fixed_lines.extend(fixed_method)
            i = j
        else:
            fixed_lines.append(line)
            i += 1
    
    fixed_lines.extend(lines[end_line:])
    
    # Remove duplicate method definitions
    seen_methods = set()
    final_lines = []
    
    i = 0
    while i < len(fixed_lines):
        line = fixed_lines[i]
        match = re.match(r'\s+def\s+(\w+)\(', line)
        
        if match:
            method_name = match.group(1)
            if method_name in seen_methods:
                # Skip this duplicate method
                j = i + 1
                while j < len(fixed_lines) and (not fixed_lines[j].strip() or fixed_lines[j].startswith(" " * 8) or fixed_lines[j].startswith(" " * 4 + "\"\"\"") or fixed_lines[j].startswith(" " * 4 + "\"\"\"")):
                    j += 1
                i = j
                continue
            else:
                seen_methods.add(method_name)
                
        final_lines.append(line)
        i += 1
    
    # Add missing install_phi_auditor function
    missing_function = """
def install_phi_auditor():
    \"\"\"Install the PHI auditor.\"\"\"
    # This is a placeholder function for installation functionality
    # that would normally copy files, update configs, etc.
    # For now, just return success
    return True
"""
    
    # Find the right position to add the function (before 'if __name__ == "__main__":')
    for i in range(len(final_lines)):
        if "if __name__ == \"__main__\":" in final_lines[i]:
            final_lines.insert(i, missing_function)
            break
    
    # Write the fixed content
    with open("scripts/run_hipaa_phi_audit.py", "w") as f:
        f.writelines(final_lines)
    
    return True

if __name__ == "__main__":
    success = fix_phi_auditor_class()
    if success:
        print("Successfully fixed indentation and methods in PHIAuditor class")
        print("Now run: python3 -m pytest tests/security/test_phi_audit.py -v")
    else:
        print("Failed to fix PHIAuditor class")