#!/usr/bin/env python3
"""
Fix indentation issues in the digital twins test file
"""

with open('app/tests/unit/presentation/api/v1/endpoints/test_digital_twins.py', 'r') as file:
    lines = file.readlines()

fixed_lines = []
for i, line in enumerate(lines):
    # Fix extra indentation in return statements on lines 246, 278, and 308
    if i in [245, 277, 307] and line.strip().startswith('return {'):
        # These lines need 4 spaces instead of 8
        fixed_lines.append('    ' + line.lstrip())
    else:
        fixed_lines.append(line)

with open('app/tests/unit/presentation/api/v1/endpoints/test_digital_twins.py', 'w') as file:
    file.writelines(fixed_lines)

print("Fixed indentation issues in test_digital_twins.py")
