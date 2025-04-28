#!/usr/bin/env python3
"""
Fix indentation issues in the rate limiting middleware test file
"""

with open('app/tests/unit/presentation/middleware/test_rate_limiting_middleware.py', 'r') as file:
    lines = file.readlines()

fixed_lines = []
for i, line in enumerate(lines):
    # Fix 'return' outside function issue for get method
    if i > 0 and i == 36 and lines[i].strip().startswith('return '):
        fixed_lines.append('        ' + line.lstrip())
    # Look for similar issues in the rest of the file
    elif line.strip().startswith('return ') and not line.startswith('        '):
        # This is likely a return statement with wrong indentation within a method
        fixed_lines.append('        ' + line.lstrip())
    else:
        fixed_lines.append(line)

with open('app/tests/unit/presentation/middleware/test_rate_limiting_middleware.py', 'w') as file:
    file.writelines(fixed_lines)

print("Fixed indentation issues in test_rate_limiting_middleware.py")
