#!/usr/bin/env python3
"""
Fix indentation errors in the main temporal neurotransmitter test
"""

file_path = 'app/tests/venv/test_temporal_neurotransmitter_analysis.py'

with open(file_path, 'r') as file:
    content = file.read()

# Fix the indentation error around line 138 for the return statement
# Find the pattern where we have a comment about empty DataFrame followed by a return statement at wrong indentation
fixed_content = content.replace("        if not readings:\n            # Return empty DataFrame with correct columns\n        return pd.DataFrame", 
                               "        if not readings:\n            # Return empty DataFrame with correct columns\n            return pd.DataFrame")

with open(file_path, 'w') as file:
    file.write(fixed_content)

print(f"Fixed indentation errors in {file_path}")
