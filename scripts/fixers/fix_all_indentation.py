#!/usr/bin/env python3
"""
Fix all indentation errors in the temporal neurotransmitter test
"""
import re

file_path = 'app/tests/venv/test_temporal_neurotransmitter_analysis.py'

with open(file_path, 'r') as file:
    content = file.read()

# Fix all instances of unindented return statements after if statements
# Pattern 1: Empty dataframe check at line ~174
content = re.sub(r'(\s+if\s+df\.empty:\s*\n)(\s+)return', r'\1\2            return', content)

# Pattern 2: Other timeframe check around line ~194
content = re.sub(r'(\s+if\s+df\.empty:\s*\n)(\s+)return', r'\1\2            return', content)

# Pattern 3: Empty check at line ~446
content = re.sub(r'(\s+if\s+df1\.empty\s+or\s+df2\.empty:\s*\n)(\s+)return', r'\1\2            return', content)

# Pattern 4: Another empty check at line ~461
content = re.sub(r'(\s+if\s+df1\.empty\s+or\s+df2\.empty:\s*\n)(\s+)return', r'\1\2            return', content)

# Pattern 5: Not enough points check at line ~489
content = re.sub(r'(\s+if\s+df_merged\.empty\s+or.+:\s*\n)(\s+)return', r'\1\2            return', content)

# Manual replacement for specific instances
patterns = [
    (r'if df.empty:\n        return', 'if df.empty:\n            return'),
    (r'if df.empty:\n            # Return empty DataFrame with correct columns\n        return', 
     'if df.empty:\n            # Return empty DataFrame with correct columns\n            return'),
    (r'if df1.empty or df2.empty:\n        return', 'if df1.empty or df2.empty:\n            return'),
    (r'if df_merged.empty or len(df_merged) < 3:  # Need at least 3 points for correlation\n        return',
     'if df_merged.empty or len(df_merged) < 3:  # Need at least 3 points for correlation\n            return')
]

for pattern, replacement in patterns:
    content = content.replace(pattern, replacement)

with open(file_path, 'w') as file:
    file.write(content)

print(f"Fixed all indentation errors in {file_path}")
