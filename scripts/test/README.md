# Test Suite Syntax Repair Tools

This directory contains tools for repairing syntax errors in test files. These tools are designed to address the syntax errors identified in our test suite during the migration process.

## Available Tools

### 1. Enhanced Syntax Fixer

`enhanced_syntax_fixer.py` - A general-purpose tool that automatically detects and fixes common syntax errors:

- Missing colons after function/class declarations
- Indentation issues
- Other common Python syntax errors

**Usage:**
```bash
python scripts/test/tools/enhanced_syntax_fixer.py
```

### 2. Specific Test File Fixer

`fix_specific_test_files.py` - A targeted tool that applies fixes to specific files known to have issues:

- Fixes files from a predefined list of problematic files
- Applies custom fixes for known error patterns

**Usage:**
```bash
python scripts/test/tools/fix_specific_test_files.py
```

### 3. Master Syntax Fix Runner

`run_syntax_fix.py` - A comprehensive tool that orchestrates the entire fixing process:

- Runs the enhanced syntax fixer
- Applies the specific file fixer
- Implements direct manual fixes for stubborn files that need specialized attention

**Usage:**
```bash
python scripts/test/run_syntax_fix.py
```

## How to Fix Test Files

For most cases, the recommended approach is to use the master syntax fix runner:

1. Navigate to your project root directory
2. Run the master script:
   ```bash
   cd /workspaces/Novamind-Backend-ONLY-TWINS/backend
   python scripts/test/run_syntax_fix.py
   ```
3. Review the output to see which files were fixed and which still need attention
4. For any files that couldn't be automatically fixed, you may need to edit them manually

## Verification

After running the syntax fixers, you can verify if the files can now be parsed correctly:

```bash
# Check a specific file
python -m py_compile app/tests/path/to/fixed_file.py

# Check all fixed files
find app/tests -name "*.py" -exec python -m py_compile {} \; 2>&1 | grep "SyntaxError"
```

If no syntax errors are reported, the files have been successfully fixed.

## Common Issues and Solutions

### Missing Colons

Look for function and class definitions without colons:

```python
# Incorrect
def test_something()
    assert True

# Correct
def test_something():
    assert True
```

### Indentation Issues

Fix indentation to follow consistent 4-space pattern:

```python
# Incorrect
def test_something():
assert True

# Correct
def test_something():
    assert True
```

### Async Method Definition

Make sure async methods have the `def` keyword:

```python
# Incorrect
async test_something():
    assert True

# Correct
async def test_something():
    assert True
```

## Troubleshooting

If you encounter issues with the syntax fixers:

1. Check the log output for detailed error messages
2. Try running the individual fixers separately to isolate the problem
3. For persistent issues, examine the problematic file manually

## Contributing

If you identify new patterns of syntax errors or want to improve the fixers:

1. Add new error patterns and their fixes to the appropriate script
2. Test your changes on a small subset of files first
3. Update this documentation with any new information