import os, re

def fix_syntax_errors(file_path):
    try:
        with open(file_path, "r") as file:
            content = file.read()
        
        # Fix leading commas in class definitions or imports
        modified = re.sub(r"^\s*,\s*(class|import|from)", r"\1", content, flags=re.MULTILINE)
        
        # Fix fixture indentation issues (docstring return on same line)
        modified = re.sub(r"(\"\"\".*?\"\"\"\s*)(\s*return\s+)", r"\1\n    \2", modified, flags=re.DOTALL)
        
        if modified != content:
            with open(file_path, "w") as file:
                file.write(modified)
            return True
        return False
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False

def fix_files_in_directory(directory):
    fixed_count = 0
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                if fix_syntax_errors(file_path):
                    fixed_count += 1
                    print(f"Fixed syntax in: {file_path}")
    return fixed_count

test_dir = "app/tests"
fixed = fix_files_in_directory(test_dir)
print(f"Total files with syntax fixed: {fixed}")

