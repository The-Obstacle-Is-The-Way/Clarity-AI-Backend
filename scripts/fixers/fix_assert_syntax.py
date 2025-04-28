import os, re

def fix_assert_calls(file_path):
    with open(file_path, "r") as file:
        content = file.read()
    
    # Replace the problematic patterns
    modified = re.sub(r"\.assert _called_once_with", ".assert_called_once_with", content)
    modified = re.sub(r"\.assert _called_with", ".assert_called_with", modified)
    modified = re.sub(r"\.assert _called_once\(", ".assert_called_once(", modified)
    modified = re.sub(r"\.assert _called\(", ".assert_called(", modified)
    
    # Only write to the file if changes were made
    if modified != content:
        with open(file_path, "w") as file:
            file.write(modified)
        return True
    return False

def fix_files_in_directory(directory):
    fixed_count = 0
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                if fix_assert_calls(file_path):
                    fixed_count += 1
                    print(f"Fixed: {file_path}")
    return fixed_count

# Fix the test files
test_dir = "app/tests"
fixed = fix_files_in_directory(test_dir)
print(f"Total files fixed: {fixed}")

