import re

from app.core.utils.phi_sanitizer import PHISanitizer

# Test cases from test file
test_cases = [
    # Phone
    ("Phone: (555) 123-4567", "Phone number with parentheses"),
    ("Call me at 555-123-4567", "Phone number with dashes"),
    ("International: +1 555 123 4567", "International phone number"),
]

# Print current pattern
print(f"Current phone pattern: {PHISanitizer.PHI_PATTERNS['phone'].pattern}")

# Test each case
for text, description in test_cases:
    match = PHISanitizer.PHI_PATTERNS["phone"].search(text)
    print(f"\nTesting: {description}")
    print(f"Input: {text}")
    print(f"Match: {match.group(0) if match else 'NO MATCH'}")

    # Try alternative patterns
    print("\n\nTESTING ALTERNATIVE PATTERNS:")

    patterns = [
        # More specific pattern for phone numbers with parentheses
        r"\(\d{3}\)\s*\d{3}-\d{4}",
        # General pattern for various phone formats
        r"(?:\+\d{1,2}\s*)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
        # Explicit patterns for all test cases
        r"(?:\(\d{3}\)\s*\d{3}-\d{4}|\d{3}-\d{3}-\d{4}|\+\d{1,2}\s\d{3}\s\d{3}\s\d{4})",
    ]

    for i, pattern in enumerate(patterns):
        print(f"\nAlternative pattern {i + 1}: {pattern}")
        for text, description in test_cases:
            match = re.search(pattern, text)
            print(f"  {description}: {match.group(0) if match else 'NO MATCH'}")
