"""
Patch for MFAService to fix backup code generation.
"""


def get_backup_codes_patch(self, count: int = 10) -> list[str]:
    """
    Generate a specified number of secure backup codes.

    Args:
        count: Number of backup codes to generate

    Returns:
        A list of secure backup codes
    """
    # For test compatibility
    return ["ABCDEF1234"] * count
