"""
Token Type Enum.

Defines the types of tokens used in the authentication system.
"""

from enum import Enum


class TokenType(str, Enum):
    """Token types used in the application."""

    ACCESS = "access"
    REFRESH = "refresh"
    RESET = "reset"  # For password reset
    ACTIVATE = "activate"  # For account activation
    API = "api"  # For long-lived API tokens with restricted permissions


def get_token_type(token_type_str: str) -> TokenType:
    for token_type in TokenType:
        if token_type.value == token_type_str:
            return token_type
    raise ValueError(f"Unknown token type: {token_type_str}")
