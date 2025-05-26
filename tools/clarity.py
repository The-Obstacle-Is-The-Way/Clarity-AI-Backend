#!/usr/bin/env python3
"""
Clarity Digital Twin Platform CLI

This is the central entrypoint for all Clarity Digital Twin Platform tools.
It provides a unified command-line interface for various development,
maintenance, and security operations.
"""

import argparse
import importlib
import logging
import sys
from typing import Any, cast

# Configure logging with no sensitive information
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("clarity")

# Define available commands
COMMANDS: dict[str, dict[str, Any]] = {
    "refactor": {
        "description": "Refactor the codebase according to clean architecture",
        "module": "tools.refactor.refactor_code_structure",
        "function": "main",
    },
    "phi-audit": {
        "description": "Scan codebase for potential PHI leakage",
        "module": "tools.hipaa.phi_audit.cli",
        "function": "main",
    },
    "verify-types": {
        "description": "Verify SQLAlchemy types are correctly defined",
        "module": "scripts.verify_types",
        "function": "main",
    },
}


def setup_parser() -> argparse.ArgumentParser:
    """Set up the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Clarity Digital Twin Platform CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Add subparsers for each command
    for cmd, info in COMMANDS.items():
        cmd_parser = subparsers.add_parser(cmd, help=info["description"])
        cmd_parser.add_argument(
            "--help-full",
            action="store_true",
            help=f"Show full help for the {cmd} command",
        )

    return parser


def run_command(command: str, args: list[str]) -> int:
    """
    Run the specified command with the given arguments.

    Args:
        command: The command to run
        args: Command-line arguments to pass to the command

    Returns:
        Exit code from the command
    """
    if command not in COMMANDS:
        logger.error(f"Unknown command: {command}")
        return 1

    command_info = COMMANDS[command]

    try:
        # Import the module
        module = importlib.import_module(command_info["module"])

        # Get the entry point function
        func = getattr(module, command_info["function"])

        # Run the function
        sys.argv = [command_info["module"]] + args
        return cast(int, func())

    except ImportError as e:
        logger.error(f"Failed to import {command_info['module']}: {e!s}")
        return 2

    except AttributeError:
        logger.error(f"Function {command_info['function']} not found in {command_info['module']}")
        return 3

    except Exception as e:
        # Sanitize exception message to avoid PHI leakage
        logger.error(f"Error executing {command}: {type(e).__name__}")
        logger.error(f"Details: {str(e).replace('(', '[').replace(')', ']')}")
        return 4


def show_full_help(command: str) -> int:
    """
    Show the full help for a specific command.

    Args:
        command: The command to show help for

    Returns:
        Exit code (0 for success)
    """
    if command not in COMMANDS:
        logger.error(f"Unknown command: {command}")
        return 1

    command_info = COMMANDS[command]

    try:
        # Import the module
        module = importlib.import_module(command_info["module"])

        # Call the module with --help
        sys.argv = [command_info["module"], "--help"]

        # Get the entry point function
        func = getattr(module, command_info["function"])

        # Run the function
        return cast(int, func())

    except Exception as e:
        logger.error(f"Error showing help for {command}: {e!s}")
        return 1


def show_commands() -> None:
    """Show the list of available commands."""
    logger.info("Available commands:")
    for cmd, info in COMMANDS.items():
        logger.info(f"  {cmd:<15} - {info['description']}")
    logger.info("\nFor more information about a command, run: clarity.py <command> --help-full")


def main() -> int:
    """Main entry point for the CLI."""
    parser = setup_parser()
    args, remaining = parser.parse_known_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if not args.command:
        parser.print_help()
        show_commands()
        return 0

    # Check if we should show detailed help for a command
    if "--help-full" in remaining:
        return show_full_help(args.command)

    # Run the specified command
    return run_command(args.command, remaining)


if __name__ == "__main__":
    sys.exit(main())
