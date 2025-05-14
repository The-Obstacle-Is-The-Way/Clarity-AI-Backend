"""
Type Verification Script for SQLAlchemy Custom Types

This script verifies that custom SQLAlchemy types are correctly defined
and properly exported from the types package, following clean architecture principles.
"""

import sys
import logging
from typing import Dict, List, Tuple, Type, Any, Optional
import importlib

# Configure logging with no sensitive information
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("type_verification")

class TypeVerifier:
    """Type verification service following clean architecture principles."""
    
    def __init__(self) -> None:
        """Initialize the type verifier."""
        self.type_paths: Dict[str, str] = {
            "GUID": "app.infrastructure.persistence.sqlalchemy.types",
            "JSONEncodedDict": "app.infrastructure.persistence.sqlalchemy.types",
            "StringListDecorator": "app.infrastructure.persistence.sqlalchemy.types",
            "FloatListDecorator": "app.infrastructure.persistence.sqlalchemy.types"
        }
    
    def verify_types(self) -> bool:
        """
        Verify that custom SQLAlchemy types can be imported and used correctly.
        
        Returns:
            bool: True if all types are verified successfully, False otherwise.
        """
        logger.info("Verifying SQLAlchemy custom types...")
        
        imported_types: Dict[str, Any] = {}
        success = True
        
        # Try importing each type individually to isolate failures
        for type_name, module_path in self.type_paths.items():
            try:
                module = importlib.import_module(module_path)
                type_cls = getattr(module, type_name)
                imported_types[type_name] = type_cls
                logger.info(f"✅ Successfully imported {type_name}")
            except ImportError as e:
                logger.error(f"❌ Import error for {type_name}: {str(e).replace('(', '[').replace(')', ']')}")
                success = False
            except AttributeError as e:
                logger.error(f"❌ Type {type_name} not found in module {module_path}")
                success = False
            except Exception as e:
                # Sanitize exception message to prevent possible PHI leakage
                logger.error(f"❌ Unexpected error importing {type_name}: {type(e).__name__}")
                success = False
        
        # Print details about successfully imported types
        if imported_types:
            logger.info("Imported type details:")
            for type_name, type_cls in imported_types.items():
                logger.info(f"  - {type_name}: {type_cls.__module__}.{type_cls.__name__}")
        
        return success

def main() -> int:
    """
    Main entry point for the script.
    
    Returns:
        int: Exit code (0 for success, 1 for failure)
    """
    verifier = TypeVerifier()
    success = verifier.verify_types()
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
