"""
Minimal verification script for SQLAlchemy custom types.

This script verifies that our custom SQLAlchemy types are correctly defined
and properly exported from the types package.
"""

import sys
import importlib

def check_types():
    """Verify that custom SQLAlchemy types can be imported and used correctly."""
    print("Verifying SQLAlchemy custom types...")
    
    # Try importing the types from the package
    try:
        from app.infrastructure.persistence.sqlalchemy.types import (
            GUID, 
            JSONEncodedDict, 
            StringListDecorator, 
            FloatListDecorator
        )
        print("✅ Successfully imported all custom types")
        
        # Print details about each type for verification
        for type_name, type_cls in [
            ("GUID", GUID),
            ("JSONEncodedDict", JSONEncodedDict),
            ("StringListDecorator", StringListDecorator),
            ("FloatListDecorator", FloatListDecorator)
        ]:
            print(f"  - {type_name}: {type_cls.__module__}.{type_cls.__name__}")
        
        return True
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {type(e).__name__}: {e}")
        return False

if __name__ == "__main__":
    success = check_types()
    sys.exit(0 if success else 1)
