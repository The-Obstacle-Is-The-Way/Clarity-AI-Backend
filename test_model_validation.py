"""
Basic test script to verify our User model consolidation.
"""
import sys
import os
import uuid
from datetime import datetime

# Add app directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import our models
from app.domain.entities.user import User as DomainUser
from app.infrastructure.persistence.sqlalchemy.models.user import User as UserModel, UserRole
from app.infrastructure.models.user_model import UserModel as LegacyUserModel
from app.infrastructure.persistence.sqlalchemy.mappers.user_mapper import UserMapper

# Verify model imports
print("Testing model imports...")
print("✅ Domain User imported successfully")
print("✅ SQLAlchemy User imported successfully")
print("✅ Legacy UserModel proxy imported successfully")
print("✅ UserMapper imported successfully")

# Create a domain user
print("\nCreating domain user...")
domain_user = DomainUser(
    id=str(uuid.uuid4()),
    username="test_user",
    email="test@example.com",
    hashed_password="hashed_password",
    is_active=True,
    roles=["admin"]
)
print(f"✅ Domain user created: {domain_user}")

# Convert to persistence model
print("\nConverting domain user to persistence model...")
persistence_model = UserMapper.to_persistence(domain_user)
print(f"✅ Persistence model created: {persistence_model}")

# Convert back to domain
print("\nConverting back to domain user...")
converted_domain_user = UserMapper.to_domain(persistence_model)
print(f"✅ Converted back to domain user: {converted_domain_user}")

# Verify legacy model alias
print("\nVerifying legacy model is an alias to canonical model...")
assert UserModel is LegacyUserModel, "Legacy UserModel should be an alias to canonical UserModel"
print("✅ Legacy UserModel is an alias to canonical UserModel")

print("\nAll tests passed! User model consolidation is working.")
