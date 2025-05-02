"""
User Model Validation Tests

This test suite validates the proper consolidation of User model representations
across domain, persistence, and legacy layers to ensure clean architecture alignment.
"""
import uuid

# Import our models
from app.domain.entities.user import User as DomainUser
from app.infrastructure.models.user_model import UserModel as LegacyUserModel
from app.infrastructure.persistence.sqlalchemy.mappers.user_mapper import UserMapper
from app.infrastructure.persistence.sqlalchemy.models.user import User as UserModel
from app.infrastructure.persistence.sqlalchemy.models.user import UserRole


class TestUserModelValidation:
    """Test suite for user model validation and proper mapping between layers."""

    def test_model_imports(self):
        """Verify all required models can be imported successfully."""
        # If we get here, imports were successful
        assert DomainUser
        assert UserModel
        assert LegacyUserModel
        assert UserMapper

    def test_domain_to_persistence_mapping(self):
        """Test domain user can be properly mapped to persistence model."""
        # Create a domain user
        domain_user = DomainUser(
            id=str(uuid.uuid4()),
            username="test_user",
            email="test@example.com",
            hashed_password="hashed_password",
            is_active=True,
            roles=["admin"]
        )
        
        # Convert to persistence model
        persistence_model = UserMapper.to_persistence(domain_user)
        
        # Verify key attributes were properly mapped
        assert persistence_model.username == domain_user.username
        assert persistence_model.email == domain_user.email
        assert persistence_model.hashed_password == domain_user.hashed_password
        assert persistence_model.is_active == domain_user.is_active

    def test_persistence_to_domain_mapping(self):
        """Test persistence model can be properly mapped back to domain entity."""
        # Create a persistence model
        user_id = str(uuid.uuid4())
        persistence_model = UserModel(
            id=user_id,
            username="test_user", 
            email="test@example.com",
            hashed_password="hashed_password",
            is_active=True
        )
        
        # Add admin role
        persistence_model.roles = [UserRole.ADMIN]
        
        # Convert to domain model
        domain_user = UserMapper.to_domain(persistence_model)
        
        # Verify key attributes were properly mapped
        assert domain_user.id == user_id
        assert domain_user.username == persistence_model.username
        assert domain_user.email == persistence_model.email
        assert domain_user.hashed_password == persistence_model.hashed_password
        assert domain_user.is_active == persistence_model.is_active
        assert "admin" in domain_user.roles

    def test_legacy_model_aliasing(self):
        """Verify legacy model is properly aliased to canonical model."""
        assert UserModel is LegacyUserModel, "Legacy UserModel should be an alias to canonical UserModel"
