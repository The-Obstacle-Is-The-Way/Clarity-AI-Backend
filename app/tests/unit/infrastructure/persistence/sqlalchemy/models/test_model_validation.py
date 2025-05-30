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

    def test_model_imports(self) -> None:
        """Verify all required models can be imported successfully."""
        # If we get here, imports were successful
        assert DomainUser
        assert UserModel
        assert LegacyUserModel
        assert UserMapper

    def test_domain_to_persistence_mapping(self) -> None:
        """Test domain user can be properly mapped to persistence model."""
        # Create a domain user with the correct attribute names
        domain_user_attrs = {
            "id": str(uuid.uuid4()),
            "username": "test_user",
            "email": "test@example.com",
            "first_name": "Test",
            "last_name": "User",
            "roles": ["admin"],
            "is_active": True,
        }

        # Add the password attribute using the correct name based on the model
        if hasattr(DomainUser, "password_hash"):
            domain_user_attrs["password_hash"] = "hashed_password"
        else:
            domain_user_attrs["hashed_password"] = "hashed_password"

        # Create domain user
        domain_user = DomainUser(**domain_user_attrs)

        # Convert to persistence model
        persistence_model = UserMapper.to_persistence(domain_user)

        # Verify key attributes were properly mapped
        assert persistence_model.username == domain_user.username
        assert persistence_model.email == domain_user.email
        assert persistence_model.is_active == domain_user.is_active

        # Verify password was correctly mapped regardless of attribute name
        if hasattr(domain_user, "password_hash"):
            assert persistence_model.password_hash == domain_user.password_hash
        else:
            assert persistence_model.password_hash == domain_user.hashed_password

    def test_persistence_to_domain_mapping(self) -> None:
        """Test persistence model can be properly mapped back to domain entity."""
        # Create a persistence model
        user_id = str(uuid.uuid4())
        persistence_model = UserModel(
            id=user_id,
            username="test_user",
            email="test@example.com",
            password_hash="hashed_password",
            is_active=True,
        )

        # Add admin role
        persistence_model.roles = [UserRole.ADMIN]

        # Convert to domain model
        domain_user = UserMapper.to_domain(persistence_model)

        # Verify key attributes were properly mapped
        assert domain_user.id == user_id
        assert domain_user.username == persistence_model.username
        assert domain_user.email == persistence_model.email
        assert domain_user.is_active == persistence_model.is_active
        assert "admin" in domain_user.roles

        # Verify password was correctly mapped regardless of attribute name
        if hasattr(domain_user, "password_hash"):
            assert domain_user.password_hash == persistence_model.password_hash
        else:
            assert domain_user.hashed_password == persistence_model.password_hash

    def test_legacy_model_aliasing(self) -> None:
        """Verify legacy model is properly aliased to canonical model."""
        # Test creating an instance of UserModel
        import uuid

        from app.infrastructure.models.user_model import UserModel

        # Create a test user with the UserModel class
        test_id = uuid.uuid4()
        test_user = UserModel(
            id=test_id,
            username="test_legacy_alias",
            email="legacy_alias@example.com",
            hashed_password="test_password",
            is_active=True,
        )

        # Verify it's actually a User instance
        from app.infrastructure.persistence.sqlalchemy.models.user import User

        assert isinstance(test_user, User), "UserModel should create User instances"

        # Test identity or compatibility of values
        assert test_user.id == test_id
        assert test_user.username == "test_legacy_alias"
        assert test_user.email == "legacy_alias@example.com"
