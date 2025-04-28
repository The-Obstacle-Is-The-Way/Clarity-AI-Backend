"""
SQLAlchemy implementation of the BiometricRuleRepository for the Novamind platform.

This module provides a concrete implementation of the BiometricRuleRepository interface
using SQLAlchemy as the ORM for database interactions. It handles the translation 
between domain entities and database models.
"""

from typing import List, Optional, Tuple, Dict, Any
from uuid import UUID

from sqlalchemy import select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import text

from app.domain.entities.biometric_rule import BiometricRule, AlertPriority
from app.domain.exceptions import RepositoryError, EntityNotFoundError
from app.domain.repositories.biometric_rule_repository import BiometricRuleRepository
from app.infrastructure.persistence.sqlalchemy.models.biometric_rule import BiometricRuleModel
from app.infrastructure.persistence.sqlalchemy.mappers.biometric_rule_mapper import map_rule_model_to_entity, map_rule_entity_to_model


class SQLAlchemyBiometricRuleRepository(BiometricRuleRepository):
    """SQLAlchemy implementation of the BiometricRuleRepository."""

    def __init__(self, session: AsyncSession):
        """
        Initialize the repository with a database session.
        
        Args:
            session: SQLAlchemy async session for database operations
        """
        self.session = session

    async def save(self, rule: BiometricRule) -> BiometricRule:
        """
        Save a biometric rule to the database.
        
        Args:
            rule: The biometric rule to save
            
        Returns:
            The saved biometric rule with any updates (e.g., ID assignment)
            
        Raises:
            RepositoryError: If there's an error saving the rule
        """
        try:
            # Map domain entity to database model
            rule_model = map_rule_entity_to_model(rule)
            
            # Add and commit
            self.session.add(rule_model)
            await self.session.commit()
            await self.session.refresh(rule_model)
            
            # Map back to domain entity and return
            return map_rule_model_to_entity(rule_model)
        except Exception as e:
            await self.session.rollback()
            raise RepositoryError(f"Error saving biometric rule: {str(e)}")

    async def get_by_id(self, rule_id: UUID) -> Optional[BiometricRule]:
        """
        Retrieve a biometric rule by its ID.
        
        Args:
            rule_id: ID of the rule to retrieve
            
        Returns:
            The biometric rule if found, None otherwise
            
        Raises:
            RepositoryError: If there's an error retrieving the rule
        """
        try:
            # Query for the rule
            stmt = select(BiometricRuleModel).where(BiometricRuleModel.id == rule_id)
            result = await self.session.execute(stmt)
            rule_model = result.scalar_one_or_none()
            
            # Return None if not found
            if not rule_model:
                return None
            
            # Map to domain entity and return
            return map_rule_model_to_entity(rule_model)
        except Exception as e:
            raise RepositoryError(f"Error retrieving biometric rule: {str(e)}")

    async def get_by_patient_id(self, patient_id: UUID) -> List[BiometricRule]:
        """
        Retrieve all biometric rules for a specific patient.
        
        Args:
            patient_id: ID of the patient
            
        Returns:
            List of biometric rules for the patient
            
        Raises:
            RepositoryError: If there's an error retrieving the rules
        """
        try:
            # Query for rules by patient_id
            stmt = select(BiometricRuleModel).where(BiometricRuleModel.patient_id == patient_id)
            result = await self.session.execute(stmt)
            rule_models = result.scalars().all()
            
            # Map to domain entities and return
            return [map_rule_model_to_entity(model) for model in rule_models]
        except Exception as e:
            raise RepositoryError(f"Error retrieving biometric rules for patient: {str(e)}")

    async def get_all_active(self) -> List[BiometricRule]:
        """
        Retrieve all active biometric rules.
        
        Returns:
            List of active biometric rules
            
        Raises:
            RepositoryError: If there's an error retrieving the rules
        """
        try:
            # Query for active rules
            stmt = select(BiometricRuleModel).where(BiometricRuleModel.is_active == True)
            result = await self.session.execute(stmt)
            rule_models = result.scalars().all()
            
            # Map to domain entities and return
            return [map_rule_model_to_entity(model) for model in rule_models]
        except Exception as e:
            raise RepositoryError(f"Error retrieving active biometric rules: {str(e)}")

    async def update(self, rule: BiometricRule) -> BiometricRule:
        """
        Update an existing biometric rule.
        
        Args:
            rule: The biometric rule with updated values
            
        Returns:
            The updated biometric rule
            
        Raises:
            RepositoryError: If there's an error updating the rule
            EntityNotFoundError: If the rule doesn't exist
        """
        try:
            # Check if rule exists
            existing_rule = await self.get_by_id(rule.id)
            if not existing_rule:
                raise EntityNotFoundError(f"Biometric rule with ID {rule.id} not found")
            
            # Map entity to model
            rule_model = map_rule_entity_to_model(rule)
            
            # Update in database
            stmt = (
                update(BiometricRuleModel)
                .where(BiometricRuleModel.id == rule.id)
                .values(**{
                    key: getattr(rule_model, key) 
                    for key in rule_model.__dict__ 
                    if not key.startswith('_')
                })
                .execution_options(synchronize_session="fetch")
            )
            await self.session.execute(stmt)
            await self.session.commit()
            
            # Return updated entity
            return rule
        except EntityNotFoundError:
            raise
        except Exception as e:
            await self.session.rollback()
            raise RepositoryError(f"Error updating biometric rule: {str(e)}")

    async def delete(self, rule_id: UUID) -> bool:
        """
        Delete a biometric rule.
        
        Args:
            rule_id: ID of the rule to delete
            
        Returns:
            True if the rule was deleted, False otherwise
            
        Raises:
            RepositoryError: If there's an error deleting the rule
        """
        try:
            # Check if rule exists
            existing_rule = await self.get_by_id(rule_id)
            if not existing_rule:
                return False
            
            # Delete from database
            stmt = delete(BiometricRuleModel).where(BiometricRuleModel.id == rule_id)
            await self.session.execute(stmt)
            await self.session.commit()
            
            return True
        except Exception as e:
            await self.session.rollback()
            raise RepositoryError(f"Error deleting biometric rule: {str(e)}")

    async def get_rules(
        self, 
        patient_id: Optional[UUID] = None, 
        page: int = 1, 
        page_size: int = 20
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        Get a paginated list of biometric rules.
        
        Args:
            patient_id: Optional filter by patient ID
            page: Page number for pagination
            page_size: Number of items per page
            
        Returns:
            Tuple of (rules list, total count)
            
        Raises:
            RepositoryError: If there's an error retrieving the rules
        """
        try:
            # Build base query
            stmt = select(BiometricRuleModel)
            
            # Apply filters
            if patient_id:
                stmt = stmt.where(BiometricRuleModel.patient_id == patient_id)
                
            # Get total count
            count_stmt = select(text("COUNT(*)")).select_from(stmt.alias())
            count_result = await self.session.execute(count_stmt)
            total = count_result.scalar_one()
            
            # Apply pagination
            offset = (page - 1) * page_size
            stmt = stmt.offset(offset).limit(page_size)
            
            # Execute and get results
            result = await self.session.execute(stmt)
            rule_models = result.scalars().all()
            
            # Convert to dicts for API response
            rules = []
            for model in rule_models:
                entity = map_rule_model_to_entity(model)
                rules.append({
                    "rule_id": str(entity.id),
                    "name": entity.name,
                    "description": entity.description,
                    "priority": entity.alert_priority,
                    "conditions": entity.conditions,
                    "logical_operator": entity.logical_operator,
                    "is_active": entity.is_active,
                    "patient_id": str(entity.patient_id) if entity.patient_id else None,
                    "created_at": entity.created_at,
                    "updated_at": entity.updated_at,
                    "provider_id": str(entity.provider_id) if entity.provider_id else None,
                    "metadata": entity.metadata
                })
            
            return rules, total
        except Exception as e:
            raise RepositoryError(f"Error retrieving biometric rules: {str(e)}")

    async def create_rule(self, rule: BiometricRule) -> Dict[str, Any]:
        """
        Create a new biometric rule.
        
        Args:
            rule: The biometric rule to create
            
        Returns:
            Dictionary representation of the created rule
            
        Raises:
            RepositoryError: If there's an error creating the rule
        """
        try:
            # Save the rule
            saved_rule = await self.save(rule)
            
            # Convert to dict for API response
            return {
                "rule_id": str(saved_rule.id),
                "name": saved_rule.name,
                "description": saved_rule.description,
                "priority": saved_rule.alert_priority,
                "conditions": saved_rule.conditions,
                "logical_operator": saved_rule.logical_operator,
                "is_active": saved_rule.is_active,
                "patient_id": str(saved_rule.patient_id) if saved_rule.patient_id else None,
                "created_at": saved_rule.created_at,
                "updated_at": saved_rule.updated_at,
                "provider_id": str(saved_rule.provider_id) if saved_rule.provider_id else None,
                "metadata": saved_rule.metadata
            }
        except Exception as e:
            raise RepositoryError(f"Error creating biometric rule: {str(e)}")

    async def update_rule(self, rule: BiometricRule) -> Dict[str, Any]:
        """
        Update an existing biometric rule.
        
        Args:
            rule: The biometric rule with updated values
            
        Returns:
            Dictionary representation of the updated rule
            
        Raises:
            RepositoryError: If there's an error updating the rule
            EntityNotFoundError: If the rule doesn't exist
        """
        try:
            # Update the rule
            updated_rule = await self.update(rule)
            
            # Convert to dict for API response
            return {
                "rule_id": str(updated_rule.id),
                "name": updated_rule.name,
                "description": updated_rule.description,
                "priority": updated_rule.alert_priority,
                "conditions": updated_rule.conditions,
                "logical_operator": updated_rule.logical_operator,
                "is_active": updated_rule.is_active,
                "patient_id": str(updated_rule.patient_id) if updated_rule.patient_id else None,
                "created_at": updated_rule.created_at,
                "updated_at": updated_rule.updated_at,
                "provider_id": str(updated_rule.provider_id) if updated_rule.provider_id else None,
                "metadata": updated_rule.metadata
            }
        except Exception as e:
            if isinstance(e, EntityNotFoundError):
                raise
            raise RepositoryError(f"Error updating biometric rule: {str(e)}")

    async def delete_rule(self, rule_id: UUID) -> bool:
        """
        Delete a biometric rule.
        
        Args:
            rule_id: ID of the rule to delete
            
        Returns:
            True if the rule was deleted, False otherwise
            
        Raises:
            RepositoryError: If there's an error deleting the rule
        """
        return await self.delete(rule_id)
