"""
Factory for creating and wiring mock Digital Twin components.
This simplifies the creation and configuration of the Digital Twin system.
"""
from typing import Dict, Optional, Tuple
from uuid import UUID

from app.domain.services.digital_twin_core_service import DigitalTwinCoreService
from app.domain.services.mentalllama_service import MentalLLaMAService
from app.domain.services.pat_service import PATService
from app.domain.services.xgboost_service import XGBoostService

from app.infrastructure.repositories.mock_digital_twin_repository import MockDigitalTwinRepository
from app.infrastructure.repositories.mock_patient_repository import MockPatientRepository
from app.infrastructure.services.mock_digital_twin_core_service import MockDigitalTwinCoreService
from app.infrastructure.services.mock_mentalllama_service import MockMentalLLaMAService
from app.infrastructure.services.mock_pat_service import MockPATService
from app.infrastructure.services.mock_xgboost_service import MockXGBoostService


class MockDigitalTwinFactory:
    """
    Factory for creating configured instances of the Digital Twin system.
    Uses the Factory pattern to simplify component creation and wiring.
    """
    
    @staticmethod
    def create_repositories() -> Tuple[MockDigitalTwinRepository, MockPatientRepository]:
        """
        Create the mock repositories needed for the Digital Twin.
        
        Returns:
            Tuple containing digital twin repository and patient repository
        """
        digital_twin_repository = MockDigitalTwinRepository()
        patient_repository = MockPatientRepository()
        
        return digital_twin_repository, patient_repository
    
    @staticmethod
    def create_ai_services() -> Tuple[MockXGBoostService, MockPATService, MockMentalLLaMAService]:
        """
        Create the mock AI services needed for the Digital Twin.
        
        Returns:
            Tuple containing XGBoost service, PAT service, and MentalLLaMA service
        """
        xgboost_service = MockXGBoostService()
        pat_service = MockPATService()
        mentalllama_service = MockMentalLLaMAService()
        
        return xgboost_service, pat_service, mentalllama_service
    
    @classmethod
    def create_digital_twin_core(cls) -> DigitalTwinCoreService:
        """
        Create a fully configured Digital Twin Core service with all dependencies.
        
        Returns:
            Configured Digital Twin Core service
        """
        # Create repositories
        digital_twin_repository, patient_repository = cls.create_repositories()
        
        # Create AI services
        xgboost_service, pat_service, mentalllama_service = cls.create_ai_services()
        
        # Create and return the core service
        return MockDigitalTwinCoreService(
            digital_twin_repository=digital_twin_repository,
            patient_repository=patient_repository,
            xgboost_service=xgboost_service,
            pat_service=pat_service,
            mentalllama_service=mentalllama_service
        )
    
    @classmethod
    def create_complete_system(cls) -> Dict:
        """
        Create a complete system with all components.
        
        Returns:
            Dictionary containing all system components
        """
        # Create repositories
        digital_twin_repository, patient_repository = cls.create_repositories()
        
        # Create AI services
        xgboost_service, pat_service, mentalllama_service = cls.create_ai_services()
        
        # Create core service
        digital_twin_core = MockDigitalTwinCoreService(
            digital_twin_repository=digital_twin_repository,
            patient_repository=patient_repository,
            xgboost_service=xgboost_service,
            pat_service=pat_service,
            mentalllama_service=mentalllama_service
        )
        
        # Return all components
        return {
            "repositories": {
                "digital_twin_repository": digital_twin_repository,
                "patient_repository": patient_repository
            },
            "services": {
                "xgboost_service": xgboost_service,
                "pat_service": pat_service,
                "mentalllama_service": mentalllama_service,
                "digital_twin_core": digital_twin_core
            }
        }